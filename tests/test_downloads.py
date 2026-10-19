"""Tests for the authenticated export download (downloads.py).

The point of the view is that an export can only be fetched with a valid
login or a valid, unexpired signature for exactly that file — never by
merely knowing a link, as with the old /local/ files.
"""

from __future__ import annotations

import os
import secrets
import time
from datetime import timedelta
from http import HTTPStatus
from pathlib import Path

import pytest
from homeassistant.components.http.auth import async_sign_path
from homeassistant.core import HomeAssistant
from homeassistant.setup import async_setup_component
from homeassistant.util import dt as dt_util
from yarl import URL

from custom_components.smgw_han.const import DOMAIN, EXPORT_URL
from custom_components.smgw_han.downloads import (
    async_register_export_view,
    export_links,
    export_root,
    new_export_dir,
    remove_expired_exports,
    remove_legacy_www_exports,
    valid_until_label,
)


@pytest.fixture(autouse=True)
def _enable(enable_custom_integrations):
    yield


@pytest.fixture
async def view(hass: HomeAssistant) -> None:
    """http plus the export view, as async_setup provides them."""
    assert await async_setup_component(hass, "http", {})
    async_register_export_view(hass)


def _write_export(
    hass: HomeAssistant, name: str, data: bytes = b"zaehlerstaende"
) -> tuple[str, Path]:
    token, folder = new_export_dir(hass)
    folder.mkdir(parents=True)
    (folder / name).write_bytes(data)
    return token, folder


def _path(token: str, name: str) -> str:
    return f"{EXPORT_URL}/{token}/{name}"


# --- the view ------------------------------------------------------------


async def test_signed_link_downloads_the_file(
    hass: HomeAssistant, view, hass_client_no_auth
):
    """The links from the popup/notification work without any login."""
    token, _ = _write_export(hass, "Zaehlerstaende.csv", b"a;b\n1;2\n")
    links, valid_until = export_links(hass, token, {"csv": "Zaehlerstaende.csv"})
    client = await hass_client_no_auth()

    resp = await client.get(URL(links["csv"]).path_qs)

    assert resp.status == HTTPStatus.OK
    assert await resp.read() == b"a;b\n1;2\n"
    assert resp.headers["Content-Disposition"] == (
        'attachment; filename="Zaehlerstaende.csv"'
    )
    assert valid_until


async def test_unsigned_request_is_refused(
    hass: HomeAssistant, view, hass_client_no_auth
):
    """Knowing the path is no longer enough — that was the old /local/ flaw."""
    token, _ = _write_export(hass, "Zaehlerstaende.csv")
    client = await hass_client_no_auth()

    resp = await client.get(_path(token, "Zaehlerstaende.csv"))

    assert resp.status == HTTPStatus.UNAUTHORIZED


async def test_signature_does_not_transfer_to_another_file(
    hass: HomeAssistant, view, hass_client_no_auth
):
    """A leaked link opens its own file only, not a neighbouring export."""
    token_a, _ = _write_export(hass, "a.csv")
    token_b, _ = _write_export(hass, "b.csv")
    signed_a = URL(
        async_sign_path(hass, _path(token_a, "a.csv"), timedelta(hours=1))
    )
    client = await hass_client_no_auth()

    resp = await client.get(
        _path(token_b, "b.csv"), params={"authSig": signed_a.query["authSig"]}
    )

    assert resp.status == HTTPStatus.UNAUTHORIZED


async def test_expired_signature_is_refused(
    hass: HomeAssistant, view, hass_client_no_auth
):
    token, _ = _write_export(hass, "Zaehlerstaende.csv")
    expired = async_sign_path(
        hass, _path(token, "Zaehlerstaende.csv"), timedelta(seconds=-10)
    )
    client = await hass_client_no_auth()

    resp = await client.get(expired)

    assert resp.status == HTTPStatus.UNAUTHORIZED


async def test_logged_in_user_gets_404_for_unknown_file(
    hass: HomeAssistant, view, hass_client
):
    client = await hass_client()

    resp = await client.get(_path(secrets.token_urlsafe(16), "nothing.csv"))

    assert resp.status == HTTPStatus.NOT_FOUND


@pytest.mark.parametrize(
    "name",
    [
        "%2E%2E",  # ".." once aiohttp has decoded the segment
        ".hidden",
        "%2E",
    ],
)
async def test_dot_names_are_never_served(
    hass: HomeAssistant, view, hass_client, name
):
    """Even a logged-in user cannot step out of the export folder."""
    client = await hass_client()
    token, folder = _write_export(hass, "ok.csv")
    (folder / ".hidden").write_bytes(b"secret")

    resp = await client.get(f"{EXPORT_URL}/{token}/{name}")

    assert resp.status == HTTPStatus.NOT_FOUND


async def test_symlink_out_of_the_export_folder_is_not_followed(
    hass: HomeAssistant, view, hass_client, tmp_path
):
    """A link planted in the folder must not reach a file elsewhere."""
    outside = tmp_path / "secrets.yaml"
    outside.write_bytes(b"password: hunter2")
    token, folder = _write_export(hass, "ok.csv")
    (folder / "leak.csv").symlink_to(outside)
    client = await hass_client()

    resp = await client.get(_path(token, "leak.csv"))

    assert resp.status == HTTPStatus.NOT_FOUND


async def test_view_is_registered_only_once(hass: HomeAssistant, view):
    """async_setup may run again (e.g. in tests); a second view would clash."""
    async_register_export_view(hass)
    assert hass.data[DOMAIN]["export_view_registered"] is True


# --- link details ----------------------------------------------------------


async def test_export_dir_is_outside_www(hass: HomeAssistant):
    token, folder = new_export_dir(hass)
    assert folder == export_root(hass) / token
    assert "www" not in folder.relative_to(hass.config.config_dir).parts
    # 16 random bytes; every character is one the view accepts.
    assert len(token) >= 21
    assert set(token) <= set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
    )


async def test_valid_until_is_about_an_hour_ahead(hass: HomeAssistant, view):
    before = dt_util.now()
    _, valid_until = export_links(hass, "t", {"csv": "x.csv"})
    expires = dt_util.parse_datetime(valid_until)

    assert expires is not None
    assert timedelta(minutes=59) < expires - before <= timedelta(hours=1)


async def test_valid_until_label_cuts_off_the_minute(hass: HomeAssistant):
    await hass.config.async_set_time_zone("Europe/Berlin")

    assert valid_until_label("2026-10-19T14:37:59+02:00") == "14:37"
    assert valid_until_label("2026-10-19T12:37:59+00:00") == "14:37"
    assert valid_until_label(None) == ""
    assert valid_until_label("") == ""
    assert valid_until_label("not a time") == ""


# --- cleanup -----------------------------------------------------------------


def test_remove_expired_exports_keeps_fresh_ones(tmp_path: Path):
    root = tmp_path / "smgw_han_exports"
    old = root / "old"
    fresh = root / "fresh"
    for folder in (old, fresh):
        folder.mkdir(parents=True)
        (folder / "x.csv").write_bytes(b"1")
    now = time.time()
    os.utime(old, (now - 7200, now - 7200))
    # Neither stray files nor links in the root are ours to delete.
    (root / "note.txt").write_bytes(b"keep")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    os.utime(elsewhere, (now - 7200, now - 7200))
    (root / "link").symlink_to(elsewhere, target_is_directory=True)

    removed = remove_expired_exports(root, now, 3600)

    assert removed == 1
    assert not old.exists()
    assert fresh.is_dir()
    assert (root / "note.txt").exists()
    assert elsewhere.is_dir()


def test_remove_expired_exports_without_folder(tmp_path: Path):
    assert remove_expired_exports(tmp_path / "missing", time.time(), 3600) == 0


def test_legacy_www_folder_is_removed_but_www_stays(tmp_path: Path):
    legacy = tmp_path / "www" / "smgw_han_exports" / "abc"
    legacy.mkdir(parents=True)
    (legacy / "Zaehlerstaende.csv").write_bytes(b"1")
    (tmp_path / "www" / "community").mkdir()

    assert remove_legacy_www_exports(str(tmp_path)) is True

    assert not (tmp_path / "www" / "smgw_han_exports").exists()
    assert (tmp_path / "www" / "community").is_dir()
    assert remove_legacy_www_exports(str(tmp_path)) is False


async def test_setup_takes_down_the_old_public_exports(hass: HomeAssistant):
    """Upgrading must close the hole in existing installs, not only the code."""
    legacy = Path(hass.config.path("www", "smgw_han_exports", "abc"))
    await hass.async_add_executor_job(
        lambda: legacy.mkdir(parents=True, exist_ok=True)
    )

    assert await async_setup_component(hass, DOMAIN, {})
    await hass.async_block_till_done()

    assert not legacy.parent.exists()
    assert hass.data[DOMAIN]["export_view_registered"] is True
