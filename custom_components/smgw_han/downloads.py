"""Authenticated download of the export files.

Up to 3.6.x the exports were written under ``<config>/www/`` and linked as
``/local/…`` — a folder Home Assistant serves to anyone, without logging in.
They now live in ``<config>/smgw_han_exports/<token>/``, which HA does not
publish, and are handed out by :class:`SmgwExportView`, which requires
authentication.

A click on a link in the export popup or a notification carries no login, so
each link is signed with ``async_sign_path``: the signature stands in for the
login, binds the exact file path, and expires after ``EXPORT_LINK_LIFETIME``.
HA keeps its signing secret in memory only, so a restart ends every
outstanding link early as well.

The files themselves are removed once a day, right after the scheduled meter
fetch (see the coordinator) — by then their links have long expired.
"""

from __future__ import annotations

import logging
import re
import secrets
import shutil
import time
from http import HTTPStatus
from pathlib import Path

from aiohttp import hdrs, web
from homeassistant.components.http.auth import async_sign_path
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.http import KEY_HASS, HomeAssistantView
from homeassistant.helpers.network import NoURLAvailableError, get_url
from homeassistant.util import dt as dt_util

from .const import (
    DOMAIN,
    EXPORT_DIR,
    EXPORT_LINK_LIFETIME,
    EXPORT_URL,
    LEGACY_WWW_EXPORT_DIR,
)

_LOGGER = logging.getLogger(__name__)

# Exactly what secrets.token_urlsafe and services._sanitize can produce. The
# filename may not start with a dot, so "." / ".." / hidden files are never
# addressable; the resolved path is checked against the export root on top.
_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
_FILENAME_RE = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]{0,254}")

_VIEW_REGISTERED = "export_view_registered"


def export_root(hass: HomeAssistant) -> Path:
    """The folder holding one sub-folder per export."""
    return Path(hass.config.path(EXPORT_DIR))


def new_export_dir(hass: HomeAssistant) -> tuple[str, Path]:
    """A fresh export folder and its token (the folder name)."""
    token = secrets.token_urlsafe(16)
    return token, export_root(hass) / token


def export_links(
    hass: HomeAssistant, token: str, written: dict[str, str]
) -> tuple[dict[str, str], str]:
    """Signed download URLs (``kind -> url``) and the time they stop working.

    Prefer an absolute URL so the link is directly usable (clickable in
    markdown/notifications, copy-pasteable from Developer Tools). Prefer the
    external URL so links work behind a reverse proxy / when accessed from
    outside (get_url falls back to the internal URL if no external one is
    configured). Falls back to a relative path if neither exists. The
    signature binds only the path, so it holds whichever host serves it.

    The expiry is taken just before signing, so it never lies after the
    moment the signatures actually expire.
    """
    try:
        base_url = get_url(hass, prefer_external=True).rstrip("/")
    except NoURLAvailableError:
        base_url = ""
    valid_until = (dt_util.now() + EXPORT_LINK_LIFETIME).isoformat(
        timespec="seconds"
    )
    links = {
        kind: base_url
        + async_sign_path(
            hass, f"{EXPORT_URL}/{token}/{fname}", EXPORT_LINK_LIFETIME
        )
        for kind, fname in written.items()
    }
    return links, valid_until


def valid_until_label(valid_until: str | None) -> str:
    """Local wall-clock time ("14:37") of a ``files_valid_until`` value.

    Empty when there is none (no files were written). The minute is cut off,
    not rounded, so the label never promises more than the signature gives.
    """
    if not valid_until:
        return ""
    parsed = dt_util.parse_datetime(valid_until)
    if parsed is None:
        return ""
    return dt_util.as_local(parsed).strftime("%H:%M")


def _served_file(root: Path, path: Path) -> bool:
    """Whether ``path`` is a regular file that really lies inside ``root``."""
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        return False
    return resolved.is_file() and resolved.is_relative_to(root.resolve())


class SmgwExportView(HomeAssistantView):
    """Serve one export file to an authenticated request.

    Any authenticated request is served, not only admins: an export started
    by an automation is signed as Home Assistant's internal content user,
    which is no admin, and its links would otherwise never work. Reaching a
    file still takes a valid login or a valid, unexpired signature for
    exactly that path — plus the random folder name.
    """

    url = EXPORT_URL + "/{token}/{filename}"
    name = "api:smgw_han:export"
    requires_auth = True

    async def get(
        self, request: web.Request, token: str, filename: str
    ) -> web.StreamResponse:
        """Return the file as a download, or 404."""
        if not (_TOKEN_RE.fullmatch(token) and _FILENAME_RE.fullmatch(filename)):
            return web.Response(status=HTTPStatus.NOT_FOUND)
        hass = request.app[KEY_HASS]
        root = export_root(hass)
        path = root / token / filename
        if not await hass.async_add_executor_job(_served_file, root, path):
            return web.Response(status=HTTPStatus.NOT_FOUND)
        # Always a download, never rendered in the browser tab. The filename
        # matched _FILENAME_RE, so it is safe inside the quoted header value.
        return web.FileResponse(
            path,
            headers={
                hdrs.CONTENT_DISPOSITION: f'attachment; filename="{filename}"'
            },
        )


@callback
def async_register_export_view(hass: HomeAssistant) -> None:
    """Register the download view once per Home Assistant run."""
    data = hass.data.setdefault(DOMAIN, {})
    if data.get(_VIEW_REGISTERED):
        return
    hass.http.register_view(SmgwExportView())
    data[_VIEW_REGISTERED] = True


def remove_expired_exports(root: Path, now: float, max_age: float) -> int:
    """Delete export folders older than ``max_age`` seconds; return the count.

    Only folders are touched — one per export, as ``new_export_dir`` creates
    them. A folder that cannot be removed is logged and skipped, so one bad
    entry never stops the rest from being cleaned up.
    """
    if not root.is_dir():
        return 0
    removed = 0
    for entry in root.iterdir():
        if entry.is_symlink() or not entry.is_dir():
            continue
        try:
            if now - entry.stat().st_mtime < max_age:
                continue
            shutil.rmtree(entry)
        except OSError as err:
            _LOGGER.warning("Could not remove export folder %s: %s", entry, err)
            continue
        removed += 1
    return removed


async def async_remove_expired_exports(hass: HomeAssistant) -> None:
    """Remove exports whose links have expired; log instead of raising."""
    try:
        removed = await hass.async_add_executor_job(
            remove_expired_exports,
            export_root(hass),
            time.time(),
            EXPORT_LINK_LIFETIME.total_seconds(),
        )
    except OSError as err:
        _LOGGER.warning("Could not clean up the export folder: %s", err)
        return
    if removed:
        _LOGGER.info("Removed %d expired export folder(s)", removed)


def remove_legacy_www_exports(config_dir: str) -> bool:
    """Delete ``<config>/www/smgw_han_exports/`` left by releases up to 3.6.x.

    Those files are reachable by anyone who has a link, for as long as they
    exist. Only that sub-folder goes — ``www/`` itself belongs to the user.
    """
    legacy = Path(config_dir, *LEGACY_WWW_EXPORT_DIR)
    if legacy.is_symlink():
        legacy.unlink()
        return True
    if not legacy.exists():
        return False
    shutil.rmtree(legacy)
    return True


async def async_remove_legacy_www_exports(hass: HomeAssistant) -> None:
    """Run :func:`remove_legacy_www_exports`; log instead of failing setup."""
    try:
        removed = await hass.async_add_executor_job(
            remove_legacy_www_exports, hass.config.config_dir
        )
    except OSError as err:
        _LOGGER.warning(
            "Could not remove the old public export folder %s: %s",
            hass.config.path(*LEGACY_WWW_EXPORT_DIR),
            err,
        )
        return
    if removed:
        _LOGGER.info(
            "Removed the old public export folder %s",
            hass.config.path(*LEGACY_WWW_EXPORT_DIR),
        )
