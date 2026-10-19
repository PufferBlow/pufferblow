"""Public, cacheable default avatars and banners.

``GET /assets/avatars/<name>.<svg|png>`` and ``GET /assets/banners/<name>.<svg|png>``. These are the
images ``avatar_url`` / ``banner_url`` point at for anyone who has not uploaded their own, so they
need no credential: any client, including ones that are not the official app, can show them. Only
files the shipped set contains are served.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from pufferblow.api.utils.default_art import asset_file

router = APIRouter()

_MEDIA_TYPES = {"svg": "image/svg+xml", "png": "image/png"}
# The files never change under a name, so they can be cached for good.
_HEADERS = {
    "Cache-Control": "public, max-age=31536000, immutable",
    "Access-Control-Allow-Origin": "*",
    "Cross-Origin-Resource-Policy": "cross-origin",
    "X-Content-Type-Options": "nosniff",
}


def _serve(folder: str, filename: str) -> FileResponse:
    path = asset_file(folder, filename)
    if path is None:
        raise HTTPException(status_code=404, detail="No such image.")
    return FileResponse(path, media_type=_MEDIA_TYPES[path.suffix.lstrip(".")], headers=_HEADERS)


@router.get("/assets/avatars/{filename}", include_in_schema=True)
async def default_avatar(filename: str):
    """A default avatar (SVG or PNG), e.g. ``pb-avatar-happy-brass.png``."""
    return _serve("avatars", filename)


@router.get("/assets/banners/{filename}", include_in_schema=True)
async def default_banner(filename: str):
    """A default banner (SVG or PNG), e.g. ``pb-banner-happy-brass.png``."""
    return _serve("banners", filename)
