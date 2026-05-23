"""Instance-sticker HTTP surface.

Thin wrappers around ``StickersManager``; all the business logic
lives there. The split keeps these handlers free of validation +
caching concerns so they read as "extract auth token → dispatch →
serialise."

Routes:

    GET    /api/v1/stickers             list active stickers (any signed-in user)
    GET    /api/v1/stickers/all         list everything including inactive (admins)
    POST   /api/v1/stickers             upload + register a sticker (admins)
    PATCH  /api/v1/stickers/{id}        rename / re-alias / activate (admins)
    DELETE /api/v1/stickers/{id}        remove from catalog (admins)

Permission model: anyone signed in can LIST active stickers (the
chat picker needs the library to render). All write paths and the
"include inactive" listing are gated by ``manage_stickers``, which
ships granted to ``owner`` and ``admin`` roles by default.

Why not split the management routes onto ``/api/v1/admin/stickers``?
The four management verbs all target the same resource ID space as
the public list, so keeping them under one prefix means clients
don't have to know two different URL trees. The privilege gate is
the boundary, not the URL.
"""

from __future__ import annotations

from fastapi import APIRouter, Body, File, Form, UploadFile, exceptions

from pufferblow.api.dependencies import get_current_user, require_privilege
from pufferblow.api.stickers.stickers_manager import StickersError
from pufferblow.core.bootstrap import api_initializer

router = APIRouter(prefix="/api/v1/stickers")


def _raise_from_stickers_error(exc: StickersError) -> None:
    """Translate a manager exception into the FastAPI exception."""
    raise exceptions.HTTPException(status_code=exc.status_code, detail=str(exc))


@router.get("", status_code=200)
async def list_stickers_route(auth_token: str):
    """Return all active stickers, picker-ordered.

    Open to any signed-in user — the chat picker needs the library
    to render and we don't want to mask the existence of stickers
    from regular users. Deactivated stickers are filtered server-
    side; the management view (``GET /all``) is admin-only.
    """
    # Lightweight auth check — we don't need the user_id, just
    # confirmation that the token is valid. ``get_current_user``
    # raises 401 on miss which is the right behavior.
    get_current_user(auth_token)
    stickers = api_initializer.stickers_manager.list_active()
    return {"status_code": 200, "stickers": stickers}


@router.get("/all", status_code=200)
async def list_all_stickers_route(auth_token: str):
    """Return every sticker including deactivated ones (admin view)."""
    require_privilege(auth_token, "manage_stickers")
    stickers = api_initializer.stickers_manager.list_all()
    return {"status_code": 200, "stickers": stickers}


@router.post("", status_code=201)
async def upload_sticker_route(
    auth_token: str,
    file: UploadFile = File(..., description="Sticker file (PNG/WebP/GIF/JPEG, ≤512 KB)"),
    display_name: str = Form(..., description="User-facing label"),
    alias: str | None = Form(default=None, description="Optional shortcode"),
):
    """Upload + catalog a new sticker.

    Multipart body (matches the channel-attachment upload pattern):

      * ``file`` — the sticker bytes
      * ``display_name`` — required label shown in the picker grid
      * ``alias`` — optional unique shortcode, e.g. ``party_parrot``

    Returns the canonical wire shape of the new sticker row, so the
    client can append to its cached library list without a refetch.
    """
    user_id = require_privilege(auth_token, "manage_stickers")
    try:
        sticker = await api_initializer.stickers_manager.upload_sticker(
            file=file,
            user_id=user_id,
            display_name=display_name,
            alias=alias,
        )
    except StickersError as exc:
        _raise_from_stickers_error(exc)
    return {"status_code": 201, "sticker": sticker}


@router.patch("/{sticker_id}", status_code=200)
async def update_sticker_route(
    sticker_id: str,
    auth_token: str,
    display_name: str | None = Body(default=None, embed=True),
    alias: str | None = Body(default=None, embed=True),
    is_active: bool | None = Body(default=None, embed=True),
):
    """Patch a sticker's metadata.

    Pass only the fields the admin actually changed:

      * ``display_name`` — rename without re-uploading bytes
      * ``alias`` — assign / change the shortcode; pass ``""`` to
        clear it (no alias). Uniqueness is enforced server-side.
      * ``is_active`` — soft-deactivate without losing the row, so
        usage stats / history are preserved.

    Returns the refreshed sticker.
    """
    require_privilege(auth_token, "manage_stickers")
    try:
        sticker = api_initializer.stickers_manager.update(
            sticker_id=sticker_id,
            display_name=display_name,
            alias=alias,
            is_active=is_active,
        )
    except StickersError as exc:
        _raise_from_stickers_error(exc)
    return {"status_code": 200, "sticker": sticker}


@router.delete("/{sticker_id}", status_code=200)
async def delete_sticker_route(sticker_id: str, auth_token: str):
    """Hard-delete a sticker.

    Already-sent messages keep rendering because they reference the
    storage URL directly. The underlying file is left to the
    orphan-cleanup background task — it'll be removed once no
    other reference holds it.
    """
    require_privilege(auth_token, "manage_stickers")
    removed = api_initializer.stickers_manager.delete(sticker_id)
    if not removed:
        raise exceptions.HTTPException(status_code=404, detail="Sticker not found.")
    return {"status_code": 200, "deleted": True}
