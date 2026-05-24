"""
ActivityPub and cross-instance DM routes.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from loguru import logger

from pufferblow.api.dependencies import get_current_user
from pufferblow.api.schemas import (
    ActivityPubFollowRequest,
    DirectMessageLoadQuery,
    DirectMessageSendRequest,
)
from pufferblow.core.bootstrap import api_initializer

router = APIRouter()


def _request_base_url(request: Request) -> str:
    """Request base url."""
    return str(request.base_url).rstrip("/")


@router.get("/.well-known/webfinger", status_code=200)
async def webfinger(resource: str, request: Request):
    """
    WebFinger endpoint for local ActivityPub actors.
    """
    if not resource.startswith("acct:"):
        raise HTTPException(status_code=400, detail="Unsupported resource format")

    value = resource[5:]
    if "@" not in value:
        raise HTTPException(status_code=400, detail="Invalid acct resource")

    username, _domain = value.split("@", 1)
    base_url = _request_base_url(request)
    actor = api_initializer.activitypub_manager.ensure_local_actor_by_username(
        username=username, base_url=base_url
    )
    if actor is None:
        raise HTTPException(status_code=404, detail="Local actor not found")

    domain = request.url.hostname or ""
    response = api_initializer.activitypub_manager.build_webfinger_response(
        username=username, domain=domain, actor_uri=actor.actor_uri
    )
    return response


@router.get("/ap/users/{user_id}", status_code=200)
async def get_actor_document(user_id: str, request: Request):
    """
    ActivityPub actor endpoint for local users.
    """
    base_url = _request_base_url(request)
    try:
        actor = api_initializer.activitypub_manager.ensure_local_actor(
            user_id=user_id, base_url=base_url
        )
    except Exception:
        raise HTTPException(status_code=404, detail="Local actor not found")

    return api_initializer.activitypub_manager.build_actor_document(actor=actor)


@router.get("/ap/users/{user_id}/outbox", status_code=200)
async def get_actor_outbox(
    user_id: str, request: Request, page: int = 1, limit: int = 20
):
    """
    ActivityPub outbox for a local actor.
    """
    if page < 1:
        raise HTTPException(status_code=400, detail="page must be >= 1")
    if limit < 1 or limit > 100:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 100")

    base_url = _request_base_url(request)
    try:
        actor = api_initializer.activitypub_manager.ensure_local_actor(
            user_id=user_id, base_url=base_url
        )
    except Exception:
        raise HTTPException(status_code=404, detail="Local actor not found")

    offset = (page - 1) * limit
    rows = api_initializer.database_handler.get_activitypub_outbox_activities(
        actor_uri=actor.actor_uri, limit=limit, offset=offset
    )
    ordered_items = []
    for row in rows:
        try:
            ordered_items.append(json.loads(row.payload_json))
        except Exception:
            continue

    return {
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": f"{actor.outbox_uri}?page={page}&limit={limit}",
        "type": "OrderedCollectionPage",
        "partOf": actor.outbox_uri,
        "orderedItems": ordered_items,
    }


@router.post("/ap/users/{user_id}/inbox", status_code=202)
async def actor_inbox(user_id: str, request: Request):
    """
    Actor-specific inbox endpoint.
    """
    base_url = _request_base_url(request)
    try:
        actor = api_initializer.activitypub_manager.ensure_local_actor(
            user_id=user_id, base_url=base_url
        )
    except Exception:
        raise HTTPException(status_code=404, detail="Local actor not found")

    payload = await request.json()
    result = await api_initializer.activitypub_manager.process_inbox_activity(
        activity=payload,
        base_url=base_url,
        target_actor_uri=actor.actor_uri,
    )
    return {"status_code": 202, "message": "Activity accepted", "result": result}


@router.post("/ap/inbox", status_code=202)
async def shared_inbox(request: Request):
    """
    Shared inbox endpoint for federated delivery.
    """
    base_url = _request_base_url(request)
    payload = await request.json()
    result = await api_initializer.activitypub_manager.process_inbox_activity(
        activity=payload,
        base_url=base_url,
        target_actor_uri=None,
    )
    return {"status_code": 202, "message": "Activity accepted", "result": result}


@router.post("/api/v1/federation/follow", status_code=200)
async def follow_remote_actor(request_body: ActivityPubFollowRequest, request: Request):
    """
    Follow a remote ActivityPub account from a local user.
    """
    user_id = get_current_user(request_body.auth_token)
    base_url = _request_base_url(request)
    try:
        result = await api_initializer.activitypub_manager.send_follow(
            local_user_id=user_id,
            remote_handle=request_body.remote_handle,
            base_url=base_url,
        )
    except Exception as exc:
        logger.error(f"Federation follow failed: {str(exc)}")
        raise HTTPException(status_code=400, detail=str(exc))

    return {
        "status_code": 200,
        "message": "Follow activity delivered",
        "result": result,
    }


@router.post("/api/v1/dms/send", status_code=201)
async def send_direct_message(request_body: DirectMessageSendRequest, request: Request):
    """
    Send direct message to local or remote peer.

    The wire model carries three optional payload classes:

      * ``message`` — text body (markdown, may be empty).
      * ``attachments`` — list of URL strings already on storage
        (e.g. uploaded earlier via ``/api/v1/storage/upload``).
      * ``sticker_ids`` — list of sticker IDs from the instance
        library. Resolved server-side and merged into the
        attachment URL list. Remote peers see the resulting URL
        as a normal media attachment; the local renderer
        recognises sticker URLs (via the cached sticker library
        keyed on URL) and routes them through the inline
        StickerRenderer.

    At least one of the three must be non-empty.
    """
    user_id = get_current_user(request_body.auth_token)
    base_url = _request_base_url(request)

    # Validate "at least one of body / attachments / stickers".
    if (
        not (request_body.message or "").strip()
        and not request_body.attachments
        and not request_body.sticker_ids
    ):
        raise HTTPException(
            status_code=400,
            detail="Either a message, attachments, or stickers must be provided.",
        )

    # Normalise the attachments list into the internal typed-dict
    # form. The wire surface accepts either plain URL strings
    # (legacy / federation-inbound) or full typed objects from the
    # client's file picker. Both end up as dicts so the read path's
    # render layer can rely on a consistent shape.
    merged_attachments: list[dict] = []
    for raw in (request_body.attachments or []):
        if isinstance(raw, str):
            # Bare URL string — wrap into the minimal dict. Filename
            # / MIME are unknown here; the renderer will fall back to
            # extension-based inference on the URL path.
            if raw.strip():
                merged_attachments.append({"url": raw})
        elif isinstance(raw, dict):
            url = raw.get("url")
            if not url:
                continue
            # Preserve any of the standard channel-attachment keys
            # that the client passed through. Unknown keys are
            # dropped so a malicious / outdated client can't sneak
            # extra payload into the persisted row.
            entry: dict = {"url": str(url)}
            for key in ("filename", "type", "size", "lqip_url"):
                if key in raw and raw[key] is not None:
                    entry[key] = raw[key]
            merged_attachments.append(entry)

    if request_body.sticker_ids and api_initializer.stickers_manager is not None:
        for sid in request_body.sticker_ids:
            sticker_row = api_initializer.database_handler.get_sticker_by_id(sid)
            if sticker_row is None or not sticker_row.is_active:
                raise HTTPException(
                    status_code=400,
                    detail=f"Sticker '{sid}' isn't available.",
                )
            # Stickers carry the same typed shape as other
            # attachments — `type: "sticker"` is what the client
            # renderer keys off to use the inline sticker bubble
            # instead of the generic image bubble.
            merged_attachments.append({
                "url": sticker_row.sticker_url,
                "filename": sticker_row.filename,
                "type": "sticker",
                "size": 0,
                "sticker_id": sticker_row.sticker_id,
                "display_name": sticker_row.display_name,
                "alias": sticker_row.alias,
            })

    try:
        result = await api_initializer.activitypub_manager.send_direct_message(
            local_user_id=user_id,
            peer=request_body.peer,
            message=request_body.message,
            base_url=base_url,
            sent_at=request_body.sent_at,
            attachments=merged_attachments,
        )
    except Exception as exc:
        logger.error(f"Direct message send failed: {str(exc)}")
        raise HTTPException(status_code=400, detail=str(exc))

    return {
        "status_code": 201,
        "message": "Direct message sent",
        "result": result,
    }


@router.get("/api/v1/dms/messages", status_code=200)
async def load_direct_messages(
    request: Request, query: DirectMessageLoadQuery = Depends()
):
    """
    Load direct message conversation with local or remote peer.
    """
    user_id = get_current_user(query.auth_token)
    base_url = _request_base_url(request)

    try:
        result = await api_initializer.activitypub_manager.load_direct_messages(
            viewer_user_id=user_id,
            peer=query.peer,
            base_url=base_url,
            page=query.page,
            messages_per_page=query.messages_per_page,
        )
    except Exception as exc:
        logger.error(f"Direct message load failed: {str(exc)}")
        raise HTTPException(status_code=400, detail=str(exc))

    return {
        "status_code": 200,
        "conversation_id": result["conversation_id"],
        "peer_actor_uri": result["peer_actor_uri"],
        "messages": result["messages"],
    }


@router.patch("/api/v1/dms/messages/{message_id}", status_code=200)
async def edit_direct_message(
    message_id: str,
    auth_token: str = Body(..., embed=True),
    message: str = Body(..., embed=True),
):
    """Edit a DM message's body.

    Same constraints as the channel edit route — only the original
    sender may edit, edit metadata is bumped server-side, body is
    re-encrypted through the existing pipeline. Federation: the
    edit is local-only for now (no AP Update activity emitted yet);
    a follow-up will propagate edits to remote peers.
    """
    cleaned = (message or "").strip()
    if not cleaned:
        raise HTTPException(
            status_code=400, detail="Edited message cannot be empty."
        )
    user_id = get_current_user(auth_token)
    try:
        result = api_initializer.messages_manager.edit_message(
            message_id=message_id,
            editor_user_id=user_id,
            new_body=cleaned,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {
        "status_code": 200,
        "message_id": result["message_id"],
        "message": result["message"],
        "edit_count": result["edit_count"],
        "last_edited_at": result["last_edited_at"],
    }


@router.get("/api/v1/dms/conversations/{conversation_id}/settings", status_code=200)
async def get_dm_conversation_settings(conversation_id: str, auth_token: str):
    """Read a conversation's per-conversation settings.

    Returns the row if present, or a defaulted shape (
    ``disappear_after_seconds = 86400``, the instance default)
    when the conversation hasn't been customised yet. Either way
    the client gets a consistent JSON shape to render.
    """
    get_current_user(auth_token)
    row = api_initializer.database_handler.get_dm_conversation_settings(
        conversation_id=conversation_id
    )
    if row is None:
        # No customised row yet — return the default-shape body so
        # the client doesn't need a separate "not set" branch.
        return {
            "status_code": 200,
            "settings": {
                "conversation_id": conversation_id,
                "disappear_after_seconds": 24 * 60 * 60,
                "is_default": True,
            },
        }
    payload = row.to_dict()
    payload["is_default"] = False
    return {"status_code": 200, "settings": payload}


@router.patch("/api/v1/dms/conversations/{conversation_id}/settings", status_code=200)
async def update_dm_conversation_settings(
    conversation_id: str,
    auth_token: str = Body(..., embed=True),
    disappear_after_seconds: int | None = Body(..., embed=True),
):
    """Update a conversation's disappearing-messages TTL.

    ``disappear_after_seconds=null`` turns the feature off — future
    messages in this conversation won't be auto-deleted. Any
    positive integer enables the feature with that interval. Zero
    is rejected because it would mean "delete on send."
    """
    get_current_user(auth_token)
    if disappear_after_seconds is not None and disappear_after_seconds <= 0:
        raise HTTPException(
            status_code=400,
            detail="disappear_after_seconds must be null (never) or > 0.",
        )
    row = api_initializer.database_handler.upsert_dm_conversation_settings(
        conversation_id=conversation_id,
        disappear_after_seconds=disappear_after_seconds,
    )
    return {"status_code": 200, "settings": row.to_dict()}


@router.get("/api/v1/dms/conversations", status_code=200)
async def list_dm_conversations(request: Request, auth_token: str):
    """List the viewer's DM conversations, most-recent-first.

    Powers the conversation-list sidebar on the client. Each entry
    carries enough hydrated data (peer identity, last message
    preview, last message timestamp, sender-is-me flag) for the UI
    to render the row without a per-conversation fetch.

    Federation-aware: peer info works for both local users and
    shadow rows (federated users we've cached). Conversations that
    can't be resolved to a peer (extremely rare — orphan rows) are
    skipped rather than returned half-hydrated.
    """
    user_id = get_current_user(auth_token)
    base_url = _request_base_url(request)

    try:
        conversations = api_initializer.activitypub_manager.list_dm_conversations(
            viewer_user_id=user_id,
            base_url=base_url,
        )
    except Exception as exc:
        logger.error(f"DM conversation list failed: {str(exc)}")
        raise HTTPException(status_code=400, detail=str(exc))

    return {
        "status_code": 200,
        "conversations": conversations,
    }
