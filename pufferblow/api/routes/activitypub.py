"""
ActivityPub and cross-instance DM routes.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Request
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

    # Resolve sticker_ids → URLs. We keep the wire shape of
    # ``attachments`` as a flat URL list because the DM federation
    # path (ActivityPub Note) expects strings; the typed-attachment
    # shape used by channels is a server-side internal convention.
    # Sticker reverse-lookup (URL → sticker_id) on read happens via
    # the cached library on the client.
    merged_attachments: list[str] = list(request_body.attachments)
    if request_body.sticker_ids and api_initializer.stickers_manager is not None:
        for sid in request_body.sticker_ids:
            sticker_row = api_initializer.database_handler.get_sticker_by_id(sid)
            if sticker_row is None or not sticker_row.is_active:
                raise HTTPException(
                    status_code=400,
                    detail=f"Sticker '{sid}' isn't available.",
                )
            merged_attachments.append(sticker_row.sticker_url)

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
