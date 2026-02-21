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
    """
    user_id = get_current_user(request_body.auth_token)
    base_url = _request_base_url(request)

    try:
        result = await api_initializer.activitypub_manager.send_direct_message(
            local_user_id=user_id,
            peer=request_body.peer,
            message=request_body.message,
            base_url=base_url,
            sent_at=request_body.sent_at,
            attachments=request_body.attachments,
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
