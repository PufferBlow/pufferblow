"""
ActivityPub and cross-instance DM routes.
"""

from __future__ import annotations

import base64
import json

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from loguru import logger

from pufferblow.api.dependencies import get_current_user
from pufferblow.api.errors import ApiError
from pufferblow.api.schemas import (
    ActivityPubFollowRequest,
    DirectMessageForwardRequest,
    DirectMessageLoadQuery,
    DirectMessageReactionRequest,
    DirectMessageSendRequest,
)
from pufferblow.core.bootstrap import api_initializer
from pufferblow.core.constants import VERSION

router = APIRouter()


def _request_base_url(request: Request) -> str:
    """Request base url."""
    return str(request.base_url).rstrip("/")


@router.get("/.well-known/nodeinfo", status_code=200)
async def nodeinfo_discovery(request: Request):
    """NodeInfo discovery document — points probing peers at `/nodeinfo/2.0`.

    Many federated servers check this before trusting a peer at all, so its
    absence (not just a wrong answer) is itself a signal some crawlers act
    on. No auth, no per-request computation — just a pointer.
    """
    base_url = _request_base_url(request)
    return {
        "links": [
            {
                "rel": "http://nodeinfo.diaspora.software/ns/schema/2.0",
                "href": f"{base_url}/nodeinfo/2.0",
            }
        ]
    }


@router.get("/nodeinfo/2.0", status_code=200)
async def nodeinfo_document():
    """NodeInfo 2.0 document. No config toggle for open registrations exists
    yet — signup is unconditionally open today, so that's what's reported.
    """
    total_users = api_initializer.database_handler.count_users()
    return {
        "version": "2.0",
        "software": {"name": "pufferblow", "version": VERSION},
        "protocols": ["activitypub"],
        "services": {"inbound": [], "outbound": []},
        "openRegistrations": True,
        "usage": {"users": {"total": total_users}},
        "metadata": {},
    }


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

    The bare collection URL (no ``page`` query param) returns the top-level
    ``OrderedCollection`` wrapper — ``totalItems`` plus a ``first`` link —
    which a real AP crawler expects before it'll follow into a page at all.
    Passing ``?page=N`` returns that page directly (unchanged shape from
    before), which is also what ``first``/``next`` point at.
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

    if "page" not in request.query_params:
        total = api_initializer.database_handler.count_activitypub_outbox_activities(
            actor_uri=actor.actor_uri
        )
        return {
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": actor.outbox_uri,
            "type": "OrderedCollection",
            "totalItems": total,
            "first": f"{actor.outbox_uri}?page=1&limit={limit}",
            "last": f"{actor.outbox_uri}?page={max(1, -(-total // limit))}&limit={limit}",
        }

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

    page_doc = {
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": f"{actor.outbox_uri}?page={page}&limit={limit}",
        "type": "OrderedCollectionPage",
        "partOf": actor.outbox_uri,
        "orderedItems": ordered_items,
    }
    if len(ordered_items) == limit:
        page_doc["next"] = f"{actor.outbox_uri}?page={page + 1}&limit={limit}"
    return page_doc


def _ordered_collection_or_page(
    *, collection_uri: str, items: list[str], request: Request, page: int, limit: int
) -> dict:
    """Shared OrderedCollection/OrderedCollectionPage builder for followers/following.

    ``items`` is the full (already-fetched) list of remote actor URIs — these
    collections aren't expected to be large enough to need DB-level paging
    the way the outbox does, so this paginates in memory over one query.
    """
    if "page" not in request.query_params:
        total = len(items)
        return {
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": collection_uri,
            "type": "OrderedCollection",
            "totalItems": total,
            "first": f"{collection_uri}?page=1&limit={limit}",
        }

    start = (page - 1) * limit
    page_items = items[start : start + limit]
    page_doc = {
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": f"{collection_uri}?page={page}&limit={limit}",
        "type": "OrderedCollectionPage",
        "partOf": collection_uri,
        "orderedItems": page_items,
    }
    if start + limit < len(items):
        page_doc["next"] = f"{collection_uri}?page={page + 1}&limit={limit}"
    return page_doc


@router.get("/ap/users/{user_id}/followers", status_code=200)
async def get_actor_followers(
    user_id: str, request: Request, page: int = 1, limit: int = 20
):
    """ActivityPub followers collection for a local actor."""
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

    rows = api_initializer.database_handler.list_activitypub_followers(
        local_actor_uri=actor.actor_uri
    )
    items = [row.remote_actor_uri for row in rows]
    return _ordered_collection_or_page(
        collection_uri=f"{actor.actor_uri}/followers", items=items, request=request, page=page, limit=limit
    )


@router.get("/ap/users/{user_id}/following", status_code=200)
async def get_actor_following(
    user_id: str, request: Request, page: int = 1, limit: int = 20
):
    """ActivityPub following collection for a local actor."""
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

    rows = api_initializer.database_handler.list_activitypub_following(
        local_actor_uri=actor.actor_uri
    )
    items = [row.remote_actor_uri for row in rows]
    return _ordered_collection_or_page(
        collection_uri=f"{actor.actor_uri}/following", items=items, request=request, page=page, limit=limit
    )


async def _verify_and_parse_inbox_request(request: Request) -> dict:
    """Read the raw body, verify its HTTP Signature, then parse it as JSON.

    Raw bytes are read first (and parsed from, not re-serialized) because
    the `Digest` check must hash exactly what the sender hashed — a
    reparse-then-`json.dumps()` round trip can reorder keys or change
    whitespace and silently break verification.

    Raises `HTTPException(401)` on a bad/missing signature. The response
    never says which part failed — same posture as the rest of this
    codebase's auth errors.
    """
    raw_body = await request.body()
    try:
        payload = json.loads(raw_body)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Activity must be a JSON object")

    claimed_actor_uri = str(payload.get("actor", "")).strip()
    if not claimed_actor_uri:
        raise HTTPException(status_code=400, detail="Activity must include 'actor'")

    path = request.url.path
    if request.url.query:
        path = f"{path}?{request.url.query}"

    try:
        await api_initializer.activitypub_manager.verify_inbox_signature(
            method=request.method,
            path=path,
            headers=request.headers,
            raw_body=raw_body,
            claimed_actor_uri=claimed_actor_uri,
        )
    except ValueError as exc:
        logger.warning(f"ActivityPub inbox signature rejected: {exc}")
        raise HTTPException(status_code=401, detail="Signature verification failed")

    return payload


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

    payload = await _verify_and_parse_inbox_request(request)
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
    payload = await _verify_and_parse_inbox_request(request)
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


@router.post("/api/v1/federation/unfollow", status_code=200)
async def unfollow_remote_actor(request_body: ActivityPubFollowRequest, request: Request):
    """
    Unfollow a remote ActivityPub account from a local user — sends
    Undo(Follow) and drops the local follow row.
    """
    user_id = get_current_user(request_body.auth_token)
    base_url = _request_base_url(request)
    try:
        result = await api_initializer.activitypub_manager.send_undo_follow(
            local_user_id=user_id,
            remote_handle=request_body.remote_handle,
            base_url=base_url,
        )
    except Exception as exc:
        logger.error(f"Federation unfollow failed: {str(exc)}")
        raise HTTPException(status_code=400, detail=str(exc))

    return {
        "status_code": 200,
        "message": "Undo(Follow) activity delivered",
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
            reply_to_message_id=request_body.reply_to_message_id,
        )
    except Exception as exc:
        logger.error(f"Direct message send failed: {str(exc)}")
        raise HTTPException(status_code=400, detail=str(exc))

    return {
        "status_code": 201,
        "message": "Direct message sent",
        "result": result,
    }


@router.post("/api/v1/messages/{message_id}/forward", status_code=201)
async def forward_message(
    message_id: str, request: Request, request_body: DirectMessageForwardRequest = Body(...)
):
    """Forward an existing message (channel or DM) into a DM with `peer`.

    Authorization happens here, before `ActivityPubManager.forward_message`
    does anything — a channel message needs channel access (reuses the
    same `Authorizer` the channel routes use), a DM message needs the
    caller to be a participant in its conversation (reuses the DM
    reaction/edit check in `ActivityPubManager.user_can_access_dm_message`).
    """
    user_id = get_current_user(request_body.auth_token)
    base_url = _request_base_url(request)

    row = api_initializer.database_handler.get_message_by_id(message_id=message_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Message not found")

    if row.channel_id:
        principal = api_initializer.user_principal_resolver.resolve(request_body.auth_token)
        try:
            api_initializer.authorizer.require_channel_access(principal, row.channel_id)
        except ApiError as exc:
            raise HTTPException(status_code=403, detail=str(exc))
    elif row.conversation_id:
        if not api_initializer.activitypub_manager.user_can_access_dm_message(user_id, row, base_url):
            raise HTTPException(status_code=403, detail="Not a participant in this conversation")
    else:
        raise HTTPException(status_code=400, detail="Message has no channel or conversation to forward from")

    if request_body.channel_id:
        # Into a channel of this instance: the same text and attachments, posted as the caller
        # (who must be allowed to send there) and marked as forwarded.
        plaintext = api_initializer.messages_manager.decrypt_message(
            user_id=str(row.sender_id),
            message_id=row.message_id,
            encrypted_message=base64.b64decode(row.hashed_message),
        )
        principal = api_initializer.user_principal_resolver.resolve(request_body.auth_token)
        outcome = api_initializer.message_service.create(
            principal,
            request_body.channel_id,
            plaintext,
            attachments=row.attachments or [],
            forwarded_from_message_id=row.message_id,
        )
        await api_initializer.event_publisher.publish_all(outcome.events)
        message_dict = outcome.value["raw"]
        return {
            "status_code": 201,
            "message": "Message forwarded",
            "result": {"channel_id": request_body.channel_id, "message_id": message_dict["message_id"]},
        }

    try:
        result = await api_initializer.activitypub_manager.forward_message(
            local_user_id=user_id, source_message=row, peer=request_body.peer, base_url=base_url
        )
    except Exception as exc:
        logger.error(f"Message forward failed: {str(exc)}")
        raise HTTPException(status_code=400, detail=str(exc))

    return {"status_code": 201, "message": "Message forwarded", "result": result}


@router.post("/api/v1/dms/messages/{message_id}/reactions", status_code=201)
async def add_dm_message_reaction(
    message_id: str, request: Request, request_body: DirectMessageReactionRequest = Body(...)
):
    """Add a reaction emoji to a DM message.

    Mirrors the channel reaction route's idempotency contract: re-applying
    the same emoji is a no-op (200, `already_present: true`).
    """
    user_id = get_current_user(request_body.auth_token)
    base_url = _request_base_url(request)
    try:
        result = await api_initializer.activitypub_manager.add_dm_reaction(
            local_user_id=user_id, message_id=message_id, emoji=request_body.emoji, base_url=base_url
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    return {
        "status_code": 201 if result["changed"] else 200,
        "already_present": not result["changed"],
        "message_id": message_id,
        "emoji": result["emoji"],
        "reactions": result["reactions"],
    }


@router.delete("/api/v1/dms/messages/{message_id}/reactions", status_code=200)
async def remove_dm_message_reaction(
    message_id: str, request: Request, auth_token: str, emoji: str
):
    """Remove a reaction emoji the viewer applied to a DM message.

    Idempotent: removing a reaction the viewer never applied returns 200
    with `already_absent: true`.
    """
    user_id = get_current_user(auth_token)
    base_url = _request_base_url(request)
    try:
        result = await api_initializer.activitypub_manager.remove_dm_reaction(
            local_user_id=user_id, message_id=message_id, emoji=emoji, base_url=base_url
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    return {
        "status_code": 200,
        "already_absent": not result["changed"],
        "message_id": message_id,
        "emoji": result["emoji"],
        "reactions": result["reactions"],
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
    request: Request,
    auth_token: str = Body(..., embed=True),
    message: str = Body(..., embed=True),
):
    """Edit a DM message's body.

    Same constraints as the channel edit route — only the original
    sender may edit, edit metadata is bumped server-side, body is
    re-encrypted through the existing pipeline. If the peer is remote,
    federates the edit as an ActivityPub Update(Note) after the local edit
    succeeds; a federation hiccup here is logged but never fails the
    request — the local edit already happened and is the source of truth.
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

    try:
        await api_initializer.activitypub_manager.send_update(
            local_user_id=user_id,
            message_id=message_id,
            new_content=result["message"],
            base_url=_request_base_url(request),
        )
    except Exception as exc:
        logger.warning(f"Federation Update for DM edit failed: {exc}")

    await api_initializer.activitypub_manager.notify_local_dm_peer(
        local_user_id=user_id,
        message_id=message_id,
        payload={
            "type": "message_edited",
            "message": result["message"],
            "edit_count": result["edit_count"],
            "last_edited_at": result["last_edited_at"],
        },
        base_url=_request_base_url(request),
    )

    return {
        "status_code": 200,
        "message_id": result["message_id"],
        "message": result["message"],
        "edit_count": result["edit_count"],
        "last_edited_at": result["last_edited_at"],
    }


@router.delete("/api/v1/dms/messages/{message_id}", status_code=200)
async def delete_direct_message(message_id: str, request: Request, auth_token: str):
    """Delete a DM message.

    Only the original sender may delete their own DM — there's no
    moderator-override concept for a private 1:1 conversation the way
    there is for channel messages. Federates as an ActivityPub Delete
    *before* removing the local row (needs the row's conversation_id to
    resolve the peer); a federation hiccup is logged but never blocks the
    local delete.
    """
    user_id = get_current_user(auth_token)
    row = api_initializer.database_handler.get_message_by_id(message_id=message_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Message not found")
    if str(row.sender_id) != str(user_id):
        raise HTTPException(status_code=403, detail="Only the original sender can delete this message.")

    try:
        await api_initializer.activitypub_manager.send_delete(
            local_user_id=user_id, message_id=message_id, base_url=_request_base_url(request)
        )
    except Exception as exc:
        logger.warning(f"Federation Delete for DM failed: {exc}")

    # Before the row goes: the peer is found through its conversation.
    await api_initializer.activitypub_manager.notify_local_dm_peer(
        local_user_id=user_id,
        message_id=message_id,
        payload={"type": "message_deleted"},
        base_url=_request_base_url(request),
    )

    api_initializer.messages_manager.delete_message(message_id=message_id, channel_id=row.channel_id)
    return {"status_code": 200, "message_id": message_id, "deleted": True}


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
