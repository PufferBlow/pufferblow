"""WebSocket session for the versioned command/event protocol.

``/ws?auth_token=...&protocol=1`` opens a protocol v1 session. The parameter is
required; ``routes/websocket.py`` refuses connections without it.

This module is the only place that touches the socket: it authenticates, builds
a transport-free :class:`ConnectionContext`, forwards frames to the dispatcher,
sends replies, then publishes the committed events.
"""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone

from fastapi import WebSocket, WebSocketDisconnect, exceptions
from loguru import logger

from pufferblow.api.commands.dispatcher import ConnectionContext
from pufferblow.api.commands.metrics import metrics
from pufferblow.api.errors import ApiError
from pufferblow.api.protocol.envelopes import (
    MAX_FRAME_BYTES,
    SUPPORTED_VERSIONS,
    ProtocolErrorCode,
    build_error,
    build_hello,
)
from pufferblow.core.bootstrap import api_initializer

#: A user may hold this many simultaneous sockets (several tabs and devices are fine).
MAX_CONNECTIONS_PER_USER = 10
#: Sockets from one address, across accounts (a household or office NAT shares one).
MAX_CONNECTIONS_PER_IP = 50
#: Sockets this process will hold at all, so a flood can't exhaust memory and file handles.
MAX_CONNECTIONS_TOTAL = 10_000


def client_ip(websocket: WebSocket) -> str:
    """The caller's address, by the same rule as the HTTP middleware (first X-Forwarded-For hop)."""
    forwarded = websocket.headers.get("x-forwarded-for", "").split(",")[0].strip()
    if forwarded:
        return forwarded
    return websocket.client.host if websocket.client else "unknown"

PRESENCE_TYPES = {"user_status_changed", "status_update", "presence_update"}
CLOSE_UNAUTHENTICATED = 4401


async def run_protocol_session(websocket: WebSocket, auth_token: str, version: int) -> None:
    manager = api_initializer.websockets_manager
    resolver = api_initializer.principal_resolver

    if version not in SUPPORTED_VERSIONS:
        metrics.incr("connections_rejected")
        raise exceptions.WebSocketException(code=1008, reason=f"Unsupported protocol version {version}.")

    # Before authenticating: cheap, and it also slows token guessing over sockets.
    ip = client_ip(websocket)
    if len(manager.active_connections) >= MAX_CONNECTIONS_TOTAL:
        metrics.incr("connections_rejected")
        raise exceptions.WebSocketException(code=1013, reason="The server is at capacity. Try again later.")
    if manager.count_connections_from_ip(ip) >= MAX_CONNECTIONS_PER_IP:
        metrics.incr("connections_rejected")
        raise exceptions.WebSocketException(code=1008, reason="Too many open connections from this address.")

    try:
        principal = resolver.resolve(auth_token)
    except ApiError:
        metrics.incr("connections_rejected")
        raise exceptions.WebSocketException(code=1008, reason="Authentication failed.") from None

    if manager._count_connections_for_user(principal.id) >= MAX_CONNECTIONS_PER_USER:
        metrics.incr("connections_rejected")
        raise exceptions.WebSocketException(code=1008, reason="Too many open connections for this account.")

    # Access is computed against the accountable (owning) user: for a bot this is its
    # owner, since channel allow-lists hold real user ids, not bot principal ids.
    channels = api_initializer.channels_manager.list_channels(
        user_id=principal.accountable_user_id, include_private_channels=principal.has("view_private_channels")
    )
    subscriptions = {c["channel_id"] for c in channels or [] if isinstance(c, dict) and c.get("channel_id")}

    session_id = f"ses_{secrets.token_urlsafe(9)}"
    ctx = ConnectionContext(
        principal=principal,
        session_id=session_id,
        connection_key=session_id,
        subscriptions=subscriptions,
        # Closes over the token; the secret is not kept on the context or logged.
        revalidate=lambda: resolver.resolve(auth_token),
    )

    await manager.connect_global(
        websocket=websocket, auth_token=auth_token, accessible_channels=list(subscriptions), context=ctx, ip=ip
    )
    metrics.incr("connections_opened")
    logger.info(f"Protocol session opened | session={session_id} principal_kind={principal.kind} channels={len(subscriptions)}")

    dispatcher = api_initializer.command_dispatcher
    publisher = api_initializer.event_publisher

    try:
        await websocket.send_json(build_hello(session_id=session_id, epoch=publisher.epoch))

        while True:
            text = await websocket.receive_text()

            handled = await _handle_housekeeping(websocket, ctx, text)
            if handled == "close":
                break
            if handled:
                continue

            result = await dispatcher.dispatch(ctx, text)
            await websocket.send_json(result.reply)

            if result.reply.get("type") == "error" and result.reply["error"]["code"] == ProtocolErrorCode.UNAUTHENTICATED:
                await websocket.close(code=CLOSE_UNAUTHENTICATED)
                break

            if result.events:
                await publisher.publish_all(result.events)

    except WebSocketDisconnect:
        logger.info(f"Protocol session closed by client | session={session_id}")
    except Exception:
        # Never let one bad frame or a downstream failure take the process down.
        logger.exception(f"Protocol session crashed | session={session_id}")
    finally:
        dispatcher._connection_limiter.forget(session_id)
        await manager.disconnect(websocket)
        metrics.incr("connections_closed")


async def _handle_housekeeping(websocket: WebSocket, ctx: ConnectionContext, text: str) -> bool | str:
    """Handle the housekeeping frames that are not commands: ping and presence.

    Returns True when the frame was consumed, ``"close"`` when the session must end.
    """
    if len(text) > MAX_FRAME_BYTES:
        return False  # the dispatcher answers with PAYLOAD_TOO_LARGE
    try:
        frame = json.loads(text)
    except ValueError:
        return False
    if not isinstance(frame, dict):
        return False

    kind = frame.get("type")

    if kind == "ping":
        # A ping doubles as the credential check, so an expired token cannot linger for long.
        try:
            ctx.principal = ctx.revalidate()
        except ApiError:
            await websocket.send_json(build_error(None, ProtocolErrorCode.UNAUTHENTICATED, "Your session has expired."))
            await websocket.close(code=CLOSE_UNAUTHENTICATED)
            return "close"
        await websocket.send_json({"type": "pong", "timestamp": datetime.now(timezone.utc).isoformat()})
        return True

    if kind in PRESENCE_TYPES:
        status = frame.get("status")
        if status is None:
            await websocket.send_json(build_error(None, ProtocolErrorCode.VALIDATION_FAILED, "Missing status field."))
            return True
        try:
            await api_initializer.websockets_manager.update_user_presence_status(
                user_id=ctx.principal.id, status=status, source="ws_client_update"
            )
        except ValueError as exc:
            await websocket.send_json(build_error(None, ProtocolErrorCode.VALIDATION_FAILED, str(exc)))
        return True

    return False
