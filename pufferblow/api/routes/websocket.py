"""WebSocket routes.

There is one socket, ``/ws``, and it speaks the command/event protocol
(``docs/protocol/v1.md``). The pre-protocol polling loops and the per-channel
socket were retired; see :mod:`pufferblow.api.routes.ws_protocol` for the session.
"""

from __future__ import annotations

from fastapi import APIRouter, WebSocket, exceptions

from pufferblow.api.routes.ws_protocol import run_protocol_session

router = APIRouter()

#: Close code for a handshake the server will not serve (policy violation).
CLOSE_POLICY = 1008


@router.websocket("/ws")
async def global_messages_websocket(
    websocket: WebSocket, auth_token: str, protocol: int | None = None
):
    """Open a protocol session.

    Args:
        websocket: The connection.
        auth_token: The caller's user or bot token.
        protocol: Protocol version, e.g. ``1``. Required: connections without it
            used to get the legacy frames and are now refused.

    Closes with 1008 when the version is missing or unsupported or the token is invalid.
    """
    if protocol is None:
        raise exceptions.WebSocketException(
            code=CLOSE_POLICY,
            reason="The legacy socket was retired. Connect with protocol=1 (see docs/protocol/v1.md).",
        )

    await run_protocol_session(websocket, auth_token, protocol)
