"""Accept the credential in a header instead of the URL.

Routes read ``auth_token`` from the query string, which puts the token in access logs, proxy
logs and browser history. This leaf middleware lets a client send it where it belongs:

* ``Authorization: Bearer <token>`` on HTTP requests and on websocket upgrades (Node, Electron's
  main process, bots and other non-browser clients can set it).
* ``Sec-WebSocket-Protocol: pufferblow.v1, bearer.<token>`` on websocket upgrades from a browser,
  which cannot set headers on ``new WebSocket(...)`` but can offer subprotocols. The server
  answers with ``pufferblow.v1`` (never with the token).

The middleware only translates: it copies the token into the ``auth_token`` query parameter the
routes already read, before anything else sees the request, so no route changes. An explicit
``auth_token`` in the query wins, which keeps older clients working. The rewritten query string
lives on a copy of the request scope, so the server's access log never records the token.

It is a leaf module (Starlette only) so it can be tested without starting the server.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, quote

#: Subprotocol a browser client offers next to ``bearer.<token>``; the server echoes this one.
WS_SUBPROTOCOL = "pufferblow.v1"
_BEARER_PREFIX = "bearer."
#: ASGI scope key under which the accepted subprotocol is handed to the websocket route.
SCOPE_SUBPROTOCOL = "pufferblow.ws_subprotocol"


def _header(scope: dict, name: bytes) -> str | None:
    for key, value in scope.get("headers", []):
        if key.lower() == name:
            return value.decode("latin-1")
    return None


def _bearer_from_authorization(value: str | None) -> str | None:
    if not value:
        return None
    scheme, _, token = value.partition(" ")
    token = token.strip()
    return token if scheme.lower() == "bearer" and token else None


def _bearer_from_subprotocols(value: str | None) -> tuple[str | None, bool]:
    """(token, offered): the ``bearer.<token>`` entry, and whether our subprotocol was offered."""
    if not value:
        return None, False
    offered = [part.strip() for part in value.split(",") if part.strip()]
    token = next((p[len(_BEARER_PREFIX):] for p in offered if p.startswith(_BEARER_PREFIX) and len(p) > len(_BEARER_PREFIX)), None)
    return token, WS_SUBPROTOCOL in offered


class HeaderAuthMiddleware:
    """Pure ASGI middleware: header credential in, ``auth_token`` query parameter out."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] in ("http", "websocket"):
            # A copy: the server's own access log reads the original scope, and must never see the token.
            scope = dict(scope)
            token = _bearer_from_authorization(_header(scope, b"authorization"))
            if scope["type"] == "websocket":
                sub_token, offered = _bearer_from_subprotocols(_header(scope, b"sec-websocket-protocol"))
                token = token or sub_token
                if offered:
                    scope[SCOPE_SUBPROTOCOL] = WS_SUBPROTOCOL
            if token:
                query = scope.get("query_string", b"")
                already = any(key == "auth_token" for key, _ in parse_qsl(query.decode("latin-1"), keep_blank_values=True))
                if not already:
                    extra = f"auth_token={quote(token, safe='')}".encode("ascii")
                    scope["query_string"] = query + (b"&" if query else b"") + extra
        await self.app(scope, receive, send)
