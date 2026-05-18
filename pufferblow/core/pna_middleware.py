"""Private Network Access (PNA) preflight acknowledgement.

This is intentionally a tiny leaf module: it pulls in only Starlette,
no database / config / bootstrap modules. That lets it be unit-tested
in isolation without spinning up the full app — the rest of
`pufferblow.core.middlewares` imports the bootstrap object, which on
import triggers the full server initialization chain.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware


class PrivateNetworkAccessMiddleware(BaseHTTPMiddleware):
    """Acknowledge Chromium's Private Network Access (PNA) preflight.

    Background:
        Chromium gates fetches that cross from a non-private origin to a
        private-network address (localhost, 127.0.0.0/8, 10.0.0.0/8,
        172.16.0.0/12, 192.168.0.0/16) behind a second handshake on top
        of regular CORS. The browser sends an `OPTIONS` preflight with
        an extra header:

            Access-Control-Request-Private-Network: true

        The browser will drop the actual request unless the response
        carries:

            Access-Control-Allow-Private-Network: true

        in addition to the usual `Access-Control-Allow-*` headers. This
        bites packaged Pufferblow clients (Electron renderer loaded
        from `app://pufferblow/`, web clients served from `https://`)
        when they try to reach a self-hosted instance on a LAN address
        or `localhost`. The renderer just sees a `Failed to fetch`
        because Chromium never lets the real request out.

    Behavior:
        This middleware sits OUTSIDE `CORSMiddleware` so it can decorate
        the preflight response that CORS has already filled in. If the
        incoming request looks like a PNA preflight, the response gets
        the `Access-Control-Allow-Private-Network` header on its way
        back to the client. Every other request passes through
        untouched.

    Authorization:
        This middleware does NOT authorize anything on its own. PNA is
        the *second* gate, on top of CORS. If `CORSMiddleware` declined
        the origin in the first place, the response will be missing
        `Access-Control-Allow-Origin` and the browser rejects it
        regardless of the PNA header.

    Spec: https://developer.chrome.com/docs/capabilities/web-apis/private-network-access
    """

    async def dispatch(self, request, call_next):
        """Dispatch."""
        is_pna_preflight = (
            request.method == "OPTIONS"
            and request.headers.get("access-control-request-private-network", "").strip().lower()
            == "true"
        )
        response = await call_next(request)
        if is_pna_preflight:
            response.headers["Access-Control-Allow-Private-Network"] = "true"
        return response
