"""Unit tests for PrivateNetworkAccessMiddleware.

The middleware is tested in isolation against a tiny Starlette app rather
than the full FastAPI bootstrap so the test doesn't need a database, a
config file, or the full middleware stack. The integration with
CORSMiddleware (where PNA actually matters) is covered by exercising
both middlewares together in the same app — exactly the layering
production uses, minus everything else.
"""

from __future__ import annotations

from fastapi.middleware.cors import CORSMiddleware
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

# Import from the leaf module so this test doesn't pull in the full
# bootstrap chain (database, config, init). Both this path and the
# `core.middlewares` re-export reach the same class.
from pufferblow.core.pna_middleware import PrivateNetworkAccessMiddleware


def _build_app(*, cors_origin: str = "http://localhost:5173") -> Starlette:
    async def hello(_request):  # type: ignore[no-untyped-def]
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/api/v1/users/list", hello, methods=["GET"])])
    # Same layering as production: CORS inside, PNA outside.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[cors_origin],
        allow_methods=["*"],
        allow_headers=["*"],
        allow_credentials=False,
    )
    app.add_middleware(PrivateNetworkAccessMiddleware)
    return app


def test_pna_preflight_gets_allow_private_network_header():
    """A preflight that asks for PNA should get the explicit allow header."""
    client = TestClient(_build_app())

    response = client.options(
        "/api/v1/users/list",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Private-Network": "true",
        },
    )

    assert response.status_code == 200
    assert response.headers.get("access-control-allow-private-network") == "true"
    # And the regular CORS allow header is still present — PNA does not
    # replace CORS, it sits on top.
    assert response.headers.get("access-control-allow-origin") == "http://localhost:5173"


def test_pna_header_not_added_when_browser_did_not_request_it():
    """A normal CORS preflight without the PNA request header gets no PNA header.

    Adding the header unconditionally would be inert but noisy; it would
    also imply to log readers that every preflight is private-network,
    which is misleading.
    """
    client = TestClient(_build_app())

    response = client.options(
        "/api/v1/users/list",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.status_code == 200
    assert "access-control-allow-private-network" not in {
        key.lower() for key in response.headers
    }


def test_pna_header_not_added_to_actual_requests():
    """The PNA header only belongs on the preflight response, never on the real one.

    A GET with the PNA request header on it (which would be unusual but
    not impossible if a client implementation misbehaves) shouldn't end
    up echoing the allow header back. Browsers don't check for it on
    non-preflight responses, and shipping it would just be noise.
    """
    client = TestClient(_build_app())

    response = client.get(
        "/api/v1/users/list",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Private-Network": "true",
        },
    )

    assert response.status_code == 200
    assert "access-control-allow-private-network" not in {
        key.lower() for key in response.headers
    }


def test_pna_request_header_value_is_compared_case_insensitively():
    """Chromium sends 'true' lowercase; defensive against future variants."""
    client = TestClient(_build_app())

    response = client.options(
        "/api/v1/users/list",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Private-Network": "TRUE",
        },
    )

    assert response.headers.get("access-control-allow-private-network") == "true"


def test_pna_does_not_grant_authorization_when_cors_rejects():
    """PNA is a second gate, not a bypass for CORS.

    A preflight from an origin not in the CORS allowlist should not get
    Access-Control-Allow-Origin. Even though our middleware happily
    decorates the response with the PNA header, the browser would still
    reject the response because the first CORS gate said no.
    """
    client = TestClient(_build_app(cors_origin="http://allowed.example"))

    response = client.options(
        "/api/v1/users/list",
        headers={
            "Origin": "http://attacker.example",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Private-Network": "true",
        },
    )

    # Starlette CORSMiddleware returns 400 for an unrecognized origin's
    # preflight; the key assertion is that the auth header is missing.
    assert response.headers.get("access-control-allow-origin") is None
