"""The credential may travel in a header instead of the URL.

The first half tests the middleware on a bare ASGI app; the second sends real requests through
the application with ``Authorization: Bearer`` and the websocket bearer subprotocol.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi import WebSocketDisconnect
from fastapi.testclient import TestClient
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route, WebSocketRoute

from pufferblow.core.bootstrap import api_initializer
from pufferblow.core.header_auth import HeaderAuthMiddleware


async def _echo(request):
    return JSONResponse({"auth_token": request.query_params.get("auth_token"), "query": request.url.query})


async def _ws(websocket):
    await websocket.accept(subprotocol=websocket.scope.get("pufferblow.ws_subprotocol"))
    await websocket.send_json({"auth_token": websocket.query_params.get("auth_token")})
    await websocket.close()


def _bare_client() -> TestClient:
    app = Starlette(routes=[Route("/echo", _echo), WebSocketRoute("/ws", _ws)])
    return TestClient(HeaderAuthMiddleware(app))


def test_a_bearer_header_becomes_the_auth_token_parameter():
    body = _bare_client().get("/echo", headers={"Authorization": "Bearer abc.def-ghi"}).json()
    assert body["auth_token"] == "abc.def-ghi"


def test_an_explicit_query_token_wins_and_other_parameters_survive():
    body = _bare_client().get("/echo?x=1&auth_token=from-url", headers={"Authorization": "Bearer from-header"}).json()
    assert body["auth_token"] == "from-url"
    assert "x=1" in body["query"] and "from-header" not in body["query"]


def test_the_token_is_url_encoded_and_other_schemes_are_ignored():
    client = _bare_client()
    assert client.get("/echo", headers={"Authorization": "Bearer a&b=c d"}).json()["auth_token"] == "a&b=c d"
    assert client.get("/echo", headers={"Authorization": "Basic abc"}).json()["auth_token"] is None
    assert client.get("/echo", headers={"Authorization": "Bearer"}).json()["auth_token"] is None


def test_a_websocket_can_carry_the_token_in_a_subprotocol_and_only_the_name_is_echoed():
    with _bare_client().websocket_connect("/ws", subprotocols=["pufferblow.v1", "bearer.tok-123"]) as ws:
        assert ws.accepted_subprotocol == "pufferblow.v1"
        assert ws.receive_json() == {"auth_token": "tok-123"}


def test_the_original_scope_is_left_alone():
    seen = {}

    async def app(scope, receive, send):
        seen["inner"] = scope["query_string"]
        await JSONResponse({})(scope, receive, send)

    outer = {}

    async def capture(scope, receive, send):
        outer["scope"] = scope
        await HeaderAuthMiddleware(app)(scope, receive, send)

    TestClient(capture).get("/", headers={"Authorization": "Bearer secret"})
    assert b"auth_token=secret" in seen["inner"]
    assert b"secret" not in outer["scope"]["query_string"]  # what the server's access log reads


# ── through the application ───────────────────────────────────────


def _signup(client: TestClient, monkeypatch) -> str:
    # The SQLite test database has no `server` row, yet signup refuses to run without one.
    monkeypatch.setattr(api_initializer.database_handler, "get_server", lambda: object(), raising=False)
    response = client.post("/api/v1/users/signup", json={"username": f"hdr_{uuid.uuid4().hex[:8]}", "password": "12345678"})
    assert response.status_code == 201, response.text
    return response.json()["auth_token"]


def test_a_route_accepts_the_bearer_header_with_no_token_in_the_url(client: TestClient, monkeypatch):
    token = _signup(client, monkeypatch)
    by_header = client.get("/api/v1/users/list", headers={"Authorization": f"Bearer {token}"})
    assert by_header.status_code == 200, by_header.text
    assert client.get("/api/v1/users/list").status_code != 200  # and without any credential it is refused


def test_the_protocol_socket_accepts_a_bearer_subprotocol_instead_of_a_url_token(client: TestClient, monkeypatch):
    token = _signup(client, monkeypatch)
    with client.websocket_connect("/ws?protocol=1", subprotocols=["pufferblow.v1", f"bearer.{token}"]) as ws:
        assert ws.accepted_subprotocol == "pufferblow.v1"
        assert ws.receive_json()["type"] == "hello"
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws?protocol=1", subprotocols=["pufferblow.v1", "bearer.nonsense"]):
            pass
