"""Socket limits per address and per process, checked before authentication.

Calls the session entry point with a fake socket and stubbed managers instead of starting the
app (see test_31 for why the TestClient fixture is avoided).
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from fastapi import exceptions

import pufferblow.api.routes.ws_protocol as ws
from pufferblow.api.websocket.websocket_manager import WebSocketsManager


def _socket(ip: str = "203.0.113.7", forwarded: str | None = None):
    headers = {"x-forwarded-for": forwarded} if forwarded else {}
    return SimpleNamespace(headers=headers, client=SimpleNamespace(host=ip))


@pytest.fixture
def manager(monkeypatch):
    manager = WebSocketsManager(user_manager=None)
    resolved: list[str] = []

    def resolve(token):
        resolved.append(token)
        raise AssertionError("authentication should not be reached")

    monkeypatch.setattr(ws.api_initializer, "websockets_manager", manager, raising=False)
    monkeypatch.setattr(ws.api_initializer, "principal_resolver", SimpleNamespace(resolve=resolve), raising=False)
    manager.resolved = resolved
    return manager


def _fill(manager: WebSocketsManager, count: int, ip: str) -> None:
    for n in range(count):
        manager.active_connections[object()] = {"user_id": f"u{n}", "ip": ip}


def _open(socket):
    asyncio.run(ws.run_protocol_session(socket, "token", 1))


def test_one_address_cannot_hold_more_than_its_share(manager):
    _fill(manager, ws.MAX_CONNECTIONS_PER_IP, "203.0.113.7")
    with pytest.raises(exceptions.WebSocketException) as caught:
        _open(_socket("203.0.113.7"))
    assert caught.value.code == 1008
    assert manager.resolved == []  # refused before the token was even looked at


def test_the_address_behind_a_proxy_is_what_counts(manager):
    _fill(manager, ws.MAX_CONNECTIONS_PER_IP, "198.51.100.9")
    with pytest.raises(exceptions.WebSocketException):
        _open(_socket("10.0.0.1", forwarded="198.51.100.9, 10.0.0.1"))


def test_a_full_server_turns_everyone_away(manager, monkeypatch):
    monkeypatch.setattr(ws, "MAX_CONNECTIONS_TOTAL", 3)
    _fill(manager, 3, "192.0.2.1")
    with pytest.raises(exceptions.WebSocketException) as caught:
        _open(_socket("203.0.113.50"))
    assert caught.value.code == 1013  # try again later
    assert manager.resolved == []


def test_other_addresses_are_not_affected(manager):
    _fill(manager, ws.MAX_CONNECTIONS_PER_IP, "203.0.113.7")
    with pytest.raises(AssertionError, match="authentication should not be reached"):
        _open(_socket("203.0.113.8"))  # got as far as authenticating
