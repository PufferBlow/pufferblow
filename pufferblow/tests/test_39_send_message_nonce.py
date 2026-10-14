"""A nonce makes the HTTP send route (the one that carries attachments) safe to retry.

Calls the route function with stubbed services instead of starting the app (see test_31
for why the TestClient fixture is avoided).
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from fastapi import exceptions

import pufferblow.api.routes.messages as routes
from pufferblow.api.principals.principal import Principal
from pufferblow.api.schemas import SendMessageForm


class MemoryStore:
    """The idempotency half of DatabaseHandler, in memory."""

    def __init__(self) -> None:
        self.rows: dict[tuple, dict] = {}

    def reserve_idempotency_key(self, principal_id, operation, key):
        row = self.rows.get((principal_id, operation, key))
        if row is None:
            self.rows[(principal_id, operation, key)] = {"status": "pending"}
            return "reserved", None
        if row["status"] == "completed":
            return "completed", row["result"]
        return "in_progress", None

    def complete_idempotency_key(self, principal_id, operation, key, result):
        self.rows[(principal_id, operation, key)] = {"status": "completed", "result": result}

    def release_idempotency_key(self, principal_id, operation, key):
        if self.rows.get((principal_id, operation, key), {}).get("status") == "pending":
            del self.rows[(principal_id, operation, key)]


class Messages:
    def __init__(self, fail: bool = False) -> None:
        self.created: list[str] = []
        self.fail = fail

    def create(self, principal, channel_id, content, **_kwargs):
        if self.fail:
            raise RuntimeError("database is down")
        message_id = f"m{len(self.created) + 1}"
        self.created.append(message_id)
        return SimpleNamespace(value={"raw": {"message_id": message_id, "message": content}}, events=[])


class Publisher:
    async def publish_all(self, events):
        return None


@pytest.fixture
def services(monkeypatch):
    store = MemoryStore()
    messages = Messages()
    initializer = routes.api_initializer
    monkeypatch.setattr(initializer, "user_principal_resolver", SimpleNamespace(resolve=lambda token: Principal(id="ada", kind="user")), raising=False)
    monkeypatch.setattr(initializer, "authorizer", SimpleNamespace(require_send=lambda principal, channel: None), raising=False)
    monkeypatch.setattr(initializer, "database_handler", store, raising=False)
    monkeypatch.setattr(initializer, "message_service", messages, raising=False)
    monkeypatch.setattr(initializer, "event_publisher", Publisher(), raising=False)
    monkeypatch.setattr(initializer, "storage_manager", None, raising=False)
    monkeypatch.setattr(routes, "_get_message_and_attachment_policy", lambda: (2000, 25))
    return SimpleNamespace(store=store, messages=messages)


def _send(text: str = "hello", nonce: str | None = "n1", channel_id: str = "c1") -> dict:
    form = SendMessageForm(auth_token="token", message=text, nonce=nonce)
    return asyncio.run(routes.channel_send_message(channel_id, (form, [], [])))


def test_a_retry_with_the_same_nonce_returns_the_first_message(services):
    first = _send()
    again = _send()

    assert services.messages.created == ["m1"]
    assert again["message_id"] == first["message_id"] == "m1"
    assert again["duplicate"] is True
    assert "duplicate" not in first


def test_different_nonces_are_different_messages(services):
    _send(nonce="n1")
    _send(nonce="n2")
    assert services.messages.created == ["m1", "m2"]


def test_without_a_nonce_nothing_is_deduplicated(services):
    _send(nonce=None)
    _send(nonce=None)
    assert services.messages.created == ["m1", "m2"]


def test_a_nonce_is_scoped_to_its_channel(services):
    _send(channel_id="c1")
    _send(channel_id="c2")
    assert services.messages.created == ["m1", "m2"]


def test_a_failed_send_frees_its_nonce_so_the_retry_runs(services):
    services.messages.fail = True
    with pytest.raises(RuntimeError):
        _send()
    services.messages.fail = False

    assert _send()["message_id"] == "m1"


def test_a_send_still_in_progress_is_told_to_retry_shortly(services):
    services.store.reserve_idempotency_key("ada", "http.send_message:c1", "n1")
    with pytest.raises(exceptions.HTTPException) as caught:
        _send()
    assert caught.value.status_code == 409
