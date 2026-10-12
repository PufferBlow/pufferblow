"""Command/event protocol v1: envelopes, dispatcher, services, delivery and bot foundations.

Most tests drive the dispatcher directly with fake sockets registered in the real
connection manager, which exercises authorization, persistence, idempotency and
delivery without depending on WebSocket timing. A few use the real ``/ws`` endpoint.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest
from fastapi import WebSocketDisconnect
from fastapi.testclient import TestClient

from pufferblow.api.commands.dispatcher import (
    CommandDispatcher,
    CommandSpec,
    ConnectionContext,
    HandlerOutput,
)
from pufferblow.api.commands.metrics import metrics
from pufferblow.api.commands.ratelimit import MemcacheRateLimiter, RateLimiter
from pufferblow.api.errors import ApiError, ErrorCode
from pufferblow.api.principals.principal import Principal
from pufferblow.api.protocol import commands as schema
from pufferblow.api.protocol.envelopes import (
    AckEnvelope,
    CommandEnvelope,
    ErrorEnvelope,
    EventEnvelope,
    HelloEnvelope,
    ProtocolErrorCode,
    build_ack,
    build_error,
    build_event,
    protocol_json_schema,
)
from pufferblow.api.protocol.errors import INTERNAL_MESSAGE
from pufferblow.api.utils.extract_user_id import extract_user_id
from pufferblow.core.bootstrap import api_initializer

PROJECT_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = PROJECT_ROOT / "docs" / "protocol" / "v1" / "fixtures"


# ── helpers ──────────────────────────────────────────────────────


class FakeSocket:
    """Stands in for a WebSocket: records frames, never touches the network."""

    client_state = 3  # already closed, so disconnect() skips close()

    def __init__(self) -> None:
        self.sent: list[dict] = []

    async def send_json(self, data: dict) -> None:
        self.sent.append(data)

    async def close(self, code: int = 1000) -> None:
        return None

    def events(self, name: str | None = None) -> list[dict]:
        return [f for f in self.sent if f.get("type") == "event" and (name is None or f["name"] == name)]


@pytest.fixture(autouse=True)
def _clean_state():
    metrics.reset()
    yield
    manager = api_initializer.websockets_manager
    if manager is not None:
        manager.active_connections.clear()


def _signup(client: TestClient) -> str:
    # The SQLite test database never gets a `server` row (create_server_row skips SQLite), yet signup
    # refuses to run without one. Present a stand-in so the real signup route is still exercised.
    api_initializer.database_handler.get_server = lambda: object()
    username = f"proto_{uuid.uuid4().hex[:8]}"
    response = client.post("/api/v1/users/signup", json={"username": username, "password": "12345678"})
    assert response.status_code == 201, response.text
    return response.json()["auth_token"]


def _new_channel(owner_token: str, *, private: bool = False) -> str:
    channel = api_initializer.channels_manager.create_channel(
        user_id=extract_user_id(owner_token),
        channel_name=f"t_{uuid.uuid4().hex[:8]}",
        is_private=private,
        channel_type="text",
    )
    return str(channel.channel_id)


def _context(token: str, *channels: str) -> ConnectionContext:
    resolver = api_initializer.user_principal_resolver
    return ConnectionContext(
        principal=resolver.resolve(token),
        session_id=f"ses_{uuid.uuid4().hex[:6]}",
        connection_key=f"key_{uuid.uuid4().hex[:6]}",
        subscriptions=set(channels),
        revalidate=lambda: resolver.resolve(token),
    )


def _attach(ctx: ConnectionContext, *, protocol: int = 1) -> FakeSocket:
    sock = FakeSocket()
    api_initializer.websockets_manager.active_connections[sock] = {
        "user_id": ctx.principal.id,
        "auth_token": "redacted",
        "scope": "global",
        "channel_id": None,
        "accessible_channels": list(ctx.subscriptions),
        "protocol": protocol,
        "context": ctx if protocol else None,
    }
    return sock


def _command(name: str, data: dict, command_id: str | None = None) -> dict:
    return {"type": "command", "version": 1, "id": command_id or f"cmd_{uuid.uuid4().hex[:8]}", "name": name, "data": data}


async def _run(ctx: ConnectionContext, frame: dict | str) -> dict:
    """Dispatch and publish exactly like the WebSocket route does; return the reply."""
    result = await api_initializer.command_dispatcher.dispatch(ctx, frame)
    await api_initializer.event_publisher.publish_all(result.events)
    return result.reply


def _message_count(channel_id: str) -> int:
    rows = api_initializer.messages_manager.load_messages(channel_id=channel_id, messages_per_page=100, page=1)
    return len(rows[0] if isinstance(rows, tuple) else rows)


def _error_code(reply: dict) -> str:
    assert reply["type"] == "error", reply
    return reply["error"]["code"]


# ── envelopes and fixtures ───────────────────────────────────────


FIXTURE_FILES = sorted(FIXTURES.glob("*.json"))


def test_fixtures_exist():
    assert len(FIXTURE_FILES) >= 15


@pytest.mark.parametrize("path", FIXTURE_FILES, ids=lambda p: p.stem)
def test_every_fixture_matches_its_schema(path: Path):
    document = json.loads(path.read_text(encoding="utf-8"))
    frame = document["frame"]

    if document["direction"] == "client_to_server":
        envelope = CommandEnvelope.model_validate(frame)
        schema.COMMAND_SCHEMAS[envelope.name].model_validate(envelope.data)
        return

    models = {"hello": HelloEnvelope, "ack": AckEnvelope, "error": ErrorEnvelope, "event": EventEnvelope}
    models[frame["type"]].model_validate(frame)
    if frame["type"] == "error":
        assert frame["error"]["code"] in ProtocolErrorCode.ALL


def test_client_copy_of_fixtures_is_identical_when_present():
    client_copy = PROJECT_ROOT.parent / "client-new" / "src" / "features" / "realtime" / "__fixtures__"
    if not client_copy.exists():
        pytest.skip("client-new is not checked out next to the backend")
    assert sorted(p.name for p in client_copy.glob("*.json")) == [p.name for p in FIXTURE_FILES]
    for path in FIXTURE_FILES:
        assert (client_copy / path.name).read_text(encoding="utf-8") == path.read_text(encoding="utf-8"), path.name


def test_json_schema_export_is_current_and_complete():
    exported = protocol_json_schema()
    assert set(exported["commands"]) == set(schema.COMMAND_SCHEMAS)
    assert set(exported["frames"]) == {"command", "hello", "ack", "error", "event"}
    committed = PROJECT_ROOT / "docs" / "protocol" / "v1" / "schema.json"
    assert json.loads(committed.read_text(encoding="utf-8")) == json.loads(json.dumps(exported)), (
        "docs/protocol/v1/schema.json is stale; run scripts/export/export_protocol_schema.py"
    )


def test_builders_produce_valid_frames():
    AckEnvelope.model_validate(build_ack("cmd_1", {"a": 1}))
    ErrorEnvelope.model_validate(build_error("cmd_1", ProtocolErrorCode.CONFLICT, "busy", retry_after=1))
    EventEnvelope.model_validate(build_event("message.created", {"id": "m"}, channel_id="c", seq=1, epoch="e"))


def test_event_ids_are_unique_and_distinct_from_command_ids():
    ids = {build_event("x", {})["id"] for _ in range(200)}
    assert len(ids) == 200
    assert all(i.startswith("evt_") for i in ids)


def test_retryable_flag_follows_the_code():
    assert build_error("c", ProtocolErrorCode.RATE_LIMITED, "slow")["error"]["retryable"] is True
    assert build_error("c", ProtocolErrorCode.PERMISSION_DENIED, "no")["error"]["retryable"] is False


# ── rate limiter ─────────────────────────────────────────────────


def test_rate_limiter_allows_a_burst_then_reports_the_wait():
    now = [100.0]
    limiter = RateLimiter(capacity=2, refill_per_second=1, clock=lambda: now[0])
    assert limiter.check("a") is None
    assert limiter.check("a") is None
    wait = limiter.check("a")
    assert wait is not None and 0 < wait <= 1
    assert limiter.check("b") is None  # other keys are independent
    now[0] += 1.5
    assert limiter.check("a") is None


class FakeMemcache:
    """Stands in for `MemcacheCache`: a plain dict with atomic-enough `incr`."""

    def __init__(self) -> None:
        self.rows: dict[str, int] = {}

    def incr(self, key, delta=1, initial=0, ttl=None):
        self.rows[key] = self.rows.get(key, initial) + delta
        return self.rows[key]

    def delete(self, key) -> None:
        self.rows.pop(key, None)


class UnreachableMemcache:
    """Stands in for a memcache daemon that is down: `incr` always fails open."""

    def incr(self, key, delta=1, initial=0, ttl=None):
        return None

    def delete(self, key) -> None:
        pass


def test_memcache_rate_limiter_allows_a_burst_then_denies_with_a_positive_retry(monkeypatch):
    import pufferblow.api.cache.memcache as memcache_module

    fake = FakeMemcache()
    monkeypatch.setattr(memcache_module, "get_cache", lambda config: fake)

    now = [1_000.0]
    limiter = MemcacheRateLimiter(config=None, capacity=2, refill_per_second=1, clock=lambda: now[0])
    assert limiter.check("principal-a") is None
    assert limiter.check("principal-a") is None
    wait = limiter.check("principal-a")
    assert wait is not None and wait > 0
    assert limiter.check("principal-b") is None  # other keys are independent


def test_memcache_rate_limiter_fails_open_when_memcache_is_unreachable(monkeypatch):
    import pufferblow.api.cache.memcache as memcache_module

    monkeypatch.setattr(memcache_module, "get_cache", lambda config: UnreachableMemcache())

    limiter = MemcacheRateLimiter(config=None, capacity=1, refill_per_second=1)
    for _ in range(10):
        assert limiter.check("principal-a") is None


# ── dispatcher without a database ────────────────────────────────


def _toy_dispatcher(**kwargs) -> tuple[CommandDispatcher, list]:
    calls: list = []

    async def handle(ctx, data):
        calls.append(data)
        return HandlerOutput(result={"channel_id": data.channel_id})

    registry = {"channel.subscribe": CommandSpec("channel.subscribe", schema.ChannelRef, handle, idempotency_key=lambda d: d.channel_id)}
    return CommandDispatcher(registry, **kwargs), calls


def _toy_ctx() -> ConnectionContext:
    return ConnectionContext(principal=Principal(id="u1", kind="user"), session_id="ses_1", connection_key="k1")


async def test_ack_echoes_the_command_id():
    dispatcher, _ = _toy_dispatcher()
    result = await dispatcher.dispatch(_toy_ctx(), _command("channel.subscribe", {"channel_id": "c"}, "cmd_abc"))
    assert result.reply["type"] == "ack" and result.reply["id"] == "cmd_abc"
    assert result.reply["data"] == {"status": "completed", "result": {"channel_id": "c"}}


@pytest.mark.parametrize(
    "raw, code",
    [
        ("not json", ProtocolErrorCode.MALFORMED),
        ("[1, 2]", ProtocolErrorCode.MALFORMED),
        (json.dumps({"type": "event", "version": 1}), ProtocolErrorCode.MALFORMED),
        (json.dumps({"type": "command", "version": 1, "name": "x", "data": {}}), ProtocolErrorCode.MALFORMED),
        (json.dumps({"type": "command", "version": 1, "id": "", "name": "x"}), ProtocolErrorCode.MALFORMED),
        (json.dumps({"type": "command", "version": 1, "id": "c", "name": "x", "data": [], }), ProtocolErrorCode.MALFORMED),
        (json.dumps({"type": "command", "version": 1, "id": "c", "name": "x", "data": {}, "principal": "admin"}), ProtocolErrorCode.MALFORMED),
        ("x" * 70_000, ProtocolErrorCode.PAYLOAD_TOO_LARGE),
    ],
    ids=["not-json", "array", "wrong-type", "missing-id", "empty-id", "data-not-object", "extra-field", "too-large"],
)
async def test_malformed_frames_become_errors_not_exceptions(raw, code):
    dispatcher, calls = _toy_dispatcher()
    result = await dispatcher.dispatch(_toy_ctx(), raw)
    assert _error_code(result.reply) == code
    assert calls == []


async def test_unsupported_protocol_version_is_rejected_with_the_command_id():
    dispatcher, calls = _toy_dispatcher()
    frame = _command("channel.subscribe", {"channel_id": "c"}, "cmd_v")
    frame["version"] = 2
    result = await dispatcher.dispatch(_toy_ctx(), frame)
    assert _error_code(result.reply) == ProtocolErrorCode.UNSUPPORTED_VERSION
    assert result.reply["id"] == "cmd_v"
    assert calls == []


async def test_unknown_command_is_rejected():
    dispatcher, _ = _toy_dispatcher()
    result = await dispatcher.dispatch(_toy_ctx(), _command("message.shout", {}, "cmd_u"))
    assert _error_code(result.reply) == ProtocolErrorCode.UNKNOWN_COMMAND
    assert result.reply["id"] == "cmd_u"


async def test_invalid_data_names_the_field_but_never_echoes_values():
    dispatcher, calls = _toy_dispatcher()
    secret = "super-secret-value"
    result = await dispatcher.dispatch(_toy_ctx(), _command("channel.subscribe", {"channel_id": "c", "principal_id": secret}))
    assert _error_code(result.reply) == ProtocolErrorCode.VALIDATION_FAILED
    assert "principal_id" in result.reply["error"]["message"]
    assert secret not in json.dumps(result.reply)
    assert calls == []


async def test_a_payload_cannot_smuggle_an_identity():
    dispatcher, _ = _toy_dispatcher()
    for field in ("user_id", "principal_id", "author_id", "auth_token"):
        result = await dispatcher.dispatch(_toy_ctx(), _command("channel.subscribe", {"channel_id": "c", field: "other"}))
        assert _error_code(result.reply) == ProtocolErrorCode.VALIDATION_FAILED


async def test_internal_errors_never_leak_details():
    async def explode(ctx, data):
        raise RuntimeError("psycopg2.OperationalError password=hunter2 host=10.0.0.5")

    dispatcher = CommandDispatcher({"channel.subscribe": CommandSpec("channel.subscribe", schema.ChannelRef, explode)})
    result = await dispatcher.dispatch(_toy_ctx(), _command("channel.subscribe", {"channel_id": "c"}))
    assert _error_code(result.reply) == ProtocolErrorCode.INTERNAL
    assert result.reply["error"]["message"] == INTERNAL_MESSAGE
    assert "hunter2" not in json.dumps(result.reply)


async def test_api_errors_map_to_protocol_codes():
    cases = [
        (ErrorCode.AUTH_PRIVILEGE_DENIED, ProtocolErrorCode.PERMISSION_DENIED),
        (ErrorCode.CHANNELS_NOT_FOUND, ProtocolErrorCode.NOT_FOUND),
        (ErrorCode.AUTH_INVALID_TOKEN, ProtocolErrorCode.UNAUTHENTICATED),
        (ErrorCode.MESSAGES_EMPTY, ProtocolErrorCode.VALIDATION_FAILED),
    ]
    for api_code, expected in cases:

        async def fail(ctx, data, _code=api_code):
            raise ApiError(_code)

        dispatcher = CommandDispatcher({"channel.subscribe": CommandSpec("channel.subscribe", schema.ChannelRef, fail)})
        result = await dispatcher.dispatch(_toy_ctx(), _command("channel.subscribe", {"channel_id": "c"}))
        assert _error_code(result.reply) == expected


async def test_rate_limit_rejects_with_a_retry_hint():
    dispatcher, calls = _toy_dispatcher(
        principal_limiter=RateLimiter(capacity=2, refill_per_second=0.001),
        connection_limiter=RateLimiter(capacity=100, refill_per_second=100),
    )
    ctx = _toy_ctx()
    for i in range(2):
        assert (await dispatcher.dispatch(ctx, _command("channel.subscribe", {"channel_id": f"c{i}"}))).reply["type"] == "ack"
    limited = await dispatcher.dispatch(ctx, _command("channel.subscribe", {"channel_id": "c9"}))
    assert _error_code(limited.reply) == ProtocolErrorCode.RATE_LIMITED
    assert limited.reply["error"]["retry_after"] > 0
    assert len(calls) == 2
    assert metrics.snapshot()["rate_limited"] == 1


async def test_revoked_credentials_stop_working_mid_connection():
    dispatcher, calls = _toy_dispatcher()
    ctx = _toy_ctx()

    def revoked():
        raise ApiError(ErrorCode.AUTH_INVALID_TOKEN)

    ctx.revalidate = revoked
    result = await dispatcher.dispatch(ctx, _command("channel.subscribe", {"channel_id": "c"}))
    assert _error_code(result.reply) == ProtocolErrorCode.UNAUTHENTICATED
    assert calls == []


class MemoryStore:
    def __init__(self) -> None:
        self.rows: dict = {}
        self.in_progress = False

    def reserve_idempotency_key(self, principal, operation, key):
        row = self.rows.get((principal, operation, key))
        if row is None:
            self.rows[(principal, operation, key)] = {"status": "pending", "result": None}
            return "reserved", None
        return ("completed", row["result"]) if row["status"] == "completed" else ("in_progress", None)

    def complete_idempotency_key(self, principal, operation, key, result):
        self.rows[(principal, operation, key)] = {"status": "completed", "result": result}

    def release_idempotency_key(self, principal, operation, key):
        self.rows.pop((principal, operation, key), None)


async def test_a_retry_with_the_same_key_returns_the_stored_result_without_rerunning():
    dispatcher, calls = _toy_dispatcher(idempotency_store=MemoryStore())
    ctx = _toy_ctx()
    first = await dispatcher.dispatch(ctx, _command("channel.subscribe", {"channel_id": "same"}, "cmd_1"))
    second = await dispatcher.dispatch(ctx, _command("channel.subscribe", {"channel_id": "same"}, "cmd_2"))
    assert len(calls) == 1
    assert second.reply["id"] == "cmd_2"  # correlated to the retry, not the original
    assert second.reply["data"]["result"] == first.reply["data"]["result"]
    assert second.reply["data"]["duplicate"] is True
    assert second.events == []
    assert metrics.snapshot()["duplicate_commands"] == 1


async def test_idempotency_is_scoped_to_the_principal():
    store = MemoryStore()
    dispatcher, calls = _toy_dispatcher(idempotency_store=store)
    other = ConnectionContext(principal=Principal(id="u2", kind="user"), session_id="s2", connection_key="k2")
    await dispatcher.dispatch(_toy_ctx(), _command("channel.subscribe", {"channel_id": "same"}))
    await dispatcher.dispatch(other, _command("channel.subscribe", {"channel_id": "same"}))
    assert len(calls) == 2


async def test_a_concurrent_duplicate_is_told_to_retry_shortly():
    store = MemoryStore()
    store.rows[("u1", "channel.subscribe", "busy")] = {"status": "pending", "result": None}
    dispatcher, calls = _toy_dispatcher(idempotency_store=store)
    result = await dispatcher.dispatch(_toy_ctx(), _command("channel.subscribe", {"channel_id": "busy"}))
    assert _error_code(result.reply) == ProtocolErrorCode.CONFLICT
    assert result.reply["error"]["retryable"] is True
    assert calls == []


async def test_a_failed_command_frees_its_key_so_the_retry_runs():
    store = MemoryStore()
    attempts = []

    async def flaky(ctx, data):
        attempts.append(1)
        if len(attempts) == 1:
            raise RuntimeError("transient")
        return HandlerOutput(result={"ok": True})

    dispatcher = CommandDispatcher(
        {"channel.subscribe": CommandSpec("channel.subscribe", schema.ChannelRef, flaky, idempotency_key=lambda d: d.channel_id)},
        idempotency_store=store,
    )
    ctx = _toy_ctx()
    first = await dispatcher.dispatch(ctx, _command("channel.subscribe", {"channel_id": "k"}))
    assert _error_code(first.reply) == ProtocolErrorCode.INTERNAL
    second = await dispatcher.dispatch(ctx, _command("channel.subscribe", {"channel_id": "k"}))
    assert second.reply["type"] == "ack" and "duplicate" not in second.reply["data"]


# ── message commands against the real services ───────────────────


async def test_message_create_persists_acks_and_then_publishes(client: TestClient):
    token = _signup(client)
    channel = _new_channel(token)
    ctx = _context(token, channel)
    sock = _attach(ctx)

    reply = await _run(ctx, _command("message.create", {"channel_id": channel, "content": "Hello!", "nonce": "n1"}, "cmd_1"))

    assert reply["type"] == "ack" and reply["id"] == "cmd_1"
    message = reply["data"]["result"]["message"]
    assert message["content"] == "Hello!" and message["channel_id"] == channel
    assert message["author_id"] == ctx.principal.id

    created = sock.events("message.created")
    assert len(created) == 1
    assert created[0]["data"]["id"] == message["id"]
    assert created[0]["id"].startswith("evt_") and created[0]["id"] != message["id"]
    assert created[0]["seq"] == 1 and created[0]["epoch"] == api_initializer.event_publisher.epoch
    assert _message_count(channel) == 1


async def test_retrying_with_the_same_nonce_creates_one_message(client: TestClient):
    token = _signup(client)
    channel = _new_channel(token)
    ctx = _context(token, channel)
    sock = _attach(ctx)

    first = await _run(ctx, _command("message.create", {"channel_id": channel, "content": "once", "nonce": "same"}, "cmd_a"))
    retry = await _run(ctx, _command("message.create", {"channel_id": channel, "content": "once", "nonce": "same"}, "cmd_b"))

    assert retry["data"]["duplicate"] is True
    assert retry["data"]["result"]["message"]["id"] == first["data"]["result"]["message"]["id"]
    assert _message_count(channel) == 1
    assert len(sock.events("message.created")) == 1  # the retry did not publish again


async def test_identical_text_with_different_nonces_is_two_messages(client: TestClient):
    token = _signup(client)
    channel = _new_channel(token)
    ctx = _context(token, channel)
    for nonce in ("n1", "n2"):
        reply = await _run(ctx, _command("message.create", {"channel_id": channel, "content": "same text", "nonce": nonce}))
        assert reply["type"] == "ack"
    assert _message_count(channel) == 2


async def test_without_a_nonce_nothing_is_deduplicated(client: TestClient):
    token = _signup(client)
    channel = _new_channel(token)
    ctx = _context(token, channel)
    for _ in range(2):
        await _run(ctx, _command("message.create", {"channel_id": channel, "content": "again"}))
    assert _message_count(channel) == 2


async def test_a_persistence_failure_is_an_error_with_no_event_and_the_retry_works(client: TestClient, monkeypatch):
    token = _signup(client)
    channel = _new_channel(token)
    ctx = _context(token, channel)
    sock = _attach(ctx)

    real = api_initializer.messages_manager.send_message

    def broken(*args, **kwargs):
        raise RuntimeError("disk on fire password=hunter2")

    monkeypatch.setattr(api_initializer.messages_manager, "send_message", broken)
    failed = await _run(ctx, _command("message.create", {"channel_id": channel, "content": "x", "nonce": "retry-me"}))
    assert _error_code(failed) == ProtocolErrorCode.INTERNAL
    assert "hunter2" not in json.dumps(failed)
    assert sock.events() == []
    assert _message_count(channel) == 0

    monkeypatch.setattr(api_initializer.messages_manager, "send_message", real)
    retried = await _run(ctx, _command("message.create", {"channel_id": channel, "content": "x", "nonce": "retry-me"}))
    assert retried["type"] == "ack" and "duplicate" not in retried["data"]
    assert _message_count(channel) == 1
    assert len(sock.events("message.created")) == 1


async def test_validation_rules_are_enforced_by_the_service(client: TestClient):
    token = _signup(client)
    channel = _new_channel(token)
    ctx = _context(token, channel)

    empty = await _run(ctx, _command("message.create", {"channel_id": channel, "content": "   "}))
    assert _error_code(empty) == ProtocolErrorCode.VALIDATION_FAILED

    missing = await _run(ctx, _command("message.create", {"channel_id": "no-such-channel", "content": "hi"}))
    assert _error_code(missing) == ProtocolErrorCode.NOT_FOUND
    assert _message_count(channel) == 0


async def test_permission_matrix(client: TestClient):
    author_token, other_token = _signup(client), _signup(client)
    channel = _new_channel(author_token)
    author, other = _context(author_token, channel), _context(other_token, channel)

    created = await _run(author, _command("message.create", {"channel_id": channel, "content": "mine"}))
    message_id = created["data"]["result"]["message"]["id"]

    # Someone else cannot rewrite or remove it.
    assert _error_code(await _run(other, _command("message.edit", {"channel_id": channel, "message_id": message_id, "content": "hacked"}))) == ProtocolErrorCode.PERMISSION_DENIED
    assert _error_code(await _run(other, _command("message.delete", {"channel_id": channel, "message_id": message_id}))) == ProtocolErrorCode.PERMISSION_DENIED
    assert _message_count(channel) == 1

    # A principal without send_messages cannot send at all.
    mute = ConnectionContext(principal=Principal(id=other.principal.id, kind="user", privileges=frozenset()), session_id="s", connection_key="k", subscriptions={channel})
    assert _error_code(await _run(mute, _command("message.create", {"channel_id": channel, "content": "hi"}))) == ProtocolErrorCode.PERMISSION_DENIED

    # A moderator may delete (but still not edit) someone else's message.
    moderator = ConnectionContext(
        principal=Principal(id=other.principal.id, kind="user", privileges=frozenset({"send_messages", "delete_messages"})),
        session_id="s2",
        connection_key="k2",
        subscriptions={channel},
    )
    assert _error_code(await _run(moderator, _command("message.edit", {"channel_id": channel, "message_id": message_id, "content": "x"}))) == ProtocolErrorCode.PERMISSION_DENIED
    deleted = await _run(moderator, _command("message.delete", {"channel_id": channel, "message_id": message_id}))
    assert deleted["data"]["result"]["deleted"] is True
    assert _message_count(channel) == 0


async def test_edit_and_delete_publish_events_and_delete_is_idempotent(client: TestClient):
    token = _signup(client)
    channel = _new_channel(token)
    ctx = _context(token, channel)
    sock = _attach(ctx)

    created = await _run(ctx, _command("message.create", {"channel_id": channel, "content": "first"}))
    message_id = created["data"]["result"]["message"]["id"]

    edited = await _run(ctx, _command("message.edit", {"channel_id": channel, "message_id": message_id, "content": "second"}))
    assert edited["data"]["result"]["edit_count"] == 1
    updated = sock.events("message.updated")[0]["data"]
    assert updated["content"] == "second" and updated["id"] == message_id

    deleted = await _run(ctx, _command("message.delete", {"channel_id": channel, "message_id": message_id}))
    assert deleted["data"]["result"]["deleted"] is True
    assert sock.events("message.deleted")[0]["data"]["id"] == message_id

    again = await _run(ctx, _command("message.delete", {"channel_id": channel, "message_id": message_id}))
    assert again["type"] == "ack" and again["data"]["result"]["already_deleted"] is True
    assert len(sock.events("message.deleted")) == 1


async def test_a_message_cannot_be_edited_through_another_channel(client: TestClient):
    token = _signup(client)
    channel_a, channel_b = _new_channel(token), _new_channel(token)
    ctx = _context(token, channel_a, channel_b)
    created = await _run(ctx, _command("message.create", {"channel_id": channel_a, "content": "in A"}))
    message_id = created["data"]["result"]["message"]["id"]

    reply = await _run(ctx, _command("message.edit", {"channel_id": channel_b, "message_id": message_id, "content": "sneaky"}))
    assert _error_code(reply) == ProtocolErrorCode.NOT_FOUND


async def test_reactions_publish_events_and_repeat_adds_are_quiet(client: TestClient):
    token = _signup(client)
    channel = _new_channel(token)
    ctx = _context(token, channel)
    sock = _attach(ctx)
    message_id = (await _run(ctx, _command("message.create", {"channel_id": channel, "content": "react"})))["data"]["result"]["message"]["id"]

    added = await _run(ctx, _command("reaction.add", {"channel_id": channel, "message_id": message_id, "emoji": "👍"}))
    assert added["data"]["result"]["changed"] is True
    assert sock.events("reaction.added")[0]["data"]["reactions"][0]["count"] == 1

    again = await _run(ctx, _command("reaction.add", {"channel_id": channel, "message_id": message_id, "emoji": "👍"}))
    assert again["data"]["result"]["changed"] is False
    assert len(sock.events("reaction.added")) == 1

    removed = await _run(ctx, _command("reaction.remove", {"channel_id": channel, "message_id": message_id, "emoji": "👍"}))
    assert removed["data"]["result"]["changed"] is True
    assert len(sock.events("reaction.removed")) == 1


# ── subscriptions, isolation, delivery ───────────────────────────


async def test_subscribe_checks_access_and_hides_private_channels(client: TestClient):
    token = _signup(client)
    private = _new_channel(token, private=True)
    ctx = _context(token)

    denied = await _run(ctx, _command("channel.subscribe", {"channel_id": private}))
    assert _error_code(denied) == ProtocolErrorCode.NOT_FOUND  # same answer as "does not exist"
    missing = await _run(ctx, _command("channel.subscribe", {"channel_id": "nope"}))
    assert denied["error"]["message"] == missing["error"]["message"]
    assert private not in ctx.subscriptions

    privileged = ConnectionContext(
        principal=Principal(id=ctx.principal.id, kind="user", privileges=frozenset({"send_messages", "view_private_channels"})),
        session_id="s",
        connection_key="k",
    )
    allowed = await _run(privileged, _command("channel.subscribe", {"channel_id": private}))
    assert allowed["type"] == "ack" and private in privileged.subscriptions
    assert allowed["data"]["result"]["epoch"] == api_initializer.event_publisher.epoch


async def test_unsubscribe_stops_delivery(client: TestClient):
    token = _signup(client)
    channel = _new_channel(token)
    ctx = _context(token, channel)
    sock = _attach(ctx)

    await _run(ctx, _command("channel.unsubscribe", {"channel_id": channel}))
    await _run(ctx, _command("message.create", {"channel_id": channel, "content": "nobody listening"}))
    assert sock.events() == []


async def test_events_never_cross_channels(client: TestClient):
    token = _signup(client)
    channel_a, channel_b = _new_channel(token), _new_channel(token)
    sender = _context(token, channel_a, channel_b)
    only_a, only_b = _context(_signup(client), channel_a), _context(_signup(client), channel_b)
    sock_a, sock_b = _attach(only_a), _attach(only_b)

    await _run(sender, _command("message.create", {"channel_id": channel_a, "content": "for A"}))

    assert len(sock_a.events("message.created")) == 1
    assert sock_b.events() == []


async def test_sequence_numbers_are_per_channel(client: TestClient):
    token = _signup(client)
    channel_a, channel_b = _new_channel(token), _new_channel(token)
    ctx = _context(token, channel_a, channel_b)
    sock = _attach(ctx)

    for channel in (channel_a, channel_a, channel_b, channel_a):
        await _run(ctx, _command("message.create", {"channel_id": channel, "content": "x"}))

    seqs = [(e["channel_id"], e["seq"]) for e in sock.events("message.created")]
    assert seqs == [(channel_a, 1), (channel_a, 2), (channel_b, 1), (channel_a, 3)]


async def test_every_connection_of_a_user_receives_the_event(client: TestClient):
    token = _signup(client)
    channel = _new_channel(token)
    first, second = _context(token, channel), _context(token, channel)
    sock1, sock2 = _attach(first), _attach(second)

    await _run(first, _command("message.create", {"channel_id": channel, "content": "multi-device"}))
    assert len(sock1.events("message.created")) == len(sock2.events("message.created")) == 1


async def test_private_channel_events_are_rechecked_at_delivery(client: TestClient):
    token = _signup(client)
    private = _new_channel(token, private=True)
    outsider = _context(_signup(client))
    outsider.subscriptions.add(private)  # a stale or forged subscription
    sock = _attach(outsider)

    from pufferblow.api.protocol.events import MESSAGE_CREATED, DomainEvent

    await api_initializer.event_publisher.publish_all([DomainEvent(MESSAGE_CREATED, {"id": "m"}, channel_id=private)])
    assert sock.events() == []


async def test_legacy_clients_get_the_legacy_frame_and_v1_clients_the_envelope(client: TestClient):
    token = _signup(client)
    channel = _new_channel(token)
    v1_ctx = _context(token, channel)
    v1 = _attach(v1_ctx)
    legacy = _attach(_context(_signup(client), channel), protocol=0)

    response = client.post(
        f"/api/v1/channels/{channel}/send_message",
        data={"auth_token": token, "message": "via http", "sent_at": ""},
    )
    assert response.status_code in (200, 201), response.text
    body = response.json()
    assert body["message_id"] and body["message_data"]["message"] == "via http"

    assert [e["data"]["content"] for e in v1.events("message.created")] == ["via http"]
    assert all(f.get("type") == "event" for f in v1.sent)
    assert [f["message"] for f in legacy.sent] == ["via http"]
    assert "type" not in legacy.sent[0]  # the old raw message shape


async def test_http_edit_delete_and_reactions_share_the_service_and_events(client: TestClient):
    token = _signup(client)
    channel = _new_channel(token)
    ctx = _context(token, channel)
    sock = _attach(ctx)

    sent = client.post(f"/api/v1/channels/{channel}/send_message", data={"auth_token": token, "message": "v1", "sent_at": ""})
    message_id = sent.json()["message_id"]
    base = f"/api/v1/channels/{channel}"

    assert client.patch(f"{base}/messages/{message_id}", json={"auth_token": token, "message": "v2"}).json()["edit_count"] == 1
    assert client.post(f"{base}/messages/{message_id}/reactions", params={"auth_token": token, "emoji": "🎉"}).status_code == 201
    assert client.delete(f"{base}/messages/{message_id}/reactions", params={"auth_token": token, "emoji": "🎉"}).status_code == 200
    assert client.delete(f"{base}/delete_message", params={"auth_token": token, "message_id": message_id}).status_code == 200

    assert [f["name"] for f in sock.events()] == ["message.created", "message.updated", "reaction.added", "reaction.removed", "message.deleted"]


async def test_http_routes_still_reject_unauthorised_edits(client: TestClient):
    owner, other = _signup(client), _signup(client)
    channel = _new_channel(owner)
    message_id = client.post(
        f"/api/v1/channels/{channel}/send_message", data={"auth_token": owner, "message": "mine", "sent_at": ""}
    ).json()["message_id"]

    response = client.patch(f"/api/v1/channels/{channel}/messages/{message_id}", json={"auth_token": other, "message": "no"})
    assert response.status_code == 403
    response = client.delete(f"/api/v1/channels/{channel}/delete_message", params={"auth_token": other, "message_id": message_id})
    assert response.status_code == 403


async def test_disconnect_removes_the_connection(client: TestClient):
    token = _signup(client)
    ctx = _context(token, _new_channel(token))
    sock = _attach(ctx)
    assert sock in api_initializer.websockets_manager.active_connections

    await api_initializer.websockets_manager.disconnect(sock)
    assert sock not in api_initializer.websockets_manager.active_connections


async def test_revalidation_drops_subscriptions_that_are_no_longer_allowed(client: TestClient):
    token = _signup(client)
    private = _new_channel(token, private=True)

    ctx = ConnectionContext(
        principal=Principal(id=extract_user_id(token), kind="user", privileges=frozenset({"send_messages", "view_private_channels"})),
        session_id="s",
        connection_key="k",
        subscriptions={private},
    )
    ctx.revalidate = lambda: Principal(id=ctx.principal.id, kind="user", privileges=frozenset({"send_messages"}))  # privilege revoked
    sock = _attach(ctx)

    removed = await api_initializer.websockets_manager.revalidate_subscriptions(api_initializer.authorizer, private)
    assert removed == 1 and private not in ctx.subscriptions
    notice = sock.events("channel.updated")[0]
    assert notice["data"] == {"channel_id": private, "access": "revoked"}


async def test_resync_returns_recent_messages_in_order_with_the_current_sequence(client: TestClient):
    token = _signup(client)
    channel = _new_channel(token)
    ctx = _context(token, channel)
    _attach(ctx)
    for text in ("one", "two", "three"):
        await _run(ctx, _command("message.create", {"channel_id": channel, "content": text}))

    reply = await _run(ctx, _command("events.resync", {"channel_id": channel, "limit": 10}))
    result = reply["data"]["result"]
    assert [m["content"] for m in result["messages"]] == ["one", "two", "three"]
    assert result["seq"] == 3 and result["epoch"] == api_initializer.event_publisher.epoch

    other = _context(_signup(client))
    assert _error_code(await _run(other, _command("events.resync", {"channel_id": _new_channel(token, private=True)}))) == ProtocolErrorCode.NOT_FOUND


# ── real /ws endpoint ────────────────────────────────────────────


def test_websocket_session_hello_command_ack_and_event(client: TestClient):
    token = _signup(client)
    channel = _new_channel(token)

    with client.websocket_connect(f"/ws?auth_token={token}&protocol=1") as ws:
        hello = ws.receive_json()
        HelloEnvelope.model_validate(hello)
        assert hello["supported"] == [1] and hello["epoch"] == api_initializer.event_publisher.epoch

        ws.send_json({"type": "ping"})
        assert ws.receive_json()["type"] == "pong"

        ws.send_json(_command("message.create", {"channel_id": channel, "content": "over the socket", "nonce": "w1"}, "cmd_ws"))
        ack = ws.receive_json()
        assert ack["type"] == "ack" and ack["id"] == "cmd_ws"
        event = ws.receive_json()
        assert event["name"] == "message.created" and event["data"]["id"] == ack["data"]["result"]["message"]["id"]

        # A broken frame is answered and the session carries on.
        ws.send_text("{not json")
        assert ws.receive_json()["error"]["code"] == ProtocolErrorCode.MALFORMED
        ws.send_json({"type": "ping"})
        assert ws.receive_json()["type"] == "pong"

    assert _message_count(channel) == 1


def test_websocket_rejects_bad_credentials_and_unknown_versions(client: TestClient):
    token = _signup(client)
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws?auth_token=garbage&protocol=1"):
            pass
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/ws?auth_token={token}&protocol=2"):
            pass


def test_websocket_closes_when_the_session_stops_validating(client: TestClient, monkeypatch):
    token = _signup(client)
    channel = _new_channel(token)
    with client.websocket_connect(f"/ws?auth_token={token}&protocol=1") as ws:
        ws.receive_json()

        def expired(_credential):
            raise ApiError(ErrorCode.AUTH_INVALID_TOKEN)

        monkeypatch.setattr(api_initializer.user_principal_resolver, "resolve", expired)
        ws.send_json(_command("message.create", {"channel_id": channel, "content": "too late"}))
        assert ws.receive_json()["error"]["code"] == ProtocolErrorCode.UNAUTHENTICATED
        with pytest.raises(WebSocketDisconnect):
            ws.receive_json()
    assert _message_count(channel) == 0


# ── principals and bots ──────────────────────────────────────────


def test_user_principal_is_derived_from_the_credential(client: TestClient):
    token = _signup(client)
    principal = api_initializer.user_principal_resolver.resolve(token)
    assert principal.kind == "user" and not principal.is_bot
    assert principal.id == extract_user_id(token) and principal.owner_user_id == principal.id
    assert principal.has("send_messages")

    with pytest.raises(ApiError):
        api_initializer.user_principal_resolver.resolve("abcd")


def test_bot_token_is_shown_once_and_only_a_hash_is_stored(client: TestClient):
    owner = extract_user_id(_signup(client))
    created = api_initializer.bot_manager.create_bot(owner, "helper", ["send_messages"])

    assert created.token.startswith("pbb_")
    prefix = created.token[len("pbb_") :].split(".")[0]
    row = api_initializer.database_handler.get_bot(created.identity.bot_id)
    assert created.token not in (row.token_hash, row.token_prefix)
    assert created.token.split(".")[1] not in row.token_hash
    assert row.token_prefix == prefix and len(row.token_hash) == 64

    verified = api_initializer.bot_manager.verify_token(created.token)
    assert verified is not None and verified.bot_id == created.identity.bot_id
    assert api_initializer.bot_manager.verify_token(created.token + "x") is None
    assert api_initializer.bot_manager.verify_token("pbb_" + prefix + ".wrong") is None
    assert api_initializer.bot_manager.verify_token("garbage") is None


def test_revoked_bot_tokens_stop_verifying(client: TestClient):
    owner = extract_user_id(_signup(client))
    created = api_initializer.bot_manager.create_bot(owner, "short-lived", ["send_messages"])
    assert api_initializer.bot_manager.revoke(created.identity.bot_id) is True
    assert api_initializer.bot_manager.verify_token(created.token) is None
    assert api_initializer.bot_manager.revoke(created.identity.bot_id) is False  # already revoked


def test_bots_cannot_be_given_administrative_scopes(client: TestClient):
    owner = extract_user_id(_signup(client))
    for scope in ("delete_messages", "manage_roles", "administrator", "*"):
        with pytest.raises(ValueError):
            api_initializer.bot_manager.create_bot(owner, "greedy", [scope])
    with pytest.raises(ValueError):
        api_initializer.bot_manager.create_bot(owner, "  ", ["send_messages"])


def test_bot_principal_never_exceeds_its_owner_or_its_scopes(client: TestClient):
    owner = extract_user_id(_signup(client))
    created = api_initializer.bot_manager.create_bot(owner, "scoped", ["send_messages", "view_private_channels"])
    principal = api_initializer.bot_principal_resolver.resolve(created.token)

    assert principal.is_bot and principal.id == f"bot:{created.identity.bot_id}"
    assert principal.owner_user_id == owner and principal.accountable_user_id == owner
    # The owner is an ordinary member: view_private_channels is in the bot's scopes but not the owner's.
    assert principal.has("send_messages")
    assert not principal.has("view_private_channels")
    assert not principal.has("delete_messages")

    with pytest.raises(ApiError):
        api_initializer.bot_principal_resolver.resolve("pbb_nope.nope")


async def test_a_bot_can_post_edit_and_delete_its_own_messages(client: TestClient):
    owner_token = _signup(client)
    owner_id = extract_user_id(owner_token)
    channel = _new_channel(owner_token)
    created = api_initializer.bot_manager.create_bot(owner_id, "poster", ["send_messages"])
    bot = api_initializer.bot_principal_resolver.resolve(created.token)

    ctx = ConnectionContext(principal=bot, session_id="s", connection_key="k", subscriptions={channel})
    sock = _attach(ctx)
    created_reply = await _run(ctx, _command("message.create", {"channel_id": channel, "content": "beep"}))
    message = created_reply["data"]["result"]["message"]
    assert message["content"] == "beep" and message["author_id"] == bot.id and message["author_name"] == "poster"
    assert _message_count(channel) == 1

    event = sock.events("message.created")[0]["data"]
    assert event["author_id"] == bot.id and event["author_name"] == "poster"

    # The row is stored under the owner (bots have no row of their own), but
    # the bot — not the owner directly — is who may edit and delete it.
    row = api_initializer.database_handler.get_message_by_id(message_id=message["id"])
    assert str(row.sender_id) == owner_id and row.sender_bot_id == created.identity.bot_id

    owner_ctx = _context(owner_token, channel)
    edited = await _run(owner_ctx, _command("message.edit", {"channel_id": channel, "message_id": message["id"], "content": "nope"}))
    assert _error_code(edited) == ProtocolErrorCode.PERMISSION_DENIED

    bot_edit = await _run(ctx, _command("message.edit", {"channel_id": channel, "message_id": message["id"], "content": "fixed"}))
    assert bot_edit["data"]["result"]["content"] == "fixed"

    bot_delete = await _run(ctx, _command("message.delete", {"channel_id": channel, "message_id": message["id"]}))
    assert bot_delete["data"]["result"]["deleted"] is True
    assert _message_count(channel) == 0


async def test_bots_still_cannot_react_pending_a_reactions_schema_change(client: TestClient):
    token = _signup(client)
    channel = _new_channel(token)
    created = api_initializer.bot_manager.create_bot(extract_user_id(token), "poster", ["send_messages"])
    bot = api_initializer.bot_principal_resolver.resolve(created.token)
    ctx = ConnectionContext(principal=bot, session_id="s", connection_key="k", subscriptions={channel})

    message_id = (await _run(ctx, _command("message.create", {"channel_id": channel, "content": "react to me"})))["data"]["result"]["message"]["id"]
    reply = await _run(ctx, _command("reaction.add", {"channel_id": channel, "message_id": message_id, "emoji": "👍"}))
    assert _error_code(reply) == ProtocolErrorCode.PERMISSION_DENIED


def test_websocket_accepts_a_bot_token_and_the_message_carries_the_bot_identity(client: TestClient):
    owner_token = _signup(client)
    channel = _new_channel(owner_token)
    created = api_initializer.bot_manager.create_bot(extract_user_id(owner_token), "sockpuppet", ["send_messages"])

    with client.websocket_connect(f"/ws?auth_token={created.token}&protocol=1") as ws:
        hello = ws.receive_json()
        HelloEnvelope.model_validate(hello)

        ws.send_json(_command("channel.subscribe", {"channel_id": channel}, "cmd_sub"))
        assert ws.receive_json()["type"] == "ack"

        ws.send_json(_command("message.create", {"channel_id": channel, "content": "hi from a bot"}, "cmd_bot"))
        ack = ws.receive_json()
        assert ack["type"] == "ack"
        event = ws.receive_json()
        assert event["name"] == "message.created"
        assert event["data"]["author_name"] == "sockpuppet"
        assert event["data"]["author_id"] == f"bot:{created.identity.bot_id}"


async def test_command_outcomes_are_counted_without_content(client: TestClient):
    token = _signup(client)
    channel = _new_channel(token)
    ctx = _context(token, channel)
    await _run(ctx, _command("message.create", {"channel_id": channel, "content": "private words"}))
    await _run(ctx, _command("message.nope", {}))

    counters = metrics.snapshot()
    assert counters["commands.message.create.ok"] == 1
    assert counters["validation_failures"] >= 1
    assert "private words" not in json.dumps(counters)
