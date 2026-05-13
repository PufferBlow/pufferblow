"""Reliability-pass tests for the ActivityPub manager.

Covers the two reliability fixes added in S5:

1. Outbound POST retries: transient failures (network errors, 5xx) are
   retried with exponential backoff; 4xx errors fail fast.
2. Inbox replay guard: duplicate ``activity.id`` short-circuits handlers
   so re-delivered activities don't double-execute side effects.

Integration tests against a real inbox flow need the TestClient fixture
which hangs in this environment; these unit tests exercise the relevant
methods directly with a stubbed httpx layer and a stubbed DB handler.
"""

import asyncio
from types import SimpleNamespace

import httpx
import pytest

from pufferblow.api.activitypub import activitypub_manager as ap_module


class _FakeResponse:
    def __init__(self, status_code: int):
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            request = httpx.Request("POST", "http://example.test/inbox")
            raise httpx.HTTPStatusError(
                f"{self.status_code} error",
                request=request,
                response=httpx.Response(self.status_code, request=request),
            )


class _FakeAsyncClient:
    """Patches into httpx.AsyncClient. Plays back a script of POST results.

    The script index is class-level because the production code opens a new
    AsyncClient per retry attempt — per-instance counters would always read
    index 0 and never advance.
    """

    instances: list["_FakeAsyncClient"] = []
    _script: list[_FakeResponse] = []
    _cursor: int = 0

    def __init__(self, *args, **kwargs):
        self.calls: list[dict] = []
        _FakeAsyncClient.instances.append(self)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url, headers=None, content=None):
        index = _FakeAsyncClient._cursor
        _FakeAsyncClient._cursor += 1
        self.calls.append({"url": url})
        return _FakeAsyncClient._script[index]


def _install_fake_client(monkeypatch, script):
    _FakeAsyncClient.instances = []
    _FakeAsyncClient._script = script
    _FakeAsyncClient._cursor = 0
    monkeypatch.setattr(ap_module.httpx, "AsyncClient", _FakeAsyncClient)


def _make_manager() -> ap_module.ActivityPubManager:
    # We never touch the DB / managers in these unit tests, so passing
    # stubs is fine. `_http_post_json` only reads its own state.
    return ap_module.ActivityPubManager(
        database_handler=SimpleNamespace(),  # type: ignore[arg-type]
        user_manager=SimpleNamespace(),  # type: ignore[arg-type]
        messages_manager=SimpleNamespace(),  # type: ignore[arg-type]
        websockets_manager=SimpleNamespace(),  # type: ignore[arg-type]
    )


@pytest.fixture(autouse=True)
def _silence_backoff(monkeypatch):
    """Skip real sleeps so the retry tests finish in milliseconds."""
    async def _no_sleep(_):
        return None

    monkeypatch.setattr(ap_module.asyncio, "sleep", _no_sleep)


def test_post_returns_after_first_success(monkeypatch):
    _install_fake_client(monkeypatch, [_FakeResponse(200)])

    manager = _make_manager()
    asyncio.run(manager._http_post_json("http://r/inbox", {"hello": "world"}))

    # One AsyncClient instance, one call.
    assert len(_FakeAsyncClient.instances) == 1
    assert len(_FakeAsyncClient.instances[0].calls) == 1


def test_post_retries_on_5xx_then_succeeds(monkeypatch):
    _install_fake_client(
        monkeypatch,
        [_FakeResponse(503), _FakeResponse(502), _FakeResponse(200)],
    )

    manager = _make_manager()
    asyncio.run(manager._http_post_json("http://r/inbox", {"x": 1}))

    # Three attempts, each in its own client context.
    assert len(_FakeAsyncClient.instances) == 3


def test_post_does_not_retry_4xx(monkeypatch):
    _install_fake_client(monkeypatch, [_FakeResponse(401), _FakeResponse(200)])

    manager = _make_manager()
    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(manager._http_post_json("http://r/inbox", {"x": 1}))

    # Only the failing 4xx attempt should have run; the 200 in the script
    # must not be consumed.
    assert len(_FakeAsyncClient.instances) == 1


def test_post_gives_up_after_max_attempts(monkeypatch):
    # All transient failures.
    _install_fake_client(
        monkeypatch,
        [_FakeResponse(500)] * ap_module.OUTBOUND_POST_MAX_ATTEMPTS,
    )

    manager = _make_manager()
    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(manager._http_post_json("http://r/inbox", {"x": 1}))

    assert (
        len(_FakeAsyncClient.instances) == ap_module.OUTBOUND_POST_MAX_ATTEMPTS
    )


def test_post_retries_on_network_error(monkeypatch):
    class _BoomClient(_FakeAsyncClient):
        async def post(self, url, headers=None, content=None):
            index = _FakeAsyncClient._cursor
            _FakeAsyncClient._cursor += 1
            self.calls.append({"url": url})
            if index == 0:
                raise httpx.ConnectError("dns went away")
            return _FakeResponse(200)

    _FakeAsyncClient.instances = []
    _FakeAsyncClient._script = []
    _FakeAsyncClient._cursor = 0
    monkeypatch.setattr(ap_module.httpx, "AsyncClient", _BoomClient)

    manager = _make_manager()
    asyncio.run(manager._http_post_json("http://r/inbox", {"x": 1}))
    # First attempt raised, second succeeded → 2 client instances.
    assert len(_FakeAsyncClient.instances) == 2


# --- Inbox replay short-circuit ---------------------------------------------


class _FakeDatabaseHandler:
    """Just enough surface for process_inbox_activity's replay guard."""

    def __init__(self, known_uris):
        self.known = set(known_uris)
        self.stored = []

    def is_activitypub_inbox_known(self, activity_uri: str) -> bool:
        return activity_uri in self.known

    def store_activitypub_inbox_activity(self, **kwargs):
        # We should never reach here when the guard short-circuits.
        self.stored.append(kwargs)


def test_process_inbox_activity_short_circuits_on_duplicate(monkeypatch):
    manager = _make_manager()
    manager.database_handler = _FakeDatabaseHandler(
        known_uris={"https://remote.test/ap/activities/abc"}
    )

    result = asyncio.run(
        manager.process_inbox_activity(
            activity={
                "id": "https://remote.test/ap/activities/abc",
                "type": "Follow",
                "actor": "https://remote.test/users/alice",
            },
            base_url="https://local.test",
        )
    )

    assert result == {
        "processed": True,
        "activity_type": "Follow",
        "action": "duplicate",
    }
    # Confirm no storage attempt was made (handler short-circuited before).
    assert manager.database_handler.stored == []


def test_process_inbox_activity_stores_when_id_unknown(monkeypatch):
    # Stub everything the Follow handler downstream wants so we can confirm
    # we get past the replay guard. The Follow handler will error out due to
    # the stubbed DB, but the storage call should happen first.
    manager = _make_manager()
    handler = _FakeDatabaseHandler(known_uris=set())
    manager.database_handler = handler

    # The Follow handler will raise because our fake DB lacks the real
    # methods; we only care that we got past the replay guard and stored
    # the activity.
    with pytest.raises(Exception):
        asyncio.run(
            manager.process_inbox_activity(
                activity={
                    "id": "https://remote.test/ap/activities/new",
                    "type": "Follow",
                    "actor": "https://remote.test/users/alice",
                },
                base_url="https://local.test",
            )
        )

    assert len(handler.stored) == 1
    assert (
        handler.stored[0]["activity_uri"]
        == "https://remote.test/ap/activities/new"
    )


def test_process_inbox_activity_synthetic_uri_when_id_missing(monkeypatch):
    manager = _make_manager()
    handler = _FakeDatabaseHandler(known_uris=set())
    manager.database_handler = handler

    # No `id` on the inbound activity — replay guard should NOT consider this
    # a duplicate (there's nothing to dedupe against), and storage should
    # receive a synthetic uri.
    with pytest.raises(Exception):
        asyncio.run(
            manager.process_inbox_activity(
                activity={
                    "type": "Follow",
                    "actor": "https://remote.test/users/alice",
                },
                base_url="https://local.test",
            )
        )

    assert len(handler.stored) == 1
    assert handler.stored[0]["activity_uri"].startswith("urn:uuid:")
