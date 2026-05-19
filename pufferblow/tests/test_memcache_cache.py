"""Unit tests for the memcache wrapper.

The tests exercise the cache as a black box — they don't need a real
memcached daemon. The MemcacheCache uses a lazily-constructed
`pymemcache.client.base.Client`; we substitute a fake client via
monkeypatch so the behavior under test is the wrapper's own logic:

  - enabled vs disabled (NullCache fallback)
  - pickle round-trips through set/get
  - quiet fallthrough on backend errors (connection refused, raised
    exception, garbage payload on read)
  - key builders match what database_handler invalidates against
"""

from __future__ import annotations

import pickle
import types

import pytest

from pufferblow.api.cache import memcache as memcache_module
from pufferblow.api.cache.memcache import (
    MemcacheCache,
    NullCache,
    get_cache,
    server_key,
    user_key,
)


@pytest.fixture(autouse=True)
def _reset_singleton():
    """Each test gets a fresh process-wide cache.

    `get_cache` caches its result in a module-level variable so two
    tests in the same suite would otherwise see each other's
    state.
    """
    memcache_module._singleton = None
    yield
    memcache_module._singleton = None


def _config(enabled: bool = True, host: str = "127.0.0.1", port: int = 11211, ttl: int = 60):
    return types.SimpleNamespace(
        MEMCACHE_ENABLED=enabled,
        MEMCACHE_HOST=host,
        MEMCACHE_PORT=port,
        MEMCACHE_DEFAULT_TTL=ttl,
    )


class FakeClient:
    """Drop-in pymemcache.Client substitute for tests.

    Mimics the subset of the client the wrapper actually uses: get,
    set, delete. Optionally raises on operations so we can exercise
    the fail-quiet branches.
    """

    def __init__(self, raise_on=None):
        self.store: dict[str, bytes] = {}
        self._raise_on = set(raise_on or ())
        self.calls: list[tuple[str, str, object]] = []

    def get(self, key):
        self.calls.append(("get", key, None))
        if "get" in self._raise_on:
            raise RuntimeError("get failed")
        return self.store.get(key)

    def set(self, key, value, expire=None):  # noqa: ARG002 — signature parity
        self.calls.append(("set", key, value))
        if "set" in self._raise_on:
            raise RuntimeError("set failed")
        self.store[key] = value

    def delete(self, key):
        self.calls.append(("delete", key, None))
        if "delete" in self._raise_on:
            raise RuntimeError("delete failed")
        self.store.pop(key, None)


# ── get_cache ────────────────────────────────────────────────────────


def test_get_cache_returns_null_when_disabled():
    cache = get_cache(_config(enabled=False))
    assert isinstance(cache, NullCache)
    assert cache.get("anything") is None
    cache.set("anything", "value")
    cache.delete("anything")  # must not raise


def test_get_cache_returns_real_cache_when_enabled():
    cache = get_cache(_config(enabled=True))
    assert isinstance(cache, MemcacheCache)


def test_get_cache_is_singleton_within_process():
    first = get_cache(_config(enabled=True))
    second = get_cache(_config(enabled=False))  # disabled config ignored — singleton wins
    assert first is second


# ── MemcacheCache happy path ─────────────────────────────────────────


def test_set_and_get_round_trip(monkeypatch):
    cache = MemcacheCache("h", 1, default_ttl=10)
    fake = FakeClient()
    monkeypatch.setattr(cache, "_ensure_client", lambda: fake)

    cache.set("k", {"hello": "world"})
    assert cache.get("k") == {"hello": "world"}
    # The wrapper should pickle on the way in.
    assert pickle.loads(fake.store["k"]) == {"hello": "world"}


def test_get_miss_returns_none(monkeypatch):
    cache = MemcacheCache("h", 1, default_ttl=10)
    monkeypatch.setattr(cache, "_ensure_client", lambda: FakeClient())
    assert cache.get("missing") is None


def test_set_uses_provided_ttl(monkeypatch):
    cache = MemcacheCache("h", 1, default_ttl=10)
    fake = FakeClient()
    captured = {}

    def fake_set(key, value, expire=None):
        captured["expire"] = expire
        fake.store[key] = value

    fake.set = fake_set  # type: ignore[method-assign]
    monkeypatch.setattr(cache, "_ensure_client", lambda: fake)

    cache.set("k", "v", ttl=99)
    assert captured["expire"] == 99


def test_set_falls_back_to_default_ttl(monkeypatch):
    cache = MemcacheCache("h", 1, default_ttl=42)
    fake = FakeClient()
    captured = {}

    def fake_set(key, value, expire=None):
        captured["expire"] = expire
        fake.store[key] = value

    fake.set = fake_set  # type: ignore[method-assign]
    monkeypatch.setattr(cache, "_ensure_client", lambda: fake)

    cache.set("k", "v")
    assert captured["expire"] == 42


# ── Fail-quietly behavior ────────────────────────────────────────────


def test_get_returns_none_when_backend_raises(monkeypatch):
    """A flaky daemon must look like a cache miss, not an exception.

    The whole point of the wrapper is that the rest of the codebase
    doesn't have to think about memcache reachability. If the daemon
    disappears, callers should hit the database without crashing.
    """
    cache = MemcacheCache("h", 1, default_ttl=10)
    monkeypatch.setattr(cache, "_ensure_client", lambda: FakeClient(raise_on=("get",)))
    assert cache.get("k") is None


def test_set_swallows_backend_errors(monkeypatch):
    cache = MemcacheCache("h", 1, default_ttl=10)
    monkeypatch.setattr(cache, "_ensure_client", lambda: FakeClient(raise_on=("set",)))
    # Must not raise.
    cache.set("k", "v")


def test_delete_swallows_backend_errors(monkeypatch):
    cache = MemcacheCache("h", 1, default_ttl=10)
    monkeypatch.setattr(cache, "_ensure_client", lambda: FakeClient(raise_on=("delete",)))
    cache.delete("k")


def test_get_returns_none_on_corrupt_payload(monkeypatch):
    """A garbage byte string in the cache should be a miss, not a crash.

    Can happen when a class we cached doesn't exist anymore after a
    schema upgrade. The wrapper should drop the stale entry on the
    floor and let the caller refill from the database.
    """
    cache = MemcacheCache("h", 1, default_ttl=10)
    fake = FakeClient()
    fake.store["k"] = b"\x00\x01not-a-pickle"
    monkeypatch.setattr(cache, "_ensure_client", lambda: fake)
    assert cache.get("k") is None


# ── Key builders ─────────────────────────────────────────────────────


def test_user_key_is_stable_for_string_uuid():
    """The database_handler invalidator calls user_key(str(user_id)).

    If the format ever drifted, get_user would read stale rows and
    invalidate would target a different slot. Lock the format here.
    """
    assert user_key("abc-123") == "pb:user:abc-123"


def test_server_key_constant():
    assert server_key() == "pb:server"
