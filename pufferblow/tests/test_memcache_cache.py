"""Unit tests for the memcache wrapper.

The tests exercise the cache as a black box — they don't need a real
memcached daemon. The MemcacheCache uses a lazily-constructed
`pymemcache.client.base.Client`; we substitute a fake client via
monkeypatch so the behavior under test is the wrapper's own logic:

  - get_cache always returns a real cache (memcache is required in
    v1.0; there is no NullCache opt-out anymore)
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


def _config(host: str = "127.0.0.1", port: int = 11211, ttl: int = 60):
    return types.SimpleNamespace(
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


def test_get_cache_returns_real_cache():
    """v1.0 made memcache required: there's no NullCache opt-out anymore."""
    cache = get_cache(_config())
    assert isinstance(cache, MemcacheCache)


def test_get_cache_is_singleton_within_process():
    """The cache is built once per process and reused.

    Subsequent calls with a different config don't rebuild — that
    matches how the rest of the server treats config.toml (re-read on
    boot, not at runtime).
    """
    first = get_cache(_config(host="127.0.0.1"))
    second = get_cache(_config(host="some-other-host"))
    assert first is second


def test_get_cache_uses_configured_host_and_port():
    """Lock the host/port pickup from config so a wiring regression is caught."""
    cache = get_cache(_config(host="custom-host", port=22222, ttl=15))
    assert isinstance(cache, MemcacheCache)
    assert cache._host == "custom-host"
    assert cache._port == 22222
    assert cache._default_ttl == 15


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


# ── New key builders (phase 1-4 expansion) ────────────────────────────


def test_new_key_builders_are_stable():
    """Pin the wire format for the new cache keys.

    Any drift here would shadow reads against writes — invalidators
    in database_handler must target the same shape readers used.
    """
    from pufferblow.api.cache.memcache import (
        blocked_ip_key,
        channel_key,
        moderation_state_key,
        rate_limit_cooldown_key,
        rate_limit_counter_key,
        rate_limit_warnings_key,
        server_settings_key,
        user_privileges_key,
    )

    assert server_settings_key() == "pb:server_settings"
    assert blocked_ip_key("1.2.3.4") == "pb:blocked_ip:1.2.3.4"
    assert moderation_state_key("u-1") == "pb:moderation:u-1"
    assert channel_key("c-1") == "pb:channel:c-1"
    assert user_privileges_key("u-1") == "pb:user_privs:u-1"
    assert rate_limit_counter_key("1.2.3.4", 42) == "pb:rl:1.2.3.4:42"
    assert rate_limit_warnings_key("1.2.3.4") == "pb:rlwarn:1.2.3.4"
    assert rate_limit_cooldown_key("1.2.3.4") == "pb:rlcd:1.2.3.4"


# ── Atomic counter primitives (incr/decr) ─────────────────────────────


class CounterFakeClient:
    """Fake client modelling the subset of pymemcache the wrapper drives.

    Stores raw bytes (which is what memcache's `incr` operates on).
    Implements the atomic-counter idiom: incr returns None on a
    missing key, set/add behave like memcached's own ADD semantics.
    """

    def __init__(self, raise_on=None):
        self.store: dict[str, bytes] = {}
        self.ttls: dict[str, int | None] = {}
        self._raise_on = set(raise_on or ())

    def _check(self, op):
        if op in self._raise_on:
            raise RuntimeError(f"{op} failed")

    def get(self, key):
        self._check("get")
        return self.store.get(key)

    def set(self, key, value, expire=None):
        self._check("set")
        self.store[key] = value
        self.ttls[key] = expire

    def add(self, key, value, expire=None):
        # `add` is a no-op when the key already exists — matches
        # memcached's semantics. Returns True on success, False on miss.
        self._check("add")
        if key in self.store:
            return False
        self.store[key] = value
        self.ttls[key] = expire
        return True

    def incr(self, key, delta):
        self._check("incr")
        raw = self.store.get(key)
        if raw is None:
            return None
        try:
            new_value = int(raw) + int(delta)
        except (TypeError, ValueError):
            return None
        self.store[key] = str(new_value).encode("ascii")
        return new_value

    def decr(self, key, delta):
        self._check("decr")
        return self.incr(key, -int(delta))

    def delete(self, key):
        self._check("delete")
        self.store.pop(key, None)


def test_incr_seeds_missing_key_then_increments(monkeypatch):
    """First incr against an absent key seeds + increments atomically."""
    cache = MemcacheCache("h", 1, default_ttl=10)
    fake = CounterFakeClient()
    monkeypatch.setattr(cache, "_ensure_client", lambda: fake)

    result = cache.incr("counter", delta=1)
    assert result == 1
    # Subsequent calls should just keep counting.
    assert cache.incr("counter", delta=1) == 2
    assert cache.incr("counter", delta=5) == 7


def test_incr_returns_none_when_backend_unreachable(monkeypatch):
    """Daemon down → None so the caller can fail open."""
    cache = MemcacheCache("h", 1, default_ttl=10)

    class Broken:
        def get(self, key): raise RuntimeError("nope")
        def set(self, *a, **kw): raise RuntimeError("nope")
        def add(self, *a, **kw): raise RuntimeError("nope")
        def incr(self, *a, **kw): raise RuntimeError("nope")
        def decr(self, *a, **kw): raise RuntimeError("nope")
        def delete(self, *a, **kw): raise RuntimeError("nope")

    monkeypatch.setattr(cache, "_ensure_client", lambda: Broken())
    assert cache.incr("k") is None


def test_decr_is_a_negative_incr(monkeypatch):
    cache = MemcacheCache("h", 1, default_ttl=10)
    fake = CounterFakeClient()
    fake.store["k"] = b"10"
    monkeypatch.setattr(cache, "_ensure_client", lambda: fake)

    assert cache.decr("k", delta=3) == 7


# ── ProcessLocalCache (two-tier LRU) ──────────────────────────────────


def test_process_local_cache_basic_lifecycle():
    from pufferblow.api.cache.memcache import ProcessLocalCache

    local = ProcessLocalCache(max_entries=2)
    local.set("a", 1, ttl_seconds=60)
    assert local.get("a") == 1
    local.delete("a")
    assert local.get("a") is None


def test_process_local_cache_respects_ttl(monkeypatch):
    """An expired entry must look like a miss AND get evicted."""
    from pufferblow.api.cache import memcache as memcache_module

    fake_clock = {"now": 1000.0}
    monkeypatch.setattr(memcache_module.time, "monotonic", lambda: fake_clock["now"])

    local = memcache_module.ProcessLocalCache(max_entries=8)
    local.set("k", "v", ttl_seconds=5)
    assert local.get("k") == "v"
    fake_clock["now"] += 10  # past TTL
    assert local.get("k") is None


def test_process_local_cache_evicts_oldest_on_overflow():
    from pufferblow.api.cache.memcache import ProcessLocalCache

    local = ProcessLocalCache(max_entries=2)
    local.set("a", 1, ttl_seconds=60)
    local.set("b", 2, ttl_seconds=60)
    local.set("c", 3, ttl_seconds=60)
    # `a` is oldest by insertion → evicted.
    assert local.get("a") is None
    assert local.get("b") == 2
    assert local.get("c") == 3


def test_process_local_cache_get_marks_lru_touch():
    """Reading bumps an entry to most-recent so it survives the next eviction."""
    from pufferblow.api.cache.memcache import ProcessLocalCache

    local = ProcessLocalCache(max_entries=2)
    local.set("a", 1, ttl_seconds=60)
    local.set("b", 2, ttl_seconds=60)
    # Touch `a` so `b` becomes the oldest.
    assert local.get("a") == 1
    local.set("c", 3, ttl_seconds=60)
    assert local.get("b") is None
    assert local.get("a") == 1
    assert local.get("c") == 3


# ── Jittered TTL ──────────────────────────────────────────────────────


def test_jittered_ttl_stays_in_band():
    """The jitter must spread workers but never drop below 1s."""
    from pufferblow.api.cache.memcache import jittered_ttl

    for _ in range(50):
        ttl = jittered_ttl(60, jitter_fraction=0.1)
        assert 53 <= ttl <= 67  # 60 ± 10% with int truncation

    assert jittered_ttl(1) == 1  # short TTLs aren't jittered
    assert jittered_ttl(60, jitter_fraction=0) == 60  # explicit no-jitter


# ── Public-host safety warning ────────────────────────────────────────


def test_publicly_reachable_classifier_recognises_safe_hosts():
    """Localhost, RFC1918 ranges, and bare docker service names are safe."""
    from pufferblow.api.cache.memcache import _looks_publicly_reachable

    for host in [
        "127.0.0.1", "localhost", "::1",
        "10.0.0.5", "192.168.1.10", "172.18.0.3",
        "memcached", "pufferblow-memcached",
        "",
    ]:
        assert _looks_publicly_reachable(host) is False, host


def test_publicly_reachable_classifier_flags_red_flags():
    """Wildcard binds and dotted public-looking names should warn."""
    from pufferblow.api.cache.memcache import _looks_publicly_reachable

    for host in ["0.0.0.0", "::", "*", "cache.example.com", "8.8.8.8"]:
        assert _looks_publicly_reachable(host) is True, host


def test_get_cache_emits_warning_when_host_looks_public(monkeypatch, caplog):
    """If an operator points at a public address, we must warn loudly.

    The cache wrapper pickle-roundtrips Python objects; exposing
    memcached on a public address is a remote-code-execution sink.
    Bootstrapping with a flagged host needs to leave a breadcrumb.
    """
    import logging

    from pufferblow.api.cache import memcache as memcache_module
    from pufferblow.api.cache.memcache import get_cache

    memcache_module._singleton = None
    captured: list[str] = []

    # loguru routes through stderr by default; capture via a custom sink.
    sink_id = memcache_module.logger.add(
        lambda message: captured.append(str(message)), level="WARNING"
    )
    try:
        cfg = types.SimpleNamespace(
            MEMCACHE_HOST="public-memcache.example.com",
            MEMCACHE_PORT=11211,
            MEMCACHE_DEFAULT_TTL=60,
        )
        get_cache(cfg)
        assert any("publicly reachable" in line for line in captured), captured
    finally:
        memcache_module.logger.remove(sink_id)


# ── Keyset cursor encode/decode (history pagination) ──────────────────


def test_message_cursor_round_trip():
    """The opaque cursor is `<sent_at_iso>|<message_id>` and round-trips."""
    import datetime as _dt
    from types import SimpleNamespace

    from pufferblow.api.database.database_handler import DatabaseHandler

    msg = SimpleNamespace(
        sent_at=_dt.datetime(2026, 5, 23, 15, 4, 5, tzinfo=_dt.timezone.utc),
        message_id="abc-123",
    )
    encoded = DatabaseHandler._encode_message_cursor(msg)
    decoded = DatabaseHandler._decode_message_cursor(encoded)
    assert decoded is not None
    assert decoded[0] == msg.sent_at
    assert decoded[1] == msg.message_id


def test_message_cursor_decode_returns_none_for_garbage():
    """Malformed / missing cursors look like 'start from the newest'."""
    from pufferblow.api.database.database_handler import DatabaseHandler

    assert DatabaseHandler._decode_message_cursor(None) is None
    assert DatabaseHandler._decode_message_cursor("") is None
    assert DatabaseHandler._decode_message_cursor("nope") is None
    assert DatabaseHandler._decode_message_cursor("not-an-iso|id") is None


def test_messages_table_has_scaleout_indexes():
    """Pin the index names so a rename would be caught immediately.

    The schema migration in `_apply_messages_scaleout_migration` issues
    `CREATE INDEX IF NOT EXISTS <name>` against these specific names —
    a drift between the declarative metadata and the migration script
    would silently shadow itself.
    """
    from pufferblow.api.database.tables.messages import Messages

    index_names = {ix.name for ix in Messages.__table__.indexes}
    assert "ix_messages_channel_sent_at_msg" in index_names
    assert "ix_messages_search_tokens" in index_names
