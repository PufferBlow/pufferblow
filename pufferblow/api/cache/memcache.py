"""Thin pickle-backed wrapper over `pymemcache.Client` + helpers for
scale-out caching of hot reads.

Memcache is a required runtime dependency of the v1.0 server. The
bundled Docker Compose stack ships a memcached service the API
depends on, so a fresh install has nothing to configure; operators
running an existing memcache cluster point `MEMCACHE_HOST` at it
via `pufferblow setup --setup-memcache`.

Three properties drive the wrapper:

1. **Failure is invisible.** A memcache that goes down should slow
   the server modestly (one TCP timeout per call), never crash it.
   Every operation is wrapped in a broad except that logs at debug
   level and falls back to the un-cached path. Cache misses (because
   the daemon is gone) look identical to cache misses (because the
   key wasn't set) at the call site.

2. **Process-local singleton.** The `Client` is built once per
   process via `get_cache()`. Workers under gunicorn each build
   their own connection on first use, which matches pymemcache's
   own thread-safety model.

3. **Two-tier read path for hot global keys.** A bounded in-process
   LRU sits in front of memcache via `ProcessLocalCache`. At 100K
   req/s even memcache becomes a single-key hot spot for things like
   `pb:server_settings`; the local layer absorbs >99% of those reads
   at zero network cost, with a short TTL (5-10s) so cross-worker
   propagation stays bounded.

The wrapper does NOT have an "off" mode. Callers can't disable the
cache; the only escape hatch is the `_is_sqlite()` short-circuit
inside `database_handler` that skips the cache for the SQLite test
harness (the test runner doesn't spin up a memcached daemon).

Values are pickled before write and unpickled on read. That lets us
cache ORM rows (Users, Server) without a separate serialization
layer; pymemcache also supports a `serde` argument to do this for us,
but pickling at the call site keeps the wire format under our
control and avoids depending on pymemcache's internal helpers.

Atomic counters (`incr`) and compare-and-swap (`cas`) primitives are
exposed for the rate-limit counters and the unread-message badges.
Both are best-effort under the same "failure is invisible" policy:
`incr` returns `None` if the daemon is unreachable and callers must
treat that as "we don't know — let it through" (fail-open).
"""

from __future__ import annotations

import pickle
import random
import threading
import time
from collections import OrderedDict
from typing import Any

from loguru import logger


class MemcacheCache:
    """Real pymemcache-backed cache.

    Wraps the client with pickle (de)serialization plus the
    fail-quietly policy described in the module docstring. The
    client is constructed lazily on first use so an unreachable
    daemon at boot doesn't block the server from starting.
    """

    enabled = True

    def __init__(self, host: str, port: int, default_ttl: int) -> None:
        self._host = host
        self._port = port
        self._default_ttl = default_ttl
        self._client = None  # lazy

    def _ensure_client(self):
        if self._client is not None:
            return self._client
        # Imported lazily so a `from .memcache import get_cache` in a
        # config-reading module doesn't crash at import-time when
        # pymemcache isn't installed yet (e.g. partial CI install).
        from pymemcache.client.base import Client

        self._client = Client(
            (self._host, self._port),
            connect_timeout=1.0,
            timeout=0.5,
            no_delay=True,
        )
        return self._client

    def get(self, key: str) -> Any | None:
        try:
            raw = self._ensure_client().get(key)
        except Exception as exc:
            logger.debug("memcache get failed: {err}", err=str(exc))
            return None
        if raw is None:
            return None
        try:
            return pickle.loads(raw)  # noqa: S301 — values we wrote ourselves
        except Exception as exc:
            # Stale schema (a class we cached no longer exists) or
            # corrupt bytes. Treat as a miss; the caller will refill.
            logger.debug("memcache deserialize failed: {err}", err=str(exc))
            return None

    def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        try:
            payload = pickle.dumps(value, protocol=pickle.HIGHEST_PROTOCOL)
        except Exception as exc:
            logger.debug("memcache serialize failed: {err}", err=str(exc))
            return
        try:
            self._ensure_client().set(key, payload, expire=ttl or self._default_ttl)
        except Exception as exc:
            logger.debug("memcache set failed: {err}", err=str(exc))

    def delete(self, key: str) -> None:
        try:
            self._ensure_client().delete(key)
        except Exception as exc:
            logger.debug("memcache delete failed: {err}", err=str(exc))

    # ── Atomic counters ────────────────────────────────────────────
    #
    # `incr` / `decr` operate on the raw bytes stored at `key`. They
    # are NOT pickle-aware — memcached's atomic counters require a
    # plain ASCII integer payload, so callers must use these helpers
    # rather than `set(key, 1)` if they want `incr` to work.
    #
    # The wrapper handles the bootstrap race for us: on the first
    # incr against a missing key, pymemcache returns None, and we
    # fall back to `add` with the initial value (which is itself
    # atomic — at most one worker wins) and re-issue the increment.

    def incr(
        self,
        key: str,
        delta: int = 1,
        initial: int = 0,
        ttl: int | None = None,
    ) -> int | None:
        """Atomically add `delta` to the integer stored at `key`.

        Returns the new value, or `None` if the daemon was
        unreachable. Callers MUST treat `None` as "don't know" and
        fail open — this is the rate-limit-counter contract: better
        to let a request through than to crash the middleware.
        """
        try:
            client = self._ensure_client()
        except Exception as exc:
            logger.debug("memcache incr connect failed: {err}", err=str(exc))
            return None
        expire = ttl or self._default_ttl
        try:
            result = client.incr(key, delta) if delta >= 0 else client.decr(key, -delta)
            if result is not None:
                return int(result)

            # Key missing. Seed it with `initial + delta` so the very
            # first call ALSO counts. `add` is atomic across workers:
            # only one wins; the loser falls through to a follow-up
            # incr that mutates the value the winner just placed.
            seeded_value = initial + delta
            seeded_bytes = str(seeded_value).encode("ascii")
            won = client.add(key, seeded_bytes, expire=expire)
            if won:
                return seeded_value

            # Lost the race — someone else seeded. Increment their
            # value to record OUR request.
            result = client.incr(key, delta) if delta >= 0 else client.decr(key, -delta)
            if result is not None:
                return int(result)
            # Pathological: still missing after a successful `add`
            # from the winner means the key got evicted between
            # `add` and `incr`. Reseed once more and accept the
            # answer.
            raw = client.get(key)
            return int(raw) if raw is not None else None
        except Exception as exc:
            logger.debug("memcache incr failed: {err}", err=str(exc))
            return None

    def decr(self, key: str, delta: int = 1, ttl: int | None = None) -> int | None:
        """Decrement convenience wrapper around `incr`."""
        return self.incr(key, delta=-delta, ttl=ttl)


# ───────────────────────────────────────────────────────────────────
# Process-local two-tier cache
# ───────────────────────────────────────────────────────────────────

class ProcessLocalCache:
    """Tiny bounded LRU that sits in front of memcache for hot keys.

    The classic anti-pattern at 100K req/s is "everything's cached in
    memcache" → the network round-trip and pickle decode for
    `pb:server_settings` happen on every request anyway, and the key
    becomes a fan-out hot spot on the memcached daemon. Adding a 5-10
    second TTL local LRU in front absorbs >99% of those reads at zero
    network cost.

    Only suitable for keys that:
      - Are READ on every request (so the local cache pays off).
      - Tolerate a few seconds of staleness across workers (because
        invalidations on worker A don't propagate to worker B's local
        LRU; only memcache's deletion + the short TTL do).

    NOT suitable for per-user keys (would blow the LRU budget) or
    keys with strict freshness requirements (passwords, auth tokens,
    moderation state for the actor in the current request).
    """

    def __init__(self, max_entries: int = 128) -> None:
        self._entries: OrderedDict[str, tuple[float, Any]] = OrderedDict()
        self._max = max_entries
        self._lock = threading.Lock()

    def get(self, key: str) -> Any | None:
        """Return the cached value if present AND unexpired, else None."""
        now = time.monotonic()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            expires_at, value = entry
            if expires_at <= now:
                # Evict eagerly so memory doesn't grow with stale entries.
                self._entries.pop(key, None)
                return None
            # LRU touch.
            self._entries.move_to_end(key)
            return value

    def set(self, key: str, value: Any, ttl_seconds: float) -> None:
        """Insert or refresh a key with an absolute expiry time."""
        expires_at = time.monotonic() + max(0.1, float(ttl_seconds))
        with self._lock:
            self._entries[key] = (expires_at, value)
            self._entries.move_to_end(key)
            while len(self._entries) > self._max:
                self._entries.popitem(last=False)

    def delete(self, key: str) -> None:
        with self._lock:
            self._entries.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


# Module-level singleton for the in-process tier. Shared by every
# caller in this worker; safe because every method is internally
# locked.
_local_cache = ProcessLocalCache(max_entries=256)


def get_local_cache() -> ProcessLocalCache:
    """Return the process-wide in-process tier."""
    return _local_cache


def jittered_ttl(base_seconds: int, jitter_fraction: float = 0.1) -> int:
    """Add ±jitter_fraction noise to a TTL.

    Stops every worker from refilling the same key in lockstep when
    the central TTL fires — would otherwise produce a synchronized
    Postgres stampede every `base_seconds`.
    """
    if base_seconds <= 1 or jitter_fraction <= 0:
        return base_seconds
    spread = base_seconds * jitter_fraction
    return max(1, int(base_seconds + random.uniform(-spread, spread)))


# Process-local singleton. `get_cache(config)` builds it on first
# call from the bootstrap config; subsequent calls reuse the same
# instance. `_singleton` is module-level state, NOT inside a class,
# so each gunicorn worker has its own connection — matching
# pymemcache's per-process model.
_singleton: MemcacheCache | None = None


def get_cache(config) -> MemcacheCache:
    """Return the process-wide cache instance.

    Reads host/port from the bootstrap config the first time it's
    called and stores the result. A subsequent config change (e.g.
    via `pufferblow setup --setup-memcache`) won't take effect until
    the worker restarts — which is consistent with how the rest of
    the server treats `config.toml` (re-read on boot, not at
    runtime).
    """
    global _singleton
    if _singleton is not None:
        return _singleton

    host = getattr(config, "MEMCACHE_HOST", "127.0.0.1")
    port = int(getattr(config, "MEMCACHE_PORT", 11211))
    ttl = int(getattr(config, "MEMCACHE_DEFAULT_TTL", 60))
    _singleton = MemcacheCache(host=host, port=port, default_ttl=ttl)
    logger.info(
        "Memcache wired at {host}:{port} (default TTL {ttl}s)",
        host=host,
        port=port,
        ttl=ttl,
    )
    return _singleton


# ───────────────────────────────────────────────────────────────────
# Convenience key builders. Keeping them in one place means future
# invalidation code can match the same key shapes the readers use
# without depending on string formatting at call sites.
# ───────────────────────────────────────────────────────────────────

def user_key(user_id: str) -> str:
    """Cache key for a `Users` row keyed by `user_id`."""
    return f"pb:user:{user_id}"


def server_key() -> str:
    """Cache key for the single-server row."""
    return "pb:server"


def server_settings_key() -> str:
    """Cache key for the single `server_settings` row.

    Read by `RateLimitingMiddleware` on every request — the canonical
    two-tier key (in-process LRU in front of memcache).
    """
    return "pb:server_settings"


def blocked_ip_key(ip: str) -> str:
    """Cache key for a per-IP `BlockedIPS` presence sentinel.

    Stores a small dict `{"blocked": True}` on hit and `{"blocked":
    False}` on negative cache (so we don't keep re-SELECTing for
    legitimate traffic). A short TTL bounds the staleness window if
    an operator unblocks an IP.
    """
    return f"pb:blocked_ip:{ip}"


def moderation_state_key(user_id: str) -> str:
    """Cache key for `get_user_moderation_state(user_id)` output."""
    return f"pb:moderation:{user_id}"


def channel_key(channel_id: str) -> str:
    """Cache key for a `Channels` row by id."""
    return f"pb:channel:{channel_id}"


def user_privileges_key(user_id: str) -> str:
    """Cache key for the resolved privilege set for a user."""
    return f"pb:user_privs:{user_id}"


def rate_limit_counter_key(ip: str, minute_bucket: int) -> str:
    """Cache key for the per-IP per-minute request counter.

    The `minute_bucket` is `epoch_seconds // 60` so the key naturally
    rolls over every minute without explicit cleanup.
    """
    return f"pb:rl:{ip}:{minute_bucket}"


def rate_limit_warnings_key(ip: str) -> str:
    """Cache key for the cumulative rate-limit warning counter per IP."""
    return f"pb:rlwarn:{ip}"


def rate_limit_cooldown_key(ip: str) -> str:
    """Cache key for an active cooldown timestamp on an IP."""
    return f"pb:rlcd:{ip}"
