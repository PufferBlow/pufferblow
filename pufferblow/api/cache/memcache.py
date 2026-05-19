"""Thin pickle-backed wrapper over `pymemcache.Client`.

`pymemcache` has been listed as a dependency since v0.x without
anything actually using it. This module wires it up — but as a small,
opt-in caching layer rather than a system everything in the codebase
has to know about. Three properties drive the design:

1. **Disabled by default.** Operators opt in via `[memcache]` in
   `config.toml`. When disabled, `get_cache()` returns a `NullCache`
   that drops all writes and returns `None` for every read. Callers
   only have to write the cache path — the disabled path is the same
   code.

2. **Failure is invisible.** A memcache that goes down should slow
   the server modestly (one TCP timeout per call), never crash it.
   Every operation is wrapped in a broad except that logs at debug
   level and falls back to the un-cached path. Cache misses (because
   the daemon is gone) look identical to cache misses (because the
   key wasn't set) at the call site.

3. **Process-local singleton.** The `Client` is built once per
   process via `get_cache()`. Workers under gunicorn each build
   their own connection on first use, which matches pymemcache's
   own thread-safety model.

Values are pickled before write and unpickled on read. That lets us
cache ORM rows (Users, Server) without a separate serialization
layer; pymemcache also supports a `serde` argument to do this for us,
but pickling at the call site keeps the wire format under our
control and avoids depending on pymemcache's internal helpers.
"""

from __future__ import annotations

import pickle
from typing import Any

from loguru import logger


class NullCache:
    """No-op cache used when the operator hasn't enabled memcache.

    Keeps the call-site signature identical to a real client so the
    caller doesn't branch on enablement at every read.
    """

    enabled = False

    def get(self, key: str) -> Any | None:  # noqa: ARG002 — signature parity
        return None

    def set(self, key: str, value: Any, ttl: int | None = None) -> None:  # noqa: ARG002
        return None

    def delete(self, key: str) -> None:  # noqa: ARG002
        return None


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


# Process-local singleton. `get_cache(config)` builds it on first
# call from the bootstrap config; subsequent calls reuse the same
# instance. `_singleton` is module-level state, NOT inside a class,
# so each gunicorn worker has its own connection — matching
# pymemcache's per-process model.
_singleton: NullCache | MemcacheCache | None = None


def get_cache(config) -> NullCache | MemcacheCache:
    """Return the process-wide cache instance.

    Reads enablement + host/port from the bootstrap config the first
    time it's called and stores the result. A subsequent config flip
    (e.g. via `pufferblow setup`) won't take effect until the worker
    restarts — which is consistent with how the rest of the server
    treats `config.toml` (re-read on boot, not at runtime).
    """
    global _singleton
    if _singleton is not None:
        return _singleton

    if not getattr(config, "MEMCACHE_ENABLED", False):
        _singleton = NullCache()
        return _singleton

    host = getattr(config, "MEMCACHE_HOST", "127.0.0.1")
    port = int(getattr(config, "MEMCACHE_PORT", 11211))
    ttl = int(getattr(config, "MEMCACHE_DEFAULT_TTL", 60))
    _singleton = MemcacheCache(host=host, port=port, default_ttl=ttl)
    logger.info(
        "Memcache enabled at {host}:{port} (default TTL {ttl}s)",
        host=host,
        port=port,
        ttl=ttl,
    )
    return _singleton


# Convenience key builders. Keeping them in one place means future
# invalidation code can match the same key shapes the readers use
# without depending on string formatting at call sites.
def user_key(user_id: str) -> str:
    """Cache key for a `Users` row keyed by `user_id`."""
    return f"pb:user:{user_id}"


def server_key() -> str:
    """Cache key for the single-server row."""
    return "pb:server"
