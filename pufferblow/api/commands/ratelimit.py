"""Token-bucket rate limiting for commands."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass


@dataclass
class _Bucket:
    tokens: float
    updated: float


class RateLimiter:
    """Allows ``capacity`` commands in a burst, refilling ``refill_per_second`` afterwards."""

    def __init__(
        self,
        capacity: float = 20,
        refill_per_second: float = 5,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_keys: int = 10_000,
    ) -> None:
        self.capacity = capacity
        self.refill_per_second = refill_per_second
        self._clock = clock
        self._max_keys = max_keys
        self._buckets: dict[str, _Bucket] = {}

    def check(self, key: str, cost: float = 1) -> float | None:
        """Spend ``cost`` tokens. Returns None when allowed, else seconds until it would be."""
        now = self._clock()
        bucket = self._buckets.get(key)
        if bucket is None:
            if len(self._buckets) >= self._max_keys:
                self._evict_idle(now)
            bucket = self._buckets[key] = _Bucket(self.capacity, now)

        bucket.tokens = min(self.capacity, bucket.tokens + (now - bucket.updated) * self.refill_per_second)
        bucket.updated = now

        if bucket.tokens >= cost:
            bucket.tokens -= cost
            return None
        return (cost - bucket.tokens) / self.refill_per_second

    def forget(self, key: str) -> None:
        self._buckets.pop(key, None)

    def _evict_idle(self, now: float) -> None:
        full_after = self.capacity / self.refill_per_second
        for key in [k for k, b in self._buckets.items() if now - b.updated > full_after]:
            del self._buckets[key]


class MemcacheRateLimiter:
    """Shared, memcache-backed counterpart to :class:`RateLimiter`.

    A WS *connection* never leaves the worker that accepted it, so a
    per-connection :class:`RateLimiter` is fine staying in-process. A
    *principal* can open several connections that land on different
    workers, though, and each worker's private token bucket would
    otherwise multiply their effective command budget by however many
    workers they spread across — the same scale-out bug
    `RateLimitingMiddleware` was rewritten to fix for HTTP (see
    `pufferblow/core/middlewares.py`). This mirrors that fix: an atomic
    fixed-window counter shared via memcache, in place of a private
    in-process bucket.

    This approximates the token bucket's long-run throughput (`capacity`
    requests per `capacity / refill_per_second` seconds) with a fixed
    window rather than a true leaky bucket — the same tradeoff the HTTP
    limiter already accepts in exchange for a primitive (`incr`) memcache
    actually offers atomically. `incr` returning `None` (memcache
    unreachable) fails open, per this cache layer's standing contract —
    a flaky daemon must slow enforcement, never take the server down.
    """

    def __init__(
        self,
        config,
        capacity: float = 30,
        refill_per_second: float = 10,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.capacity = capacity
        self.refill_per_second = refill_per_second
        self._config = config
        self._clock = clock
        self._window_seconds = max(1, int(capacity / refill_per_second)) if refill_per_second > 0 else 1

    def check(self, key: str, cost: float = 1) -> float | None:
        from pufferblow.api.cache.memcache import command_rate_limit_key, get_cache

        window = self._window_seconds
        now = self._clock()
        bucket = int(now // window)
        count = get_cache(self._config).incr(
            command_rate_limit_key(key, bucket), delta=int(cost), initial=0, ttl=window * 2
        )
        if count is None:
            return None  # memcache unreachable — fail open

        if count <= self.capacity:
            return None

        seconds_into_window = now - bucket * window
        return max(0.01, window - seconds_into_window)

    def forget(self, key: str) -> None:
        from pufferblow.api.cache.memcache import command_rate_limit_key, get_cache

        bucket = int(self._clock() // self._window_seconds)
        get_cache(self._config).delete(command_rate_limit_key(key, bucket))
