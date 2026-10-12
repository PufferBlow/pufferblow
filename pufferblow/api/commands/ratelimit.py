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
