"""Tiny in-process counters for the command protocol.

Deliberately dependency free: counters are plain integers keyed by name, exposed
as a dict for the instance health endpoint and logs. Replace with a real
metrics client later without touching callers.
"""

from __future__ import annotations

import threading
from collections import Counter


class Metrics:
    def __init__(self) -> None:
        self._counters: Counter[str] = Counter()
        self._lock = threading.Lock()

    def incr(self, name: str, amount: int = 1) -> None:
        with self._lock:
            self._counters[name] += amount

    def observe_latency(self, command: str, seconds: float) -> None:
        with self._lock:
            self._counters[f"latency_ms_total.{command}"] += int(seconds * 1000)
            self._counters[f"latency_count.{command}"] += 1

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counters)

    def reset(self) -> None:
        with self._lock:
            self._counters.clear()


metrics = Metrics()
