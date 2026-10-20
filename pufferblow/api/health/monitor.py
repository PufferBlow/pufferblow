"""The instance watching itself: how long requests take, how often it was fine, and what went wrong.

* :class:`LatencyRecorder` keeps request durations for the last 24 hours in five-minute buckets (a small
  random sample per bucket, so memory is bounded however busy the instance is) and answers with p50 and
  p95. It lives in memory: a restart starts the chart again, which is honest, because the process is new.
* :class:`HealthMonitor` is the thing that samples. Once a minute it takes the instance's health, counts it
  against today (the uptime bar), and opens an incident when something is wrong and resolves it when it is
  right again.

Nothing here reaches out to other instances: a health check that dials peers would be slow and could be
aimed at somewhere it should not.
"""

from __future__ import annotations

import asyncio
import contextlib
import random
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

BUCKET_SECONDS = 300
BUCKETS = 288  # 24 hours
SAMPLES_PER_BUCKET = 200
SAMPLE_INTERVAL_SECONDS = 60
UPTIME_DAYS = 90


def percentile(sorted_values: list[float], q: float) -> float:
    """Nearest-rank percentile of an already sorted list (``q`` in 0..1). 0 for an empty list."""
    if not sorted_values:
        return 0.0
    rank = max(1, min(len(sorted_values), round(q * len(sorted_values) + 0.4999999)))
    return float(sorted_values[rank - 1])


class LatencyRecorder:
    def __init__(self, clock: Callable[[], float] = time.time, rng: random.Random | None = None) -> None:
        self._clock = clock
        self._rng = rng or random.Random()
        #: bucket number -> [samples, how many were seen in all]
        self._buckets: dict[int, list[Any]] = {}

    def record(self, milliseconds: float) -> None:
        number = int(self._clock() // BUCKET_SECONDS)
        bucket = self._buckets.setdefault(number, [[], 0])
        bucket[1] += 1
        if len(bucket[0]) < SAMPLES_PER_BUCKET:
            bucket[0].append(float(milliseconds))
        else:  # reservoir sampling: every request seen has the same chance of being kept
            slot = self._rng.randrange(bucket[1])
            if slot < SAMPLES_PER_BUCKET:
                bucket[0][slot] = float(milliseconds)
        for old in [n for n in self._buckets if n <= number - BUCKETS]:
            del self._buckets[old]

    def series(self) -> list[dict]:
        """One point per five minutes that saw any request, oldest first."""
        points = []
        for number in sorted(self._buckets):
            samples, seen = self._buckets[number]
            ordered = sorted(samples)
            points.append({"t": number * BUCKET_SECONDS, "count": seen, "p50": percentile(ordered, 0.5), "p95": percentile(ordered, 0.95)})
        return points

    def summary(self, window_seconds: int = 3600) -> dict:
        """p50, p95 and the number of requests over the last ``window_seconds``."""
        floor = int((self._clock() - window_seconds) // BUCKET_SECONDS)
        samples: list[float] = []
        seen = 0
        for number, (values, count) in self._buckets.items():
            if number >= floor:
                samples.extend(values)
                seen += count
        samples.sort()
        return {"p50": percentile(samples, 0.5), "p95": percentile(samples, 0.95), "samples": seen, "window_seconds": window_seconds}


def _reasons(health: dict) -> list[str]:
    """What is wrong in a health payload, as short names."""
    reasons = []
    if not health.get("api_loaded", True):
        reasons.append("api")
    if not (health.get("database") or {}).get("connected", True):
        reasons.append("database")
    sfu = health.get("media_sfu") or {}
    if sfu.get("enabled") and sfu.get("status") != "ok":
        reasons.append("voice")
    if not reasons and health.get("status") != "ok":
        reasons.append("components")
    return reasons


class HealthMonitor:
    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self.started_at = clock()
        self.latency = LatencyRecorder(clock)

    @property
    def uptime_seconds(self) -> int:
        return int(self._clock() - self.started_at)

    def sample(self, database: Any, health: dict) -> list[str]:
        """Count one check against today, and open or resolve the incident. Returns what is wrong (empty if nothing)."""
        reasons = _reasons(health)
        today = datetime.fromtimestamp(self._clock(), timezone.utc).strftime("%Y-%m-%d")
        database.record_health_check(today, ok=not reasons)
        current = database.current_health_incident()
        if reasons and current is None:
            database.open_health_incident(f"Trouble with {', '.join(reasons)}", "Found by the instance's own check; it resolves itself when the check passes again.")
        elif not reasons and current is not None:
            database.resolve_health_incident(current["incident_id"])
        return reasons

    def uptime_days(self, database: Any, days: int = UPTIME_DAYS) -> list[dict]:
        """One entry per day for the last ``days`` days, oldest first. A day with no checks has ``ratio`` None."""
        today = datetime.fromtimestamp(self._clock(), timezone.utc).date()
        first = today - timedelta(days=days - 1)
        recorded = {row["day"]: row for row in database.list_uptime_days(first.isoformat())}
        out = []
        for offset in range(days):
            day = (first + timedelta(days=offset)).isoformat()
            row = recorded.get(day)
            ratio = None if row is None or row["checks"] == 0 else row["ok"] / row["checks"]
            out.append({"day": day, "checks": row["checks"] if row else 0, "ratio": ratio})
        return out


monitor = HealthMonitor()


def uptime_percent(days: list[dict]) -> float | None:
    """Over all days that were checked: the share of checks that found everything working, or None if none."""
    checks = sum(d["checks"] for d in days)
    if checks == 0:
        return None
    ok = sum(d["checks"] * d["ratio"] for d in days if d["ratio"] is not None)
    return round(100 * ok / checks, 3)


@contextlib.asynccontextmanager
async def health_sampling(take_health: Callable[[], dict], get_database: Callable[[], Any], interval: float = SAMPLE_INTERVAL_SECONDS):
    """Run the once-a-minute check for as long as the application is up."""

    async def loop() -> None:
        while True:
            try:
                database = get_database()
                if database is not None:
                    health = await asyncio.to_thread(take_health)
                    await asyncio.to_thread(monitor.sample, database, health)
            except asyncio.CancelledError:
                raise
            except Exception:  # a failed check must never take the application down
                from loguru import logger

                logger.exception("health check failed")
            await asyncio.sleep(interval)

    task = asyncio.create_task(loop())
    try:
        yield
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
