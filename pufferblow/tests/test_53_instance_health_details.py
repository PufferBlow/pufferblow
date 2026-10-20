"""The detailed health of an instance: latency, uptime history, incidents, checks.

The pieces that keep time (the latency recorder, the sampler's incident logic) are tested with a clock
and a fake database; the rest goes through the application.
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from pufferblow.api.health.monitor import (
    BUCKET_SECONDS,
    SAMPLES_PER_BUCKET,
    HealthMonitor,
    LatencyRecorder,
    percentile,
    uptime_percent,
)
from pufferblow.core.bootstrap import api_initializer

# ── the recorder ──────────────────────────────────────────────────


class Clock:
    def __init__(self, now: float = 1_800_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def test_percentiles_are_nearest_rank_and_safe_when_empty():
    assert percentile([], 0.95) == 0.0
    values = [float(n) for n in range(1, 101)]
    assert percentile(values, 0.5) == 50.0
    assert percentile(values, 0.95) == 95.0
    assert percentile([7.0], 0.95) == 7.0


def test_latency_is_grouped_in_five_minute_buckets_oldest_first():
    clock = Clock()
    recorder = LatencyRecorder(clock)
    for ms in (10, 20, 30):
        recorder.record(ms)
    clock.now += BUCKET_SECONDS
    recorder.record(500)

    first, second = recorder.series()
    assert first["count"] == 3 and first["p50"] == 20.0
    assert second["count"] == 1 and second["p95"] == 500.0
    assert first["t"] < second["t"]


def test_the_summary_covers_only_the_window():
    clock = Clock()
    recorder = LatencyRecorder(clock)
    recorder.record(900)  # long ago
    clock.now += 3 * 3600
    recorder.record(10)
    recorder.record(30)
    assert recorder.summary(3600) == {"p50": 10.0, "p95": 30.0, "samples": 2, "window_seconds": 3600}
    assert recorder.summary(6 * 3600)["samples"] == 3


def test_a_day_old_bucket_is_forgotten_and_memory_stays_bounded():
    clock = Clock()
    recorder = LatencyRecorder(clock, random.Random(1))
    recorder.record(1)
    clock.now += 25 * 3600
    for _ in range(SAMPLES_PER_BUCKET * 5):  # far more requests than the bucket keeps
        recorder.record(5)
    [only] = recorder.series()
    assert only["count"] == SAMPLES_PER_BUCKET * 5  # it still knows how many there were
    assert len(recorder._buckets[next(iter(recorder._buckets))][0]) == SAMPLES_PER_BUCKET


# ── the sampler ───────────────────────────────────────────────────


class FakeDatabase:
    def __init__(self) -> None:
        self.checks: list[tuple[str, bool]] = []
        self.incident: dict | None = None
        self.opened: list[str] = []
        self.resolved: list[str] = []

    def record_health_check(self, day, ok):
        self.checks.append((day, ok))

    def current_health_incident(self):
        return self.incident

    def open_health_incident(self, title, body=""):
        self.opened.append(title)
        self.incident = {"incident_id": "i1", "title": title}
        return "i1"

    def resolve_health_incident(self, incident_id):
        self.resolved.append(incident_id)
        self.incident = None

    def list_uptime_days(self, since_day):
        by_day: dict[str, list[bool]] = {}
        for day, ok in self.checks:
            if day >= since_day:
                by_day.setdefault(day, []).append(ok)
        return [{"day": d, "checks": len(v), "ok": sum(v)} for d, v in sorted(by_day.items())]


GOOD = {"status": "ok", "api_loaded": True, "database": {"connected": True}, "media_sfu": {"enabled": False}}
BAD_DB = {**GOOD, "status": "degraded", "database": {"connected": False}}


def test_a_failing_check_opens_one_incident_and_a_passing_one_resolves_it():
    database, monitor = FakeDatabase(), HealthMonitor(Clock())
    assert monitor.sample(database, GOOD) == []
    assert monitor.sample(database, BAD_DB) == ["database"]
    assert monitor.sample(database, BAD_DB) == ["database"]  # still failing: not a second incident
    assert database.opened == ["Trouble with database"]
    assert monitor.sample(database, GOOD) == []
    assert database.resolved == ["i1"] and database.incident is None
    assert [ok for _, ok in database.checks] == [True, False, False, True]


def test_voice_that_is_enabled_but_not_answering_counts():
    database = FakeDatabase()
    health = {**GOOD, "status": "degraded", "media_sfu": {"enabled": True, "status": "unreachable"}}
    assert HealthMonitor(Clock()).sample(database, health) == ["voice"]


def test_uptime_days_are_ninety_long_and_unchecked_days_have_no_ratio():
    clock = Clock(datetime(2026, 10, 20, 12, tzinfo=timezone.utc).timestamp())
    database, monitor = FakeDatabase(), HealthMonitor(clock)
    monitor.sample(database, GOOD)
    monitor.sample(database, BAD_DB)

    days = monitor.uptime_days(database)

    assert len(days) == 90 and days[-1]["day"] == "2026-10-20" and days[0]["day"] == "2026-07-23"
    assert days[-1]["ratio"] == 0.5 and days[-1]["checks"] == 2
    assert days[0]["ratio"] is None  # nobody was watching
    assert uptime_percent(days) == 50.0
    assert uptime_percent([{"day": "x", "checks": 0, "ratio": None}]) is None


# ── the database ──────────────────────────────────────────────────


def test_the_database_counts_checks_per_day_and_tracks_one_incident(client: TestClient):
    handler = api_initializer.database_handler
    handler.record_health_check("2026-10-19", ok=True)
    handler.record_health_check("2026-10-19", ok=False)
    handler.record_health_check("2026-10-20", ok=True)
    assert handler.list_uptime_days("2026-10-19") == [{"day": "2026-10-19", "checks": 2, "ok": 1}, {"day": "2026-10-20", "checks": 1, "ok": 1}]
    assert handler.list_uptime_days("2026-10-20") == [{"day": "2026-10-20", "checks": 1, "ok": 1}]

    assert handler.current_health_incident() is None
    incident_id = handler.open_health_incident("Trouble with database", "details")
    assert handler.current_health_incident()["title"] == "Trouble with database"
    handler.resolve_health_incident(incident_id)
    handler.resolve_health_incident(incident_id)  # harmless the second time
    assert handler.current_health_incident() is None
    [listed] = handler.list_health_incidents()
    assert listed["state"] == "resolved" and listed["ended_at"] is not None


# ── through the application ───────────────────────────────────────


def _details(client: TestClient, token: str):
    return client.get("/api/v1/system/health", params={"auth_token": token})


def _owner(client: TestClient) -> str:
    """The token of an instance owner (signing up through the API never makes one)."""
    user = api_initializer.user_manager.sign_up(username=f"owner_{uuid.uuid4().hex[:6]}", password="12345678", is_owner=True)
    return api_initializer.auth_token_manager.issue_session_tokens(user_id=str(user.user_id), origin_server=user.origin_server)["access_token"]


def test_an_admin_gets_the_detailed_health(client: TestClient):
    token = _owner(client)
    for _ in range(3):
        client.post("/api/v1/users/profile", json={"auth_token": token})

    reply = _details(client, token)

    assert reply.status_code == 200, reply.text
    health = reply.json()["health"]
    assert health["status"] in ("ok", "degraded") and health["checks"]["database"]["status"] == "ok"  # (degraded: the test harness runs without every component)
    assert health["checks"]["storage"]["status"] in ("ok", "down")
    assert health["checks"]["realtime"]["status"] == "ok"
    assert isinstance(health["version"], str) and health["uptime_s"] >= 0
    assert len(health["uptime_days"]) == 90
    assert health["latency"]["samples"] >= 3 and health["latency"]["series"]  # the requests above were recorded
    assert "p95" in health["latency"] and isinstance(health["incidents"], list) and health["peers"] == []
    assert health["resources"] is None or set(health["resources"]) == {"cpu", "memory", "disk"}


def test_other_people_and_strangers_do_not(client: TestClient, make_account):
    member = make_account("member")

    assert _details(client, member.auth_token).status_code == 403
    assert _details(client, "not-a-token").status_code in (400, 401, 403)
    assert client.get("/api/v1/system/health").status_code in (400, 422)


def test_the_small_public_answer_stays_small(client: TestClient):
    body = client.get("/healthz").json()
    for private in ("version", "uptime_s", "latency", "peers", "incidents", "resources"):
        assert private not in body


def test_the_health_checks_are_not_counted_as_traffic(client: TestClient):
    from pufferblow.api.health.monitor import monitor

    before = monitor.latency.summary(24 * 3600)["samples"]
    client.get("/healthz")
    client.get("/readyz")
    assert monitor.latency.summary(24 * 3600)["samples"] == before


def test_linked_instances_are_listed_by_host(client: TestClient):
    from pufferblow.api.database.tables.activitypub import ActivityPubFollow

    handler = api_initializer.database_handler
    assert handler.list_federation_hosts() == []  # no federation tables yet: nothing to list, and no error
    ActivityPubFollow.__table__.create(handler.database_engine, checkfirst=True)
    with handler.database_session() as session:
        for remote in ("https://Mesh.Garden/users/rina", "https://mesh.garden/users/teo", "https://kiln.social/users/ada"):
            session.add(ActivityPubFollow(local_actor_uri="https://here/users/me", remote_actor_uri=remote, accepted=True, direction="outgoing"))
        session.add(ActivityPubFollow(local_actor_uri="https://here/users/me", remote_actor_uri="https://pending.example/users/x", accepted=False))
        session.commit()

    hosts = handler.list_federation_hosts()

    assert [h["host"] for h in hosts] == ["kiln.social", "mesh.garden"]  # accepted only, lower-cased, one entry per host
    assert hosts[1]["follows"] == 2 and hosts[1]["last_activity"]


@pytest.mark.asyncio
async def test_the_sampler_runs_checks_and_stops_with_the_application():
    import asyncio

    from pufferblow.api.health.monitor import health_sampling

    database, seen = FakeDatabase(), []

    def take():
        seen.append(1)
        return GOOD

    async with health_sampling(take, lambda: database, interval=0.01):
        await asyncio.sleep(0.08)
    count = len(seen)
    await asyncio.sleep(0.05)

    assert count >= 2 and len(database.checks) >= 2
    assert len(seen) == count  # nothing keeps sampling after shutdown
