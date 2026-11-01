"""Realtime events and cache changes across workers (the bus), tested with stand-ins for the database and the sockets."""

from __future__ import annotations

import asyncio
import json

import pytest

from pufferblow.api.database import bus_setup
from pufferblow.api.events.pg_bus import BUS_CHANNEL, CACHE_CHANNEL, MAX_INLINE_BYTES, PostgresPublisher, invalidate_from_notification
from pufferblow.api.protocol.events import DomainEvent


class FakeDatabase:
    """What the workers share: one counter per channel, one epoch, a spool, and a log of notifications."""

    def __init__(self) -> None:
        self.seq: dict[str, int] = {}
        self.spool: dict[int, dict] = {}
        self.notified: list[tuple[str, str]] = []

    def next_channel_event_seq(self, channel_id):
        self.seq[channel_id] = self.seq.get(channel_id, 0) + 1
        return self.seq[channel_id]

    def get_channel_event_high_water(self, channel_id):
        return self.seq.get(channel_id, 0)

    def get_realtime_epoch(self):
        return "shared-epoch"

    def notify_realtime(self, channel, payload):
        self.notified.append((channel, payload))

    def spool_realtime_frame(self, frame):
        spool_id = len(self.spool) + 1
        self.spool[spool_id] = frame
        return spool_id

    def read_spooled_realtime_frame(self, spool_id):
        return self.spool.get(spool_id)


class FakeSockets:
    def __init__(self) -> None:
        self.channel_frames: list[tuple[str, dict]] = []
        self.user_frames: list[tuple[str, dict]] = []
        self.disconnected: list[str] = []

    async def disconnect_user(self, user_id):
        self.disconnected.append(user_id)

    async def deliver_channel_event(self, channel_id, frame):
        self.channel_frames.append((channel_id, frame))

    async def deliver_user_event(self, user_id, frame):
        self.user_frames.append((user_id, frame))


def worker(database: FakeDatabase) -> tuple[PostgresPublisher, FakeSockets]:
    sockets = FakeSockets()
    publisher = PostgresPublisher(sockets, database)
    publisher.epoch = "shared-epoch"
    publisher._loop = asyncio.get_running_loop()
    return publisher, sockets


def message(channel="c1", text="hi") -> DomainEvent:
    return DomainEvent(name="message.created", channel_id=channel, data={"message": {"content": text}}, sequenced=True)


async def settle() -> None:
    await asyncio.sleep(0.05)


@pytest.mark.asyncio
async def test_a_message_reaches_the_sockets_of_every_worker_in_one_order():
    database = FakeDatabase()
    a, a_sockets = worker(database)
    b, b_sockets = worker(database)

    await a.publish(message(text="one"))
    await b.publish(message(text="two"))
    # What each worker sent is heard by the other.
    for channel, payload in database.notified:
        a._on_notification(channel, payload)
        b._on_notification(channel, payload)
    await settle()

    for sockets in (a_sockets, b_sockets):
        frames = [frame for _, frame in sockets.channel_frames]
        assert sorted(f["seq"] for f in frames) == [1, 2]  # both messages, numbered by the database, not by the worker
        assert {f["data"]["message"]["content"] for f in frames} == {"one", "two"}
        assert {f["epoch"] for f in frames} == {"shared-epoch"}


@pytest.mark.asyncio
async def test_a_worker_does_not_deliver_its_own_event_twice():
    database = FakeDatabase()
    a, a_sockets = worker(database)
    await a.publish(message())
    for channel, payload in database.notified:
        a._on_notification(channel, payload)
    await settle()
    assert len(a_sockets.channel_frames) == 1


@pytest.mark.asyncio
async def test_an_event_for_one_person_reaches_their_sockets_on_other_workers():
    database = FakeDatabase()
    a, _ = worker(database)
    b, b_sockets = worker(database)
    await a.publish(DomainEvent(name="call.invited", target_user_id="u9", data={"call": "x"}))
    for channel, payload in database.notified:
        b._on_notification(channel, payload)
    await settle()
    assert [(user, frame["name"]) for user, frame in b_sockets.user_frames] == [("u9", "call.invited")]


@pytest.mark.asyncio
async def test_an_event_without_a_sequence_is_still_passed_on():
    database = FakeDatabase()
    a, _ = worker(database)
    b, b_sockets = worker(database)
    await a.publish(DomainEvent(name="typing.started", channel_id="c1", data={"user": "u1"}, sequenced=False))
    for channel, payload in database.notified:
        b._on_notification(channel, payload)
    await settle()
    (channel, frame), = b_sockets.channel_frames
    assert channel == "c1" and "seq" not in frame or frame.get("seq") is None


@pytest.mark.asyncio
async def test_a_frame_too_big_for_a_notification_travels_by_the_spool():
    database = FakeDatabase()
    a, _ = worker(database)
    b, b_sockets = worker(database)
    await a.publish(message(text="x" * (MAX_INLINE_BYTES * 2)))

    (channel, payload), = database.notified
    assert channel == BUS_CHANNEL and len(payload.encode()) < 500  # an id, not the frame
    assert json.loads(payload)["x"] in database.spool

    b._on_notification(channel, payload)
    await settle()
    (_, frame), = b_sockets.channel_frames
    assert frame["data"]["message"]["content"] == "x" * (MAX_INLINE_BYTES * 2)


@pytest.mark.asyncio
async def test_a_worker_learns_the_position_of_a_channel_from_what_the_others_send():
    database = FakeDatabase()
    a, _ = worker(database)
    b, _ = worker(database)
    for _ in range(3):
        await a.publish(message())
    for channel, payload in database.notified:
        b._on_notification(channel, payload)
    await settle()
    assert b.current_seq("c1") == 3
    # and a worker that heard nothing reads it from the database when someone subscribes
    c, _ = worker(database)
    await c.ensure_loaded("c1")
    assert c.current_seq("c1") == 3


@pytest.mark.asyncio
async def test_a_failure_to_tell_the_others_does_not_fail_the_event():
    database = FakeDatabase()
    a, a_sockets = worker(database)

    def broken(channel, payload):
        raise RuntimeError("database away")

    database.notify_realtime = broken
    await a.publish(message())
    assert len(a_sockets.channel_frames) == 1  # delivered here; the others will see a gap and resynchronise


class RecordingHandler:
    def __init__(self) -> None:
        self.calls: list[tuple] = []
        self.config = None

    def _invalidate_user_cache(self, i):
        self.calls.append(("user", i))

    def _invalidate_user_privileges_cache(self, i):
        self.calls.append(("privileges", i))

    def _invalidate_role_cache(self, i):
        self.calls.append(("role", i))

    def user_ids_with_roles(self, roles):
        return ["u1", "u2"] if "mod" in roles else []

    def _invalidate_server_settings_cache(self):
        self.calls.append(("settings",))

    def _invalidate_blocked_ip_cache(self, ip):
        self.calls.append(("ip", ip))


def test_a_changed_role_makes_every_worker_forget_it_and_what_its_holders_may_do():
    handler = RecordingHandler()
    invalidate_from_notification(handler, json.dumps({"t": "role", "id": "mod"}))
    assert ("role", "mod") in handler.calls
    assert [c for c in handler.calls if c[0] == "privileges"] == [("privileges", "u1"), ("privileges", "u2")]


def test_settings_and_blocked_addresses_are_forgotten_too():
    handler = RecordingHandler()
    invalidate_from_notification(handler, json.dumps({"t": "settings", "id": ""}))
    invalidate_from_notification(handler, json.dumps({"t": "ip", "id": "10.0.0.9"}))
    assert handler.calls == [("settings",), ("ip", "10.0.0.9")]


def test_the_trigger_installer_leaves_other_databases_alone_and_covers_the_tables_that_matter():
    import sqlalchemy as sa

    engine = sa.create_engine("sqlite://")
    with engine.begin() as connection:
        bus_setup.apply(connection)  # no error, nothing to do
    assert {t for t, _, _ in bus_setup.TRIGGERS} == {"users", "roles", "server_settings", "blocked_ips"}
    assert CACHE_CHANNEL in "".join(bus_setup.FUNCTIONS.values())


@pytest.mark.asyncio
async def test_workers_built_before_the_fork_each_get_their_own_origin_when_they_start(monkeypatch):
    """The server builds the publisher once and then forks its workers: an id made at construction would be shared,
    and every worker would take the others' notifications for its own and drop them."""
    import pufferblow.api.events.pg_bus as bus

    class NoListener:
        def __init__(self, *a, **k): pass
        def start(self): pass
        def stop(self): pass

    class Engine:
        class url:
            @staticmethod
            def set(**k):
                class U:
                    @staticmethod
                    def render_as_string(hide_password=False): return "postgresql://x"
                return U

    database = FakeDatabase()
    database.database_engine = Engine
    monkeypatch.setattr(bus, "PgListener", NoListener)
    built_once = PostgresPublisher(FakeSockets(), database)
    first_origin = built_once.origin

    pids = iter([101, 202])
    monkeypatch.setattr(bus.os, "getpid", lambda: next(pids))
    await built_once.start()
    started_as_first = built_once.origin
    await built_once.start()  # a second process, same object as it was before the fork
    assert started_as_first != built_once.origin and first_origin not in (started_as_first, built_once.origin)


class PersonDatabase(FakeDatabase):
    """Answers the questions the cache-change handler asks."""

    config = None

    def __init__(self, status) -> None:
        super().__init__()
        self.status = status

    def get_user(self, user_id):
        from types import SimpleNamespace

        return None if self.status is None else SimpleNamespace(membership_status=self.status)

    def _invalidate_user_cache(self, i): pass
    def _invalidate_user_privileges_cache(self, i): pass


@pytest.mark.asyncio
@pytest.mark.parametrize("status, closed", [("kicked", True), ("deleted", True), ("remote", True), (None, True), ("active", False)])
async def test_every_worker_closes_the_sockets_of_someone_who_was_removed(monkeypatch, status, closed):
    """The route that removes someone closes the sockets of its own worker only; the others hear it from the database."""
    import pufferblow.api.cache.memcache as memcache

    class NoCache:
        def delete(self, key): pass

    monkeypatch.setattr(memcache, "get_cache", lambda config: NoCache())
    other_worker, sockets = worker(PersonDatabase(status))
    other_worker._on_notification(CACHE_CHANNEL, json.dumps({"t": "user", "id": "u7"}))
    await settle()
    assert sockets.disconnected == (["u7"] if closed else [])


def test_a_parked_frame_is_sealed_in_the_database_and_cleared_when_old(client):
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import select, update

    from pufferblow.api.database.tables.realtime_bus import RealtimeSpool
    from pufferblow.core.bootstrap import api_initializer

    database = api_initializer.database_handler
    secret_text = "this is a private message nobody should read in a table"
    spool_id = database.spool_realtime_frame({"data": {"message": {"content": secret_text}}})

    with database.database_session() as session:
        stored = json.dumps(session.execute(select(RealtimeSpool.frame).where(RealtimeSpool.spool_id == spool_id)).scalar_one())
    assert secret_text not in stored and "private" not in stored
    assert database.read_spooled_realtime_frame(spool_id)["data"]["message"]["content"] == secret_text

    with database.database_session() as session:
        session.execute(update(RealtimeSpool).where(RealtimeSpool.spool_id == spool_id).values(created_at=datetime.now(timezone.utc) - timedelta(minutes=5)))
        session.commit()
    assert database.purge_realtime_spool() >= 1
    assert database.read_spooled_realtime_frame(spool_id) is None
