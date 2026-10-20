"""Per-channel event sequence numbers survive a restart.

Uses a stand-in connection manager and an in-memory store, so no database or socket is involved, plus
one test against the real database handler to check the table round-trips.
"""

from __future__ import annotations

import asyncio

from pufferblow.api.events.publisher import SEQ_BLOCK, InProcessPublisher
from pufferblow.api.protocol.events import MESSAGE_CREATED, DomainEvent


class Connections:
    def __init__(self) -> None:
        self.frames: list[dict] = []

    async def deliver_channel_event(self, channel_id: str, frame: dict) -> None:
        self.frames.append(frame)

    async def deliver_user_event(self, user_id: str, frame: dict) -> None:
        self.frames.append(frame)


class Store:
    """The two calls the publisher needs, remembering what it was told."""

    def __init__(self, marks: dict[str, int] | None = None, fail_writes: bool = False) -> None:
        self.marks = dict(marks or {})
        self.writes: list[tuple[str, int]] = []
        self.fail_writes = fail_writes

    def get_channel_event_high_water(self, channel_id: str) -> int:
        return self.marks.get(channel_id, 0)

    def set_channel_event_high_water(self, channel_id: str, high_water: int) -> None:
        if self.fail_writes:
            raise RuntimeError("database down")
        self.writes.append((channel_id, high_water))
        self.marks[channel_id] = max(self.marks.get(channel_id, 0), high_water)


def _event(channel: str = "c1") -> DomainEvent:
    return DomainEvent(MESSAGE_CREATED, {"id": "m"}, channel_id=channel)


async def _publish(publisher: InProcessPublisher, count: int, channel: str = "c1") -> list[int]:
    for _ in range(count):
        await publisher.publish(_event(channel))
    return [frame["seq"] for frame in publisher._connections.frames if frame.get("channel_id") == channel]


def test_a_fresh_channel_starts_at_one_and_counts_up():
    publisher = InProcessPublisher(Connections(), Store())
    assert asyncio.run(_publish(publisher, 3)) == [1, 2, 3]


def test_numbers_continue_above_what_an_earlier_process_used():
    store = Store()
    first = InProcessPublisher(Connections(), store)
    used = asyncio.run(_publish(first, 5))
    assert used == [1, 2, 3, 4, 5]

    # a restart: a new publisher (new epoch) on the same store
    second = InProcessPublisher(Connections(), store)
    after = asyncio.run(_publish(second, 2))

    assert after[0] > max(used)  # never a number an earlier event already had
    assert after == [after[0], after[0] + 1]
    assert second.epoch != first.epoch  # clients also resync on the new epoch


def test_the_database_is_written_once_per_block_not_once_per_event():
    store = Store()
    publisher = InProcessPublisher(Connections(), store)

    asyncio.run(_publish(publisher, SEQ_BLOCK + 1))

    assert len(store.writes) == 2  # one block for 1..SEQ_BLOCK, the next when it ran out
    assert store.writes[0] == ("c1", SEQ_BLOCK)
    assert store.marks["c1"] >= SEQ_BLOCK + 1


def test_channels_have_their_own_numbers_and_marks():
    store = Store({"busy": 500})
    publisher = InProcessPublisher(Connections(), store)

    async def go():
        await _publish(publisher, 2, "quiet")
        return await _publish(publisher, 2, "busy")

    assert asyncio.run(go()) == [501, 502]
    assert [f["seq"] for f in publisher._connections.frames if f["channel_id"] == "quiet"] == [1, 2]


def test_current_seq_is_the_channels_real_position_once_loaded():
    publisher = InProcessPublisher(Connections(), Store({"c1": 40}))

    async def go():
        before = publisher.current_seq("c1")  # not loaded yet
        await publisher.ensure_loaded("c1")
        return before, publisher.current_seq("c1")

    assert asyncio.run(go()) == (0, 40)


def test_a_store_that_fails_does_not_stop_events():
    publisher = InProcessPublisher(Connections(), Store(fail_writes=True))
    assert asyncio.run(_publish(publisher, 3)) == [1, 2, 3]  # in-memory counting carries on


def test_without_a_store_it_still_counts_in_memory():
    publisher = InProcessPublisher(Connections())
    assert asyncio.run(_publish(publisher, 2)) == [1, 2]


def test_unsequenced_events_do_not_use_up_numbers():
    publisher = InProcessPublisher(Connections(), Store())

    async def go():
        await publisher.publish(DomainEvent("typing.started", {}, channel_id="c1", sequenced=False))
        await publisher.publish(_event())

    asyncio.run(go())
    assert [f.get("seq") for f in publisher._connections.frames] == [None, 1]


def test_the_database_handler_keeps_the_mark_and_it_only_moves_up(client):
    from pufferblow.core.bootstrap import api_initializer

    db = api_initializer.database_handler
    assert db.get_channel_event_high_water("chan") == 0
    db.set_channel_event_high_water("chan", 64)
    db.set_channel_event_high_water("chan", 10)  # a stale write cannot lower it
    assert db.get_channel_event_high_water("chan") == 64
    db.set_channel_event_high_water("chan", 128)
    assert db.get_channel_event_high_water("chan") == 128
