"""Turns committed domain events into frames and hands them to a transport.

``EventPublisher`` is the seam for a future message broker: the services and the
dispatcher only know this interface. :class:`InProcessPublisher` delivers to the
WebSocket connections of this one process.

Ordering and delivery: every channel event gets a sequence number from a counter
that is monotonic *within one server process* (``epoch``). A client that sees a
gap, or a different epoch than before, knows it may have missed events and
resynchronises the channel. Delivery is at-least-once from the client's point of
view and clients must treat events as idempotent (by event id and entity id).
"""

from __future__ import annotations

import asyncio
import secrets
from abc import ABC, abstractmethod
from collections import defaultdict
from collections.abc import Iterable

from loguru import logger

from pufferblow.api.commands.metrics import metrics
from pufferblow.api.protocol.envelopes import build_event
from pufferblow.api.protocol.events import DomainEvent


class EventPublisher(ABC):
    epoch: str

    @abstractmethod
    async def publish(self, event: DomainEvent) -> None: ...

    async def publish_all(self, events: Iterable[DomainEvent]) -> None:
        for event in events:
            try:
                await self.publish(event)
            except Exception:
                # The mutation is already committed; a failed fan-out is healed by client resync.
                metrics.incr("publish_failures")
                logger.exception(f"Event publication failed | event={event.name} channel={event.channel_id}")

    @abstractmethod
    def current_seq(self, channel_id: str) -> int: ...

    async def ensure_loaded(self, channel_id: str) -> None:
        """Make ``current_seq`` accurate for a channel that has not been used since the process started."""


#: How many sequence numbers are reserved in the database at a time. A bigger block means fewer writes;
#: after a restart a channel skips at most this many numbers, which clients see as a gap and resync.
SEQ_BLOCK = 64


class InProcessPublisher(EventPublisher):
    """Delivers to this process's connections.

    Sequence numbers are per channel and never go backwards across restarts: each channel's counter starts
    from a persisted high-water mark and reserves new numbers in blocks of ``SEQ_BLOCK``. ``epoch`` still changes
    with every process, so clients also resynchronise after a restart; the persisted mark guarantees a number is
    never reused for a different event.
    """

    def __init__(self, websockets_manager, seq_store=None) -> None:
        """``seq_store`` needs ``get_channel_event_high_water(channel_id)`` and
        ``set_channel_event_high_water(channel_id, n)`` (the database handler); without it counters are in memory only."""
        self._connections = websockets_manager
        self._store = seq_store
        self.epoch = secrets.token_urlsafe(8)
        self._seq: dict[str, int] = defaultdict(int)
        self._reserved: dict[str, int] = {}
        self._load_locks: dict[str, asyncio.Lock] = {}

    def current_seq(self, channel_id: str) -> int:
        return self._seq[channel_id]

    async def ensure_loaded(self, channel_id: str) -> None:
        if self._store is None or channel_id in self._reserved:
            return
        lock = self._load_locks.setdefault(channel_id, asyncio.Lock())
        async with lock:
            if channel_id in self._reserved:
                return
            try:
                mark = await asyncio.to_thread(self._store.get_channel_event_high_water, channel_id)
            except Exception:
                logger.exception(f"Could not read the event sequence mark | channel={channel_id}")
                mark = 0
            self._seq[channel_id] = max(self._seq[channel_id], mark)
            self._reserved[channel_id] = mark

    async def _reserve_for_next(self, channel_id: str) -> None:
        """Make sure the number about to be used is covered by the persisted mark, writing a new block
        when it is not. Done *before* the counter moves, so the number and its frame are taken together."""
        if self._store is None or self._seq[channel_id] + 1 <= self._reserved.get(channel_id, 0):
            return
        target = self._seq[channel_id] + SEQ_BLOCK
        try:
            await asyncio.to_thread(self._store.set_channel_event_high_water, channel_id, target)
            self._reserved[channel_id] = target
        except Exception:
            # Not worth losing the event over: the counter keeps working in memory, and the next
            # event tries to reserve again.
            logger.exception(f"Could not persist the event sequence mark | channel={channel_id}")

    async def publish(self, event: DomainEvent) -> None:
        if event.target_user_id is not None:
            frame = build_event(event.name, event.data, epoch=self.epoch)
            await self._connections.deliver_user_event(event.target_user_id, frame)
            return

        if event.channel_id is None:
            return

        if not event.sequenced:
            frame = build_event(event.name, event.data, channel_id=event.channel_id, epoch=self.epoch)
            await self._connections.deliver_channel_event(event.channel_id, frame)
            return

        await self.ensure_loaded(event.channel_id)
        await self._reserve_for_next(event.channel_id)
        self._seq[event.channel_id] += 1
        frame = build_event(
            event.name,
            event.data,
            channel_id=event.channel_id,
            seq=self._seq[event.channel_id],
            epoch=self.epoch,
        )
        await self._connections.deliver_channel_event(event.channel_id, frame)
