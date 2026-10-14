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


class InProcessPublisher(EventPublisher):
    def __init__(self, websockets_manager) -> None:
        self._connections = websockets_manager
        self.epoch = secrets.token_urlsafe(8)
        self._seq: dict[str, int] = defaultdict(int)

    def current_seq(self, channel_id: str) -> int:
        return self._seq[channel_id]

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

        self._seq[event.channel_id] += 1
        frame = build_event(
            event.name,
            event.data,
            channel_id=event.channel_id,
            seq=self._seq[event.channel_id],
            epoch=self.epoch,
        )
        await self._connections.deliver_channel_event(event.channel_id, frame)
