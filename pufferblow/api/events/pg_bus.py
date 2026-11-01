"""Realtime events and cache invalidation across the workers of one server, over PostgreSQL ``LISTEN/NOTIFY``.

A server runs several worker processes, and a person's socket lives in exactly one of them. The in-process publisher only
reaches the sockets of the worker that handled the request, so with more than one worker a message reached only the
people who happened to be connected to that same worker. :class:`PostgresPublisher` fixes that:

* the sequence number of a channel's events is taken from the database (``next_channel_event_seq``), so all workers agree
  on one order, and every worker uses the same ``epoch``;
* the frame is delivered to this worker's sockets and sent as a notification; every other worker is listening and
  delivers it to its own sockets. The notification carries the frame itself (a Postgres notification holds about 8 kB;
  a larger frame is parked in a table and the notification carries its id);
* a notification is sent when the transaction commits and never for a rollback, and a worker that is disconnected from
  the database for a moment misses some: clients see a gap in the sequence and resynchronise, as they already do.

The same connection also listens for ``pufferblow_cache`` notifications, which database triggers send when a person's
roles or membership change, a role is edited, settings change or an address is blocked (see ``api/database/bus_setup.py``).
Each worker then drops its cached copies, so a removal, a ban or a role change takes effect everywhere at once, even when
the code that made the change forgot to invalidate.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import threading
import time

from loguru import logger

from pufferblow.api.events.publisher import InProcessPublisher
from pufferblow.api.protocol.envelopes import build_event
from pufferblow.api.protocol.events import DomainEvent

BUS_CHANNEL = "pufferblow_bus"
CACHE_CHANNEL = "pufferblow_cache"
#: Notifications are limited to 8000 bytes; stay well under it (the rest of the payload is a few dozen bytes).
MAX_INLINE_BYTES = 6500


def listener_conninfo(engine) -> str:
    """A plain ``postgresql://`` address for the listening connection, from the SQLAlchemy engine (which names a driver)."""
    return engine.url.set(drivername="postgresql").render_as_string(hide_password=False)


class PgListener:
    """One dedicated connection, on its own thread, that listens for notifications and hands each to ``handler``.

    It reconnects by itself (a dropped connection must not end realtime for the rest of the process's life) and says
    so through ``on_connect``, because notifications sent while it was away are gone.
    """

    def __init__(self, conninfo: str, channels: list[str], handler, on_connect=None) -> None:
        self._conninfo = conninfo
        self._channels = channels
        self._handler = handler
        self._on_connect = on_connect
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="pufferblow-pg-listener", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3)

    def _run(self) -> None:
        import psycopg

        delay = 0.5
        while not self._stop.is_set():
            try:
                with psycopg.connect(self._conninfo, autocommit=True) as connection:
                    for channel in self._channels:
                        connection.execute(f"LISTEN {channel}")
                    logger.info("Listening for realtime notifications | channels={channels}", channels=",".join(self._channels))
                    delay = 0.5
                    if self._on_connect is not None:
                        self._on_connect()
                    while not self._stop.is_set():
                        for notification in connection.notifies(timeout=1.0):
                            try:
                                self._handler(notification.channel, notification.payload)
                            except Exception:
                                logger.exception(f"A realtime notification could not be handled | channel={notification.channel}")
                            if self._stop.is_set():
                                break
            except Exception as exc:
                if self._stop.is_set():
                    return
                logger.warning("The realtime listener lost its connection: {err}. Retrying in {delay:.1f}s", err=str(exc)[:160], delay=delay)
                time.sleep(delay)
                delay = min(delay * 2, 10.0)


class PostgresPublisher(InProcessPublisher):
    """Delivers to this worker's sockets and to every other worker's, through the database."""

    def __init__(self, websockets_manager, database_handler) -> None:
        super().__init__(websockets_manager, seq_store=None)
        self._db = database_handler
        #: Tells a worker which notifications are its own (it has already delivered those). Made again in `start()`:
        #: the server builds this object once and then forks its workers, so an id made here would be the same in all of them.
        self.origin = f"{time.time_ns():x}"
        self._loop: asyncio.AbstractEventLoop | None = None
        self._listener: PgListener | None = None

    async def start(self) -> None:
        """Take the shared epoch and start listening. Call once the server is up, on its event loop."""
        self._loop = asyncio.get_running_loop()
        self.origin = f"{os.getpid()}-{secrets.token_hex(6)}"
        self.epoch = await asyncio.to_thread(self._db.get_realtime_epoch)
        self._listener = PgListener(
            listener_conninfo(self._db.database_engine),
            [BUS_CHANNEL, CACHE_CHANNEL],
            self._on_notification,
            on_connect=self._forget_local_caches,
        )
        self._listener.start()
        self._purger = asyncio.create_task(self._purge_spool_regularly())

    async def stop(self) -> None:
        if getattr(self, "_purger", None) is not None:
            self._purger.cancel()
        if self._listener is not None:
            await asyncio.to_thread(self._listener.stop)

    async def _purge_spool_regularly(self) -> None:
        """Parked frames are removed after each new one, but a quiet server would keep the last one: so also on a timer."""
        while True:
            await asyncio.sleep(30)
            try:
                await asyncio.to_thread(self._db.purge_realtime_spool)
            except Exception:
                logger.exception("Could not clear the parked realtime frames")

    # ── sequence numbers: the database's, so every worker agrees ──────────────

    async def ensure_loaded(self, channel_id: str) -> None:
        try:
            mark = await asyncio.to_thread(self._db.get_channel_event_high_water, channel_id)
        except Exception:
            logger.exception(f"Could not read the event sequence | channel={channel_id}")
            return
        self._seq[channel_id] = max(self._seq[channel_id], mark)

    async def publish(self, event: DomainEvent) -> None:
        if event.target_user_id is not None:
            frame = build_event(event.name, event.data, epoch=self.epoch)
            await self._connections.deliver_user_event(event.target_user_id, frame)
            await self._broadcast("u", str(event.target_user_id), frame)
            return

        if event.channel_id is None:
            return

        if not event.sequenced:
            frame = build_event(event.name, event.data, channel_id=event.channel_id, epoch=self.epoch)
            await self._connections.deliver_channel_event(event.channel_id, frame)
            await self._broadcast("c", event.channel_id, frame)
            return

        seq = await asyncio.to_thread(self._db.next_channel_event_seq, event.channel_id)
        self._seq[event.channel_id] = max(self._seq[event.channel_id], seq)
        frame = build_event(event.name, event.data, channel_id=event.channel_id, seq=seq, epoch=self.epoch)
        await self._connections.deliver_channel_event(event.channel_id, frame)
        await self._broadcast("c", event.channel_id, frame)

    async def _broadcast(self, kind: str, target: str, frame: dict) -> None:
        """Tell the other workers. A failure here is the same as a worker that missed it: clients resynchronise."""
        try:
            payload = json.dumps({"o": self.origin, "k": kind, "t": target, "f": frame}, separators=(",", ":"), default=str)
            if len(payload.encode("utf-8")) > MAX_INLINE_BYTES:
                spool_id = await asyncio.to_thread(self._db.spool_realtime_frame, json.loads(json.dumps(frame, default=str)))
                payload = json.dumps({"o": self.origin, "k": kind, "t": target, "x": spool_id}, separators=(",", ":"))
            await asyncio.to_thread(self._db.notify_realtime, BUS_CHANNEL, payload)
        except Exception:
            logger.exception(f"Could not send a realtime event to the other workers | target={target}")

    # ── what arrives from the other workers ────────────────────────────────────

    def _on_notification(self, channel: str, payload: str) -> None:
        """Runs on the listener's thread."""
        if channel == CACHE_CHANNEL:
            invalidate_from_notification(self._db, payload)
            self._close_sockets_of_removed_person(payload)
            return
        body = json.loads(payload)
        if body.get("o") == self.origin:
            return
        frame = body.get("f")
        if frame is None and body.get("x") is not None:
            frame = self._db.read_spooled_realtime_frame(body["x"])
        if frame is None or self._loop is None or self._loop.is_closed():
            return
        asyncio.run_coroutine_threadsafe(self._deliver_remote(body.get("k"), str(body.get("t")), frame), self._loop)

    async def _deliver_remote(self, kind: str | None, target: str, frame: dict) -> None:
        if kind == "u":
            await self._connections.deliver_user_event(target, frame)
            return
        seq = frame.get("seq")
        if isinstance(seq, int):
            self._seq[target] = max(self._seq[target], seq)
        await self._connections.deliver_channel_event(target, frame)

    def _close_sockets_of_removed_person(self, payload: str) -> None:
        """Someone removed, erased, declined or who left must not keep receiving events on the sockets this worker holds.

        The route that removes them closes the sockets of its own worker only; this is how every other worker finds out
        (it also covers a change made straight in the database). Runs on the listener's thread, after the caches were
        dropped, so the status read is the current one.
        """
        body = json.loads(payload)
        if body.get("t") != "user" or self._loop is None or self._loop.is_closed():
            return
        ident = str(body.get("id") or "")
        user = self._db.get_user(user_id=ident) if ident else None
        status = (getattr(user, "membership_status", None) or "active") if user is not None else "gone"
        if status != "active":
            asyncio.run_coroutine_threadsafe(self._connections.disconnect_user(ident), self._loop)

    def _forget_local_caches(self) -> None:
        """Notifications sent while the listener was away are gone, so what this worker kept in memory may be stale."""
        try:
            from pufferblow.api.cache.memcache import get_local_cache

            get_local_cache().clear()
        except Exception:
            logger.debug("Could not clear the in-process cache after reconnecting")


def invalidate_from_notification(database_handler, payload: str) -> None:
    """Drop the cached copies of whatever a trigger said changed (``{"t": kind, "id": ...}``)."""
    body = json.loads(payload)
    kind, ident = body.get("t"), str(body.get("id") or "")
    if kind == "user":
        database_handler._invalidate_user_cache(ident)
        database_handler._invalidate_user_privileges_cache(ident)
        from pufferblow.api.cache.memcache import get_cache, moderation_state_key

        get_cache(database_handler.config).delete(moderation_state_key(ident))
    elif kind == "role":
        database_handler._invalidate_role_cache(ident)
        for holder in database_handler.user_ids_with_roles({ident}):
            database_handler._invalidate_user_privileges_cache(holder)
    elif kind == "settings":
        database_handler._invalidate_server_settings_cache()
    elif kind == "ip":
        database_handler._invalidate_blocked_ip_cache(ident)
