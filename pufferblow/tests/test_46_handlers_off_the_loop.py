"""Command handlers hand the blocking service calls to a worker thread.

A slow query in one command must not stall the event loop, which serves every other connection.
Uses a stand-in service so no database is involved.
"""

from __future__ import annotations

import asyncio
import threading
import time
from types import SimpleNamespace

from pufferblow.api.commands.dispatcher import CommandDispatcher, ConnectionContext
from pufferblow.api.commands.handlers import build_registry
from pufferblow.api.principals.principal import Principal
from pufferblow.api.services.messages import ServiceResult


class SlowMessages:
    """Records the thread each call ran on and blocks like a slow query would."""

    def __init__(self, delay: float = 0.3) -> None:
        self.delay = delay
        self.threads: list[int] = []

    def _work(self):
        self.threads.append(threading.get_ident())
        time.sleep(self.delay)

    def create(self, principal, channel_id, content, **_kw):
        self._work()
        return ServiceResult(value={"message": {"id": "m1", "content": content}}, events=[])

    def edit(self, *_a):
        self._work()
        return ServiceResult(value={"id": "m1"}, events=[])

    def delete(self, *_a):
        self._work()
        return ServiceResult(value={"id": "m1", "deleted": True}, events=[])

    def add_reaction(self, *_a):
        self._work()
        return ServiceResult(value={"changed": True}, events=[])

    remove_reaction = add_reaction

    def recent(self, *_a):
        self._work()
        return []


class SlowAuthorizer:
    def __init__(self) -> None:
        self.threads: list[int] = []

    def can_subscribe(self, *_a):
        self.threads.append(threading.get_ident())
        time.sleep(0.1)
        return True


def _setup(messages=None, authorizer=None, revalidate=None):
    messages = messages or SlowMessages()
    authorizer = authorizer or SlowAuthorizer()
    async def ensure_loaded(_channel_id):
        return None

    publisher = SimpleNamespace(current_seq=lambda _c: 0, ensure_loaded=ensure_loaded, epoch="ep")
    dispatcher = CommandDispatcher(build_registry(messages=messages, authorizer=authorizer, publisher=publisher))
    principal = Principal(id="u1", kind="user", privileges=frozenset({"send_messages"}))
    ctx = ConnectionContext(principal=principal, session_id="s", connection_key="k", subscriptions=set(), revalidate=revalidate)
    return dispatcher, ctx, messages, authorizer


def _command(name, data):
    return {"type": "command", "version": 1, "id": "cmd_1", "name": name, "data": data}


def test_a_slow_service_call_does_not_block_the_loop():
    async def main():
        dispatcher, ctx, messages, _ = _setup()
        ticks = 0

        async def ticker():
            nonlocal ticks
            while True:
                await asyncio.sleep(0.01)
                ticks += 1

        task = asyncio.create_task(ticker())
        result = await dispatcher.dispatch(ctx, _command("message.create", {"channel_id": "c1", "content": "hi"}))
        task.cancel()

        assert result.reply["type"] == "ack"
        # The service slept 0.3 s. On the loop that would allow no ticks; in a thread, about thirty.
        assert ticks >= 10, ticks
        assert messages.threads and messages.threads[0] != threading.get_ident()

    asyncio.run(main())


def test_every_handler_that_touches_the_database_runs_in_a_worker_thread():
    async def main():
        dispatcher, ctx, messages, authorizer = _setup()
        main_thread = threading.get_ident()
        commands = [
            ("message.create", {"channel_id": "c1", "content": "x"}),
            ("message.edit", {"channel_id": "c1", "message_id": "m1", "content": "y"}),
            ("message.delete", {"channel_id": "c1", "message_id": "m1"}),
            ("reaction.add", {"channel_id": "c1", "message_id": "m1", "emoji": "🎉"}),
            ("reaction.remove", {"channel_id": "c1", "message_id": "m1", "emoji": "🎉"}),
            ("events.resync", {"channel_id": "c1", "limit": 5}),
            ("channel.subscribe", {"channel_id": "c1"}),
        ]
        for name, data in commands:
            reply = (await dispatcher.dispatch(ctx, _command(name, data))).reply
            assert reply["type"] == "ack", (name, reply)
        assert len(messages.threads) == 6 and len(authorizer.threads) == 1
        assert main_thread not in messages.threads + authorizer.threads
        assert ctx.subscriptions == {"c1"}  # loop-owned state is still updated on the loop

    asyncio.run(main())


def test_the_credential_check_between_commands_runs_in_a_worker_thread():
    seen: list[int] = []

    def revalidate():
        seen.append(threading.get_ident())
        return Principal(id="u1", kind="user", privileges=frozenset({"send_messages"}))

    async def main():
        dispatcher, ctx, *_ = _setup(revalidate=revalidate)
        await dispatcher.dispatch(ctx, _command("message.create", {"channel_id": "c1", "content": "hi"}))
        assert seen and seen[0] != threading.get_ident()

    asyncio.run(main())


def test_two_connections_make_progress_at_the_same_time():
    async def main():
        messages = SlowMessages(delay=0.3)
        dispatcher_a, ctx_a, *_ = _setup(messages=messages)
        dispatcher_b, ctx_b, *_ = _setup(messages=messages)
        started = time.perf_counter()
        await asyncio.gather(
            dispatcher_a.dispatch(ctx_a, _command("message.create", {"channel_id": "c1", "content": "a"})),
            dispatcher_b.dispatch(ctx_b, _command("message.create", {"channel_id": "c1", "content": "b"})),
        )
        # Back to back on the loop this would take 0.6 s.
        assert time.perf_counter() - started < 0.55

    asyncio.run(main())


def test_a_check_that_straddles_an_access_change_is_run_again():
    async def main():
        _, ctx, *_ = _setup()
        calls: list[int] = []

        def check():
            calls.append(len(calls))
            if len(calls) == 1:
                time.sleep(0.1)  # the first answer is computed from permissions that then change
            return len(calls)

        async def revoke():
            await asyncio.sleep(0.03)
            ctx.access_version += 1  # what WebSocketsManager.revalidate_subscriptions does

        asyncio.create_task(revoke())
        assert await ctx.in_thread_unless_access_changed(check) == 2  # the stale first answer was discarded
        assert len(calls) == 2

    asyncio.run(main())


def test_subscribe_does_not_resurrect_a_subscription_revoked_while_it_checked():
    async def main():
        class Authorizer:
            allowed = True

            def can_subscribe(self, *_a):
                answer = self.allowed  # read first, then "query": the answer predates a revocation
                time.sleep(0.1)
                return answer

        authorizer = Authorizer()
        dispatcher, ctx, *_ = _setup(authorizer=authorizer)

        async def revoke():
            await asyncio.sleep(0.03)
            authorizer.allowed = False
            ctx.access_version += 1  # what WebSocketsManager.revalidate_subscriptions does

        asyncio.create_task(revoke())
        reply = (await dispatcher.dispatch(ctx, _command("channel.subscribe", {"channel_id": "c1"}))).reply
        assert reply["type"] == "error"
        assert ctx.subscriptions == set()

    asyncio.run(main())
