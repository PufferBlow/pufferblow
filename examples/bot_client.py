"""A small bot on the command/event protocol: it answers ``!ping`` with ``pong``.

Setup
-----
1. Install the SDK (``pip install pypufferblow``, or ``pip install -e ../pypufferblow`` from a checkout).
2. Create a bot on your instance (the instance owner does this) and give it the ``send_messages`` scope.
   The token is shown once; keep it out of source control.
3. Put the instance address and the token in the environment, never in this file::

       export PUFFERBLOW_INSTANCE=chat.example.org        # or localhost:7575
       export PUFFERBLOW_BOT_TOKEN=...                    # the bot's token

4. Run it::

       python examples/bot_client.py

What it shows: connecting (the client reconnects by itself and catches up after a drop), reading events,
and sending a message. Sending is retried safely: ``create_message`` uses an idempotency nonce, so a
reply whose acknowledgment was lost is never posted twice.
"""

from __future__ import annotations

import asyncio
import os
import sys

from pypufferblow.realtime import ProtocolClient

PREFIX = "!"


async def run(instance: str, token: str) -> None:
    async with ProtocolClient(token, instance) as client:
        print(f"connected to {instance} as session {client.session_id}")

        async for event in client.events():
            if event.name != "message.created" or event.channel_id is None:
                continue
            content = str(event.data.get("content", ""))
            # The bot sees its own messages too. Its reply ("pong") has no prefix, so it is never
            # mistaken for a command; keep that in mind before making a bot answer anything it says.
            if not content.startswith(PREFIX):
                continue

            command, _, _rest = content[len(PREFIX):].partition(" ")
            if command == "ping":
                await client.create_message(event.channel_id, "pong")


def main() -> int:
    instance = os.environ.get("PUFFERBLOW_INSTANCE", "").strip()
    token = os.environ.get("PUFFERBLOW_BOT_TOKEN", "").strip()
    if not instance or not token:
        print("Set PUFFERBLOW_INSTANCE and PUFFERBLOW_BOT_TOKEN (see the top of this file).", file=sys.stderr)
        return 2
    try:
        asyncio.run(run(instance, token))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
