# Python SDK (`pypufferblow`)

`pypufferblow` is the official Python SDK and bot framework for
Pufferblow. It wraps the same REST + WebSocket API that the
[reference client](client.md) uses, so anything the official
client can do, a Python program using this SDK can do too.

Source: [`PufferBlow/pypufferblow`](https://github.com/PufferBlow/pypufferblow).

!!! note "Audience"
    This page is a brief tour for server developers and people
    evaluating whether to build a bot. The SDK's own README has
    the canonical, exhaustive reference.

## Install

```bash
pip install pypufferblow
```

Requires Python 3.11+. With Poetry:

```bash
poetry add pypufferblow
```

## A 30-second bot

The smallest useful program — sign in, send one message, exit:

```python
from pypufferblow import Client, ClientOptions

client = Client(ClientOptions(
    instance="https://chat.example.org",
    username="alice",
    password="secret",
))

client.users.sign_in()
client.channels().send_message(
    channel_id="general",
    message="Hello from a Python script.",
)
```

That's the entire surface area for a one-shot announcement
bot. The SDK handles JWT issuance, refresh-token rotation, and
the `origin_server` claim transparently.

## Real-time

For an always-on bot you'll want WebSocket fanout instead of
polling:

```python
ws = client.websocket()

def on_message(msg):
    if msg.message.startswith("!ping"):
        client.channels().send_message(msg.channel_id, "pong")

ws.on_message = on_message
ws.connect()      # listens on every channel the bot can see
```

A channel-scoped connection is also available
(`client.create_channel_websocket(channel_id=...)`); the global
one is usually what you want for a bot.

## Async

Every blocking call has an `_async` twin:

```python
await client.users.sign_in_async()
channels = await client.channels.list_channels_async()
await client.channels.send_message_async("general", "hello")
```

Mix and match in the same program — the SDK uses `httpx` under
the hood and shares connection pools between sync and async
paths.

## Bot framework

For something more structured than callbacks, the SDK includes
a decorator-style bot framework inspired by `discord.py`:

```python
from pypufferblow import Bot, BotOptions

bot = Bot(BotOptions(
    instance="https://chat.example.org",
    username="my_bot",
    password="secret",
))

@bot.command("ping")
async def ping(ctx):
    await ctx.reply("pong")

@bot.command("echo")
async def echo(ctx, *args):
    await ctx.reply(" ".join(args) or "(nothing to echo)")

bot.run()
```

`bot.run()` handles sign-in, the WebSocket reconnect loop, and
command dispatch. Decorated functions get a `ctx` with reply,
edit, react, and channel-info shortcuts so commands don't have
to thread the raw client through.

## Federation

Cross-instance follows and DMs are first-class:

```python
fed = client.federation()
fed.follow_remote_account("alice@other-instance.org")
fed.send_direct_message(peer="alice@other-instance.org",
                        message="hi")
```

These go through your home instance's ActivityPub bridge — the
SDK is talking to *your* server, which then federates to the
peer. From the SDK's point of view there's no special remote
codepath.

## What the SDK does **not** do

- **Voice / WebRTC.** Voice is a browser-grade WebRTC flow
  that depends on `getUserMedia`, audio context, etc. A
  headless Python bot can't currently join a voice channel.
- **OAuth.** Pufferblow auth is username + password →
  JWT today. If your bot needs SSO, that has to land
  server-side first.
- **Local message persistence.** The SDK is stateless. If your
  bot needs to remember things, persist them yourself
  (SQLite, Redis, whatever).

## When **not** to use the SDK

The SDK is a Python wrapper, not the protocol. If you're
writing a bot in another language or a service that consumes
Pufferblow events as part of a larger system, going direct to
the REST + WebSocket API is fine — see the
[API reference](api-reference.md). The wire protocol is
documented and stable within the `0.x` series; the SDK adds
ergonomics, not capability.

## Cross-repo links

- Source: [`PufferBlow/pypufferblow`](https://github.com/PufferBlow/pypufferblow)
- PyPI: [`pypufferblow`](https://pypi.org/project/pypufferblow/)
- Issues: [`PufferBlow/pypufferblow/issues`](https://github.com/PufferBlow/pypufferblow/issues)
