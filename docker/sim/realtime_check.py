"""Does a message reach every connected person, whichever worker holds their socket?

    python docker/sim/realtime_check.py --host host.docker.internal:7576 --sockets 24

Opens one websocket per simulated person, subscribes them all to the same channel, has the owner send one message over
HTTP, and counts who is told about it. With one worker that is everybody. With several workers, a server that only
delivers to the sockets of the worker that handled the request reaches roughly one in N.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import time
import uuid

import httpx
import websockets

PASSWORD = "simpass123"


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="host.docker.internal:7576")
    parser.add_argument("--sockets", type=int, default=24)
    parser.add_argument("--messages", type=int, default=12)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    base, ws_base = f"http://{args.host}", f"ws://{args.host}"

    async with httpx.AsyncClient(timeout=30) as http:
        owner = (await http.get(f"{base}/api/v1/users/signin", params={"username": "owner", "password": PASSWORD})).json()["auth_token"]
        channels = (await http.post(f"{base}/api/v1/channels/list/", json={"auth_token": owner})).json()["channels"]
        channel = next(c["channel_id"] for c in channels if c["channel_type"] == "text" and c["channel_name"] == "general")

        tokens = []
        stamp = uuid.uuid4().hex[:6]
        for i in range(args.sockets):
            name = f"rt_{stamp}_{i:02d}"
            reply = await http.post(f"{base}/api/v1/users/signup", json={"username": name, "password": PASSWORD})
            tokens.append(reply.json()["auth_token"])

    received: dict[int, list[tuple[int | None, str | None]]] = {i: [] for i in range(args.sockets)}
    ready = 0

    async def listen(i: int, token: str) -> None:
        nonlocal ready
        async with websockets.connect(f"{ws_base}/ws?protocol=1&auth_token={token}", max_size=2**22) as socket:
            await socket.send(json.dumps({"type": "command", "version": 1, "id": f"sub{i}", "name": "channel.subscribe", "data": {"channel_id": channel}}))
            subscribed = False
            deadline = time.monotonic() + 40
            while time.monotonic() < deadline:
                try:
                    raw = await asyncio.wait_for(socket.recv(), timeout=1.0)
                except asyncio.TimeoutError:
                    continue
                frame = json.loads(raw)
                if frame.get("id") == f"sub{i}" and not subscribed:
                    subscribed = True
                    ready += 1
                if frame.get("type") == "event" and frame.get("name") == "message.created":
                    received[i].append((frame.get("seq"), frame.get("epoch")))

    async def guarded(i: int, token: str) -> None:
        try:
            await listen(i, token)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # a socket that could not even join is a result, not a crash
            print(f"  socket {i:02d} failed: {type(exc).__name__}: {str(exc)[:120]}")

    tasks = [asyncio.create_task(guarded(i, t)) for i, t in enumerate(tokens)]
    for _ in range(100):
        if ready >= args.sockets:
            break
        await asyncio.sleep(0.2)
    print(f"{ready}/{args.sockets} sockets subscribed")

    for n in range(args.messages):
        # A fresh connection each time, so different messages are handled by different workers.
        async with httpx.AsyncClient(timeout=30, headers={"Connection": "close"}) as http:
            await http.post(f"{base}/api/v1/channels/{channel}/send_message", data={"auth_token": owner, "message": f"rt check {n}"})
        await asyncio.sleep(0.3)
    await asyncio.sleep(4)
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)

    full = sum(1 for got in received.values() if len(got) >= args.messages)
    anyone = sum(1 for got in received.values() if got)
    print(f"{full}/{args.sockets} sockets got all {args.messages} messages ({anyone} got at least one)")
    if args.verbose:
        for i, got in received.items():
            print(f"  socket {i:02d}: {len(got):2d} messages, seq {sorted(s for s, _ in got if s is not None)}")
    epochs = {e for got in received.values() for _, e in got}
    seqs = sorted({s for got in received.values() for s, _ in got if s is not None})
    print(f"epochs seen: {len(epochs)}; sequence numbers seen: {seqs}")
    return 0 if full == args.sockets else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
