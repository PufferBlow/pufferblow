"""Removing someone must close their sockets on every worker, and a big message must not sit in the database in the clear.

    python docker/sim/removal_check.py --host host.docker.internal:7576
"""

from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import time
import uuid

import httpx
import websockets

PASSWORD = "simpass123"


def psql(sql: str) -> str:
    return subprocess.run(["docker", "exec", "pbsim-pb1-db-1", "psql", "-U", "pufferblow", "-d", "pufferblow", "-At", "-c", sql], capture_output=True, text=True).stdout.strip()


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="host.docker.internal:7576")
    args = parser.parse_args()
    base, ws_base = f"http://{args.host}", f"ws://{args.host}"
    failures = 0

    async with httpx.AsyncClient(timeout=30) as http:
        owner = (await http.get(f"{base}/api/v1/users/signin", params={"username": "owner", "password": PASSWORD})).json()["auth_token"]
        channels = (await http.post(f"{base}/api/v1/channels/list/", json={"auth_token": owner})).json()["channels"]
        channel = next(c["channel_id"] for c in channels if c["channel_type"] == "text" and c["channel_name"] == "general")
        name = f"gone_{uuid.uuid4().hex[:6]}"
        token = (await http.post(f"{base}/api/v1/users/signup", json={"username": name, "password": PASSWORD})).json()["auth_token"]
        user_id = (await http.post(f"{base}/api/v1/users/profile", json={"auth_token": token})).json()["user_data"]["user_id"]

        closed_at: dict[int, float] = {}
        events_after: dict[int, int] = {}
        opened = 0
        removed_at = 0.0

        async def listen(i: int) -> None:
            nonlocal opened
            try:
                async with websockets.connect(f"{ws_base}/ws?protocol=1&auth_token={token}") as socket:
                    await socket.send(json.dumps({"type": "command", "version": 1, "id": f"s{i}", "name": "channel.subscribe", "data": {"channel_id": channel}}))
                    opened += 1
                    while True:
                        frame = json.loads(await socket.recv())
                        if frame.get("type") == "event" and removed_at and frame.get("name") == "message.created":
                            events_after[i] = events_after.get(i, 0) + 1
            except websockets.ConnectionClosed:
                closed_at[i] = time.monotonic()
            except Exception:
                closed_at[i] = time.monotonic()

        tasks = []
        for i in range(10):
            tasks.append(asyncio.create_task(listen(i)))
            await asyncio.sleep(0.15)  # separate connections, so they land on different workers
        await asyncio.sleep(1.5)
        print(f"{opened}/10 sockets open for one person")

        removed_at = time.monotonic()
        kicked = await http.post(f"{base}/api/v1/server/members/{user_id}/kick", json={"auth_token": owner})
        await asyncio.sleep(2.5)
        # a message sent now must not reach any socket of the removed person
        await http.post(f"{base}/api/v1/channels/{channel}/send_message", data={"auth_token": owner, "message": "after the removal"})
        await asyncio.sleep(1.5)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

        slowest = max((t - removed_at for t in closed_at.values()), default=0)
        print(f"kick answered {kicked.status_code}; {len(closed_at)}/{opened} sockets were closed (the last {slowest:.2f}s after); {sum(events_after.values())} events reached them afterwards")
        failures += len(closed_at) < opened or bool(events_after)

        # a message too big for a notification: it must arrive, and the table must not hold its words
        marker = f"sealedcheck{uuid.uuid4().hex[:8]}"
        big = (marker + " ") * 1200
        async with websockets.connect(f"{ws_base}/ws?protocol=1&auth_token={owner}") as watcher:
            await watcher.send(json.dumps({"type": "command", "version": 1, "id": "w", "name": "channel.subscribe", "data": {"channel_id": channel}}))
            await asyncio.sleep(1.0)
            sent = await http.post(f"{base}/api/v1/channels/{channel}/send_message", data={"auth_token": owner, "message": big})
            got = False
            try:
                for _ in range(30):
                    frame = json.loads(await asyncio.wait_for(watcher.recv(), timeout=2))
                    if frame.get("name") == "message.created" and marker in json.dumps(frame):
                        got = True
                        break
            except asyncio.TimeoutError:
                pass
        in_table = psql(f"select count(*) from realtime_spool where frame::text like '%{marker}%'")
        rows = psql("select count(*) from realtime_spool")
        print(f"big message sent ({sent.status_code}, {len(big)} chars): received {'yes' if got else 'NO'}; rows of the spool holding its words in the clear: {in_table}; spool rows now: {rows}")
        failures += (not got) or in_table != "0"

    print("OK" if not failures else "PROBLEMS")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
