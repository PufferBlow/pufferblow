"""Load the simulated server and watch how it answers while it is busy.

    python docker/sim/load.py --host host.docker.internal:7576 --workers 60 --seconds 20

Each worker repeats a mix of everyday requests (profile, channel list, message history, user list, sending a message)
as fast as the server answers. Beside them a probe asks `/healthz` every 200 ms: if the server is still answering the
probe quickly, a client would not be blacked out. Reports requests per second, how long requests took, and how long
the probe waited (the longest wait is how long the whole server was stuck).
"""

from __future__ import annotations

import argparse
import asyncio
import random
import statistics
import time

import httpx

PASSWORD = "simpass123"


def pct(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    values = sorted(values)
    return values[min(len(values) - 1, int(q * len(values)))]


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="host.docker.internal:7576")
    parser.add_argument("--workers", type=int, default=60)
    parser.add_argument("--seconds", type=int, default=20)
    args = parser.parse_args()
    base = f"http://{args.host}"

    limits = httpx.Limits(max_connections=args.workers + 10)
    async with httpx.AsyncClient(timeout=60.0, limits=limits) as client:
        signin = await client.get(f"{base}/api/v1/users/signin", params={"username": "owner", "password": PASSWORD})
        token = signin.json()["auth_token"]
        channels = (await client.post(f"{base}/api/v1/channels/list/", json={"auth_token": token})).json()["channels"]
        text = [c["channel_id"] for c in channels if c["channel_type"] == "text"]

        durations: dict[str, list[float]] = {}
        failures: dict[str, int] = {}
        stop = asyncio.Event()

        async def timed(label: str, request) -> None:
            started = time.perf_counter()
            try:
                response = await request
                ok = response.status_code < 500 and response.status_code != 429
            except httpx.HTTPError:
                ok = False
            durations.setdefault(label, []).append(time.perf_counter() - started)
            if not ok:
                failures[label] = failures.get(label, 0) + 1

        async def worker() -> None:
            while not stop.is_set():
                channel = random.choice(text)
                choice = random.random()
                if choice < 0.25:
                    await timed("profile", client.post(f"{base}/api/v1/users/profile", json={"auth_token": token}))
                elif choice < 0.45:
                    await timed("channel list", client.post(f"{base}/api/v1/channels/list/", json={"auth_token": token}))
                elif choice < 0.75:
                    await timed("history", client.get(f"{base}/api/v1/channels/{channel}/load_messages", params={"auth_token": token, "page": 1, "messages_per_page": 30}))
                elif choice < 0.85:
                    await timed("user list", client.get(f"{base}/api/v1/users/list", params={"auth_token": token}))
                else:
                    await timed("send", client.post(f"{base}/api/v1/channels/{channel}/send_message", data={"auth_token": token, "message": "load"}))

        probes: list[float] = []

        async def probe() -> None:
            while not stop.is_set():
                started = time.perf_counter()
                try:
                    await client.get(f"{base}/healthz", timeout=60.0)
                    probes.append(time.perf_counter() - started)
                except httpx.HTTPError:
                    probes.append(60.0)
                await asyncio.sleep(0.2)

        tasks = [asyncio.create_task(worker()) for _ in range(args.workers)] + [asyncio.create_task(probe())]
        started = time.perf_counter()
        await asyncio.sleep(args.seconds)
        stop.set()
        await asyncio.gather(*tasks, return_exceptions=True)
        elapsed = time.perf_counter() - started

    total = sum(len(v) for v in durations.values())
    print(f"{args.workers} workers for {elapsed:.0f}s: {total} requests, {total / elapsed:.0f}/s, {sum(failures.values())} failed")
    print(f"{'request':14} {'count':>6} {'median':>8} {'p95':>8} {'max':>8}  failed")
    for label, values in sorted(durations.items()):
        print(f"{label:14} {len(values):6} {statistics.median(values) * 1000:7.0f}ms {pct(values, 0.95) * 1000:7.0f}ms {max(values) * 1000:7.0f}ms  {failures.get(label, 0)}")
    print(f"health probe: {len(probes)} asks, median {statistics.median(probes) * 1000:.0f}ms, p95 {pct(probes, 0.95) * 1000:.0f}ms, longest wait {max(probes):.1f}s")


if __name__ == "__main__":
    asyncio.run(main())
