#!/usr/bin/env python
"""Fill the simulation instances with people and watch what happens.

    python docker/sim/simulate.py --users 50 --own 127.0.0.1:7575

Per instance it makes `--users` people (`sim_<n>_<NN>`). They join other instances with the account they have (the
real join flow: a signed assertion from their home, an invitation code where one is needed, a request where one is
asked), post in the channels, make friends, send direct messages (to people on their own instance and on others) and
ring each other. With `--own` they also join an instance of yours (for example your own on 7575) and post there.

Nothing is faked: a thing that fails is counted and its error kept, and the report at the end says what worked and what
did not. The run is repeatable (`--seed`). Needs `httpx` (it is in Pufferblow's own environment).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field

import httpx

PASSWORD = "simpass123"
HOSTS = {"pb1": "host.docker.internal:7576", "pb2": "host.docker.internal:7577", "pb3": "host.docker.internal:7578"}
SENTENCES = [
    "anyone up for a game tonight?",
    "just pushed the fix, can someone look?",
    "the new build feels so much faster",
    "lunch? the noodle place is open",
    "I can't believe it's already friday",
    "who has the link to the notes from last week",
    "the fish in the header is my favourite thing here",
    "reminder: standup in ten minutes",
    "this channel is so quiet today",
    "found a great article about distributed systems",
    "can we move the meeting to tomorrow?",
    "that was a long one, but we got there",
]


@dataclass
class Person:
    home: str
    name: str
    token: str = ""
    user_id: str = ""
    #: host -> token for the instances they joined with this account.
    sessions: dict[str, str] = field(default_factory=dict)

    @property
    def handle(self) -> str:
        return f"{self.name}@{HOSTS[self.home]}"


class Report:
    def __init__(self) -> None:
        self.ok: Counter[str] = Counter()
        self.failed: Counter[str] = Counter()
        self.samples: dict[str, list[str]] = defaultdict(list)
        self.notes: list[str] = []

    def good(self, what: str) -> None:
        self.ok[what] += 1

    def bad(self, what: str, why: str) -> None:
        self.failed[what] += 1
        if len(self.samples[what]) < 3:
            self.samples[what].append(why[:240])

    def show(self) -> str:
        lines = [f"{'operation':<46}{'ok':>7}{'failed':>8}"]
        for what in sorted(set(self.ok) | set(self.failed)):
            lines.append(f"{what:<46}{self.ok[what]:>7}{self.failed[what]:>8}")
        for what, sample in self.samples.items():
            lines.append(f"\n  {what}:")
            lines.extend(f"    - {s}" for s in sample)
        lines.extend(["", *self.notes])
        return "\n".join(lines)


class Net:
    """HTTP to every instance, paced per instance so the server's own rate limit is not what is being measured."""

    def __init__(self, per_second: float = 14.0) -> None:
        self.client = httpx.AsyncClient(timeout=30.0)
        self.gap = 1.0 / per_second
        self.next_at: dict[str, float] = defaultdict(float)
        self.lock = asyncio.Lock()

    async def call(self, host: str, method: str, path: str, **kwargs) -> httpx.Response:
        async with self.lock:
            now = time.monotonic()
            at = max(now, self.next_at[host])
            self.next_at[host] = at + self.gap
        if at > now:
            await asyncio.sleep(at - now)
        return await self.client.request(method, f"http://{host}{path}", **kwargs)


def reason(response: httpx.Response) -> str:
    try:
        body = response.json()
        return f"{response.status_code} {body.get('error_code') or ''} {body.get('user_message') or body.get('message') or body.get('detail') or ''}".strip()
    except Exception:
        return f"{response.status_code} {response.text[:120]}"


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--users", type=int, default=50, help="people per instance")
    parser.add_argument("--own", default="", help="an extra instance (host:port) every simulated person also joins, e.g. 127.0.0.1:7575")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--messages", type=int, default=6, help="channel messages per person per instance they are in")
    parser.add_argument("--out", default="sim-report.json")
    args = parser.parse_args()
    rng = random.Random(args.seed)
    net, report = Net(), Report()
    own = args.own.strip()

    # ── the instances are up, and the owners can sign in ──
    owners: dict[str, str] = {}
    for key, host in HOSTS.items():
        for _ in range(60):
            try:
                if (await net.call(host, "GET", "/healthz")).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            await asyncio.sleep(2)
        else:
            print(f"{key} ({host}) did not come up", file=sys.stderr)
            return 1
        response = await net.call(host, "POST", "/api/v1/users/signin", json={"username": "owner", "password": PASSWORD})
        owners[key] = response.json()["auth_token"]
        print(f"{key}: up, join mode {(await net.call(host, 'GET', '/api/v1/system/server-info')).json()['server_info']['join_mode']}")

    channels: dict[str, dict[str, str]] = {}

    async def channel_ids(host: str, token: str) -> dict[str, str]:
        response = await net.call(host, "POST", "/api/v1/channels/list/", json={"auth_token": token})
        return {c["channel_name"]: c["channel_id"] for c in response.json().get("channels", []) if c["channel_type"] == "text"}

    # ── invitation codes for the invite-only instance (enough for everyone who will use one) ──
    codes: list[str] = []
    for _ in range(max(2, (args.users * 3) // 20 + 1)):
        response = await net.call(HOSTS["pb2"], "POST", "/api/v1/server/invites", json={"auth_token": owners["pb2"], "note": "simulation", "max_uses": 20})
        codes.append(response.json()["invite"]["code"])
    report.notes.append(f"pb2: made {len(codes)} invitation codes of 20 uses")

    def code_for(index: int) -> str:
        return codes[(index // 20) % len(codes)]

    # ── people ──
    people: dict[str, list[Person]] = {key: [] for key in HOSTS}
    pending_local: list[tuple[str, Person]] = []

    async def make(key: str, index: int) -> None:
        person = Person(home=key, name=f"sim_{key[-1]}_{index:02d}")
        body = {"username": person.name, "password": PASSWORD}
        if key == "pb2":
            body["invite_code"] = code_for(index)
        if key == "pb3":
            body["message"] = f"simulated person {index}"
        response = await net.call(HOSTS[key], "POST", "/api/v1/users/signup", json=body)
        if response.status_code == 201:
            person.token = response.json()["auth_token"]
            people[key].append(person)
            report.good(f"{key}: sign up")
        elif response.status_code == 202:
            pending_local.append((key, person))
            report.good(f"{key}: sign up (waits for approval)")
        else:
            report.bad(f"{key}: sign up", reason(response))

    await asyncio.gather(*[make(key, i) for key in HOSTS for i in range(args.users)])

    # pb3 asks its moderators: approve most local requests, leave a few waiting for a person to try in the screens.
    waiting = await net.call(HOSTS["pb3"], "GET", "/api/v1/server/join-requests", params={"auth_token": owners["pb3"], "status": "pending"})
    requests = waiting.json().get("requests", [])
    keep_waiting = {r["request_id"] for r in requests[-5:]}
    for request in requests:
        if request["request_id"] in keep_waiting:
            continue
        response = await net.call(HOSTS["pb3"], "POST", f"/api/v1/server/join-requests/{request['request_id']}/approve", json={"auth_token": owners["pb3"]})
        report.good("pb3: approve a local request") if response.status_code == 200 else report.bad("pb3: approve a local request", reason(response))
    for key, person in pending_local:
        response = await net.call(HOSTS[key], "POST", "/api/v1/users/signin", json={"username": person.name, "password": PASSWORD})
        if response.status_code == 200:
            person.token = response.json()["auth_token"]
            people[key].append(person)
            report.good("pb3: sign in once approved")
        elif "membership_pending" in response.text:
            report.good("pb3: still waiting (left for the screens)")
        else:
            report.bad("pb3: sign in once approved", reason(response))

    for key in HOSTS:
        for person in people[key]:
            response = await net.call(HOSTS[key], "POST", "/api/v1/users/profile", json={"auth_token": person.token})
            if response.status_code == 200:
                person.user_id = response.json()["user_data"]["user_id"]
        channels[key] = await channel_ids(HOSTS[key], owners[key])

    # ── joining other instances with the account they have ──
    async def join(person: Person, target_key: str | None, target_host: str, index: int) -> None:
        label = f"join {target_key or 'own'}"
        response = await net.call(HOSTS[person.home], "POST", "/api/v1/federation/assertions", json={"auth_token": person.token, "audience": target_host})
        if response.status_code != 200:
            report.bad(f"{label}: assertion from home", reason(response))
            return
        body = {"assertion": response.json()["assertion"]}
        if target_key == "pb2":
            body["invite_code"] = code_for(index)
        if target_key == "pb3":
            body["message"] = f"{person.name} from {person.home}"
        joined = await net.call(target_host, "POST", "/api/v1/federation/join", json=body)
        if joined.status_code == 200:
            person.sessions[target_host] = joined.json()["auth_token"]
            report.good(f"{label}: joined")
        elif joined.status_code == 202:
            report.good(f"{label}: request waiting")
        else:
            report.bad(f"{label}: join", reason(joined))

    jobs = []
    for key in HOSTS:
        for index, person in enumerate(people[key]):
            others = [k for k in HOSTS if k != key]
            for target_key in rng.sample(others, rng.choice([1, 2])):
                jobs.append(join(person, target_key, HOSTS[target_key], index))
            if own:
                jobs.append(join(person, None, own, index))
    await asyncio.gather(*jobs)

    # pb3: approve most requests from other instances' people, leave a few, then everyone asks again.
    waiting = await net.call(HOSTS["pb3"], "GET", "/api/v1/server/join-requests", params={"auth_token": owners["pb3"], "status": "pending"})
    requests = [r for r in waiting.json().get("requests", []) if r["kind"] == "federated"]
    keep_waiting = {r["request_id"] for r in requests[-5:]}
    for request in requests:
        if request["request_id"] not in keep_waiting:
            response = await net.call(HOSTS["pb3"], "POST", f"/api/v1/server/join-requests/{request['request_id']}/approve", json={"auth_token": owners["pb3"]})
            report.good("pb3: approve a request from elsewhere") if response.status_code == 200 else report.bad("pb3: approve a request from elsewhere", reason(response))

    async def ask_again(person: Person) -> None:
        host = HOSTS["pb3"]
        if host in person.sessions:
            return
        response = await net.call(HOSTS[person.home], "POST", "/api/v1/federation/assertions", json={"auth_token": person.token, "audience": host})
        if response.status_code != 200:
            return
        status = await net.call(host, "POST", "/api/v1/federation/join/status", json={"assertion": response.json()["assertion"]})
        if status.status_code == 200 and status.json().get("status") == "joined":
            person.sessions[host] = status.json()["auth_token"]
            report.good("pb3: asked again, now in")
        elif status.status_code == 202:
            report.good("pb3: asked again, still waiting")
        elif status.status_code == 200 and status.json().get("status") == "none":
            pass  # never asked pb3
        else:
            report.bad("pb3: asked again", reason(status))

    await asyncio.gather(*[ask_again(p) for key in HOSTS for p in people[key]])

    # ── talking ──
    async def post(host: str, token: str, channel_id: str, text: str, label: str) -> None:
        response = await net.call(host, "POST", f"/api/v1/channels/{channel_id}/send_message", data={"auth_token": token, "message": text})
        report.good(label) if response.status_code in (200, 201) else report.bad(label, reason(response))

    async def talk(person: Person) -> None:
        places = [(HOSTS[person.home], person.token, "home")] + [(host, token, "visited") for host, token in person.sessions.items()]
        for host, token, kind in places:
            key = next((k for k, v in HOSTS.items() if v == host), "own")
            ids = channels.get(key) or await channel_ids(host, token)
            channels.setdefault(key, ids)
            usable = [cid for name, cid in ids.items() if name != "staff"]
            if not usable:
                report.bad(f"post: no channels on {key}", "empty channel list")
                continue
            for _ in range(rng.randint(2, args.messages)):
                text = rng.choice(SENTENCES)
                if rng.random() < 0.15:
                    text = f"@owner {text}"
                await post(host, token, rng.choice(usable), text, f"post on {key} ({kind})")

    await asyncio.gather(*[talk(p) for key in HOSTS for p in people[key]])

    # ── friends ──
    async def befriend(a: Person, b: Person) -> None:
        sent = await net.call(HOSTS[a.home], "POST", "/api/v1/friends/requests", params={"auth_token": a.token}, json={"target_username": b.name, "target_origin_server": ""})
        if sent.status_code not in (200, 201):
            report.bad("friends: request", reason(sent))
            return
        report.good("friends: request")
        incoming = await net.call(HOSTS[b.home], "GET", "/api/v1/friends/requests", params={"auth_token": b.token})
        match = next((r for r in incoming.json().get("incoming", []) if r.get("other_username") == a.name or r.get("username") == a.name), None)
        if match is None:
            report.bad("friends: request arrived", f"{b.name} did not see a request from {a.name}")
            return
        accepted = await net.call(HOSTS[b.home], "POST", f"/api/v1/friends/requests/{match['friendship_id']}/accept", params={"auth_token": b.token})
        report.good("friends: accept") if accepted.status_code == 200 else report.bad("friends: accept", reason(accepted))

    pairs = []
    for key in HOSTS:
        group = people[key][:]
        rng.shuffle(group)
        pairs += [(group[i], group[i + 1]) for i in range(0, min(len(group) - 1, 30), 2)]
    await asyncio.gather(*[befriend(a, b) for a, b in pairs])

    # ── direct messages: on one instance, and from one instance to another ──
    async def dm(sender: Person, peer: str, label: str, receiver: Person | None) -> None:
        text = f"dm {rng.randint(1000, 9999)}: {rng.choice(SENTENCES)}"
        response = await net.call(HOSTS[sender.home], "POST", "/api/v1/dms/send", json={"auth_token": sender.token, "peer": peer, "message": text, "attachments": []})
        if response.status_code not in (200, 201):
            report.bad(f"dm {label}: send", reason(response))
            return
        report.good(f"dm {label}: send")
        if receiver is None:
            return
        for _ in range(8):  # remote delivery is a signed post to the other instance: give it a moment
            seen = await net.call(HOSTS[receiver.home], "GET", "/api/v1/dms/messages", params={"auth_token": receiver.token, "peer": sender.handle if sender.home != receiver.home else sender.name, "page": 1, "messages_per_page": 20})
            if seen.status_code == 200 and text in seen.text:
                report.good(f"dm {label}: arrived")
                return
            await asyncio.sleep(1)
        report.bad(f"dm {label}: arrived", f"{receiver.name} never saw the message from {sender.name}")

    dm_jobs = []
    for key in HOSTS:
        group = people[key]
        for a, b in zip(group[0:20:2], group[1:20:2]):
            dm_jobs.append(dm(a, b.name, "same instance", b))
        for other in [k for k in HOSTS if k != key]:
            for a, b in zip(group[20:30], people[other][20:30]):
                dm_jobs.append(dm(a, b.handle, f"{key} to {other}", b))
    await asyncio.gather(*dm_jobs)

    # ── calls (the control side: ringing, answering, ending; real audio needs a browser, see the e2e harness) ──
    async def call(a: Person, b: Person) -> None:
        host = HOSTS[a.home]
        rung = await net.call(host, "POST", f"/api/v1/dm-calls/{b.user_id}/invite", json={"auth_token": a.token, "callee_id": b.user_id})
        if rung.status_code not in (200, 201):
            report.bad("call: ring", reason(rung))
            return
        call_id = rung.json()["call_id"]
        report.good("call: ring")
        accepted = await net.call(host, "POST", f"/api/v1/dm-calls/{call_id}/accept", json={"auth_token": b.token})
        if accepted.status_code != 200:
            report.bad("call: answer", reason(accepted))
            return
        report.good("call: answer")
        signalled = await net.call(host, "POST", f"/api/v1/dm-calls/{call_id}/signal", json={"auth_token": a.token, "signal_type": "offer", "payload": {"sdp": "v=0"}})
        report.good("call: signal") if signalled.status_code == 200 else report.bad("call: signal", reason(signalled))
        ended = await net.call(host, "POST", f"/api/v1/dm-calls/{call_id}/end", json={"auth_token": a.token})
        report.good("call: end") if ended.status_code == 200 else report.bad("call: end", reason(ended))

    await asyncio.gather(*[call(a, b) for key in HOSTS for a, b in zip(people[key][30:42:2], people[key][31:42:2])])
    report.notes.append("calls between people on different instances are not built yet, so none were tried; real audio is covered by client/e2e/voice")

    # ── what each instance looks like now ──
    for key, host in HOSTS.items():
        info = (await net.call(host, "GET", "/api/v1/system/server-info")).json()["server_info"]
        pending = (await net.call(host, "GET", "/api/v1/server/join-requests", params={"auth_token": owners[key], "status": "pending"})).json().get("pending")
        report.notes.append(f"{key} ({info['server_name']}, {info['join_mode']}): {info['members_count']} members, {pending} requests still waiting")
    if own:
        info = (await net.call(own, "GET", "/api/v1/system/server-info")).json()["server_info"]
        report.notes.append(f"{own} ({info['server_name']}): {info['members_count']} members now")

    print("\n" + report.show())
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump({"ok": report.ok, "failed": report.failed, "samples": report.samples, "notes": report.notes}, handle, indent=2)
    await net.client.aclose()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
