"""Two protocol clients ("two browsers") against a running instance: send, edit, react, delete,
drop the network and resync, and a send whose ack is lost then retried with the same nonce.

Usage (from pufferblow/, with pypufferblow importable or checked out next to this repo):

    poetry run python scripts/manual_protocol_check.py [http://localhost:7575]

It signs up two throwaway accounts (``mc_a_*``, ``mc_b_*``) on the instance and deletes the
messages it posts in the first public text channel. The accounts stay; remove them if you care.
"""
import asyncio
import sys
import uuid
from pathlib import Path

import requests

_sibling = Path(__file__).resolve().parents[2] / "pypufferblow"
if _sibling.is_dir():
    sys.path.insert(0, str(_sibling))
from pypufferblow.protocol import ProtocolError, build_command  # noqa: E402
from pypufferblow.realtime import ProtocolClient  # noqa: E402

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://localhost:7575"
tag = uuid.uuid4().hex[:6]
results: list[tuple[str, bool, str]] = []


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""), flush=True)


def signup(name):
    r = requests.post(f"{BASE}/api/v1/users/signup", json={"username": name, "password": "manualcheck-pw1"})
    r.raise_for_status()
    return r.json()["auth_token"]


class Browser:
    def __init__(self, label, token):
        self.label, self.events, self.resyncs = label, [], []
        self.client = ProtocolClient(
            token, BASE, ping_interval=5, max_backoff=2,
            on_event=lambda e: self.events.append(e),
            on_resync=lambda ch, msgs: self.resyncs.append((ch, msgs)),
        )

    async def wait_for(self, name, pred=lambda e: True, timeout=8):
        end = asyncio.get_running_loop().time() + timeout
        while asyncio.get_running_loop().time() < end:
            for e in self.events:
                if e.name == name and pred(e):
                    return e
            await asyncio.sleep(0.05)
        return None

    async def drop(self):
        """Kill the TCP connection without a close handshake, as a lost network would."""
        sock = self.client._socket
        sock.transport.abort()

    async def wait_connected(self, timeout=15):
        end = asyncio.get_running_loop().time() + timeout
        while asyncio.get_running_loop().time() < end:
            if self.client.connected:
                return True
            await asyncio.sleep(0.1)
        return False


async def main():
    ta, tb = signup(f"mc_a_{tag}"), signup(f"mc_b_{tag}")
    r = requests.post(f"{BASE}/api/v1/channels/list/", json={"auth_token": ta})
    channels = [c for c in r.json()["channels"] if c.get("channel_type") == "text" and not c.get("is_private")]
    if not channels:
        print("no public text channel available:", r.text[:300])
        return
    ch = channels[0]["channel_id"]
    print("channel:", channels[0]["channel_name"], ch)

    a, b = Browser("A", ta), Browser("B", tb)
    await a.client.start()
    await b.client.start()
    check("both clients connect and get a hello", a.client.connected and b.client.connected)
    a.client.watch(ch)
    b.client.watch(ch)
    await a.client.resync(ch)
    await b.client.resync(ch)
    made: list[str] = []

    # send
    m = await a.client.create_message(ch, f"manual check {tag}: hello")
    made.append(m.id)
    ev = await b.wait_for("message.created", lambda e: e.data.get("id") == m.id)
    check("send: B receives A's message", ev is not None and ev.data["content"].endswith("hello"))
    own = await a.wait_for("message.created", lambda e: e.data.get("id") == m.id)
    check("send: A also gets its own event once", own is not None and sum(1 for e in a.events if e.name == "message.created" and e.data.get("id") == m.id) == 1)
    check("send: events carry a sequence", ev is not None and isinstance(ev.seq, int) and ev.channel_id == ch, f"seq={getattr(ev, 'seq', None)}")

    # edit
    await a.client.edit_message(ch, m.id, f"manual check {tag}: edited")
    ev = await b.wait_for("message.updated", lambda e: e.data.get("id") == m.id)
    check("edit: B sees the new text", ev is not None and ev.data["content"].endswith("edited"))

    # someone else cannot edit or delete
    try:
        await b.client.edit_message(ch, m.id, "hijack")
        check("edit: B may not edit A's message", False)
    except ProtocolError as e:
        check("edit: B may not edit A's message", True, e.code)
    try:
        await b.client.delete_message(ch, m.id)
        check("delete: B (no moderation) may not delete A's message", False)
    except ProtocolError as e:
        check("delete: B (no moderation) may not delete A's message", True, e.code)

    # react
    await b.client.add_reaction(ch, m.id, "🎉")
    ev = await a.wait_for("reaction.added", lambda e: e.data.get("message_id") == m.id)
    check("react: A sees B's reaction", ev is not None and ev.data["emoji"] == "🎉")
    await b.client.remove_reaction(ch, m.id, "🎉")
    ev = await a.wait_for("reaction.removed", lambda e: e.data.get("message_id") == m.id)
    check("react: A sees it removed", ev is not None)

    # delete
    await a.client.delete_message(ch, m.id)
    ev = await b.wait_for("message.deleted", lambda e: e.data.get("id") == m.id)
    check("delete: B sees the message disappear", ev is not None)

    # drop the network on B while A keeps talking
    b.resyncs.clear()
    await b.drop()
    await asyncio.sleep(0.3)
    check("drop: B notices it is disconnected", not b.client.connected)
    missed = []
    for i in range(2):
        mm = await a.client.create_message(ch, f"manual check {tag}: while B was offline {i}")
        missed.append(mm.id)
        made.append(mm.id)
    check("drop: B reconnects by itself", await b.wait_connected())
    await asyncio.sleep(2)
    seen_in_resync = {x.id for _, msgs in b.resyncs for x in msgs}
    seen_live = {e.data.get("id") for e in b.events if e.name == "message.created"}
    check("drop: B resyncs and sees the messages it missed", all(i in seen_in_resync or i in seen_live for i in missed),
          f"resyncs={len(b.resyncs)} missed_in_resync={sum(i in seen_in_resync for i in missed)}/2")

    # events keep flowing after the reconnect
    m2 = await a.client.create_message(ch, f"manual check {tag}: after reconnect")
    made.append(m2.id)
    check("drop: live events resume after the reconnect", await b.wait_for("message.created", lambda e: e.data.get("id") == m2.id) is not None)

    # a send whose ack is lost, then retried with the same nonce
    nonce = uuid.uuid4().hex
    frame = build_command("cmd_lost", "message.create", {"channel_id": ch, "content": f"manual check {tag}: lost ack", "nonce": nonce})
    await a.client._socket.send(frame)
    await a.drop()
    check("retry: A reconnects after losing the ack", await a.wait_connected())
    retried = await a.client.create_message(ch, f"manual check {tag}: lost ack", nonce=nonce)
    made.append(retried.id)
    await asyncio.sleep(1)
    page = await a.client.resync(ch, limit=50)
    copies = [x for x in page if x.content.endswith("lost ack")]
    check("retry: same nonce yields one message, not two", len(copies) == 1, f"copies={len(copies)}")

    # cleanup our messages (A owns them all)
    for mid in made + [x for x in [retried.id] if x not in made]:
        try:
            await a.client.delete_message(ch, mid)
        except Exception:
            pass
    await a.client.close()
    await b.client.close()

    print()
    failed = [r for r in results if not r[1]]
    print(f"{len(results) - len(failed)}/{len(results)} checks passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    asyncio.run(main())
