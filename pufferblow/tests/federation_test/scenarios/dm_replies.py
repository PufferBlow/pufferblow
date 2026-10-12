"""DM reply threading, federated both directions.

Covers the trickier half too: bob replying to alice's message needs
`inReplyTo` to resolve against alice's *deterministic* object id, and
alice's `_handle_create` needs to resolve bob's inbound `inReplyTo` back to
the local row it stored for her own original message
(`_local_message_from_object_uri`) — not just the simpler case of a reply
staying on the same side that started the thread.
"""

from __future__ import annotations

import httpx

from common import Reporter
from topology import ALICE, BOB


def run(reporter: Reporter) -> None:
    reporter.section("DM reply threading (alice@A <-> bob@B)")

    root_resp = httpx.post(
        f"{ALICE.base_url}/api/v1/dms/send",
        json={"auth_token": ALICE.auth_token, "peer": BOB.handle, "message": "root message"},
        timeout=15.0,
    )
    reporter.check("alice sends the root message", root_resp.status_code == 201, root_resp.text)
    root_id = root_resp.json().get("result", {}).get("message_id", "")

    bob_messages = httpx.get(
        f"{BOB.base_url}/api/v1/dms/messages", params={"auth_token": BOB.auth_token, "peer": ALICE.handle}, timeout=10.0
    ).json()
    root_on_bob = next((m for m in bob_messages.get("messages", []) if m.get("message") == "root message"), None)
    reporter.check("bob received the root message", root_on_bob is not None, str(bob_messages))

    reply_resp = httpx.post(
        f"{BOB.base_url}/api/v1/dms/send",
        json={
            "auth_token": BOB.auth_token,
            "peer": ALICE.handle,
            "message": "replying to your root message",
            "reply_to_message_id": root_on_bob.get("message_id") if root_on_bob else "",
        },
        timeout=15.0,
    )
    reporter.check("bob replies to alice's root message", reply_resp.status_code == 201, reply_resp.text)

    alice_messages = httpx.get(
        f"{ALICE.base_url}/api/v1/dms/messages", params={"auth_token": ALICE.auth_token, "peer": BOB.handle}, timeout=10.0
    ).json()
    reply_on_alice = next(
        (m for m in alice_messages.get("messages", []) if m.get("message") == "replying to your root message"), None
    )
    reporter.check("alice received bob's reply", reply_on_alice is not None, str(alice_messages))
    if reply_on_alice is not None:
        reporter.check(
            "alice's copy of bob's reply resolves reply_to_message_id back to HER OWN root message id",
            reply_on_alice.get("reply_to_message_id") == root_id,
            str(reply_on_alice),
        )

    for message_id in (root_id,):
        httpx.request(
            "DELETE", f"{ALICE.base_url}/api/v1/dms/messages/{message_id}", params={"auth_token": ALICE.auth_token}, timeout=15.0
        )
