"""Basic DM send / edit / delete — both the federated path (alice@A -> bob@B)
and the local-delivery path (alice@A -> carol@A, same instance).
"""

from __future__ import annotations

import httpx

from common import Reporter
from topology import ALICE, BOB, CAROL


def _send(reporter: Reporter, sender, peer_handle: str, text: str, *, expect_remote: bool) -> str:
    resp = httpx.post(
        f"{sender.base_url}/api/v1/dms/send",
        json={"auth_token": sender.auth_token, "peer": peer_handle, "message": text},
        timeout=15.0,
    )
    reporter.check(f"{sender.username} sends a DM to {peer_handle}", resp.status_code == 201, resp.text)
    result = resp.json().get("result", {})
    key = "delivered_remote" if expect_remote else "delivered_local"
    reporter.check(f"DM delivery was {'remote' if expect_remote else 'local'}", result.get(key) is True, str(result))
    return result.get("message_id", "")


def run(reporter: Reporter) -> None:
    reporter.section("DM basics — federated (alice@A -> bob@B)")
    message_id = _send(reporter, ALICE, BOB.handle, "hello from alice", expect_remote=True)

    bob_messages = httpx.get(
        f"{BOB.base_url}/api/v1/dms/messages", params={"auth_token": BOB.auth_token, "peer": ALICE.handle}, timeout=10.0
    )
    reporter.check("bob can load the conversation", bob_messages.status_code == 200, bob_messages.text)
    contents = [m.get("message", "") for m in bob_messages.json().get("messages", [])]
    reporter.check("bob received alice's DM content", "hello from alice" in contents, str(contents))

    edit_resp = httpx.patch(
        f"{ALICE.base_url}/api/v1/dms/messages/{message_id}",
        json={"auth_token": ALICE.auth_token, "message": "hello from alice (edited)"},
        timeout=15.0,
    )
    reporter.check("alice edits her DM (federates an Update)", edit_resp.status_code == 200, edit_resp.text)

    delete_resp = httpx.request(
        "DELETE", f"{ALICE.base_url}/api/v1/dms/messages/{message_id}", params={"auth_token": ALICE.auth_token}, timeout=15.0
    )
    reporter.check("alice deletes her DM (federates a Delete)", delete_resp.status_code == 200, delete_resp.text)

    reporter.section("DM basics — local delivery (alice@A -> carol@A, same instance)")
    local_message_id = _send(reporter, ALICE, CAROL.handle, "hello carol, same instance", expect_remote=False)

    carol_messages = httpx.get(
        f"{CAROL.base_url}/api/v1/dms/messages",
        params={"auth_token": CAROL.auth_token, "peer": ALICE.handle},
        timeout=10.0,
    )
    reporter.check("carol can load the local conversation", carol_messages.status_code == 200, carol_messages.text)
    local_contents = [m.get("message", "") for m in carol_messages.json().get("messages", [])]
    reporter.check(
        "carol received alice's locally-delivered DM", "hello carol, same instance" in local_contents, str(local_contents)
    )

    delete_resp = httpx.request(
        "DELETE",
        f"{ALICE.base_url}/api/v1/dms/messages/{local_message_id}",
        params={"auth_token": ALICE.auth_token},
        timeout=15.0,
    )
    reporter.check("alice deletes the local DM to carol", delete_resp.status_code == 200, delete_resp.text)
