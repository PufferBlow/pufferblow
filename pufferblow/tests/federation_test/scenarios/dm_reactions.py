"""DM reactions — add/remove, federated both directions via Like/Undo(Like).

bob reacting to alice's message is the straightforward case (the message
is addressable via alice's deterministic object id). There's no inbound
case covered for alice reacting to something BOB sent her, by design —
see `ActivityPubManager._federate_dm_reaction`'s docstring: reacting to a
message the PEER authored can't federate back through this mechanism yet
(same remote-object-id limitation `_handle_like` documents).
"""

from __future__ import annotations

import httpx

from common import Reporter
from topology import ALICE, BOB


def run(reporter: Reporter) -> None:
    reporter.section("DM reactions (bob reacts to alice's message, alice@A <-> bob@B)")

    send_resp = httpx.post(
        f"{ALICE.base_url}/api/v1/dms/send",
        json={"auth_token": ALICE.auth_token, "peer": BOB.handle, "message": "react to this"},
        timeout=15.0,
    )
    reporter.check("alice sends a message to react to", send_resp.status_code == 201, send_resp.text)
    message_id_on_alice = send_resp.json().get("result", {}).get("message_id", "")

    bob_messages = httpx.get(
        f"{BOB.base_url}/api/v1/dms/messages", params={"auth_token": BOB.auth_token, "peer": ALICE.handle}, timeout=10.0
    ).json()
    target_on_bob = next((m for m in bob_messages.get("messages", []) if m.get("message") == "react to this"), None)
    reporter.check("bob received the message to react to", target_on_bob is not None, str(bob_messages))
    message_id_on_bob = target_on_bob.get("message_id") if target_on_bob else ""

    add_resp = httpx.post(
        f"{BOB.base_url}/api/v1/dms/messages/{message_id_on_bob}/reactions",
        json={"auth_token": BOB.auth_token, "emoji": "\U0001F44D"},
        timeout=15.0,
    )
    reporter.check("bob adds a reaction to alice's message", add_resp.status_code == 201, add_resp.text)

    # alice's copy is the one with the deterministic object id bob's Like
    # activity referenced, so her OWN message_id (not bob's local row id)
    # is what the federated Like landed against.
    alice_reaction_check = httpx.get(
        f"{ALICE.base_url}/api/v1/dms/messages", params={"auth_token": ALICE.auth_token, "peer": BOB.handle}, timeout=10.0
    ).json()
    target_on_alice = next(
        (m for m in alice_reaction_check.get("messages", []) if m.get("message_id") == message_id_on_alice), None
    )
    reactions = (target_on_alice or {}).get("reactions", [])
    reporter.check(
        "the Like federated to alice and is visible on her copy",
        any(r.get("emoji") == "\U0001F44D" for r in reactions),
        str(reactions),
    )

    remove_resp = httpx.request(
        "DELETE",
        f"{BOB.base_url}/api/v1/dms/messages/{message_id_on_bob}/reactions",
        params={"auth_token": BOB.auth_token, "emoji": "\U0001F44D"},
        timeout=15.0,
    )
    reporter.check("bob removes the reaction", remove_resp.status_code == 200, remove_resp.text)

    httpx.request(
        "DELETE",
        f"{ALICE.base_url}/api/v1/dms/messages/{message_id_on_alice}",
        params={"auth_token": ALICE.auth_token},
        timeout=15.0,
    )
