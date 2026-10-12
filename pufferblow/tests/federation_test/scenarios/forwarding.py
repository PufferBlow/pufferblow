"""Forwarding — DM-to-DM, and channel-to-DM.

DM-to-DM: alice sends bob a message; bob forwards HIS copy of it (a
different local row, different object id than alice's) on to carol, who is
on a third relationship entirely (same instance as alice, different from
both alice and bob). Exercises `ActivityPubManager.forward_message`'s
DM-participation authorization check.

Channel-to-DM: the admin account (seeded by bootstrap_instance.py, since
public signup never grants `create_channels`) has a seed message sitting
in a public channel; alice forwards it into her DM with bob. Exercises the
route's channel-access authorization branch instead of the DM one.
"""

from __future__ import annotations

import httpx

from common import Reporter
from topology import ADMIN_A, ALICE, BOB, CAROL


def _dm_to_dm(reporter: Reporter) -> None:
    reporter.section("Forwarding: DM-to-DM (alice -> bob, then bob forwards to carol)")

    send_resp = httpx.post(
        f"{ALICE.base_url}/api/v1/dms/send",
        json={"auth_token": ALICE.auth_token, "peer": BOB.handle, "message": "forward me please"},
        timeout=15.0,
    )
    reporter.check("alice sends the message to be forwarded", send_resp.status_code == 201, send_resp.text)
    message_id_on_alice = send_resp.json().get("result", {}).get("message_id", "")

    bob_messages = httpx.get(
        f"{BOB.base_url}/api/v1/dms/messages", params={"auth_token": BOB.auth_token, "peer": ALICE.handle}, timeout=10.0
    ).json()
    target_on_bob = next((m for m in bob_messages.get("messages", []) if m.get("message") == "forward me please"), None)
    reporter.check("bob received the message", target_on_bob is not None, str(bob_messages))
    message_id_on_bob = target_on_bob.get("message_id") if target_on_bob else ""

    forward_resp = httpx.post(
        f"{BOB.base_url}/api/v1/messages/{message_id_on_bob}/forward",
        json={"auth_token": BOB.auth_token, "peer": CAROL.handle},
        timeout=15.0,
    )
    reporter.check("bob forwards alice's message on to carol", forward_resp.status_code == 201, forward_resp.text)

    carol_messages = httpx.get(
        f"{CAROL.base_url}/api/v1/dms/messages", params={"auth_token": CAROL.auth_token, "peer": BOB.handle}, timeout=10.0
    ).json()
    forwarded_on_carol = next(
        (m for m in carol_messages.get("messages", []) if m.get("message") == "forward me please"), None
    )
    reporter.check("carol received the forwarded message content", forwarded_on_carol is not None, str(carol_messages))
    if forwarded_on_carol is not None:
        reporter.check(
            "carol's copy records forwarded_from_message_id",
            bool(forwarded_on_carol.get("forwarded_from_message_id")),
            str(forwarded_on_carol),
        )

    httpx.request(
        "DELETE", f"{ALICE.base_url}/api/v1/dms/messages/{message_id_on_alice}", params={"auth_token": ALICE.auth_token}, timeout=15.0
    )


def _channel_to_dm(reporter: Reporter) -> None:
    reporter.section("Forwarding: channel-to-DM (admin's seed message -> alice forwards to bob)")

    channels_resp = httpx.post(
        f"{ADMIN_A.base_url}/api/v1/channels/list/", json={"auth_token": ADMIN_A.auth_token}, timeout=10.0
    )
    reporter.check("admin can list channels", channels_resp.status_code == 200, channels_resp.text)
    channels = channels_resp.json().get("channels", [])
    seed_channel = next((c for c in channels if c.get("channel_name") == "general"), None)
    reporter.check("the seeded 'general' channel exists", seed_channel is not None, str(channels))
    if seed_channel is None:
        return
    channel_id = seed_channel.get("channel_id")

    load_resp = httpx.get(
        f"{ADMIN_A.base_url}/api/v1/channels/{channel_id}/load_messages",
        params={"auth_token": ADMIN_A.auth_token},
        timeout=10.0,
    )
    reporter.check("admin can load the seeded channel's messages", load_resp.status_code == 200, load_resp.text)
    channel_messages = load_resp.json().get("messages", [])
    seed_message = next(
        (m for m in channel_messages if "forwarded into a DM" in (m.get("message") or "")), None
    )
    reporter.check("the seed message is present in the channel", seed_message is not None, str(channel_messages))
    if seed_message is None:
        return
    seed_message_id = seed_message.get("message_id")

    # alice isn't the channel owner, but it's a public channel — forwarding
    # only needs read access, same as the channel routes already require.
    forward_resp = httpx.post(
        f"{ALICE.base_url}/api/v1/messages/{seed_message_id}/forward",
        json={"auth_token": ALICE.auth_token, "peer": BOB.handle},
        timeout=15.0,
    )
    reporter.check("alice forwards the channel message into her DM with bob", forward_resp.status_code == 201, forward_resp.text)

    bob_messages = httpx.get(
        f"{BOB.base_url}/api/v1/dms/messages", params={"auth_token": BOB.auth_token, "peer": ALICE.handle}, timeout=10.0
    ).json()
    forwarded_on_bob = next(
        (m for m in bob_messages.get("messages", []) if m.get("message") == seed_message.get("message")), None
    )
    reporter.check("bob received the forwarded channel message", forwarded_on_bob is not None, str(bob_messages))


def run(reporter: Reporter) -> None:
    _dm_to_dm(reporter)
    _channel_to_dm(reporter)
