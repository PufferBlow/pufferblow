"""Channel voice (SFU) — join/leave, participant visibility, self-state actions.

Same-instance only: voice channels aren't federated (`docs/developer/
architecture.md`: "Voice is SFU-only" — and that's local-instance SFU
plumbing, not ActivityPub). Uses alice@A and carol@A, the harness's
same-instance pair, against a voice channel created by admin_a (public
signup never grants `create_channels`).

This only exercises the control-plane REST surface
(`/api/v2/voice/*`) — no real WebRTC/SFU connection is made, so it
doesn't touch `media-sfu` at all. That's the same boundary `media-sfu`'s
own `stress_test.go` harness draws (signaling path, not real RTP media).
"""

from __future__ import annotations

import httpx

from common import Reporter
from topology import ADMIN_A, ALICE, CAROL

_CHANNEL_NAME = "fed-voice-test"


def _get_or_create_voice_channel(reporter: Reporter) -> str:
    create_resp = httpx.post(
        f"{ADMIN_A.base_url}/api/v1/channels/create/",
        json={
            "auth_token": ADMIN_A.auth_token,
            "channel_name": _CHANNEL_NAME,
            "is_private": False,
            "channel_type": "voice",
        },
        timeout=15.0,
    )
    if create_resp.status_code == 409:
        # Already created by a previous run against instances that weren't
        # recreated — look it up instead of failing.
        list_resp = httpx.post(
            f"{ADMIN_A.base_url}/api/v1/channels/list/",
            json={"auth_token": ADMIN_A.auth_token},
            timeout=10.0,
        )
        reporter.check("admin can list channels to find the existing voice channel", list_resp.status_code == 200, list_resp.text)
        existing = next(
            (c for c in list_resp.json().get("channels", []) if c.get("channel_name") == _CHANNEL_NAME), None
        )
        reporter.check(f"voice channel '{_CHANNEL_NAME}' exists from a prior run", existing is not None, str(list_resp.text))
        return existing.get("channel_id") if existing else ""

    reporter.check("admin creates the voice channel", create_resp.status_code == 200, create_resp.text)
    return create_resp.json().get("channel_data", {}).get("channel_id", "")


def run(reporter: Reporter) -> None:
    reporter.section("Channel voice — join/leave, participants, self-state actions")

    channel_id = _get_or_create_voice_channel(reporter)
    if not channel_id:
        return

    alice_join = httpx.post(
        f"{ALICE.base_url}/api/v2/voice/channels/{channel_id}/sessions",
        json={"auth_token": ALICE.auth_token, "quality_profile": "balanced"},
        timeout=15.0,
    )
    reporter.check("alice joins the voice channel", alice_join.status_code == 200, alice_join.text)
    alice_payload = alice_join.json()
    session_id = alice_payload.get("session_id", "")
    reporter.check("alice's join returns a session_id", bool(session_id), str(alice_payload))
    reporter.check("alice's join returns ice_servers", len(alice_payload.get("ice_servers", [])) > 0, str(alice_payload))
    reporter.check("participant_count is 1 with only alice connected", alice_payload.get("participant_count") == 1, str(alice_payload))

    carol_join = httpx.post(
        f"{CAROL.base_url}/api/v2/voice/channels/{channel_id}/sessions",
        json={"auth_token": CAROL.auth_token, "quality_profile": "balanced"},
        timeout=15.0,
    )
    reporter.check("carol joins the same voice channel", carol_join.status_code == 200, carol_join.text)
    carol_payload = carol_join.json()
    reporter.check("carol joins the SAME session as alice", carol_payload.get("session_id") == session_id, str(carol_payload))
    reporter.check("participant_count is 2 once carol joins", carol_payload.get("participant_count") == 2, str(carol_payload))

    participants_resp = httpx.get(
        f"{ALICE.base_url}/api/v2/voice/channels/{channel_id}/participants",
        params={"auth_token": ALICE.auth_token},
        timeout=10.0,
    )
    reporter.check("participants can be read without joining again", participants_resp.status_code == 200, participants_resp.text)
    participants = participants_resp.json().get("participants", [])
    participant_user_ids = {p.get("user_id") for p in participants}
    reporter.check(
        "both alice and carol are listed as connected participants",
        {ALICE.user_id, CAROL.user_id} <= participant_user_ids,
        str(participants),
    )

    mute_resp = httpx.post(
        f"{ALICE.base_url}/api/v2/voice/sessions/{session_id}/actions",
        json={"auth_token": ALICE.auth_token, "action": "mute_self", "payload": {"value": True}},
        timeout=10.0,
    )
    reporter.check("alice mutes herself", mute_resp.status_code == 200, mute_resp.text)

    participants_after_mute = httpx.get(
        f"{CAROL.base_url}/api/v2/voice/channels/{channel_id}/participants",
        params={"auth_token": CAROL.auth_token},
        timeout=10.0,
    ).json().get("participants", [])
    alice_state = next((p for p in participants_after_mute if p.get("user_id") == ALICE.user_id), None)
    reporter.check("carol can see alice's mute state change", bool(alice_state and alice_state.get("is_muted") is True), str(participants_after_mute))

    carol_leave = httpx.post(
        f"{CAROL.base_url}/api/v2/voice/sessions/{session_id}/leave",
        json={"auth_token": CAROL.auth_token},
        timeout=10.0,
    )
    reporter.check("carol leaves the voice session", carol_leave.status_code == 200, carol_leave.text)
    reporter.check("participant_count drops to 1 after carol leaves", carol_leave.json().get("participant_count") == 1, carol_leave.text)
    reporter.check("session isn't ended while alice is still connected", carol_leave.json().get("session_ended") is False, carol_leave.text)

    alice_leave = httpx.post(
        f"{ALICE.base_url}/api/v2/voice/sessions/{session_id}/leave",
        json={"auth_token": ALICE.auth_token},
        timeout=10.0,
    )
    reporter.check("alice leaves the voice session", alice_leave.status_code == 200, alice_leave.text)
    reporter.check("the now-empty session is ended", alice_leave.json().get("session_ended") is True, alice_leave.text)
