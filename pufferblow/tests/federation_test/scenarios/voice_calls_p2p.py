"""1:1 DM voice calls — invite/accept/reject/signal-relay/end, and the SFU
fallback path.

Same-instance only, deliberately: `DmCallManager` signals over the global
WebSocket stream between two users of the SAME Pufferblow instance — there
is no federation story for DM calls (see `docs/developer/architecture.md`,
"DM voice calls"). Uses alice@A and carol@A, the harness's same-instance
pair.

This exercises the REST control surface only (`/api/v1/dm-calls/*`). The
actual signaling relay happens over a WebSocket this harness doesn't open a
client for, so "the invite was relayed" isn't independently verified here
the way message *content* is for DMs elsewhere in this suite — only that
the control plane accepted/transitioned the call state correctly. A real
WS listener would be needed to assert delivery, which is out of scope for
this harness (see `common.py`'s own "pure HTTP-client helpers" framing).
"""

from __future__ import annotations

import httpx

from common import Reporter
from topology import ALICE, CAROL


def _invite(reporter: Reporter, caller, callee, *, label: str) -> dict:
    resp = httpx.post(
        f"{caller.base_url}/api/v1/dm-calls/{callee.user_id}/invite",
        json={"auth_token": caller.auth_token},
        timeout=10.0,
    )
    reporter.check(label, resp.status_code == 200, resp.text)
    return resp.json()


def _basic_call_flow(reporter: Reporter) -> None:
    reporter.section("DM calls — invite/accept/signal/end (alice@A <-> carol@A)")

    call = _invite(reporter, ALICE, CAROL, label="alice invites carol to a call")
    call_id = call.get("call_id", "")
    reporter.check("invite returns a call_id", bool(call_id), str(call))
    reporter.check("invite starts in 'ringing' status", call.get("status") == "ringing", str(call))

    bad_accept = httpx.post(
        f"{ALICE.base_url}/api/v1/dm-calls/{call_id}/accept",
        json={"auth_token": ALICE.auth_token},
        timeout=10.0,
    )
    reporter.check("the caller can't accept their own call", bad_accept.status_code == 400, bad_accept.text)

    accept_resp = httpx.post(
        f"{CAROL.base_url}/api/v1/dm-calls/{call_id}/accept",
        json={"auth_token": CAROL.auth_token},
        timeout=10.0,
    )
    reporter.check("carol accepts the call", accept_resp.status_code == 200, accept_resp.text)
    reporter.check("the call is now 'accepted'", accept_resp.json().get("status") == "accepted", accept_resp.text)

    offer_resp = httpx.post(
        f"{ALICE.base_url}/api/v1/dm-calls/{call_id}/signal",
        json={"auth_token": ALICE.auth_token, "signal_type": "offer", "payload": {"sdp": "v=0..."}},
        timeout=10.0,
    )
    reporter.check("alice's SDP offer is relayed", offer_resp.status_code == 200 and offer_resp.json().get("relayed") is True, offer_resp.text)

    answer_resp = httpx.post(
        f"{CAROL.base_url}/api/v1/dm-calls/{call_id}/signal",
        json={"auth_token": CAROL.auth_token, "signal_type": "answer", "payload": {"sdp": "v=0..."}},
        timeout=10.0,
    )
    reporter.check("carol's SDP answer is relayed", answer_resp.status_code == 200 and answer_resp.json().get("relayed") is True, answer_resp.text)

    candidate_resp = httpx.post(
        f"{ALICE.base_url}/api/v1/dm-calls/{call_id}/signal",
        json={"auth_token": ALICE.auth_token, "signal_type": "candidate", "payload": {"candidate": "candidate:1 1 UDP ..."}},
        timeout=10.0,
    )
    reporter.check("an ICE candidate is relayed", candidate_resp.status_code == 200 and candidate_resp.json().get("relayed") is True, candidate_resp.text)

    end_resp = httpx.post(
        f"{CAROL.base_url}/api/v1/dm-calls/{call_id}/end",
        json={"auth_token": CAROL.auth_token},
        timeout=10.0,
    )
    reporter.check("carol ends the call", end_resp.status_code == 200, end_resp.text)

    signal_after_end = httpx.post(
        f"{ALICE.base_url}/api/v1/dm-calls/{call_id}/signal",
        json={"auth_token": ALICE.auth_token, "signal_type": "candidate", "payload": {}},
        timeout=10.0,
    )
    reporter.check("signaling on an ended call is rejected", signal_after_end.status_code == 400, signal_after_end.text)


def _reject_flow(reporter: Reporter) -> None:
    reporter.section("DM calls — reject")

    call = _invite(reporter, ALICE, CAROL, label="alice invites carol again (for reject)")
    call_id = call.get("call_id", "")

    reject_resp = httpx.post(
        f"{CAROL.base_url}/api/v1/dm-calls/{call_id}/reject",
        json={"auth_token": CAROL.auth_token},
        timeout=10.0,
    )
    reporter.check("carol rejects the call", reject_resp.status_code == 200, reject_resp.text)

    accept_after_reject = httpx.post(
        f"{CAROL.base_url}/api/v1/dm-calls/{call_id}/accept",
        json={"auth_token": CAROL.auth_token},
        timeout=10.0,
    )
    reporter.check("a rejected call can't then be accepted", accept_after_reject.status_code == 400, accept_after_reject.text)


def _sfu_fallback_flow(reporter: Reporter) -> None:
    reporter.section("DM calls — P2P-failed fallback to the SFU")

    call = _invite(reporter, ALICE, CAROL, label="alice invites carol (for SFU fallback)")
    call_id = call.get("call_id", "")
    httpx.post(f"{CAROL.base_url}/api/v1/dm-calls/{call_id}/accept", json={"auth_token": CAROL.auth_token}, timeout=10.0)

    alice_fallback = httpx.post(
        f"{ALICE.base_url}/api/v1/dm-calls/{call_id}/fallback",
        json={"auth_token": ALICE.auth_token, "quality_profile": "balanced"},
        timeout=15.0,
    )
    reporter.check("alice requests the SFU fallback session", alice_fallback.status_code == 200, alice_fallback.text)
    alice_payload = alice_fallback.json()
    reporter.check("fallback is tagged with the dm_fallback backend", alice_payload.get("backend") == "sfu_v2_dm_fallback", str(alice_payload))
    reporter.check("fallback returns ice_servers", len(alice_payload.get("ice_servers", [])) > 0, str(alice_payload))

    carol_fallback = httpx.post(
        f"{CAROL.base_url}/api/v1/dm-calls/{call_id}/fallback",
        json={"auth_token": CAROL.auth_token, "quality_profile": "balanced"},
        timeout=15.0,
    )
    reporter.check("carol requests the SFU fallback session", carol_fallback.status_code == 200, carol_fallback.text)
    reporter.check(
        "both participants land in the SAME fallback session",
        carol_fallback.json().get("session_id") == alice_payload.get("session_id"),
        f"alice={alice_payload} carol={carol_fallback.json()}",
    )


def run(reporter: Reporter) -> None:
    _basic_call_flow(reporter)
    _reject_flow(reporter)
    _sfu_fallback_flow(reporter)
