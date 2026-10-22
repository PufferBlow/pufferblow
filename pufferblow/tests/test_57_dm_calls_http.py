"""1:1 calls over HTTP and the realtime socket: ringing, relayed signals, busy lines, dropped connections."""

from __future__ import annotations

import uuid

from fastapi.testclient import TestClient

from pufferblow.core.bootstrap import api_initializer

CALLS = "/api/v1/dm-calls"


def _user(name: str):
    user = api_initializer.user_manager.sign_up(username=f"{name}_{uuid.uuid4().hex[:6]}", password="12345678")
    token = api_initializer.auth_token_manager.issue_session_tokens(user_id=str(user.user_id), origin_server=user.origin_server)["access_token"]
    return str(user.user_id), token


def _socket(client: TestClient, token: str):
    ws = client.websocket_connect(f"/ws?auth_token={token}&protocol=1")
    return ws


def _next_call_event(ws, name: str) -> dict:
    """Read frames until the named event arrives (hello and unrelated events are skipped)."""
    for _ in range(20):
        frame = ws.receive_json()
        if frame.get("name") == name:
            return frame["data"]
    raise AssertionError(f"no {name} event arrived")


def _invite(client: TestClient, token: str, callee_id: str):
    return client.post(f"{CALLS}/{callee_id}/invite", json={"auth_token": token, "callee_id": callee_id})


def test_a_call_rings_the_callee_and_both_sides_get_ice_servers(client: TestClient):
    alice_id, alice = _user("alice")
    bob_id, bob = _user("bob")

    with _socket(client, bob) as bob_ws:
        bob_ws.receive_json()  # hello
        invited = _invite(client, alice, bob_id)
        assert invited.status_code == 200, invited.text
        assert isinstance(invited.json()["ice_servers"], list)
        call_id = invited.json()["call_id"]

        ring = _next_call_event(bob_ws, "user.dm_call_invite")
        assert ring == {"call_id": call_id, "caller_id": alice_id}

        accepted = client.post(f"{CALLS}/{call_id}/accept", json={"auth_token": bob})
        assert accepted.status_code == 200 and isinstance(accepted.json()["ice_servers"], list)


def test_signals_including_the_relay_key_exchange_reach_the_other_side_unread(client: TestClient):
    alice_id, alice = _user("alice")
    bob_id, bob = _user("bob")
    call_id = _invite(client, alice, bob_id).json()["call_id"]
    client.post(f"{CALLS}/{call_id}/accept", json={"auth_token": bob})

    with _socket(client, bob) as bob_ws:
        bob_ws.receive_json()
        payload = {"relay_key": {"v": 1, "public_key": {"kty": "EC"}}, "e2ee": {"v": 1, "signature": "abc"}}
        sent = client.post(f"{CALLS}/{call_id}/signal", json={"auth_token": alice, "signal_type": "relay", "payload": payload})
        assert sent.status_code == 200, sent.text

        event = _next_call_event(bob_ws, "user.dm_call_relay")
        assert event == {"call_id": call_id, "from_user_id": alice_id, "payload": payload}  # passed through as it was


def test_unknown_signal_types_and_oversized_signals_are_refused(client: TestClient):
    _, alice = _user("alice")
    bob_id, bob = _user("bob")
    call_id = _invite(client, alice, bob_id).json()["call_id"]
    client.post(f"{CALLS}/{call_id}/accept", json={"auth_token": bob})

    bad_type = client.post(f"{CALLS}/{call_id}/signal", json={"auth_token": alice, "signal_type": "bye", "payload": {}})
    too_big = client.post(f"{CALLS}/{call_id}/signal", json={"auth_token": alice, "signal_type": "offer", "payload": {"sdp": "x" * 40_000}})

    assert bad_type.status_code == 400
    assert too_big.status_code == 400


def test_calling_someone_who_does_not_exist_is_a_404(client: TestClient):
    _, alice = _user("alice")
    assert _invite(client, alice, str(uuid.uuid4())).status_code == 404


def test_only_the_callers_own_state_can_refuse_an_invite(client: TestClient):
    alice_id, alice = _user("alice")
    bob_id, bob = _user("bob")
    carol_id, carol = _user("carol")
    assert _invite(client, alice, bob_id).status_code == 200

    assert _invite(client, alice, carol_id).status_code == 409  # alice is already calling
    assert _invite(client, carol, alice_id).status_code == 200  # being rung does not stop carol calling
    assert _invite(client, bob, carol_id).status_code == 200  # nor bob, who is being rung


def test_a_busy_callee_is_not_rung_and_looks_exactly_like_an_unanswered_call(client: TestClient):
    alice_id, alice = _user("alice")
    bob_id, bob = _user("bob")
    _, dave = _user("dave")
    busy_call = _invite(client, alice, bob_id).json()["call_id"]
    client.post(f"{CALLS}/{busy_call}/accept", json={"auth_token": bob})  # bob is on a call

    with _socket(client, bob) as bob_ws:
        bob_ws.receive_json()
        to_busy = _invite(client, dave, bob_id)
        assert to_busy.status_code == 200
        assert set(to_busy.json()) == {"status_code", "call_id", "caller_id", "callee_id", "status", "ice_servers"}  # no tell-tale field
        assert to_busy.json()["status"] == "ringing"
        # bob heard nothing: his socket has only what the hello and the earlier events put there
        bob_ws.send_json({"type": "ping"})
        seen = []
        while True:
            frame = bob_ws.receive_json()
            if frame.get("type") == "pong":
                break
            seen.append(frame.get("name"))
        assert "user.dm_call_invite" not in seen


def test_signals_before_the_callee_accepts_are_refused(client: TestClient):
    _, alice = _user("alice")
    bob_id, _ = _user("bob")
    call_id = _invite(client, alice, bob_id).json()["call_id"]

    early = client.post(f"{CALLS}/{call_id}/signal", json={"auth_token": alice, "signal_type": "offer", "payload": {}})

    assert early.status_code == 400
