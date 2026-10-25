"""Searching a direct-message conversation and pinning messages in it."""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from pufferblow.core.bootstrap import api_initializer


@pytest.fixture(autouse=True)
def _activitypub_tables(client):
    import pufferblow.api.database.tables.activitypub  # noqa: F401
    from pufferblow.api.database.tables.declarative_base import Base

    Base.metadata.create_all(
        api_initializer.database_handler.database_engine,
        tables=[t for t in Base.metadata.sorted_tables if t.name.startswith("activitypub")],
    )


def _user(name: str):
    user = api_initializer.user_manager.sign_up(username=f"{name}_{uuid.uuid4().hex[:5]}", password="12345678")
    token = api_initializer.auth_token_manager.issue_session_tokens(user_id=str(user.user_id), origin_server=user.origin_server)["access_token"]
    return user, token


def _send(client: TestClient, token: str, peer: str, text: str) -> tuple[str, str]:
    reply = client.post("/api/v1/dms/send", json={"auth_token": token, "peer": peer, "message": text, "attachments": []})
    assert reply.status_code == 201, reply.text
    result = reply.json()["result"]
    return result["conversation_id"], result["message_id"]


def _conversation(client: TestClient):
    ada, ada_token = _user("ada")
    grace, grace_token = _user("grace")
    ids = [_send(client, ada_token, grace.username, text) for text in ("the picnic is at noon", "bring lemonade", "see you there")]
    return ada_token, grace_token, ids[0][0], [i for _, i in ids]


def _url(conversation: str, tail: str) -> str:
    return f"/api/v1/dms/conversations/{conversation}/{tail}"


def test_search_finds_matches_in_the_conversation_newest_first(client: TestClient):
    ada_token, grace_token, conversation, _ = _conversation(client)

    found = client.get(_url(conversation, "search"), params={"auth_token": ada_token, "q": "lemon"})
    assert found.status_code == 200, found.text
    assert [m["message"] for m in found.json()["messages"]] == ["bring lemonade"]

    other_side = client.get(_url(conversation, "search"), params={"auth_token": grace_token, "q": "picnic"})
    assert [m["message"] for m in other_side.json()["messages"]] == ["the picnic is at noon"]
    assert client.get(_url(conversation, "search"), params={"auth_token": ada_token, "q": "zebra"}).json()["messages"] == []


def test_search_checks_the_query_and_who_is_asking(client: TestClient):
    ada_token, _, conversation, _ = _conversation(client)
    _, stranger = _user("eve")

    assert client.get(_url(conversation, "search"), params={"auth_token": ada_token, "q": "x"}).status_code == 400
    assert client.get(_url(conversation, "search"), params={"auth_token": ada_token, "q": "lemon", "limit": 500}).status_code == 400
    assert client.get(_url(conversation, "search"), params={"auth_token": stranger, "q": "lemon"}).status_code == 404


def test_either_person_can_pin_and_both_see_it(client: TestClient):
    ada_token, grace_token, conversation, ids = _conversation(client)

    pinned = client.put(_url(conversation, f"messages/{ids[1]}/pin"), params={"auth_token": grace_token})
    assert pinned.status_code == 200 and pinned.json() == {"status_code": 200, "pinned": True, "already": False}
    assert client.put(_url(conversation, f"messages/{ids[1]}/pin"), params={"auth_token": ada_token}).json()["already"] is True
    client.put(_url(conversation, f"messages/{ids[0]}/pin"), params={"auth_token": ada_token})

    for token in (ada_token, grace_token):
        listed = client.get(_url(conversation, "pins"), params={"auth_token": token}).json()
        assert [p["message"] for p in listed["pins"]] == ["the picnic is at noon", "bring lemonade"]  # newest pin first
        assert listed["limit"] == 50 and all(p["pinned_at"] and p["pinned_by"] for p in listed["pins"])

    gone = client.delete(_url(conversation, f"messages/{ids[1]}/pin"), params={"auth_token": ada_token})
    assert gone.json()["removed"] is True
    assert client.delete(_url(conversation, f"messages/{ids[1]}/pin"), params={"auth_token": ada_token}).json()["removed"] is False
    assert [p["message"] for p in client.get(_url(conversation, "pins"), params={"auth_token": grace_token}).json()["pins"]] == ["the picnic is at noon"]


def test_pins_stay_inside_their_conversation_and_their_two_people(client: TestClient):
    ada_token, _, conversation, ids = _conversation(client)
    _, stranger = _user("eve")
    other_conversation, _ = _send(client, ada_token, _user("sam")[0].username, "elsewhere")

    assert client.put(_url(conversation, f"messages/{ids[0]}/pin"), params={"auth_token": stranger}).status_code == 404
    assert client.get(_url(conversation, "pins"), params={"auth_token": stranger}).status_code == 404
    assert client.delete(_url(conversation, f"messages/{ids[0]}/pin"), params={"auth_token": stranger}).status_code == 404
    # A message from another conversation cannot be pinned into this one.
    _, elsewhere_id = _send(client, ada_token, _user("tom")[0].username, "not here")
    assert client.put(_url(conversation, f"messages/{elsewhere_id}/pin"), params={"auth_token": ada_token}).status_code == 404
    assert client.get(_url(other_conversation, "pins"), params={"auth_token": ada_token}).json()["pins"] == []


def test_a_conversation_holds_at_most_fifty_pins(client: TestClient):
    ada_token, _, conversation, ids = _conversation(client)
    db = api_initializer.database_handler
    for n in range(49):
        db.pin_message(conversation, f"filler-{n}", "someone")
    assert client.put(_url(conversation, f"messages/{ids[0]}/pin"), params={"auth_token": ada_token}).status_code == 200
    full = client.put(_url(conversation, f"messages/{ids[1]}/pin"), params={"auth_token": ada_token})
    assert full.status_code == 409
