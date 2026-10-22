"""The conversation list: a conversation shows for the person who started it, before any reply."""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete

from pufferblow.api.database.dm_members_mixin import DmConversationMembers
from pufferblow.core.bootstrap import api_initializer


@pytest.fixture(autouse=True)
def _activitypub_tables(client):
    # create_all cannot build the whole schema on sqlite; direct messages need these.
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


def _send(client: TestClient, token: str, peer: str, text: str) -> str:
    reply = client.post("/api/v1/dms/send", json={"auth_token": token, "peer": peer, "message": text, "attachments": []})
    assert reply.status_code == 201, reply.text
    return reply.json()["result"]["conversation_id"]


def _conversations(client: TestClient, token: str) -> list[dict]:
    reply = client.get("/api/v1/dms/conversations", params={"auth_token": token})
    assert reply.status_code == 200, reply.text
    return reply.json()["conversations"]


def test_the_person_who_sends_first_sees_the_conversation_before_any_reply(client: TestClient):
    ada, ada_token = _user("ada")
    grace, grace_token = _user("grace")

    conversation = _send(client, ada_token, grace.username, "hello grace")

    mine = _conversations(client, ada_token)
    assert [c["conversation_id"] for c in mine] == [conversation]
    assert mine[0]["peer_username"] == grace.username
    assert mine[0]["last_message_preview"] == "hello grace" and mine[0]["last_message_sender_is_me"] is True
    assert [c["conversation_id"] for c in _conversations(client, grace_token)] == [conversation]


def test_history_loads_from_the_conversation_the_list_names(client: TestClient):
    ada, ada_token = _user("ada")
    grace, _ = _user("grace")
    _send(client, ada_token, grace.username, "one")
    _send(client, ada_token, grace.username, "two")

    peer = _conversations(client, ada_token)[0]["peer_username"]
    loaded = client.get("/api/v1/dms/messages", params={"auth_token": ada_token, "peer": peer, "page": 1, "messages_per_page": 50}).json()

    assert [m["message"] for m in loaded["messages"]] == ["one", "two"]


def test_a_conversation_started_before_members_were_recorded_is_still_found(client: TestClient):
    ada, ada_token = _user("ada")
    grace, _ = _user("grace")
    conversation = _send(client, ada_token, grace.username, "from before")
    with api_initializer.database_handler.database_session() as session:
        session.execute(delete(DmConversationMembers))  # as if it predates the table
        session.commit()

    found = _conversations(client, ada_token)

    assert [c["conversation_id"] for c in found] == [conversation]
    assert found[0]["peer_username"] == grace.username
    assert api_initializer.database_handler.get_dm_other_member(conversation, str(ada.user_id)) == str(grace.user_id)  # and remembered


def test_conversations_with_different_people_stay_separate_and_newest_first(client: TestClient):
    ada, ada_token = _user("ada")
    grace, _ = _user("grace")
    linus, _ = _user("linus")
    first = _send(client, ada_token, grace.username, "to grace")
    second = _send(client, ada_token, linus.username, "to linus")

    assert [c["conversation_id"] for c in _conversations(client, ada_token)] == [second, first]
