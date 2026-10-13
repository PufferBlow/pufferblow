import pytest
from fastapi.testclient import TestClient

from pufferblow.api.notifications.notifications_manager import extract_mention_usernames, mentions_everyone
from pufferblow.core.bootstrap import api_initializer


def _user(username: str, *, owner: bool = False):
    user = api_initializer.user_manager.sign_up(username=username, password="a-long-password", is_owner=owner)
    tokens = api_initializer.auth_token_manager.issue_session_tokens(
        user_id=str(user.user_id), origin_server=user.origin_server
    )
    return user, tokens["access_token"]


def _channel(client: TestClient, token: str, name: str, *, private: bool = False) -> str:
    response = client.post(
        "/api/v1/channels/create/",
        json={"auth_token": token, "channel_name": name, "is_private": private, "channel_type": "text"},
    )
    assert response.status_code == 200, response.text
    return response.json()["channel_data"]["channel_id"]


def _send(client: TestClient, token: str, channel_id: str, text: str) -> str:
    response = client.post(f"/api/v1/channels/{channel_id}/send_message", data={"auth_token": token, "message": text})
    assert response.status_code in (200, 201), response.text
    return response.json()["message_id"]


def _notes(client: TestClient, token: str) -> list[dict]:
    return client.get("/api/v1/notifications/", params={"auth_token": token}).json()["notifications"]


def test_the_everyone_mention_is_recognised_as_its_own_word():
    assert mentions_everyone("@everyone dinner is ready")
    assert mentions_everyone("hello @EVERYONE")
    assert not mentions_everyone("mail me at ann@everyone.example")
    assert not mentions_everyone("@everyones")
    # It is not a person, so it never counts as a name to look up.
    assert extract_mention_usernames("@everyone and @ann") == ["ann"]


def test_a_mention_by_name_notifies_that_person(client: TestClient):
    _, owner = _user("mention_owner", owner=True)
    _, ann = _user("mention_ann")
    channel = _channel(client, owner, "mention-room")

    message = _send(client, owner, channel, "@mention_ann have a look")

    [note] = _notes(client, ann)
    assert (note["type"], note["channel_id"], note["message_id"]) == ("mention", channel, message)
    assert _notes(client, owner) == []


def test_the_owner_can_ping_everyone_but_not_themselves(client: TestClient):
    _, owner = _user("everyone_owner", owner=True)
    _, ann = _user("everyone_ann")
    _, bob = _user("everyone_bob")
    channel = _channel(client, owner, "everyone-room")

    _send(client, owner, channel, "@everyone standup in five")

    assert [n["type"] for n in _notes(client, ann)] == ["mention"]
    assert [n["type"] for n in _notes(client, bob)] == ["mention"]
    assert _notes(client, owner) == []


def test_a_regular_member_cannot_ping_everyone(client: TestClient):
    _, owner = _user("plain_owner", owner=True)
    _, ann = _user("plain_ann")
    _, bob = _user("plain_bob")
    channel = _channel(client, owner, "plain-room")

    _send(client, ann, channel, "@everyone look at this")

    assert _notes(client, owner) == []
    assert _notes(client, bob) == []


def test_everyone_skips_people_who_muted_the_channel(client: TestClient, monkeypatch):
    _, owner = _user("muting_owner", owner=True)
    _, ann = _user("muting_ann")
    bob_user, bob = _user("muting_bob")
    channel = _channel(client, owner, "muting-room")
    # (Preferences can't round-trip through the SQLite test database, so the lookup is stubbed.)
    monkeypatch.setattr(
        api_initializer.database_handler, "muted_user_ids_for_channel", lambda channel_id: {str(bob_user.user_id)}
    )

    _send(client, owner, channel, "@everyone hi")

    assert len(_notes(client, ann)) == 1
    assert _notes(client, bob) == []


def test_naming_someone_and_everyone_is_still_one_notification(client: TestClient):
    _, owner = _user("both_owner", owner=True)
    _, ann = _user("both_ann")
    channel = _channel(client, owner, "both-room")

    _send(client, owner, channel, "@everyone and especially @both_ann")

    assert len(_notes(client, ann)) == 1


def test_in_a_private_channel_only_those_who_can_read_it_are_pinged(client: TestClient):
    _, owner = _user("private_owner", owner=True)
    _, ann = _user("private_ann")
    channel = _channel(client, owner, "private-room", private=True)

    _send(client, owner, channel, "@everyone secret news")

    assert _notes(client, ann) == []  # a regular member can't read this channel


def test_nobody_can_sign_up_as_everyone(client: TestClient):
    with pytest.raises(ValueError, match="reserved"):
        api_initializer.user_manager.sign_up(username="Everyone", password="a-long-password")


def test_the_username_validator_used_by_sign_up_and_renaming_refuses_a_reserved_name():
    from pufferblow.api.errors import ApiError
    from pufferblow.api.routes.users import _validate_username_format

    with pytest.raises(ApiError):
        _validate_username_format("everyone")
    with pytest.raises(ApiError):
        _validate_username_format("Everyone")
    _validate_username_format("everyone_else")  # only the exact name is reserved


def test_nobody_can_rename_themselves_to_everyone(client: TestClient):
    user, token = _user("rename_me")

    over_http = client.put("/api/v1/users/profile", json={"auth_token": token, "new_username": "Everyone"})
    assert over_http.status_code == 400, over_http.text

    with pytest.raises(ValueError, match="reserved"):
        api_initializer.user_manager.update_username(user_id=str(user.user_id), new_username="everyone")
    assert api_initializer.database_handler.get_user(user_id=str(user.user_id)).username == "rename_me"
