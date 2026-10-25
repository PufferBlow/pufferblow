"""Search filters: from, mentions, has, before, after and author type, for channels and direct messages."""

from __future__ import annotations

import io
import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from pufferblow.api.messages.search_filters import SearchFilters, build_filters, matches
from pufferblow.core.bootstrap import api_initializer


def _png() -> bytes:
    from PIL import Image

    out = io.BytesIO()
    Image.new("RGB", (8, 8), (10, 120, 200)).save(out, format="PNG")
    return out.getvalue()


# ── the filters themselves ────────────────────────────────────────


def test_build_filters_checks_and_normalises_what_a_client_sent():
    f = build_filters(from_user_id=" u1 ", mentions="@Ada", has="link, image,link", before="2026-03-31", after="2026-03-01", author_type="USER")
    assert (f.from_user_id, f.mentions, f.has, f.author_type) == ("u1", "ada", ("link", "image"), "user")
    assert f.before == datetime(2026, 3, 31, tzinfo=timezone.utc)  # before that day began
    assert f.after == datetime(2026, 3, 2, tzinfo=timezone.utc)  # after that day ended
    assert build_filters().active is False
    for bad in ({"has": "gif"}, {"author_type": "robot"}, {"before": "march"}, {"after": "2026-04-01", "before": "2026-03-01"}):
        with pytest.raises(ValueError):
            build_filters(**bad)


def _message(**fields) -> dict:
    return {"sender_user_id": "u1", "message": "hello", "attachments": [], "sent_at": "2026-03-10T12:00:00+00:00", **fields}


def test_matches_each_filter():
    assert matches(_message(), SearchFilters()) is True
    assert matches(_message(), build_filters(from_user_id="u1")) and not matches(_message(), build_filters(from_user_id="u2"))
    assert matches(_message(message="hi @Ada, ok"), build_filters(mentions="ada")) and not matches(_message(), build_filters(mentions="ada"))
    assert matches(_message(message="see https://x.test/a"), build_filters(has="link")) and not matches(_message(), build_filters(has="link"))
    pic = {"type": "image/png", "filename": "a.png", "url": "/u"}
    doc = {"type": "application/pdf", "filename": "a.pdf", "url": "/d"}
    assert matches(_message(attachments=[pic]), build_filters(has="image")) and not matches(_message(attachments=[doc]), build_filters(has="image"))
    assert matches(_message(attachments=[doc]), build_filters(has="file")) and matches(_message(attachments=[pic, doc]), build_filters(has="image,file"))
    assert matches(_message(attachments=[{"type": "sticker"}]), build_filters(has="sticker"))
    assert matches(_message(attachments=[{"type": "audio/ogg"}]), build_filters(has="sound")) and matches(_message(attachments=[{"type": "video/mp4"}]), build_filters(has="video"))


def test_matches_dates_and_author_type():
    inside = build_filters(after="2026-03-09", before="2026-03-11")
    assert matches(_message(), inside)
    assert not matches(_message(sent_at="2026-03-09T23:00:00+00:00"), inside)  # the 9th itself is not "after the 9th"
    assert not matches(_message(sent_at="2026-03-11T00:00:00+00:00"), inside)
    assert matches(_message(sent_at=datetime(2026, 3, 10, tzinfo=timezone.utc)), inside)
    assert matches(_message(sender_user_id="bot:b1"), build_filters(author_type="bot")) and not matches(_message(), build_filters(author_type="bot"))
    assert matches(_message(), build_filters(author_type="user")) and not matches(_message(sender_user_id="bot:b1"), build_filters(author_type="user"))


# ── channel search over HTTP ──────────────────────────────────────


def _person(name: str, *, owner: bool = False):
    user = api_initializer.user_manager.sign_up(username=f"{name}{uuid.uuid4().hex[:4]}", password="12345678", is_owner=owner)
    token = api_initializer.auth_token_manager.issue_session_tokens(user_id=str(user.user_id), origin_server=user.origin_server)["access_token"]
    return user, token


def _post(client: TestClient, token: str, channel_id: str, text: str, files=None):
    sent = client.post(f"/api/v1/channels/{channel_id}/send_message", data={"auth_token": token, "message": text}, files=files or None)
    assert sent.status_code in (200, 201), sent.text


def _channel(client: TestClient):
    owner, owner_token = _person("owner", owner=True)
    made = client.post("/api/v1/channels/create/", json={"auth_token": owner_token, "channel_name": "filters", "is_private": False, "channel_type": "text"})
    channel_id = made.json()["channel_data"]["channel_id"]
    friend, friend_token = _person("friend")
    _post(client, owner_token, channel_id, "plan the trip with @" + friend.username)
    _post(client, friend_token, channel_id, "here is the map https://maps.test/trip")
    _post(client, friend_token, channel_id, "photo from the trip", files={"attachments": ("trip.png", _png(), "image/png")})
    _post(client, owner_token, channel_id, "notes", files={"attachments": ("notes.txt", b"packing list", "text/plain")})
    return channel_id, owner, owner_token, friend, friend_token


def _found(client: TestClient, channel_id: str, token: str, **params) -> list[str]:
    reply = client.get(f"/api/v1/channels/{channel_id}/search", params={"auth_token": token, **params})
    assert reply.status_code == 200, reply.text
    return [m["message"] for m in reply.json()["messages"]]


def test_channel_search_by_filters_alone_and_combined_with_text(client: TestClient):
    channel_id, owner, owner_token, friend, _ = _channel(client)

    assert set(_found(client, channel_id, owner_token, from_user_id=str(owner.user_id))) == {f"plan the trip with @{friend.username}", "notes"}
    assert _found(client, channel_id, owner_token, mentions=friend.username) == [f"plan the trip with @{friend.username}"]
    assert _found(client, channel_id, owner_token, has="link") == ["here is the map https://maps.test/trip"]
    assert _found(client, channel_id, owner_token, has="image") == ["photo from the trip"]
    assert _found(client, channel_id, owner_token, has="file") == ["notes"]
    assert set(_found(client, channel_id, owner_token, q="trip", from_user_id=str(friend.user_id))) == {"here is the map https://maps.test/trip", "photo from the trip"}
    assert _found(client, channel_id, owner_token, q="trip", from_user_id=str(friend.user_id), has="image") == ["photo from the trip"]
    assert _found(client, channel_id, owner_token, q="trip", has="video") == []


def test_channel_search_by_date_and_author_type(client: TestClient):
    channel_id, _, owner_token, *_ = _channel(client)
    assert len(_found(client, channel_id, owner_token, after="2020-01-01")) == 4
    assert _found(client, channel_id, owner_token, before="2020-01-01") == []
    assert len(_found(client, channel_id, owner_token, author_type="user")) == 4
    assert _found(client, channel_id, owner_token, author_type="bot") == []


def test_channel_search_needs_a_text_or_a_filter_and_checks_values(client: TestClient):
    channel_id, _, owner_token, *_ = _channel(client)
    for params in ({}, {"q": "x"}, {"has": "gif"}, {"before": "soon"}, {"q": "trip", "author_type": "robot"}):
        reply = client.get(f"/api/v1/channels/{channel_id}/search", params={"auth_token": owner_token, **params})
        assert reply.status_code == 400, (params, reply.text)


# ── direct messages ───────────────────────────────────────────────


@pytest.fixture
def _activitypub_tables(client):
    import pufferblow.api.database.tables.activitypub  # noqa: F401
    from pufferblow.api.database.tables.declarative_base import Base

    Base.metadata.create_all(
        api_initializer.database_handler.database_engine,
        tables=[t for t in Base.metadata.sorted_tables if t.name.startswith("activitypub")],
    )


def test_direct_message_search_takes_the_same_filters(client: TestClient, _activitypub_tables):
    ada, ada_token = _person("ada")
    grace, grace_token = _person("grace")

    def send(token: str, peer: str, text: str) -> str:
        reply = client.post("/api/v1/dms/send", json={"auth_token": token, "peer": peer, "message": text, "attachments": []})
        assert reply.status_code == 201, reply.text
        return reply.json()["result"]["conversation_id"]

    conversation = send(ada_token, grace.username, "lunch at noon https://menu.test")
    send(grace_token, ada.username, "sounds good, @" + ada.username)
    send(ada_token, grace.username, "see you")

    def found(**params) -> list[str]:
        reply = client.get(f"/api/v1/dms/conversations/{conversation}/search", params={"auth_token": ada_token, **params})
        assert reply.status_code == 200, reply.text
        return [m["message"] for m in reply.json()["messages"]]

    assert found(from_user_id=str(grace.user_id)) == ["sounds good, @" + ada.username]
    assert found(has="link") == ["lunch at noon https://menu.test"]
    assert found(mentions=ada.username) == ["sounds good, @" + ada.username]
    assert found(q="good", from_user_id=str(ada.user_id)) == []
    assert client.get(f"/api/v1/dms/conversations/{conversation}/search", params={"auth_token": ada_token}).status_code == 400
    assert client.get(f"/api/v1/dms/conversations/{conversation}/search", params={"auth_token": ada_token, "has": "gif"}).status_code == 400
