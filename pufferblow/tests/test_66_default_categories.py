"""Every instance starts with "Text Channels" and "Voice Channels"; new channels go into them."""

from __future__ import annotations

import uuid

import sqlalchemy as sa
from fastapi.testclient import TestClient

from pufferblow.api.database.default_categories import TEXT_NAME, VOICE_NAME, seed_default_categories
from pufferblow.core.bootstrap import api_initializer


def _engine_with_channels(rows: list[tuple[str, str, str | None]]):
    engine = sa.create_engine("sqlite://")
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE channel_categories (category_id TEXT PRIMARY KEY, name TEXT UNIQUE, position INTEGER, default_for TEXT, created_at TEXT)"))
        conn.execute(sa.text("CREATE TABLE channels (channel_id TEXT PRIMARY KEY, channel_type TEXT, category_id TEXT)"))
        for channel_id, kind, category in rows:
            conn.execute(sa.text("INSERT INTO channels VALUES (:i, :k, :c)"), {"i": channel_id, "k": kind, "c": category})
    return engine


def test_seeding_creates_the_two_categories_and_files_loose_channels_by_type():
    engine = _engine_with_channels([("t1", "text", None), ("v1", "voice", None), ("t2", "text", "mine")])
    with engine.begin() as conn:
        assert seed_default_categories(conn) is True
        cats = {r.default_for: r for r in conn.execute(sa.text("SELECT * FROM channel_categories")).fetchall()}
        assert (cats["text"].name, cats["text"].position, cats["voice"].name, cats["voice"].position) == (TEXT_NAME, 0, VOICE_NAME, 1)
        placed = dict(conn.execute(sa.text("SELECT channel_id, category_id FROM channels")).fetchall())
    assert placed["t1"] == cats["text"].category_id and placed["v1"] == cats["voice"].category_id
    assert placed["t2"] == "mine"  # a channel that already had a category stays there


def test_seeding_leaves_an_instance_that_already_has_categories_alone_and_is_safe_twice():
    engine = _engine_with_channels([("t1", "text", None)])
    with engine.begin() as conn:
        conn.execute(sa.text("INSERT INTO channel_categories VALUES ('c1', 'Mine', 0, NULL, 'x')"))
        assert seed_default_categories(conn) is False
        assert conn.execute(sa.text("SELECT COUNT(*) FROM channel_categories")).scalar() == 1
        assert conn.execute(sa.text("SELECT category_id FROM channels")).scalar() is None
    fresh = _engine_with_channels([])
    with fresh.begin() as conn:
        assert seed_default_categories(conn) is True
        assert seed_default_categories(conn) is False
        assert conn.execute(sa.text("SELECT COUNT(*) FROM channel_categories")).scalar() == 2


def test_seeding_does_nothing_without_the_tables():
    with sa.create_engine("sqlite://").begin() as conn:
        assert seed_default_categories(conn) is False


def _owner(client: TestClient):
    user = api_initializer.user_manager.sign_up(username=f"owner{uuid.uuid4().hex[:5]}", password="12345678", is_owner=True)
    return api_initializer.auth_token_manager.issue_session_tokens(user_id=str(user.user_id), origin_server=user.origin_server)["access_token"]


def _create(client: TestClient, token: str, name: str, kind: str) -> str:
    made = client.post("/api/v1/channels/create/", json={"auth_token": token, "channel_name": name, "is_private": False, "channel_type": kind})
    assert made.status_code == 200, made.text
    return made.json()["channel_data"]["channel_id"]


def _category_of(client: TestClient, token: str, channel_id: str):
    listed = client.post("/api/v1/channels/list/", json={"auth_token": token}).json()["channels"]
    return next(c for c in listed if c["channel_id"] == channel_id).get("category_id")


def test_a_new_channel_lands_in_the_default_category_for_its_type_even_after_a_rename(client: TestClient):
    token = _owner(client)
    db = api_initializer.database_handler
    for category in db.list_categories():
        db.delete_category(category["category_id"])
    with db.database_session() as session:
        from pufferblow.api.database.tables.channel_organization import ChannelCategories

        session.add(ChannelCategories(category_id="cat-text", name="Text Channels", position=0, default_for="text"))
        session.add(ChannelCategories(category_id="cat-voice", name="Voice Channels", position=1, default_for="voice"))
        session.commit()

    assert _category_of(client, token, _create(client, token, "talk", "text")) == "cat-text"
    assert _category_of(client, token, _create(client, token, "lounge", "voice")) == "cat-voice"

    renamed = client.put("/api/v1/channels/categories/cat-text", json={"auth_token": token, "name": "Chat"})
    assert renamed.status_code == 200, renamed.text
    assert _category_of(client, token, _create(client, token, "more-talk", "text")) == "cat-text"  # found by its role, not its name


def test_with_no_default_category_a_channel_stays_loose(client: TestClient):
    token = _owner(client)
    db = api_initializer.database_handler
    for category in db.list_categories():
        db.delete_category(category["category_id"])
    assert _category_of(client, token, _create(client, token, "loose", "text")) in (None, "")
