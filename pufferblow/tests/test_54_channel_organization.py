"""Channel categories, topics, ordering and pins."""

from __future__ import annotations

import uuid

from fastapi.testclient import TestClient

from pufferblow.core.bootstrap import api_initializer


def _user(name: str, *, owner: bool = False):
    user = api_initializer.user_manager.sign_up(username=f"{name}_{uuid.uuid4().hex[:6]}", password="12345678", is_owner=owner)
    token = api_initializer.auth_token_manager.issue_session_tokens(user_id=str(user.user_id), origin_server=user.origin_server)["access_token"]
    return user, token


def _channel(owner, name: str | None = None, *, private: bool = False) -> str:
    return str(
        api_initializer.channels_manager.create_channel(
            user_id=str(owner.user_id), channel_name=name or f"c_{uuid.uuid4().hex[:8]}", is_private=private, channel_type="text"
        ).channel_id
    )


def _say(owner, channel_id: str, text: str) -> str:
    return str(api_initializer.messages_manager.send_message(channel_id=channel_id, user_id=str(owner.user_id), message=text).message_id)


CATS = "/api/v1/channels/categories"


def _make_category(client: TestClient, token: str, name: str) -> dict:
    reply = client.post(CATS, json={"auth_token": token, "name": name})
    assert reply.status_code == 201, reply.text
    return reply.json()["category"]


def _channels(client: TestClient, token: str) -> dict[str, dict]:
    reply = client.post("/api/v1/channels/list/", json={"auth_token": token})
    assert reply.status_code == 200, reply.text
    return {c["channel_id"]: c for c in reply.json()["channels"]}


# ── categories ────────────────────────────────────────────────────


def test_categories_start_empty_and_are_listed_in_order(client: TestClient):
    _, token = _user("owner", owner=True)
    assert client.get(CATS, params={"auth_token": token}).json()["categories"] == []

    info, talk = _make_category(client, token, "Information"), _make_category(client, token, "Talk")

    listed = client.get(CATS, params={"auth_token": token}).json()["categories"]
    assert [c["name"] for c in listed] == ["Information", "Talk"]
    assert [c["position"] for c in listed] == [0, 1]
    assert info["category_id"] != talk["category_id"]


def test_any_member_can_read_the_categories_but_only_editors_change_them(client: TestClient):
    _, owner = _user("owner", owner=True)
    _, member = _user("member")
    category = _make_category(client, owner, "Talk")

    assert client.get(CATS, params={"auth_token": member}).status_code == 200
    assert client.post(CATS, json={"auth_token": member, "name": "Mine"}).status_code == 403
    assert client.put(f"{CATS}/{category['category_id']}", json={"auth_token": member, "name": "Mine"}).status_code == 403
    assert client.delete(f"{CATS}/{category['category_id']}", params={"auth_token": member}).status_code == 403
    assert client.put(f"{CATS}/order", json={"auth_token": member, "category_ids": []}).status_code == 403
    assert [c["name"] for c in client.get(CATS, params={"auth_token": owner}).json()["categories"]] == ["Talk"]


def test_a_category_name_is_unique_trimmed_and_bounded(client: TestClient):
    _, token = _user("owner", owner=True)
    _make_category(client, token, "  Talk  ")

    assert client.post(CATS, json={"auth_token": token, "name": "Talk"}).status_code == 409
    assert client.post(CATS, json={"auth_token": token, "name": ""}).status_code in (400, 422)
    assert client.post(CATS, json={"auth_token": token, "name": "x" * 65}).status_code in (400, 422)
    assert client.get(CATS, params={"auth_token": token}).json()["categories"][0]["name"] == "Talk"


def test_renaming_a_category_checks_for_clashes_and_missing_ids(client: TestClient):
    _, token = _user("owner", owner=True)
    a, b = _make_category(client, token, "A"), _make_category(client, token, "B")

    assert client.put(f"{CATS}/{a['category_id']}", json={"auth_token": token, "name": "B"}).status_code == 409
    renamed = client.put(f"{CATS}/{a['category_id']}", json={"auth_token": token, "name": "Alpha"})
    assert renamed.status_code == 200 and renamed.json()["category"]["name"] == "Alpha"
    assert client.put(f"{CATS}/nope", json={"auth_token": token, "name": "X"}).status_code == 404
    assert b["category_id"]


def test_reordering_puts_the_named_first_and_keeps_the_rest_after(client: TestClient):
    _, token = _user("owner", owner=True)
    a, b, c = (_make_category(client, token, n) for n in ("A", "B", "C"))

    reply = client.put(f"{CATS}/order", json={"auth_token": token, "category_ids": [c["category_id"], "unknown", a["category_id"]]})

    assert reply.status_code == 200, reply.text
    assert [x["name"] for x in reply.json()["categories"]] == ["C", "A", "B"]
    assert [x["name"] for x in client.get(CATS, params={"auth_token": token}).json()["categories"]] == ["C", "A", "B"]
    assert b["category_id"]


def test_deleting_a_category_keeps_its_channels_uncategorised(client: TestClient):
    owner, token = _user("owner", owner=True)
    category = _make_category(client, token, "Talk")
    channel = _channel(owner)
    client.put(f"/api/v1/channels/{channel}/update", json={"auth_token": token, "category_id": category["category_id"]})
    assert _channels(client, token)[channel]["category_id"] == category["category_id"]

    assert client.delete(f"{CATS}/{category['category_id']}", params={"auth_token": token}).status_code == 200

    assert _channels(client, token)[channel]["category_id"] is None
    assert client.delete(f"{CATS}/{category['category_id']}", params={"auth_token": token}).status_code == 404


# ── topic, category and position on a channel ─────────────────────


def test_a_new_channel_has_no_category_topic_or_position(client: TestClient):
    owner, token = _user("owner", owner=True)
    created = _channel(owner)
    channel = _channels(client, token)[created]
    assert channel["category_id"] is None and channel["topic"] is None and channel["position"] == 0


def test_the_topic_is_set_trimmed_limited_and_cleared(client: TestClient):
    owner, token = _user("owner", owner=True)
    channel = _channel(owner)
    update = lambda **fields: client.put(f"/api/v1/channels/{channel}/update", json={"auth_token": token, **fields})

    assert update(topic="  Patch talk and build sessions ").status_code == 200
    assert _channels(client, token)[channel]["topic"] == "Patch talk and build sessions"
    assert update(topic="x" * 257).status_code in (400, 422)
    assert _channels(client, token)[channel]["topic"] == "Patch talk and build sessions"  # a refused update changes nothing
    assert update(topic="").status_code == 200
    assert _channels(client, token)[channel]["topic"] is None


def test_a_channel_moves_into_a_category_and_back_out(client: TestClient):
    owner, token = _user("owner", owner=True)
    category = _make_category(client, token, "Talk")
    channel = _channel(owner)
    update = lambda **fields: client.put(f"/api/v1/channels/{channel}/update", json={"auth_token": token, **fields})

    assert update(category_id=category["category_id"], position=3).status_code == 200
    placed = _channels(client, token)[channel]
    assert placed["category_id"] == category["category_id"] and placed["position"] == 3

    assert update(category_id=None).status_code == 200  # an explicit null takes it out
    assert _channels(client, token)[channel]["category_id"] is None
    assert _channels(client, token)[channel]["position"] == 3  # the position was not touched


def test_a_channel_update_that_does_not_mention_the_category_leaves_it(client: TestClient):
    owner, token = _user("owner", owner=True)
    category = _make_category(client, token, "Talk")
    channel = _channel(owner)
    client.put(f"/api/v1/channels/{channel}/update", json={"auth_token": token, "category_id": category["category_id"]})

    client.put(f"/api/v1/channels/{channel}/update", json={"auth_token": token, "topic": "hello"})

    assert _channels(client, token)[channel]["category_id"] == category["category_id"]


def test_an_unknown_category_is_refused(client: TestClient):
    owner, token = _user("owner", owner=True)
    channel = _channel(owner)
    reply = client.put(f"/api/v1/channels/{channel}/update", json={"auth_token": token, "category_id": "nope"})
    assert reply.status_code == 404


def test_only_editors_change_a_channels_topic(client: TestClient):
    owner, _ = _user("owner", owner=True)
    _, member = _user("member")
    channel = _channel(owner)
    assert client.put(f"/api/v1/channels/{channel}/update", json={"auth_token": member, "topic": "mine"}).status_code == 403


def test_a_topic_change_is_announced_to_the_channel(client: TestClient):
    import asyncio

    from pufferblow.api.protocol.events import CHANNEL_UPDATED

    owner, token = _user("owner", owner=True)
    channel = _channel(owner)
    seen = []
    publisher = api_initializer.event_publisher
    original = publisher.publish_all

    async def spy(events):
        seen.extend(events)
        return await original(events)

    publisher.publish_all = spy
    try:
        client.put(f"/api/v1/channels/{channel}/update", json={"auth_token": token, "topic": "Patch talk"})
    finally:
        publisher.publish_all = original
    announced = [e for e in seen if e.name == CHANNEL_UPDATED and e.data.get("topic") == "Patch talk"]
    assert announced and announced[0].data["channel_id"] == channel
    assert asyncio  # (the route is async; the test client drives it)


# ── pins ──────────────────────────────────────────────────────────


def _pin(client: TestClient, token: str, channel: str, message: str):
    return client.put(f"/api/v1/channels/{channel}/messages/{message}/pin", params={"auth_token": token})


def _pins(client: TestClient, token: str, channel: str):
    reply = client.get(f"/api/v1/channels/{channel}/pins", params={"auth_token": token})
    assert reply.status_code == 200, reply.text
    return reply.json()["pins"]


def test_a_moderator_pins_a_message_and_everyone_who_can_read_the_channel_sees_it(client: TestClient):
    owner, token = _user("owner", owner=True)
    _, member = _user("member")
    channel = _channel(owner)
    message = _say(owner, channel, "the rules")

    pinned = _pin(client, token, channel, message)

    assert pinned.status_code == 200 and pinned.json() == {"status_code": 200, "pinned": True, "already": False}
    for who in (token, member):
        [pin] = _pins(client, who, channel)
        assert pin["message_id"] == message and pin["pinned_by"] == str(owner.user_id) and pin["pinned_at"]


def test_pinning_twice_is_harmless_and_unpinning_removes_it(client: TestClient):
    owner, token = _user("owner", owner=True)
    channel = _channel(owner)
    message = _say(owner, channel, "hello")

    _pin(client, token, channel, message)
    assert _pin(client, token, channel, message).json()["already"] is True
    assert len(_pins(client, token, channel)) == 1

    gone = client.delete(f"/api/v1/channels/{channel}/messages/{message}/pin", params={"auth_token": token})
    assert gone.status_code == 200 and gone.json()["removed"] is True
    assert _pins(client, token, channel) == []
    again = client.delete(f"/api/v1/channels/{channel}/messages/{message}/pin", params={"auth_token": token})
    assert again.json()["removed"] is False


def test_the_newest_pin_comes_first(client: TestClient):
    owner, token = _user("owner", owner=True)
    channel = _channel(owner)
    first, second = _say(owner, channel, "one"), _say(owner, channel, "two")
    _pin(client, token, channel, first)
    _pin(client, token, channel, second)
    assert [p["message_id"] for p in _pins(client, token, channel)] == [second, first]


def test_members_cannot_pin_or_unpin(client: TestClient):
    owner, token = _user("owner", owner=True)
    _, member = _user("member")
    channel = _channel(owner)
    message = _say(owner, channel, "hello")
    _pin(client, token, channel, message)

    assert _pin(client, member, channel, message).status_code == 403
    assert client.delete(f"/api/v1/channels/{channel}/messages/{message}/pin", params={"auth_token": member}).status_code == 403
    assert len(_pins(client, token, channel)) == 1


def test_a_message_from_another_channel_cannot_be_pinned_here(client: TestClient):
    owner, token = _user("owner", owner=True)
    here, there = _channel(owner), _channel(owner)
    message = _say(owner, there, "elsewhere")
    assert _pin(client, token, here, message).status_code == 404
    assert _pin(client, token, here, "no-such-message").status_code == 404


def test_private_channel_pins_are_for_people_who_can_see_the_channel(client: TestClient):
    owner, token = _user("owner", owner=True)
    _, outsider = _user("outsider")
    channel = _channel(owner, private=True)
    message = _say(owner, channel, "secret")
    _pin(client, token, channel, message)

    assert client.get(f"/api/v1/channels/{channel}/pins", params={"auth_token": outsider}).status_code in (403, 404)
    assert len(_pins(client, token, channel)) == 1


def test_a_channel_holds_a_limited_number_of_pins(client: TestClient):
    from pufferblow.api.database.channel_org_mixin import MAX_PINS_PER_CHANNEL

    owner, token = _user("owner", owner=True)
    channel = _channel(owner)
    handler = api_initializer.database_handler
    for i in range(MAX_PINS_PER_CHANNEL):
        assert handler.pin_message(channel, f"m{i}", str(owner.user_id)) == "pinned"

    extra = _say(owner, channel, "one too many")
    full = _pin(client, token, channel, extra)

    assert full.status_code == 409 and str(MAX_PINS_PER_CHANNEL) in full.text
    assert handler.pin_message(channel, "m0", str(owner.user_id)) == "already"  # re-pinning an existing one is not "full"


def test_deleting_a_message_unpins_it(client: TestClient):
    owner, token = _user("owner", owner=True)
    channel = _channel(owner)
    message = _say(owner, channel, "short lived")
    _pin(client, token, channel, message)

    api_initializer.database_handler.delete_message(message_id=message, channel_id=channel)

    assert _pins(client, token, channel) == []
    assert api_initializer.database_handler.pin_message(channel, "other", "u") == "pinned"  # the count did not keep the stale pin


def test_a_pin_is_announced_and_an_unpin_too(client: TestClient):
    from pufferblow.api.protocol.events import CHANNEL_UPDATED

    owner, token = _user("owner", owner=True)
    channel = _channel(owner)
    message = _say(owner, channel, "hello")
    seen = []
    publisher = api_initializer.event_publisher
    original = publisher.publish_all

    async def spy(events):
        seen.extend(events)
        return await original(events)

    publisher.publish_all = spy
    try:
        _pin(client, token, channel, message)
        _pin(client, token, channel, message)  # already pinned: no second announcement
        client.delete(f"/api/v1/channels/{channel}/messages/{message}/pin", params={"auth_token": token})
    finally:
        publisher.publish_all = original

    pins = [e.data["pin"] for e in seen if e.name == CHANNEL_UPDATED and "pin" in e.data]
    assert pins == [{"message_id": message, "pinned": True}, {"message_id": message, "pinned": False}]


def test_the_migration_adds_the_columns_to_an_older_channels_table():
    import importlib.util
    from pathlib import Path

    import sqlalchemy as sa
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    path = Path(__file__).resolve().parents[1] / "migrations" / "versions" / "0006_channel_organization.py"
    spec = importlib.util.spec_from_file_location("rev0006", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    engine = sa.create_engine("sqlite://")
    with engine.begin() as connection:
        connection.execute(sa.text("CREATE TABLE channels (channel_id VARCHAR PRIMARY KEY, channel_name VARCHAR)"))
        connection.execute(sa.text("INSERT INTO channels VALUES ('c1', 'general')"))
        with Operations.context(MigrationContext.configure(connection)):
            module.upgrade()
            module.upgrade()  # idempotent
        columns = {c["name"] for c in sa.inspect(connection).get_columns("channels")}
        row = connection.execute(sa.text("SELECT category_id, position, topic FROM channels")).one()
    assert {"category_id", "position", "topic"} <= columns
    assert tuple(row) == (None, 0, None)  # an existing channel keeps working: no category, first, no topic
