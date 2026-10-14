"""Who may read a channel, and live delivery to the people a private channel was shared with.

Stubs the channel and user managers instead of starting the app (see test_31 for why
the TestClient fixture is avoided).
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from pufferblow.api.commands.dispatcher import ConnectionContext
from pufferblow.api.principals.authorizer import Authorizer
from pufferblow.api.principals.principal import Principal
from pufferblow.api.protocol.envelopes import build_event
from pufferblow.api.websocket.websocket_manager import WebSocketsManager


class FakeChannels:
    def __init__(self, **channels) -> None:
        self.rows = channels

    def get_channel(self, channel_id: str):
        return self.rows.get(channel_id)


class FakeUsers:
    def __init__(self, privileged: set[str] = frozenset()) -> None:
        self.privileged = privileged

    def has_privilege(self, user_id: str, privilege_id: str) -> bool:
        return privilege_id == "view_private_channels" and user_id in self.privileged


class FakeSocket:
    def __init__(self) -> None:
        self.sent: list[dict] = []

    async def send_json(self, data: dict) -> None:
        self.sent.append(data)


def _channel(private: bool, members: list[str] | None = None):
    return SimpleNamespace(is_private=private, allowed_users=members or [])


def _user(user_id: str, *privileges: str) -> Principal:
    return Principal(id=user_id, kind="user", privileges=frozenset(privileges))


CHANNELS = FakeChannels(
    general=_channel(private=False),
    staff=_channel(private=True, members=["member"]),
)


# ── authorizer ───────────────────────────────────────────────────


def test_a_public_channel_is_readable_by_anyone():
    authorizer = Authorizer(user_manager=None, channels_manager=CHANNELS)
    assert authorizer.can_read_channel(_user("stranger"), "general")


def test_a_private_channel_admits_its_members_and_privilege_holders_only():
    authorizer = Authorizer(user_manager=None, channels_manager=CHANNELS)
    assert authorizer.can_read_channel(_user("member"), "staff")
    assert authorizer.can_read_channel(_user("admin", "view_private_channels"), "staff")
    assert not authorizer.can_read_channel(_user("stranger"), "staff")


def test_a_bot_reads_a_private_channel_through_its_owner():
    authorizer = Authorizer(user_manager=None, channels_manager=CHANNELS)
    bot = Principal(id="bot", kind="bot", owner_user_id="member")
    assert authorizer.can_read_channel(bot, "staff")


def test_a_missing_channel_admits_no_one():
    authorizer = Authorizer(user_manager=None, channels_manager=CHANNELS)
    assert not authorizer.can_read_channel(_user("admin", "view_private_channels"), "gone")


# ── delivery ─────────────────────────────────────────────────────


def _manager(privileged: set[str] = frozenset()) -> WebSocketsManager:
    manager = WebSocketsManager(user_manager=FakeUsers(privileged))
    manager.channels_manager = CHANNELS
    return manager


def _connect(manager: WebSocketsManager, principal: Principal, *channels: str) -> FakeSocket:
    socket = FakeSocket()
    context = ConnectionContext(principal=principal, session_id=principal.id, connection_key=principal.id, subscriptions=set(channels))
    manager.active_connections[socket] = {"user_id": principal.id, "protocol": 1, "context": context}
    return socket


def test_private_channel_events_reach_its_members():
    manager = _manager(privileged={"admin"})
    member = _connect(manager, _user("member"), "staff")
    admin = _connect(manager, _user("admin", "view_private_channels"), "staff")
    stranger = _connect(manager, _user("stranger"), "staff")  # subscribed somehow, still not allowed

    asyncio.run(manager.deliver_channel_event("staff", build_event("message.created", {}, channel_id="staff")))

    assert len(member.sent) == 1
    assert len(admin.sent) == 1
    assert stranger.sent == []


def test_a_member_removed_from_the_list_stops_receiving_at_once():
    manager = _manager()
    member = _connect(manager, _user("member"), "staff")
    CHANNELS.rows["staff"] = _channel(private=True, members=[])
    try:
        asyncio.run(manager.deliver_channel_event("staff", build_event("message.created", {}, channel_id="staff")))
    finally:
        CHANNELS.rows["staff"] = _channel(private=True, members=["member"])
    assert member.sent == []


# ── granting access to open sessions ─────────────────────────────


def test_a_new_channel_subscribes_everyone_who_can_read_it_and_tells_them():
    manager = _manager()
    authorizer = Authorizer(user_manager=None, channels_manager=CHANNELS)
    alice = _connect(manager, _user("alice"))
    bob = _connect(manager, _user("bob"))

    granted = asyncio.run(
        manager.grant_subscriptions(authorizer, "general", name="channel.created", data={"channel_id": "general"})
    )

    assert granted == 2
    for socket in (alice, bob):
        context = manager.active_connections[socket]["context"]
        assert "general" in context.subscriptions
        (notice,) = socket.sent
        assert notice["name"] == "channel.created"
        assert notice["channel_id"] == "general"
        assert "seq" not in notice


def test_sharing_a_private_channel_reaches_only_the_people_it_was_shared_with():
    manager = _manager()
    authorizer = Authorizer(user_manager=None, channels_manager=CHANNELS)
    member = _connect(manager, _user("member"))
    stranger = _connect(manager, _user("stranger"))

    asyncio.run(
        manager.grant_subscriptions(authorizer, "staff", name="channel.updated", data={"channel_id": "staff", "access": "granted"})
    )

    assert "staff" in manager.active_connections[member]["context"].subscriptions
    assert member.sent[0]["data"] == {"channel_id": "staff", "access": "granted"}
    assert "staff" not in manager.active_connections[stranger]["context"].subscriptions
    assert stranger.sent == []


def test_sessions_already_subscribed_are_not_told_again():
    manager = _manager()
    authorizer = Authorizer(user_manager=None, channels_manager=CHANNELS)
    socket = _connect(manager, _user("alice"), "general")

    granted = asyncio.run(manager.grant_subscriptions(authorizer, "general", name="channel.updated", data={}))

    assert granted == 0
    assert socket.sent == []
