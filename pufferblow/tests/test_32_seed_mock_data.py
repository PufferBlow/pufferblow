"""`pufferblow seed` fills an instance with sample data and can be run twice."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from pufferblow.cli.cli import _build_parser
from pufferblow.cli.commands.seed import CHANNELS, DEFAULT_PASSWORD, PEOPLE, SCRIPT, seed_mock_data
from pufferblow.core.bootstrap import api_initializer


@pytest.fixture
def instance(client: TestClient):
    """An initialised instance (temporary SQLite database), as the server would have after setup."""
    # The SQLite test database never gets a `server` row, which user creation needs for the joined-servers list.
    api_initializer.database_handler.get_server_id = lambda: "test-server"
    return api_initializer


def _messages(channel: str, per_page: int = 500) -> list[dict]:
    channel_id = api_initializer.channels_manager._generate_channel_id(channel_name=channel)
    rows = api_initializer.messages_manager.load_messages(channel_id=channel_id, messages_per_page=per_page, page=1)
    return rows[0] if isinstance(rows, tuple) else rows


def test_creates_people_channels_and_history(instance):
    report = seed_mock_data(instance, filler=40)

    assert sorted(report.users_created) == sorted(name for name, *_ in PEOPLE)
    assert sorted(report.channels_created) == sorted(name for name, *_ in CHANNELS)
    assert report.notes == []

    for name, *_ in PEOPLE:
        assert instance.user_manager.check_username(name)

    welcome = _messages("welcome")
    assert len(welcome) == sum(1 for c, *_ in SCRIPT if c == "welcome")
    assert len(_messages("random")) >= 40
    assert _messages("Lounge") == []  # voice channels have no chat


def test_history_is_spread_over_days_and_in_order(instance):
    seed_mock_data(instance, filler=0)
    sent = [m["sent_at"] for m in _messages("general")]
    assert sent == sorted(sent)
    assert sent[0] < sent[-1]


def test_reactions_and_mentions_are_stored(instance):
    report = seed_mock_data(instance, filler=0)
    assert report.reactions > 0

    reacted = [m for m in _messages("welcome") if m.get("reactions")]
    assert reacted, "expected at least one welcome message with reactions"
    assert any(any(r["emoji"] == "🎉" for r in m["reactions"]) for m in reacted)
    assert any("@grace" in m.get("message", "") for m in _messages("general"))


def test_private_channel_is_private_and_limited_to_staff(instance):
    seed_mock_data(instance, filler=0)
    staff = instance.channels_manager._generate_channel_id(channel_name="staff")
    assert instance.channels_manager.is_private(staff) is True

    ids = {n: str(instance.database_handler.get_user(username=n).user_id) for n, *_ in PEOPLE}
    allowed = {str(u) for u in (instance.database_handler.get_channel_data(staff).allowed_users or [])}
    assert ids["grace"] in allowed  # added explicitly
    assert ids["linus"] not in allowed


def test_ada_has_read_history_with_a_few_unread_left(instance):
    seed_mock_data(instance, filler=0)
    ada = str(instance.database_handler.get_user(username="ada").user_id)
    unread = instance.database_handler.get_unread_message_counts_by_channel(user_id=ada)

    announcements = instance.channels_manager._generate_channel_id(channel_name="announcements")
    general = instance.channels_manager._generate_channel_id(channel_name="general")
    assert unread.get(announcements, 0) == 2
    assert unread.get(general, 0) == 0


def test_running_it_twice_adds_nothing_the_second_time(instance):
    first = seed_mock_data(instance, filler=10)
    counts = {c: len(_messages(c)) for c, *_ in CHANNELS if c not in ("Lounge", "Stand-up")}

    second = seed_mock_data(instance, filler=10)

    assert second.users_created == [] and second.channels_created == [] and second.messages == 0
    assert sorted(second.users_existing) == sorted(first.users_created)
    assert {c: len(_messages(c)) for c in counts} == counts


def test_the_password_is_passed_to_sign_up_and_defaults_to_the_demo_one(instance, monkeypatch):
    used: list[str] = []
    real = instance.user_manager.sign_up

    def spy(**kwargs):
        used.append(kwargs["password"])
        return real(**kwargs)

    monkeypatch.setattr(instance.user_manager, "sign_up", spy)
    seed_mock_data(instance, password="Another-demo-pass-9", filler=0)
    assert set(used) == {"Another-demo-pass-9"} and len(used) == len(PEOPLE)
    assert DEFAULT_PASSWORD != "Another-demo-pass-9"


def test_owner_option_makes_that_person_the_owner(instance):
    seed_mock_data(instance, owner="ada", filler=0)
    ada = str(instance.database_handler.get_user(username="ada").user_id)
    grace = str(instance.database_handler.get_user(username="grace").user_id)
    assert instance.user_manager.is_server_owner(user_id=ada) is True
    assert instance.user_manager.is_server_owner(user_id=grace) is False


def test_friendships_are_created(instance):
    from pufferblow.api.database.tables.friend_request_blocks import FriendRequestBlocks
    from pufferblow.api.database.tables.friendships import Friendships

    report = seed_mock_data(instance, filler=0)
    assert report.friendships == 2 and not any("Friend" in n for n in report.notes)

    # Read the tables directly: the manager's list helpers hydrate users with UUID-typed lookups SQLite cannot do.
    with instance.database_handler.database_session() as session:
        statuses = sorted(str(row.status) for row in session.query(Friendships).all())
        blocks = session.query(FriendRequestBlocks).count()
    assert statuses == ["accepted", "accepted", "pending", "pending"]
    assert blocks == 1


def test_the_command_is_registered():
    help_text = _build_parser().format_help() + _build_parser().parse_args(["seed", "--yes", "--owner", "ada"]).__dict__.__repr__()
    assert "seed" in help_text
    args = _build_parser().parse_args(["seed", "--yes", "--owner", "ada", "--filler", "5", "--password", "x"])
    assert (args.assume_yes, args.owner, args.filler, args.password) == (True, "ada", 5, "x")
