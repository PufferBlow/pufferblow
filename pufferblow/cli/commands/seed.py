"""Fill an instance with sample data so a client can be tried against something real.

    pufferblow seed [--password PW] [--filler N] [--owner NAME] [--yes]

It creates people, channels, a few days of conversation, reactions, friendships and notification
settings by going through the same managers the API routes use, so passwords are hashed, messages
are encrypted and indexed, and the rows look exactly like real ones. Re-running it adds only what
is missing and never touches existing messages.

Do not run it against an instance people use: the accounts share one well-known password.
"""

from __future__ import annotations

import datetime as dt
import random
import sys
from dataclasses import dataclass, field
from typing import Any

from loguru import logger

DEFAULT_PASSWORD = "Pufferblow-demo-2026"
DEFAULT_FILLER = 100

#: (username, status, about). The first is the account to sign in with.
PEOPLE: list[tuple[str, str, str | None]] = [
    ("ada", "online", "Building things on my own server."),
    ("grace", "online", "Compilers and coffee."),
    ("linus", "idle", None),
    ("alan", "dnd", "Deep work. Back at 5."),
    ("margaret", "offline", None),
    ("edsger", "afk", "Away from keyboard."),
]

#: (name, type, is_private, usernames that may see it when private)
CHANNELS: list[tuple[str, str, bool, tuple[str, ...]]] = [
    ("welcome", "text", False, ()),
    ("announcements", "text", False, ()),
    ("general", "text", False, ()),
    ("random", "text", False, ()),
    ("design", "text", False, ()),
    ("staff", "text", True, ("ada", "grace")),
    ("hybrid", "mixed", False, ()),
    ("Lounge", "voice", False, ()),
    ("Stand-up", "voice", False, ()),
]

# (channel, author, text, minutes ago, [(emoji, [reacting users])])
Script = tuple[str, str, str, int, list[tuple[str, list[str]]]]
SCRIPT: list[Script] = [
    ("welcome", "ada", "Welcome to the Dev Community. Channels on the left, people on the right.", 4300, []),
    ("welcome", "ada", "Right-click a message, a channel or the server for its menu.", 4298, []),
    ("welcome", "grace", "Thanks for setting this up! 🎉", 4200, [("🎉", ["ada", "linus"]), ("👍", ["ada"])]),
    ("welcome", "linus", "Is voice working yet?", 4190, []),
    ("welcome", "ada", "Join Lounge, grace is already in there.", 4185, []),
    ("announcements", "ada", "Release candidate is tagged. Please test the protocol changes this week.", 2900, [("🚀", ["grace", "linus", "alan"])]),
    ("announcements", "grace", "I'll take the voice side.", 2880, []),
    ("announcements", "ada", "Maintenance window on Friday at 18:00 UTC. Expect a short restart.", 90, []),
    ("general", "linus", "Morning all.", 1500, []),
    ("general", "linus", "Anyone seen the new design for the call bar?", 1499, []),
    ("general", "grace", "Yes, it's in #design. Looks good.", 1490, []),
    ("general", "alan", "Still on the old build, will update after lunch.", 1400, []),
    (
        "general",
        "grace",
        "Here is a longer one to see how wrapping behaves: the quick brown fox jumps over the lazy dog, and then keeps going for a while so the line has to break somewhere sensible, even in a narrow window.",
        600,
        [],
    ),
    ("general", "ada", "@grace can you look at the reconnect handling when you have a minute?", 240, []),
    ("general", "grace", "On it.", 235, [("👍", ["ada"])]),
    ("general", "linus", "Lunch?", 30, []),
    ("general", "margaret", "Give me ten minutes.", 28, []),
    ("general", "margaret", "Okay, ready.", 15, []),
    ("random", "edsger", "Premature optimisation is the root of all evil.", 3000, []),
    ("random", "linus", "Knuth said that, not you.", 2990, []),
    ("random", "edsger", "He did, I only repeat things worth repeating.", 2985, []),
    ("random", "grace", "Multi-line test:\nline one\nline two\nline three", 200, []),
    ("random", "linus", "🐡", 198, [("😂", ["grace", "edsger"])]),
    ("design", "grace", "Pinned the checklist for the call bar.", 700, []),
    ("design", "alan", "Can we make the unread badge a bit less loud?", 640, []),
    ("design", "ada", "Agreed, try 10.5px with the error colour at 90%.", 120, [("👍", ["alan", "grace"])]),
    ("staff", "ada", "Only staff can see this channel. Rotate the bot token on Friday.", 800, []),
    ("staff", "grace", "Noted.", 790, []),
    ("hybrid", "ada", "This channel supports text and voice.", 500, []),
]

#: Messages that arrive after everyone's caught up, so a few channels show unread badges.
FRESH: list[tuple[str, str, str]] = [
    ("announcements", "grace", "Notes for the maintenance window are in the wiki."),
    ("announcements", "linus", "Reminder: back up before Friday."),
    ("design", "alan", "@ada the badge looks better. One more nit on spacing."),
]

FILLER_LINES = [
    "Has anyone tried the new build yet?",
    "Pushed a fix for the reconnect bug.",
    "Coffee break, back in ten.",
    "Does this look right to you? 🤔",
    "Can someone review my PR?",
    "That's a great point, thanks.",
    "I'll write it up and share it here.",
    "lol",
    "Anyone around? Need a second pair of eyes.",
    "Reminder: stand-up in five minutes.",
]
FILLER_AUTHORS = ("linus", "edsger", "grace", "alan")


@dataclass
class SeedReport:
    users_created: list[str] = field(default_factory=list)
    users_existing: list[str] = field(default_factory=list)
    channels_created: list[str] = field(default_factory=list)
    messages: int = 0
    reactions: int = 0
    friendships: int = 0
    notes: list[str] = field(default_factory=list)


def _iso(minutes_ago: int, now: dt.datetime) -> str:
    return (now - dt.timedelta(minutes=minutes_ago)).isoformat()


def seed_mock_data(api: Any, *, password: str = DEFAULT_PASSWORD, filler: int = DEFAULT_FILLER, owner: str | None = None) -> SeedReport:
    """Populate the instance behind `api` (the bootstrap object). Safe to run twice."""
    report = SeedReport()
    users, channels, messages = api.user_manager, api.channels_manager, api.messages_manager
    db = api.database_handler
    now = dt.datetime.now(dt.timezone.utc)

    # ── people ───────────────────────────────────────────────
    ids: dict[str, str] = {}
    for name, status, about in PEOPLE:
        if users.check_username(name):
            ids[name] = str(db.get_user(username=name).user_id)
            report.users_existing.append(name)
            continue
        wants_owner = owner is not None and name == owner
        user = users.sign_up(username=name, password=password, is_owner=wants_owner, is_moderator=name == "grace")
        ids[name] = str(user.user_id)
        report.users_created.append(name)
        if status != "online":
            users.update_user_status(user_id=user.user_id, status=status)
        if about:
            try:
                users.update_user_about(user_id=user.user_id, new_about=about)
            except Exception:  # noqa: BLE001 - the profile blurb is decoration
                report.notes.append(f"Could not set the profile text for {name}.")

    # ── channels ─────────────────────────────────────────────
    channel_ids: dict[str, str] = {}
    for name, kind, private, members in CHANNELS:
        channel_id = channels._generate_channel_id(channel_name=name)
        channel_ids[name] = channel_id
        if channels.check_channel(channel_id):
            continue
        channels.create_channel(user_id=ids["ada"], channel_name=name, is_private=private, channel_type=kind)
        report.channels_created.append(name)
        for member in members:
            if member != "ada":
                db.add_user_to_channel(to_add_user_id=ids[member], channel_id=channel_id)

    # ── conversation ─────────────────────────────────────────
    def has_messages(channel: str) -> bool:
        rows = messages.load_messages(channel_id=channel_ids[channel], messages_per_page=1, page=1)
        return bool(rows[0] if isinstance(rows, tuple) else rows)

    fresh_channels = {c for c, *_ in CHANNELS if c not in ("Lounge", "Stand-up") and not has_messages(c)}
    rng = random.Random(7)  # same filler every run
    rows: list[tuple[int, str, str, str, list[tuple[str, list[str]]]]] = [
        (minutes, channel, author, text, reactions) for channel, author, text, minutes, reactions in SCRIPT if channel in fresh_channels
    ]
    if "random" in fresh_channels:
        for i in range(filler):
            rows.append((5000 + (filler - i) * 11, "random", rng.choice(FILLER_AUTHORS), f"{rng.choice(FILLER_LINES)} ({i + 1})", []))

    for minutes, channel, author, text, reactions in sorted(rows, key=lambda r: -r[0]):
        record = messages.send_message(channel_id=channel_ids[channel], user_id=ids[author], message=text, sent_at=_iso(minutes, now))
        report.messages += 1
        for emoji, reactors in reactions:
            for reactor in reactors:
                if messages.add_reaction(message_id=str(record.message_id), user_id=ids[reactor], emoji=emoji):
                    report.reactions += 1

    # ── what ada has read: everything, then a few fresh messages on top ──
    if fresh_channels:
        for channel in fresh_channels:
            db.mark_channel_read(user_id=ids["ada"], channel_id=channel_ids[channel])
        for channel, author, text in FRESH:
            if channel in fresh_channels:
                messages.send_message(channel_id=channel_ids[channel], user_id=ids[author], message=text)
                report.messages += 1
        if "random" in channel_ids:
            db.upsert_notification_preference(user_id=ids["ada"], channel_id=channel_ids["random"], muted=True, mention_only=False)

    # ── friends ──────────────────────────────────────────────
    friends = api.friends_manager
    if friends is not None:
        try:
            for other in ("grace", "linus"):
                request = friends.send_request(requester_id=ids["ada"], addressee_id=ids[other])
                if getattr(request, "status", "") == "pending":
                    friends.accept_request(friendship_id=str(request.friendship_id), actor_user_id=ids[other])
                    report.friendships += 1
            friends.send_request(requester_id=ids["alan"], addressee_id=ids["ada"])  # waiting for ada
            friends.send_request(requester_id=ids["ada"], addressee_id=ids["margaret"])  # waiting for margaret
            friends.block_user(blocker_id=ids["ada"], blocked_id=ids["edsger"])
        except Exception as exc:  # noqa: BLE001 - friendships are a bonus; report and carry on
            report.notes.append(f"Friend data was only partly created: {exc}")

    return report


def seed_command(*, password: str = DEFAULT_PASSWORD, filler: int = DEFAULT_FILLER, owner: str | None = None, assume_yes: bool = False) -> None:
    """CLI entry: confirm, load the configured instance, seed it, print how to sign in."""
    from pufferblow.api.config.config_handler import ConfigHandler
    from pufferblow.cli.common import configure_cli_logging, ensure_database_exists, load_config_or_exit, load_runtime

    configure_cli_logging()
    load_config_or_exit()
    database_uri = ConfigHandler().resolve_database_uri()
    if not database_uri:
        logger.error("No bootstrap database URI found. Run `pufferblow setup` first.")
        raise SystemExit(1)

    shown = database_uri.split("@")[-1]  # never echo credentials
    if not assume_yes:
        if not sys.stdin.isatty():
            logger.error("Refusing to seed without --yes when there is no terminal to confirm on.")
            raise SystemExit(1)
        from rich.prompt import Confirm

        if not Confirm.ask(f"Add sample users, channels and messages to the database at {shown}?", default=False):
            raise SystemExit(0)

    ensure_database_exists(database_uri)
    load_runtime(database_uri=database_uri, setup_tables=False)
    from pufferblow.core.bootstrap import api_initializer

    if api_initializer.database_handler.get_server() is None:
        logger.error("This instance has no server yet. Run `pufferblow setup` first.")
        raise SystemExit(1)

    report = seed_mock_data(api_initializer, password=password, filler=filler, owner=owner)

    # Plain prints: the log sink redacts anything that looks like a credential, and this is meant to be read.
    print()
    print(f"Added {len(report.users_created)} users, {len(report.channels_created)} channels, {report.messages} messages, {report.reactions} reactions.")
    if report.users_existing:
        print(f"Already there: {', '.join(report.users_existing)} (left as they were).")
    for note in report.notes:
        print(f"Note: {note}")
    if report.users_created:
        print()
        print("Sign in with any of:", ", ".join(name for name, *_ in PEOPLE))
        print(f"Password for all of them: {password}")
        if owner:
            print(f"{owner} is the server owner (control panel).")
        else:
            print("Nobody was made owner. Use your own owner account to see the control panel, or pass --owner ada next time on a fresh instance.")
