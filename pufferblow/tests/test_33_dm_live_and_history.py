"""DMs for protocol-v1 clients: per-user frames arrive as v1 events, and history
pages come newest first.

Builds a DatabaseHandler against a throwaway SQLite file instead of the full app
(see test_31 for why the TestClient fixture is avoided).
"""

from __future__ import annotations

import asyncio
import datetime
import os
import tempfile
import uuid

import pytest
import sqlalchemy

from pufferblow.api.database.database_handler import DatabaseHandler
from pufferblow.api.database.tables.messages import Messages
from pufferblow.api.encrypt.encrypt import Encrypt
from pufferblow.api.models.config_model import Config
from pufferblow.api.websocket.websocket_manager import WebSocketsManager, as_protocol_event


# ── v1 events for per-user frames ────────────────────────────────


@pytest.mark.parametrize(
    "legacy_type, event_name",
    [
        ("message", "dm.message.created"),
        ("message_edited", "dm.message.updated"),
        ("message_deleted", "dm.message.deleted"),
        ("reaction", "dm.reaction.updated"),
    ],
)
def test_dm_frames_become_dm_events(legacy_type, event_name):
    frame = as_protocol_event({"type": legacy_type, "conversation_id": "conv", "message_id": "m1"})
    assert frame["type"] == "event"
    assert frame["version"] == 1
    assert frame["name"] == event_name
    assert frame["data"] == {"conversation_id": "conv", "message_id": "m1"}


def test_other_per_user_frames_become_user_events():
    assert as_protocol_event({"type": "call_invite", "call_id": "c"})["name"] == "user.call_invite"


def test_v1_frames_pass_through():
    frame = {"type": "event", "version": 1, "id": "evt_1", "name": "x", "data": {}}
    assert as_protocol_event(frame) is frame


class FakeSocket:
    def __init__(self) -> None:
        self.sent: list[dict] = []

    async def send_json(self, data: dict) -> None:
        self.sent.append(data)


def test_broadcast_to_user_sends_a_v1_event_to_each_of_that_user_s_sessions():
    manager = WebSocketsManager(user_manager=None)
    v1, second_tab, other_user = FakeSocket(), FakeSocket(), FakeSocket()
    manager.active_connections = {
        second_tab: {"user_id": "u1", "protocol": 1},
        v1: {"user_id": "u1", "protocol": 1},
        other_user: {"user_id": "u2", "protocol": 1},
    }

    asyncio.run(manager.broadcast_to_user("u1", {"type": "message", "conversation_id": "conv", "message_id": "m1"}))

    assert [frame["name"] for frame in second_tab.sent] == ["dm.message.created"]
    assert [frame["name"] for frame in v1.sent] == ["dm.message.created"]
    assert other_user.sent == []


# ── history order ────────────────────────────────────────────────


@pytest.fixture
def db():
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
    tmp.close()
    engine = sqlalchemy.create_engine(f"sqlite:///{tmp.name}")
    handler = DatabaseHandler(database_engine=engine, encrypt_manager=Encrypt(), config=Config())
    yield handler
    handler.database_engine.dispose()
    try:
        if os.path.exists(tmp.name):
            os.unlink(tmp.name)
    except PermissionError:
        pass


def test_dm_history_pages_newest_first_each_page_oldest_first(db):
    start = datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc)
    sender = str(uuid.uuid4())
    ids = []
    with db.database_session() as session:
        for minute in range(5):
            message_id = str(uuid.uuid4())
            ids.append(message_id)
            session.add(
                Messages(
                    message_id=message_id,
                    hashed_message="x",
                    sender_id=sender,
                    conversation_id="conv",
                    sent_at=start + datetime.timedelta(minutes=minute),
                )
            )
        session.commit()

    page_one = [row[0].message_id for row in db.fetch_conversation_messages("conv", messages_per_page=2, page=1)]
    page_two = [row[0].message_id for row in db.fetch_conversation_messages("conv", messages_per_page=2, page=2)]
    page_three = [row[0].message_id for row in db.fetch_conversation_messages("conv", messages_per_page=2, page=3)]

    assert page_one == ids[3:5]
    assert page_two == ids[1:3]
    assert page_three == ids[0:1]
