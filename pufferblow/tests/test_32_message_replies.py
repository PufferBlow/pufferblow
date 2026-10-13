"""Replies: sending one (REST/WS share MessageService.create) and the preview of the
answered message that every hydrated or freshly created reply carries.

Collaborators are stubbed, so this runs without the full app (and its TestClient).
"""

from __future__ import annotations

import base64
from types import SimpleNamespace

import pytest

from pufferblow.api.errors import ApiError, ErrorCode
from pufferblow.api.messages.messages_manager import REPLY_PREVIEW_LENGTH, MessagesManager
from pufferblow.api.principals.principal import Principal
from pufferblow.api.protocol.events import message_view
from pufferblow.api.services.messages import MessageService

CHANNEL = "chan-1"
OTHER_CHANNEL = "chan-2"


class FakeMessages:
    def __init__(self) -> None:
        self.sent: list[dict] = []

    def send_message(self, **kwargs):
        self.sent.append(kwargs)
        return SimpleNamespace(message_id="new-1", hashed_message="h", sent_at=None)

    def reply_preview(self, message_id: str) -> dict:
        return {"message_id": message_id, "author_name": "grace", "content": "original", "deleted": False}


class FakeDb:
    def __init__(self, rows: dict) -> None:
        self.rows = rows

    def get_message_by_id(self, message_id: str):
        return self.rows.get(message_id)


def _service(rows: dict) -> tuple[MessageService, FakeMessages]:
    messages = FakeMessages()
    service = MessageService(
        messages_manager=messages,
        channels_manager=SimpleNamespace(get_channel_type=lambda channel_id: "text"),
        database_handler=FakeDb(rows),
        user_manager=SimpleNamespace(user_profile=lambda user_id: {"username": "ada"}),
        authorizer=SimpleNamespace(require_send=lambda principal, channel_id: None),
        policy=lambda: (4000, 25),
    )
    return service, messages


USER = Principal(id="user-1", kind="user")


def test_a_reply_is_saved_with_its_target_and_carries_a_preview():
    service, messages = _service({"orig-1": SimpleNamespace(channel_id=CHANNEL)})

    outcome = service.create(USER, CHANNEL, "agreed", reply_to_message_id="orig-1")

    assert messages.sent[0]["reply_to_message_id"] == "orig-1"
    view = outcome.value["message"]
    assert view["reply_to_message_id"] == "orig-1"
    assert view["reply_to"] == {"message_id": "orig-1", "author_name": "grace", "content": "original", "deleted": False}
    # The real-time event carries the same view.
    assert outcome.events[0].data["reply_to"]["message_id"] == "orig-1"


def test_a_plain_message_has_no_reply():
    service, messages = _service({})
    view = service.create(USER, CHANNEL, "hello").value["message"]
    assert messages.sent[0]["reply_to_message_id"] is None
    assert view["reply_to_message_id"] is None
    assert view["reply_to"] is None


@pytest.mark.parametrize(
    "rows",
    [{}, {"orig-1": SimpleNamespace(channel_id=OTHER_CHANNEL)}],
    ids=["missing", "other-channel"],
)
def test_a_reply_must_answer_a_message_in_the_same_channel(rows):
    service, messages = _service(rows)
    with pytest.raises(ApiError) as caught:
        service.create(USER, CHANNEL, "hi", reply_to_message_id="orig-1")
    assert caught.value.code == ErrorCode.MESSAGES_NOT_FOUND
    assert messages.sent == []


def test_message_view_passes_the_reply_through():
    view = message_view({"message_id": "m", "reply_to_message_id": "o", "reply_to": {"message_id": "o"}})
    assert view["reply_to_message_id"] == "o"
    assert view["reply_to"] == {"message_id": "o"}


def _manager(rows: dict, users: dict) -> MessagesManager:
    manager = MessagesManager.__new__(MessagesManager)
    manager.database_handler = SimpleNamespace(
        get_message_by_id=lambda message_id: rows.get(message_id),
        get_user=lambda user_id: users.get(user_id),
    )
    manager.decrypt_message = lambda user_id, message_id, encrypted_message: encrypted_message.decode()
    return manager


def test_reply_preview_has_the_author_a_snippet_and_attachment_flag():
    long_text = "x" * (REPLY_PREVIEW_LENGTH + 50)
    row = SimpleNamespace(
        message_id="orig-1",
        sender_id="u-grace",
        hashed_message=base64.b64encode(long_text.encode()).decode(),
        attachments=[{"url": "/storage/a.png"}],
    )
    manager = _manager({"orig-1": row}, {"u-grace": SimpleNamespace(username="grace", avatar_url="/a.png")})

    preview = manager.reply_preview("orig-1")

    assert preview == {
        "message_id": "orig-1",
        "author_id": "u-grace",
        "author_name": "grace",
        "author_avatar_url": "/a.png",
        "content": "x" * REPLY_PREVIEW_LENGTH,
        "has_attachments": True,
        "deleted": False,
    }


def test_reply_preview_of_a_deleted_message():
    assert _manager({}, {}).reply_preview("gone") == {"message_id": "gone", "deleted": True}
