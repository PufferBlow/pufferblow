"""A file can be sent with a description (alt text): kept on the attachment and returned with the message."""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from pufferblow.api.services.attachments import MAX_DESCRIPTION_LENGTH, clean_descriptions
from pufferblow.core.bootstrap import api_initializer


def _owner_and_channel(client: TestClient, name: str) -> tuple[str, str]:
    user = api_initializer.user_manager.sign_up(username=f"{name}_owner", password="owner-password", is_owner=True)
    token = api_initializer.auth_token_manager.issue_session_tokens(user_id=str(user.user_id), origin_server=user.origin_server)["access_token"]
    made = client.post("/api/v1/channels/create/", json={"auth_token": token, "channel_name": name, "is_private": False, "channel_type": "text"})
    assert made.status_code == 200
    channel_id = made.json()["channel_data"]["channel_id"]
    return token, channel_id


def test_clean_descriptions_pairs_one_text_per_file_and_never_fails():
    assert clean_descriptions(json.dumps(["  a cat ", "", "x"]), 3) == ["a cat", "", "x"]
    assert clean_descriptions(json.dumps(["only one"]), 3) == ["only one", "", ""]
    assert clean_descriptions(json.dumps(["a", "b", "c"]), 2) == ["a", "b"]
    for junk in ("", "not json", "{}", json.dumps([1, None, {"x": 1}]), None):
        assert clean_descriptions(junk, 2) == ["", ""]
    assert len(clean_descriptions(json.dumps(["x" * 5000]), 1)[0]) == MAX_DESCRIPTION_LENGTH


def test_send_message_keeps_each_files_description(client: TestClient):
    token, channel_id = _owner_and_channel(client, "described")
    sent = client.post(
        f"/api/v1/channels/{channel_id}/send_message",
        data={"auth_token": token, "message": "two files", "attachment_descriptions": json.dumps(["The release notes", ""])},
        files=[("attachments", ("notes.txt", b"hello", "text/plain")), ("attachments", ("more.txt", b"world!", "text/plain"))],
    )
    assert sent.status_code == 200, sent.text
    first, second = sent.json()["attachments"]
    assert first["description"] == "The release notes"
    assert "description" not in second

    loaded = client.get(f"/api/v1/channels/{channel_id}/load_messages", params={"auth_token": token})
    assert loaded.status_code == 200, loaded.text
    stored = [a for m in loaded.json()["messages"] for a in m.get("attachments", [])]
    assert [a.get("description") for a in stored if a["filename"].endswith("notes.txt")] == ["The release notes"]


def test_a_send_without_descriptions_is_unchanged(client: TestClient):
    token, channel_id = _owner_and_channel(client, "plain")
    sent = client.post(
        f"/api/v1/channels/{channel_id}/send_message",
        data={"auth_token": token, "message": "no text"},
        files={"attachments": ("notes.txt", b"hello", "text/plain")},
    )
    assert sent.status_code == 200, sent.text
    assert "description" not in sent.json()["attachments"][0]
