"""Pictures that move, and the custom emoji catalog.

The server's icon and banner can be uploaded (animated ones included) and choosing one switches the server to
show it; the audit log can be read in the window the control panel asks for; custom emoji live in the sticker
catalog, told apart by a kind, and need a shortcode.
"""

from __future__ import annotations

import io
import uuid
from pathlib import Path

from fastapi.testclient import TestClient
from PIL import Image

from pufferblow.core.bootstrap import api_initializer


def _owner() -> str:
    user = api_initializer.user_manager.sign_up(username=f"owner_{uuid.uuid4().hex[:6]}", password="12345678", is_owner=True)
    return api_initializer.auth_token_manager.issue_session_tokens(user_id=str(user.user_id), origin_server=user.origin_server)["access_token"]


def _point_storage_at(tmp_path: Path) -> None:
    api_initializer.config.STORAGE_PATH = str(tmp_path)
    api_initializer.storage_manager.STORAGE_PATH = str(tmp_path)
    api_initializer.storage_manager.config["storage_path"] = str(tmp_path)
    if hasattr(api_initializer.storage_manager.backend, "storage_path"):
        api_initializer.storage_manager.backend.storage_path = tmp_path


def _animated_gif() -> bytes:
    frames = [Image.new("RGB", (64, 64), colour) for colour in ("red", "green", "blue")]
    out = io.BytesIO()
    frames[0].save(out, format="GIF", save_all=True, append_images=frames[1:], duration=80, loop=0)
    return out.getvalue()


def _png(size: tuple[int, int] = (32, 32)) -> bytes:
    out = io.BytesIO()
    Image.new("RGB", size, "purple").save(out, format="PNG")
    return out.getvalue()


def _info(client: TestClient) -> dict:
    return client.get("/api/v1/system/server-info").json()["server_info"]


# ── the audit log window ──────────────────────────────────────────


def test_the_audit_log_can_be_read_in_the_window_the_panel_asks_for(client: TestClient):
    token = _owner()
    for limit in (10, 200, 500):
        assert client.post("/api/v1/system/recent-activity", json={"auth_token": token, "limit": limit}).status_code == 200
    assert client.post("/api/v1/system/recent-activity", json={"auth_token": token, "limit": 501}).status_code in (400, 422)


# ── the server's own pictures ─────────────────────────────────────


def test_an_uploaded_server_icon_is_shown_instead_of_the_look(client: TestClient, tmp_path: Path):
    token = _owner()
    _point_storage_at(tmp_path)
    assert _info(client)["avatar_kind"] != "image"

    reply = client.post("/api/v1/system/upload-avatar", data={"auth_token": token}, files={"avatar": ("icon.gif", _animated_gif(), "image/gif")})
    assert reply.status_code == 201, reply.text

    info = _info(client)
    assert info["avatar_kind"] == "image"
    assert info["avatar_url"] == reply.json()["avatar_url"]
    assert info["banner_kind"] != "image"  # only what was uploaded changes


def test_an_uploaded_server_banner_is_shown_and_the_default_can_come_back(client: TestClient, tmp_path: Path):
    token = _owner()
    _point_storage_at(tmp_path)

    reply = client.post("/api/v1/system/upload-banner", data={"auth_token": token}, files={"banner": ("banner.gif", _animated_gif(), "image/gif")})
    assert reply.status_code == 201, reply.text
    assert _info(client)["banner_kind"] == "image"

    back = client.put("/api/v1/system/server-appearance", json={"auth_token": token, "banner_kind": "default"})
    assert back.status_code == 200, back.text
    assert _info(client)["banner_kind"] == "default"


def test_the_animation_is_kept_as_uploaded(client: TestClient, tmp_path: Path):
    token = _owner()
    _point_storage_at(tmp_path)
    original = _animated_gif()

    reply = client.post("/api/v1/system/upload-avatar", data={"auth_token": token}, files={"avatar": ("icon.gif", original, "image/gif")})
    assert reply.status_code == 201, reply.text

    served = client.get(reply.json()["avatar_url"])
    assert served.status_code == 200
    with Image.open(io.BytesIO(served.content)) as image:
        assert getattr(image, "n_frames", 1) == 3


def test_only_those_who_manage_the_server_may_change_its_pictures(client: TestClient, tmp_path: Path):
    _point_storage_at(tmp_path)
    user = api_initializer.user_manager.sign_up(username=f"member_{uuid.uuid4().hex[:6]}", password="12345678")
    token = api_initializer.auth_token_manager.issue_session_tokens(user_id=str(user.user_id), origin_server=user.origin_server)["access_token"]
    reply = client.post("/api/v1/system/upload-avatar", data={"auth_token": token}, files={"avatar": ("icon.png", _png(), "image/png")})
    assert reply.status_code == 403


# ── custom emoji ──────────────────────────────────────────────────


def _catalog_table() -> None:
    """The sticker catalog is left out of the SQLite test database; make it for the tests that need it."""
    from pufferblow.api.database.tables.sticker_catalog import ServerStickers

    ServerStickers.__table__.create(api_initializer.database_handler.database_engine, checkfirst=True)


def _upload_catalog(client: TestClient, token: str, name: str, alias: str | None, kind: str | None, content: bytes, content_type: str):
    data = {"display_name": name}
    if alias is not None:
        data["alias"] = alias
    if kind is not None:
        data["kind"] = kind
    return client.post("/api/v1/stickers", params={"auth_token": token}, data=data, files={"file": (f"{name}.png", content, content_type)})


def test_an_emoji_needs_a_shortcode_and_is_listed_with_its_kind(client: TestClient, tmp_path: Path):
    token = _owner()
    _point_storage_at(tmp_path)
    _catalog_table()

    refused = _upload_catalog(client, token, "Wave", None, "emoji", _png(), "image/png")
    assert refused.status_code == 400, refused.text

    made = _upload_catalog(client, token, "Wave", "wave", "emoji", _png((16, 16)), "image/png")
    assert made.status_code == 201, made.text
    assert made.json()["sticker"]["kind"] == "emoji"

    sticker = _upload_catalog(client, token, "Big hello", None, None, _png((48, 48)), "image/png")
    assert sticker.status_code == 201, sticker.text
    assert sticker.json()["sticker"]["kind"] == "sticker"

    listed = {row["alias"] or row["display_name"]: row["kind"] for row in client.get("/api/v1/stickers", params={"auth_token": token}).json()["stickers"]}
    assert listed == {"wave": "emoji", "Big hello": "sticker"}


def test_the_same_picture_can_be_both_a_sticker_and_an_emoji(client: TestClient, tmp_path: Path):
    token = _owner()
    _point_storage_at(tmp_path)
    _catalog_table()
    picture = _png((20, 20))
    assert _upload_catalog(client, token, "Cat", "cat", "emoji", picture, "image/png").status_code == 201
    again = _upload_catalog(client, token, "Cat", None, "sticker", picture, "image/png")
    assert again.status_code == 201, again.text
    assert again.json()["sticker"]["kind"] == "sticker"


def test_an_unknown_kind_is_refused(client: TestClient, tmp_path: Path):
    token = _owner()
    _point_storage_at(tmp_path)
    _catalog_table()
    assert _upload_catalog(client, token, "Odd", "odd", "badge", _png(), "image/png").status_code == 400
