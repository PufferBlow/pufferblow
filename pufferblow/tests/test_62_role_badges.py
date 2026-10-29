"""Role badges: what a role may carry after a person's name, and the rules that keep one from passing for another.

The rules live in ``pufferblow.api.utils.role_badges``; the first half tests them directly and the second half
goes through the application, as the owner and as someone who is not.
"""

from __future__ import annotations

import io
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from PIL import Image

from pufferblow.api.utils.role_badges import (
    BUILT_IN_BADGES,
    GLYPHS,
    MAX_BADGED_ROLES,
    TONES,
    RoleBadgeError,
    check_badge,
    check_badge_image,
    effective_badge,
)
from pufferblow.core.bootstrap import api_initializer

# ── the rules ─────────────────────────────────────────────────────


def _png(size: tuple[int, int] = (128, 128), fmt: str = "PNG") -> bytes:
    out = io.BytesIO()
    Image.new("RGBA", size, (169, 156, 242, 255)).save(out, format=fmt)
    return out.getvalue()


def test_the_choices_are_the_designs():
    assert TONES == ("brass", "coral", "rose", "violet", "sky", "sage", "white", "grey")
    assert len(GLYPHS) == 20 and "crown" in GLYPHS and "upload" not in GLYPHS


def test_a_community_badge_is_stored_as_chosen():
    assert check_badge({"tone": "violet", "glyph": "film"}, []) == {"tier": "community", "tone": "violet", "glyph": "film"}


@pytest.mark.parametrize(
    "raw, field",
    [
        ({"tone": "neon", "glyph": "film"}, "tone"),
        ({"tone": "sky", "glyph": "sword"}, "glyph"),
        ({"tier": "system", "tone": "sky", "glyph": "bot"}, "tier"),
        ({"tier": "ruler", "tone": "sky", "glyph": "bot"}, "tier"),
        ({"tone": "sky", "glyph": "bot", "size": 3}, "size"),
        ({"tone": "sky", "glyph": "film", "image_url": "/storage/x"}, "image_url"),
        ({"tone": "sky", "glyph": "image"}, "image_url"),
        ({"tone": "sky", "glyph": "image", "image_url": "https://elsewhere.test/a.png"}, "image_url"),
        ({"tone": "sky", "glyph": "image", "image_url": "/storage/../etc"}, "image_url"),
    ],
)
def test_anything_unknown_or_out_of_range_is_refused_by_name(raw, field):
    with pytest.raises(RoleBadgeError) as raised:
        check_badge(raw, [])
    assert raised.value.field == field


def test_the_staff_shape_is_only_for_roles_that_can_moderate():
    with pytest.raises(RoleBadgeError) as raised:
        check_badge({"tier": "staff", "tone": "sky", "glyph": "shield"}, ["send_messages"])
    assert raised.value.field == "tier"
    for privilege in ("ban_users", "mute_users", "moderate_content"):
        assert check_badge({"tier": "staff", "tone": "sky", "glyph": "shield"}, [privilege])["tier"] == "staff"


def test_an_image_badge_points_at_an_uploaded_picture():
    badge = check_badge({"tone": "grey", "glyph": "image", "image_url": "/storage/abc123"}, [])
    assert badge == {"tier": "community", "tone": "grey", "glyph": "image", "image_url": "/storage/abc123"}


def test_the_built_in_roles_are_shown_with_theirs_and_nobody_else_is():
    assert effective_badge("owner", None) == BUILT_IN_BADGES["owner"] == {"tier": "staff", "tone": "brass", "glyph": "crown"}
    assert effective_badge("moderator", None)["glyph"] == "shield"
    assert effective_badge("user", None) is None
    assert effective_badge("coach", None) is None
    assert effective_badge("coach", {"tier": "community", "tone": "violet", "glyph": "target", "junk": 1}) == {"tier": "community", "tone": "violet", "glyph": "target"}


def test_a_badge_picture_is_a_small_square_png():
    check_badge_image(_png())
    for content, why in [
        (b"", "empty"),
        (_png((64, 64)), "128"),
        (_png((128, 64)), "128"),
        (_png(fmt="GIF"), "PNG"),
        (b"\x89PNG\r\n\x1a\nnot really", "read"),
        (b"<svg xmlns='http://www.w3.org/2000/svg'/>", "PNG"),
        (b"\x89PNG\r\n\x1a\n" + b"0" * (257 * 1024), "KB"),
    ]:
        with pytest.raises(RoleBadgeError, match=why):
            check_badge_image(content)


# ── through the application ───────────────────────────────────────


def _session(*, owner: bool) -> str:
    user = api_initializer.user_manager.sign_up(username=f"u_{uuid.uuid4().hex[:6]}", password="12345678", is_owner=owner)
    return api_initializer.auth_token_manager.issue_session_tokens(user_id=str(user.user_id), origin_server=user.origin_server)["access_token"]


def _point_storage_at(tmp_path: Path) -> None:
    api_initializer.config.STORAGE_PATH = str(tmp_path)
    api_initializer.storage_manager.STORAGE_PATH = str(tmp_path)
    api_initializer.storage_manager.config["storage_path"] = str(tmp_path)
    if hasattr(api_initializer.storage_manager.backend, "storage_path"):
        api_initializer.storage_manager.backend.storage_path = tmp_path


def _create(client: TestClient, token: str, name: str, privileges: list[str] | None = None, badge: dict | None = None):
    body: dict = {"auth_token": token, "role_name": name, "privileges_ids": privileges or []}
    if badge is not None:
        body["badge"] = badge
    return client.post("/api/v1/system/roles", json=body)


def _roles(client: TestClient, token: str) -> dict[str, dict]:
    reply = client.post("/api/v1/system/roles/list", json={"auth_token": token})
    assert reply.status_code == 200, reply.text
    return {role["role_id"]: role for role in reply.json()["roles"]}


def test_the_built_in_roles_list_with_their_badges(client: TestClient):
    token = _session(owner=True)
    roles = _roles(client, token)
    assert roles["owner"]["badge"] == {"tier": "staff", "tone": "brass", "glyph": "crown"}
    assert "admin" not in roles
    assert roles["moderator"]["badge"]["glyph"] == "shield"
    assert roles["user"]["badge"] is None


def test_a_custom_role_is_created_with_a_badge_and_everyone_sees_it(client: TestClient):
    token = _session(owner=True)
    reply = _create(client, token, "Clip judge", badge={"tone": "violet", "glyph": "film"})
    assert reply.status_code == 201, reply.text
    assert reply.json()["role"]["badge"] == {"tier": "community", "tone": "violet", "glyph": "film"}

    member = _session(owner=False)  # listing is open to anyone signed in
    assert _roles(client, member)["clip-judge"]["badge"]["glyph"] == "film"


def test_a_role_without_a_badge_has_none(client: TestClient):
    token = _session(owner=True)
    assert _create(client, token, "Plain").json()["role"]["badge"] is None


def test_the_staff_shape_needs_a_moderation_privilege(client: TestClient):
    token = _session(owner=True)
    refused = _create(client, token, "Fake mod", ["send_messages"], {"tier": "staff", "tone": "sky", "glyph": "shield"})
    assert refused.status_code == 400
    assert refused.json()["details"]["field"] == "badge.tier"

    allowed = _create(client, token, "Real mod", ["mute_users"], {"tier": "staff", "tone": "sky", "glyph": "shield"})
    assert allowed.status_code == 201, allowed.text
    assert allowed.json()["role"]["badge"]["tier"] == "staff"


def test_a_bad_badge_is_refused_by_name_and_nothing_is_created(client: TestClient):
    token = _session(owner=True)
    reply = _create(client, token, "Odd", badge={"tone": "neon", "glyph": "film"})
    assert reply.status_code == 400
    assert reply.json()["details"]["field"] == "badge.tone"
    assert "odd" not in _roles(client, token)


def test_updating_changes_keeps_or_removes_the_badge(client: TestClient):
    token = _session(owner=True)
    _create(client, token, "Coach", badge={"tone": "violet", "glyph": "target"})
    put = lambda **extra: client.put("/api/v1/system/roles/coach", json={"auth_token": token, "role_name": "Coach", "privileges_ids": [], **extra})

    assert put(badge={"tone": "sage", "glyph": "star"}).json()["role"]["badge"] == {"tier": "community", "tone": "sage", "glyph": "star"}
    assert put().json()["role"]["badge"]["glyph"] == "star"  # nothing said: kept
    assert put(remove_badge=True).json()["role"]["badge"] is None


def test_losing_the_moderation_privilege_is_refused_while_the_staff_badge_stays(client: TestClient):
    token = _session(owner=True)
    _create(client, token, "Warden", ["ban_users"], {"tier": "staff", "tone": "coral", "glyph": "key"})
    reply = client.put("/api/v1/system/roles/warden", json={"auth_token": token, "role_name": "Warden", "privileges_ids": ["send_messages"]})
    assert reply.status_code == 400
    assert reply.json()["details"]["field"] == "badge.tier"
    # ...but it can lose both at once
    done = client.put("/api/v1/system/roles/warden", json={"auth_token": token, "role_name": "Warden", "privileges_ids": ["send_messages"], "remove_badge": True})
    assert done.status_code == 200, done.text


def test_only_the_owner_gives_a_role_a_badge(client: TestClient):
    member = _session(owner=False)
    assert _create(client, member, "Sneaky", badge={"tone": "sky", "glyph": "film"}).status_code == 403


def test_a_server_has_at_most_fifty_badged_roles(client: TestClient):
    token = _session(owner=True)
    for i in range(MAX_BADGED_ROLES):
        assert _create(client, token, f"Role {i}", badge={"tone": "sky", "glyph": "film"}).status_code == 201
    over = _create(client, token, "One more", badge={"tone": "sky", "glyph": "film"})
    assert over.status_code == 400
    assert over.json()["details"]["limit"] == MAX_BADGED_ROLES
    assert _create(client, token, "No badge needed").status_code == 201


def test_a_person_carries_the_badges_of_their_roles(client: TestClient):
    token = _session(owner=True)
    _create(client, token, "Clip judge", badge={"tone": "violet", "glyph": "film"})
    user = api_initializer.user_manager.sign_up(username=f"judge_{uuid.uuid4().hex[:5]}", password="12345678")
    assert client.put(f"/api/v1/system/users/{user.user_id}/roles", json={"auth_token": token, "roles_ids": ["clip-judge"]}).status_code == 200

    profile = client.post("/api/v1/users/profile", json={"auth_token": token, "user_id": str(user.user_id)}).json()["user_data"]
    assert [r["badge"] for r in profile["resolved_roles"]] == [{"tier": "community", "tone": "violet", "glyph": "film"}]


def _upload(client: TestClient, token: str, content: bytes, name: str = "badge.png"):
    return client.post("/api/v1/system/role-badge-images", data={"auth_token": token}, files={"file": (name, content, "image/png")})


def test_a_badge_picture_is_uploaded_and_used(client: TestClient, tmp_path: Path):
    token = _session(owner=True)
    _point_storage_at(tmp_path)

    up = _upload(client, token, _png())
    assert up.status_code == 201, up.text
    url = up.json()["url"]
    assert url.startswith("/storage/")

    made = _create(client, token, "Artist", badge={"tone": "violet", "glyph": "image", "image_url": url})
    assert made.status_code == 201, made.text
    assert made.json()["role"]["badge"]["image_url"] == url
    assert client.get(url).status_code == 200


def test_a_picture_that_is_not_a_128_square_png_is_refused(client: TestClient, tmp_path: Path):
    token = _session(owner=True)
    _point_storage_at(tmp_path)
    for content in (_png((64, 64)), _png(fmt="GIF"), b"not a picture"):
        reply = _upload(client, token, content)
        assert reply.status_code == 400, reply.text
        assert reply.json()["details"]["field"] == "file"


def test_only_the_owner_uploads_badge_pictures(client: TestClient, tmp_path: Path):
    _point_storage_at(tmp_path)
    assert _upload(client, _session(owner=False), _png()).status_code == 403
