"""Default avatars and banners are real hosted files, assigned from an id.

Every client follows `avatar_url` / `banner_url`, so the art has to be served from the instance and
the URLs have to be in the data. The first half tests the selection and the files; the second sends
real requests through the application.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from pufferblow.api.utils.default_art import (
    ASSET_ROOT,
    EXPRESSIONS,
    TONES,
    asset_file,
    default_avatar_url,
    default_banner_url,
    is_default_art_url,
    plan_appearance_update,
)
from pufferblow.core.bootstrap import api_initializer


# ── the set ───────────────────────────────────────────────────────


def test_every_tone_and_expression_ships_as_svg_and_png_for_avatars_and_banners():
    for tone in TONES:
        for expression in EXPRESSIONS:
            for folder, kind in (("avatars", "avatar"), ("banners", "banner")):
                for suffix in ("svg", "png"):
                    assert (ASSET_ROOT / folder / f"pb-{kind}-{expression}-{tone}.{suffix}").is_file(), (folder, expression, tone, suffix)


def test_the_files_carry_no_provenance_blob_and_the_pngs_are_real_images():
    for svg in ASSET_ROOT.glob("*/*.svg"):
        text = svg.read_text(encoding="utf-8")
        assert "c2pa" not in text and "<metadata" not in text, svg.name
    for png in ASSET_ROOT.glob("*/*.png"):
        assert png.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n", png.name


# ── choosing ──────────────────────────────────────────────────────


def test_the_same_id_always_gets_the_same_art_and_different_ids_spread_out():
    assert default_avatar_url("user-1") == default_avatar_url("user-1")
    assert default_banner_url("user-1") == default_banner_url("user-1")
    picks = {default_avatar_url(str(uuid.UUID(int=i))) for i in range(400)}
    assert len(picks) > 40  # 72 are possible; a spread, not a pile-up


def test_a_banner_shares_its_avatars_tone():
    for seed in ("a", "b", "c", "an-id", str(uuid.uuid4())):
        avatar_tone = default_avatar_url(seed).rsplit("-", 1)[1].split(".")[0]
        banner_tone = default_banner_url(seed).rsplit("-", 1)[1].split(".")[0]
        assert avatar_tone == banner_tone


def test_urls_are_server_relative_and_recognised_as_default_art():
    url = default_avatar_url("x")
    assert url.startswith("/assets/avatars/pb-avatar-") and url.endswith(".svg")
    assert default_avatar_url("x", "png").endswith(".png")
    assert is_default_art_url(url) and is_default_art_url("https://chat.example/assets/banners/pb-banner-wink-sky.png?v=1")
    assert not is_default_art_url("/storage/" + "a" * 64) and not is_default_art_url(None) and not is_default_art_url("")


def test_only_files_of_the_set_resolve():
    assert asset_file("avatars", "pb-avatar-happy-brass.svg") is not None
    assert asset_file("banners", "pb-banner-wink-sky.png") is not None
    for folder, name in [
        ("avatars", "../default-art/avatars/pb-avatar-happy-brass.svg"),
        ("avatars", "..%2f..%2fapi.py"),
        ("avatars", "pb-avatar-happy-brass.svg.exe"),
        ("avatars", "nope.svg"),
        ("secrets", "pb-avatar-happy-brass.svg"),
        ("avatars", "pb-avatar-happy-brass"),
        ("avatars", ".png"),
    ]:
        assert asset_file(folder, name) is None, (folder, name)


# ── changing appearance ───────────────────────────────────────────

_DEFAULT_AVATAR = default_avatar_url("u1")
_DEFAULT_BANNER = default_banner_url("u1")
_UPLOAD = "/storage/" + "b" * 64


def _plan(**kw):
    base = dict(
        stable_id="u1",
        current_seed="u1",
        current_avatar_url=_DEFAULT_AVATAR,
        current_banner_url=_DEFAULT_BANNER,
        avatar_kind=None,
        banner_kind=None,
        new_seed=None,
    )
    return plan_appearance_update(**{**base, **kw})


def test_shuffling_repaints_the_default_art_from_the_new_seed():
    plan = _plan(new_seed="fresh-seed")
    assert plan.avatar_url == default_avatar_url("fresh-seed")
    assert plan.banner_url == default_banner_url("fresh-seed")


def test_shuffling_leaves_an_upload_alone():
    plan = _plan(current_avatar_url=_UPLOAD, current_banner_url=_UPLOAD, new_seed="fresh-seed")
    assert plan.avatar_url is None and plan.banner_url is None


def test_going_back_to_the_default_art_replaces_an_upload():
    plan = _plan(current_avatar_url=_UPLOAD, current_banner_url=_UPLOAD, avatar_kind="identicon", banner_kind="default")
    assert plan.avatar_url == _DEFAULT_AVATAR and plan.banner_url == _DEFAULT_BANNER


def test_image_is_only_honoured_while_there_is_an_upload_to_go_back_to():
    nothing = _plan(avatar_kind="image", banner_kind="image")
    assert nothing.avatar_kind is None and nothing.banner_kind is None  # the default art stays
    upload = _plan(current_avatar_url=_UPLOAD, current_banner_url=_UPLOAD, avatar_kind="image", banner_kind="image")
    assert upload.avatar_kind == "image" and upload.banner_kind == "image" and upload.avatar_url is None


def test_a_solid_banner_clears_the_banner_image():
    plan = _plan(banner_kind="solid")
    assert plan.banner_kind == "solid" and plan.banner_url == ""


# ── through the application ───────────────────────────────────────


def _signup(client: TestClient, monkeypatch) -> tuple[str, str]:
    # The SQLite test database has no `server` row, yet signup refuses to run without one.
    monkeypatch.setattr(api_initializer.database_handler, "get_server", lambda: object(), raising=False)
    response = client.post("/api/v1/users/signup", json={"username": f"art_{uuid.uuid4().hex[:8]}", "password": "12345678"})
    assert response.status_code == 201, response.text
    body = response.json()
    return body["auth_token"], body.get("user_id") or ""


def test_the_asset_route_serves_svg_and_png_publicly_with_long_cache(client: TestClient):
    svg = client.get("/assets/avatars/pb-avatar-happy-brass.svg")  # no credential
    assert svg.status_code == 200
    assert svg.headers["content-type"].startswith("image/svg+xml")
    assert "immutable" in svg.headers["cache-control"] and "max-age=31536000" in svg.headers["cache-control"]
    assert svg.headers["access-control-allow-origin"] == "*"
    assert b"<svg" in svg.content

    png = client.get("/assets/banners/pb-banner-happy-brass.png")
    assert png.status_code == 200 and png.headers["content-type"] == "image/png" and png.content[:4] == b"\x89PNG"


@pytest.mark.parametrize("path", [
    "/assets/avatars/nope.svg",
    "/assets/avatars/pb-avatar-happy-brass.gif",
    "/assets/banners/pb-avatar-happy-brass.svg",
    "/assets/avatars/..%2f..%2fapi.py",
    "/assets/avatars/%2e%2e/%2e%2e/api.py",
])
def test_the_asset_route_serves_nothing_else(client: TestClient, path: str):
    assert client.get(path).status_code in (400, 404)


def test_a_new_account_gets_default_art_in_its_profile(client: TestClient, monkeypatch):
    token, _ = _signup(client, monkeypatch)
    profile = client.post("/api/v1/users/profile", json={"auth_token": token}).json()["user_data"]
    assert profile["avatar_url"].startswith("/assets/avatars/pb-avatar-")
    assert profile["banner_url"].startswith("/assets/banners/pb-banner-")
    assert profile["avatar_kind"] == "identicon" and profile["banner_kind"] == "default"
    # ...and the very URL it was given is a real image.
    assert client.get(profile["avatar_url"]).status_code == 200
    assert client.get(profile["banner_url"]).status_code == 200


def test_shuffling_through_the_appearance_route_changes_the_hosted_art(client: TestClient, monkeypatch):
    token, _ = _signup(client, monkeypatch)
    before = client.post("/api/v1/users/profile", json={"auth_token": token}).json()["user_data"]
    changed = set()
    for _ in range(6):  # a shuffle can land on the same art; six in a row will not
        reply = client.put("/api/v1/users/profile/appearance", json={"auth_token": token, "shuffle_avatar_seed": True})
        assert reply.status_code == 200, reply.text
        assert reply.json()["avatar_url"].startswith("/assets/avatars/")
        changed.add(reply.json()["avatar_url"])
    after = client.post("/api/v1/users/profile", json={"auth_token": token}).json()["user_data"]
    assert after["avatar_url"] in changed and (len(changed) > 1 or after["avatar_url"] != before["avatar_url"])


def test_a_solid_banner_clears_the_url_and_default_brings_it_back(client: TestClient, monkeypatch):
    token, _ = _signup(client, monkeypatch)
    client.put("/api/v1/users/profile/appearance", json={"auth_token": token, "banner_kind": "solid"})
    solid = client.post("/api/v1/users/profile", json={"auth_token": token}).json()["user_data"]
    assert not solid.get("banner_url") and solid["banner_kind"] == "solid"
    client.put("/api/v1/users/profile/appearance", json={"auth_token": token, "banner_kind": "default"})
    back = client.post("/api/v1/users/profile", json={"auth_token": token}).json()["user_data"]
    assert back["banner_url"].startswith("/assets/banners/")
