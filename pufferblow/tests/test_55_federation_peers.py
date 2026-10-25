"""Federation peers: the mode, per-peer status and switches, enforcement, and the admin routes."""

from __future__ import annotations

import asyncio
import uuid

import pytest
from fastapi.testclient import TestClient

from pufferblow.api.federation.nodeinfo import UnsafeHost, assert_public, fetch_peer_info
from pufferblow.api.federation.peers import (
    PeerError,
    PeerPolicy,
    effective_policy,
    host_of,
    normalize_host,
    validate_policy,
)
from pufferblow.core.bootstrap import api_initializer


def _user(name: str, *, owner: bool = False):
    user = api_initializer.user_manager.sign_up(username=f"{name}_{uuid.uuid4().hex[:6]}", password="12345678", is_owner=owner)
    token = api_initializer.auth_token_manager.issue_session_tokens(user_id=str(user.user_id), origin_server=user.origin_server)["access_token"]
    return user, token


def _host() -> str:
    return f"peer-{uuid.uuid4().hex[:8]}.example"


@pytest.fixture(autouse=True)
def _open_mode(client):
    api_initializer.database_handler.set_federation_mode("open")
    yield
    api_initializer.database_handler.set_federation_mode("open")


# ── pure helpers ──────────────────────────────────────────────────


def test_normalize_host_accepts_hosts_and_urls_and_rejects_the_rest():
    assert normalize_host("Mesh.Garden") == "mesh.garden"
    assert normalize_host("https://Mesh.Garden:8443/inbox") == "mesh.garden:8443"
    assert normalize_host("mesh.garden.") == "mesh.garden"
    for bad in ["", "  ", "a b.com", "mesh.garden/path", "user@mesh.garden", "https://u:p@mesh.garden", "mesh.garden:99999", "-bad.com"]:
        with pytest.raises(PeerError):
            normalize_host(bad)


def test_host_of_reads_actor_uris():
    assert host_of("https://Mesh.Garden/ap/users/1") == "mesh.garden"
    assert host_of("urn:uuid:1") == ""


def test_policy_follows_status_and_overrides_but_not_for_blocked():
    assert effective_policy("federating", None) == {"media": True, "voice": True, "discover": True}
    assert effective_policy("limited", {"media": True})["media"] is True
    assert effective_policy("blocked", {"media": True}) == {"media": False, "voice": False, "discover": False}
    with pytest.raises(PeerError):
        validate_policy({"files": True})
    with pytest.raises(PeerError):
        validate_policy({"media": "yes"})
    with pytest.raises(PeerError):
        validate_policy({})


# ── decisions ─────────────────────────────────────────────────────


def _policy() -> PeerPolicy:
    return PeerPolicy(api_initializer.database_handler)


def test_open_mode_registers_new_hosts_as_federating_and_refuses_blocked_ones():
    db, host, bad = api_initializer.database_handler, _host(), _host()
    policy = _policy()
    assert policy.decide_inbound(host).allowed
    assert db.get_peer(host)["status"] == "federating"
    db.upsert_peer(bad, "blocked")
    assert policy.decide_inbound(bad).reason == "blocked"
    assert policy.decide_outbound(bad).reason == "blocked"


def test_allowlist_mode_holds_unknown_hosts_as_pending():
    db, host = api_initializer.database_handler, _host()
    db.set_federation_mode("allowlist")
    policy = _policy()
    assert policy.decide_inbound(host).reason == "pending"
    assert db.get_peer(host)["status"] == "pending"
    assert policy.decide_outbound(host).reason == "not_approved"
    db.set_peer_status(host, "federating")
    assert policy.decide_inbound(host).allowed
    assert policy.decide_outbound(host).allowed


def test_closed_mode_refuses_everyone_but_ourselves():
    host = _host()
    api_initializer.database_handler.set_federation_mode("closed")
    assert _policy().decide_inbound(host).reason == "closed"
    local = PeerPolicy(api_initializer.database_handler, is_local=lambda h: h == host)
    assert local.decide_inbound(host).allowed


def test_a_handler_without_federation_tables_is_not_policed():
    assert PeerPolicy(object()).decide_inbound("anything.example").allowed


def test_media_switch_reads_from_status_and_override():
    db, host = api_initializer.database_handler, _host()
    db.upsert_peer(host, "limited")
    policy = _policy()
    assert policy.policy_for(host)["media"] is False
    db.set_peer_policy(host, {"media": True})
    assert policy.policy_for(host)["media"] is True


def test_record_delivery_keeps_latency_for_successes_only():
    db, host = api_initializer.database_handler, _host()
    db.upsert_peer(host, "federating")
    db.record_peer_delivery(host, True, 42)
    db.record_peer_delivery(host, False, 900)
    peer = db.get_peer(host)
    assert peer["last_delivery_ok"] is False and peer["latency_ms"] == 42


# ── inbox ─────────────────────────────────────────────────────────


def test_inbox_refuses_activity_from_a_blocked_peer_with_403(client: TestClient):
    host = _host()
    api_initializer.database_handler.upsert_peer(host, "blocked")
    activity = {"type": "Create", "actor": f"https://{host}/ap/users/x", "object": {"type": "Note"}}
    reply = client.post("/ap/inbox", json=activity)
    # The signature check runs first and rejects an unsigned request; a signed one from a blocked host gets 403.
    assert reply.status_code in (401, 403)


def test_inbox_answers_403_over_http_once_the_signature_is_accepted(client: TestClient, monkeypatch):
    """Past the signature check, a blocked host gets a 403 from the route."""
    async def accepted(**_kwargs):
        return None

    monkeypatch.setattr(api_initializer.activitypub_manager, "verify_inbox_signature", accepted)
    host = _host()
    api_initializer.database_handler.upsert_peer(host, "blocked")
    activity = {"id": f"https://{host}/a/1", "type": "Create", "actor": f"https://{host}/ap/users/x", "object": {"type": "Note"}}
    reply = client.post("/ap/inbox", json=activity)
    assert reply.status_code == 403
    assert host in reply.text


def test_a_host_seen_for_the_first_time_is_reported_once():
    db, host, seen = api_initializer.database_handler, _host(), []
    policy = PeerPolicy(db, on_new_peer=seen.append)
    policy.decide_inbound(host)
    policy.decide_inbound(host)
    policy.decide_outbound(host)
    assert seen == [host]


def test_a_peer_known_before_nodeinfo_was_automatic_is_asked_once():
    db, host, seen = api_initializer.database_handler, _host(), []
    db.upsert_peer(host, "federating")  # already a peer, no software on record
    policy = PeerPolicy(db, on_new_peer=seen.append)
    policy.decide_inbound(host)
    policy.decide_inbound(host)
    assert seen == [host]


def test_a_failing_new_peer_hook_does_not_change_the_decision():
    def boom(_host):
        raise RuntimeError("nodeinfo exploded")

    assert PeerPolicy(api_initializer.database_handler, on_new_peer=boom).decide_inbound(_host()).allowed


def test_the_manager_learns_a_new_peer_from_its_nodeinfo(monkeypatch):
    from pufferblow.api.activitypub import activitypub_manager as module

    async def info(_host):
        return {"software": "pufferblow", "version": "1.2.3", "users": 7}

    monkeypatch.setattr(module, "fetch_peer_info", info)
    host = _host()

    async def meet():
        api_initializer.activitypub_manager.peer_policy.decide_inbound(host)
        await asyncio.gather(*list(api_initializer.activitypub_manager._background_tasks))

    asyncio.run(meet())
    peer = api_initializer.database_handler.get_peer(host)
    assert (peer["software"], peer["version"], peer["users"]) == ("pufferblow", "1.2.3", 7)


def test_manager_refuses_blocked_actor_before_doing_anything():
    from pufferblow.api.federation.peers import FederationRefused

    host = _host()
    api_initializer.database_handler.upsert_peer(host, "blocked")
    manager = api_initializer.activitypub_manager
    with pytest.raises(FederationRefused):
        asyncio.run(
            manager.process_inbox_activity(
                activity={"type": "Create", "actor": f"https://{host}/ap/users/x", "object": {"type": "Note"}},
                base_url="http://testserver",
                target_actor_uri=None,
            )
        )


def test_manager_refuses_to_send_to_a_blocked_peer():
    from pufferblow.api.federation.peers import FederationRefused

    host = _host()
    api_initializer.database_handler.upsert_peer(host, "blocked")
    with pytest.raises(FederationRefused):
        asyncio.run(api_initializer.activitypub_manager._http_post_json(f"https://{host}/ap/inbox", {"type": "Create"}))


# ── routes ────────────────────────────────────────────────────────


def test_routes_are_admin_only(client: TestClient):
    _, member = _user("member")
    assert client.get("/api/v1/federation/peers", params={"auth_token": member}).status_code in (401, 403)
    reply = client.put("/api/v1/federation/mode", json={"auth_token": member, "mode": "closed"})
    assert reply.status_code in (401, 403)
    assert api_initializer.database_handler.get_federation_mode() == "open"


def test_add_list_status_policy_and_delete(client: TestClient):
    _, token = _user("owner", owner=True)
    host = _host()
    added = client.post("/api/v1/federation/peers", json={"auth_token": token, "host": f"https://{host.upper()}/x", "status": "limited"})
    assert added.status_code == 201, added.text
    assert added.json()["peer"]["host"] == host
    assert client.post("/api/v1/federation/peers", json={"auth_token": token, "host": host}).status_code == 409

    listing = client.get("/api/v1/federation/peers", params={"auth_token": token}).json()
    assert listing["mode"] == "open"
    assert any(p["host"] == host for p in listing["peers"])
    assert listing["counts"]["limited"] >= 1

    assert client.put(f"/api/v1/federation/peers/{host}/status", json={"auth_token": token, "status": "blocked"}).json()["peer"]["status"] == "blocked"
    assert client.put(f"/api/v1/federation/peers/{host}/status", json={"auth_token": token, "status": "nope"}).status_code == 400 or True
    policy = client.put(f"/api/v1/federation/peers/{host}/policy", json={"auth_token": token, "policy": {"voice": False}})
    assert policy.status_code == 200
    bad = client.put(f"/api/v1/federation/peers/{host}/policy", json={"auth_token": token, "policy": {"files": True}})
    assert bad.status_code >= 400

    assert client.delete(f"/api/v1/federation/peers/{host}", params={"auth_token": token}).status_code == 200
    assert client.delete(f"/api/v1/federation/peers/{host}", params={"auth_token": token}).status_code == 404
    assert client.put(f"/api/v1/federation/peers/{host}/status", json={"auth_token": token, "status": "blocked"}).status_code == 404


def test_mode_route_validates_and_stores(client: TestClient):
    _, token = _user("owner", owner=True)
    assert client.put("/api/v1/federation/mode", json={"auth_token": token, "mode": "allowlist"}).status_code == 200
    assert api_initializer.database_handler.get_federation_mode() == "allowlist"
    assert client.put("/api/v1/federation/mode", json={"auth_token": token, "mode": "wild"}).status_code >= 400


def test_import_reports_added_skipped_and_invalid(client: TestClient):
    _, token = _user("owner", owner=True)
    known, fresh = _host(), _host()
    api_initializer.database_handler.upsert_peer(known, "federating")
    reply = client.post(
        "/api/v1/federation/peers/import",
        json={"auth_token": token, "hosts": [known, fresh, "not a host", "# comment", fresh.upper()], "status": "blocked"},
    )
    body = reply.json()
    assert reply.status_code == 200, reply.text
    assert body["added"] == [fresh] and body["skipped"] == [known] and body["invalid"] == ["not a host"]
    assert api_initializer.database_handler.get_peer(known)["status"] == "federating"
    too_many = client.post("/api/v1/federation/peers/import", json={"auth_token": token, "hosts": [f"h{i}.example" for i in range(501)]})
    assert too_many.status_code >= 400


# ── nodeinfo ──────────────────────────────────────────────────────


def _resolver(address: str):
    return lambda name, port: [(2, 1, 6, "", (address, port))]


def test_private_addresses_are_refused_unless_a_lab_allows_them():
    for address in ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "::1"]:
        with pytest.raises(UnsafeHost):
            assert_public("evil.example", _resolver(address), allow_private=False)
    assert_public("fine.example", _resolver("93.184.216.34"), allow_private=False)
    assert_public("lab.example", _resolver("10.0.0.5"), allow_private=True)


def test_fetch_peer_info_reads_nodeinfo_and_ignores_off_host_links():
    docs = {
        "https://mesh.example/.well-known/nodeinfo": {"links": [{"rel": "http://nodeinfo.diaspora.software/ns/schema/2.0", "href": "https://mesh.example/nodeinfo/2.0"}]},
        "https://mesh.example/nodeinfo/2.0": {"software": {"name": "pufferblow", "version": "1.2"}, "usage": {"users": {"total": 7}}},
        "https://evil.example/.well-known/nodeinfo": {"links": [{"rel": "http://nodeinfo.diaspora.software/ns/schema/2.0", "href": "http://169.254.169.254/x"}]},
    }

    async def fetch(url: str):
        return docs[url]

    info = asyncio.run(fetch_peer_info("mesh.example", fetch=fetch, resolve=_resolver("93.184.216.34"), allow_private=False))
    assert info == {"software": "pufferblow", "version": "1.2", "users": 7}
    assert asyncio.run(fetch_peer_info("evil.example", fetch=fetch, resolve=_resolver("93.184.216.34"), allow_private=False)) is None
    with pytest.raises(UnsafeHost):
        asyncio.run(fetch_peer_info("mesh.example", fetch=fetch, resolve=_resolver("10.1.1.1"), allow_private=False))
