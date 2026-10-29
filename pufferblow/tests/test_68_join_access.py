"""Who may join: the join mode, invitation codes, requests to join, and joining with an account from another server."""

from __future__ import annotations

import time
import uuid
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from pufferblow.api.activitypub.activitypub_manager import ActivityPubManager
from pufferblow.api.database.tables.declarative_base import Base
from pufferblow.api.errors import ApiError
from pufferblow.api.federation.identity_assertion import (
    AssertionInvalid,
    sign_assertion,
    verify_assertion,
)
from pufferblow.api.models.config_model import instance_id_of
from pufferblow.core.bootstrap import api_initializer

HOME = "home.example:7001"


@pytest.fixture(autouse=True)
def _activitypub_tables(client):
    """The SQLite test database has no ActivityPub tables; joining from another server stores the person's actor."""
    import pufferblow.api.database.tables.activitypub  # noqa: F401

    Base.metadata.create_all(api_initializer.database_handler.database_engine, tables=[t for t in Base.metadata.sorted_tables if t.name.startswith("activitypub")])
    api_initializer.database_handler.set_federation_mode("open")
    api_initializer.database_handler.set_join_mode("open")
    yield


def _token(user) -> str:
    return api_initializer.auth_token_manager.issue_session_tokens(user_id=str(user.user_id), origin_server=user.origin_server)["access_token"]


def _staff(role: str | None = None):
    user = api_initializer.user_manager.sign_up(username=f"{role or 'owner'}_{uuid.uuid4().hex[:6]}", password="12345678", is_owner=role is None)
    if role:
        api_initializer.database_handler.update_user_roles(str(user.user_id), [role])
    return user, _token(user)


def _mode(owner_token: str, client: TestClient, mode: str):
    return client.put("/api/v1/system/server-info", json={"auth_token": owner_token, "join_mode": mode})


def _signup(client: TestClient, **extra):
    return client.post("/api/v1/users/signup", json={"username": f"person_{uuid.uuid4().hex[:8]}", "password": "12345678", **extra})


def _code(client: TestClient, token: str, **limits) -> str:
    response = client.post("/api/v1/server/invites", json={"auth_token": token, **limits})
    assert response.status_code == 201, response.text
    return response.json()["invite"]["code"]


# ── the join mode ─────────────────────────────────────────────────


def test_the_public_server_info_says_who_may_join(client: TestClient):
    _, owner = _staff()
    assert client.get("/api/v1/system/server-info").json()["server_info"]["join_mode"] == "open"
    assert _mode(owner, client, "request").status_code == 200
    assert client.get("/api/v1/system/server-info").json()["server_info"]["join_mode"] == "request"


def test_only_someone_who_manages_settings_can_change_it(client: TestClient):
    person = api_initializer.user_manager.sign_up(username=f"plain_{uuid.uuid4().hex[:6]}", password="12345678")
    assert _mode(_token(person), client, "invite").status_code in (401, 403)
    assert api_initializer.database_handler.get_join_mode() == "open"


def test_an_unknown_mode_is_refused(client: TestClient):
    _, owner = _staff()
    assert _mode(owner, client, "whenever").status_code in (400, 422)


# ── signing up ────────────────────────────────────────────────────


def test_an_open_server_lets_anyone_sign_up(client: TestClient):
    assert _signup(client).status_code == 201


def test_an_invite_only_server_needs_a_code_and_spends_it(client: TestClient):
    _, owner = _staff()
    _mode(owner, client, "invite")
    refused = _signup(client)
    assert refused.status_code == 403 and refused.json()["error_code"] == "join.invite_required"

    code = _code(client, owner, max_uses=1)
    assert _signup(client, invite_code=code).status_code == 201
    again = _signup(client, invite_code=code)
    assert again.status_code == 403 and again.json()["error_code"] == "join.invite_invalid"


def test_a_wrong_expired_or_revoked_code_all_look_the_same(client: TestClient):
    _, owner = _staff()
    _mode(owner, client, "invite")
    revoked = _code(client, owner)
    assert client.delete(f"/api/v1/server/invites/{revoked}", params={"auth_token": owner}).status_code == 200
    expired = _code(client, owner)
    api_initializer.database_handler.database_session  # noqa: B018  (keep the handler warm)
    from sqlalchemy import update

    from pufferblow.api.database.tables.server_access import ServerInvites
    from datetime import datetime, timedelta, timezone

    with api_initializer.database_handler.database_session() as session:
        session.execute(update(ServerInvites).where(ServerInvites.code == expired).values(expires_at=datetime.now(timezone.utc) - timedelta(hours=1)))
        session.commit()
    answers = [_signup(client, invite_code=value).json() for value in ("NOTACODE1234", revoked, expired)]
    assert {a["error_code"] for a in answers} == {"join.invite_invalid"}
    assert len({a["user_message"] if "user_message" in a else a.get("message") for a in answers}) == 1


def test_a_code_with_one_use_left_goes_to_one_person_when_two_race(client: TestClient):
    _, owner = _staff()
    _mode(owner, client, "invite")
    code = _code(client, owner, max_uses=1)
    results = [api_initializer.database_handler.redeem_invite(code) for _ in range(5)]
    assert results.count(True) == 1


def test_a_request_server_holds_the_account_until_it_is_decided(client: TestClient):
    owner_user, owner = _staff()
    _mode(owner, client, "request")
    username = f"asker_{uuid.uuid4().hex[:6]}"
    response = client.post("/api/v1/users/signup", json={"username": username, "password": "12345678", "message": "hi, I know alice"})
    assert response.status_code == 202 and response.json()["status"] == "pending"
    assert "auth_token" not in response.json()

    blocked = client.post("/api/v1/users/signin", json={"username": username, "password": "12345678"})
    assert blocked.status_code == 403 and blocked.json()["error_code"] == "auth.membership_pending"
    wrong = client.post("/api/v1/users/signin", json={"username": username, "password": "not-it"})
    assert wrong.json()["error_code"] == "auth.invalid_credentials"  # who is waiting is not given away

    [asked] = client.get("/api/v1/server/join-requests", params={"auth_token": owner, "status": "pending"}).json()["requests"]
    assert (asked["handle"], asked["kind"], asked["message"]) == (username, "local", "hi, I know alice")
    approved = client.post(f"/api/v1/server/join-requests/{asked['request_id']}/approve", json={"auth_token": owner})
    assert approved.status_code == 200 and approved.json()["pending"] == 0
    assert client.post("/api/v1/users/signin", json={"username": username, "password": "12345678"}).status_code == 200
    assert client.post(f"/api/v1/server/join-requests/{asked['request_id']}/approve", json={"auth_token": owner}).status_code == 404  # already decided
    assert owner_user is not None


def test_a_denied_request_stays_out_and_a_code_skips_the_wait(client: TestClient):
    _, owner = _staff()
    _mode(owner, client, "request")
    username = f"nope_{uuid.uuid4().hex[:6]}"
    client.post("/api/v1/users/signup", json={"username": username, "password": "12345678"})
    [asked] = client.get("/api/v1/server/join-requests", params={"auth_token": owner}).json()["requests"]
    assert client.post(f"/api/v1/server/join-requests/{asked['request_id']}/deny", json={"auth_token": owner}).status_code == 200
    denied = client.post("/api/v1/users/signin", json={"username": username, "password": "12345678"})
    assert denied.json()["error_code"] == "auth.membership_denied"
    assert _signup(client, invite_code=_code(client, owner)).status_code == 201


# ── who can decide ────────────────────────────────────────────────


def test_a_moderator_can_decide_and_make_codes_but_a_member_cannot(client: TestClient):
    _, owner = _staff()
    _mode(owner, client, "request")
    _, moderator = _staff("moderator")
    member = api_initializer.user_manager.sign_up(username=f"member_{uuid.uuid4().hex[:6]}", password="12345678")
    for route in ("/api/v1/server/invites", "/api/v1/server/join-requests"):
        assert client.get(route, params={"auth_token": moderator}).status_code == 200
        assert client.get(route, params={"auth_token": _token(member)}).status_code == 403
    assert client.post("/api/v1/server/invites", json={"auth_token": _token(member)}).status_code == 403
    assert _code(client, moderator, note="for the mods' friend", expires_in_hours=2)


def test_the_codes_list_says_how_each_stands(client: TestClient):
    _, owner = _staff()
    used, spare = _code(client, owner, max_uses=1), _code(client, owner)
    api_initializer.database_handler.redeem_invite(used)
    states = {i["code"]: i["state"] for i in client.get("/api/v1/server/invites", params={"auth_token": owner}).json()["invites"]}
    assert states == {used: "used_up", spare: "active"}


# ── identity assertions ───────────────────────────────────────────


def _keys():
    public, private = ActivityPubManager._generate_keypair()
    return public, private


def test_an_assertion_checks_out_only_for_the_right_server_key_and_time():
    public, private = _keys()
    other_public, _ = _keys()
    token = sign_assertion(private_key_pem=private, handle=f"alice@{HOME}", actor_uri=f"http://{HOME}/ap/users/1", issuer=HOME, audience="there.example:7002")
    claims = verify_assertion(token, public_key_pem=public, audience="there.example:7002")
    assert claims["sub"] == f"alice@{HOME}"
    for bad in (
        dict(public_key_pem=other_public, audience="there.example:7002"),
        dict(public_key_pem=public, audience="elsewhere.example:7003"),
        dict(public_key_pem=public, audience="there.example:7002", now=time.time() + 600),
    ):
        with pytest.raises(AssertionInvalid):
            verify_assertion(token, **bad)
    with pytest.raises(AssertionInvalid):
        verify_assertion(token[:-4] + "AAAA", public_key_pem=public, audience="there.example:7002")


# ── joining with an account from another server ───────────────────


class _Remote:
    """Another server's person, as this server's federation lookups would find them."""

    def __init__(self, name: str = "alice", host: str = HOME):
        self.name, self.host = name, host
        self.public, self.private = _keys()
        self.actor_uri = f"http://{host}/ap/users/{uuid.uuid4()}"
        self.row = SimpleNamespace(
            actor_uri=self.actor_uri,
            preferred_username=name,
            inbox_uri=f"{self.actor_uri}/inbox",
            outbox_uri=f"{self.actor_uri}/outbox",
            shared_inbox_uri=f"http://{host}/ap/inbox",
            public_key_pem=self.public,
            user_id=None,
        )

    def assertion(self, audience: str | None = None) -> str:
        return sign_assertion(
            private_key_pem=self.private,
            handle=f"{self.name}@{self.host}",
            actor_uri=self.actor_uri,
            issuer=self.host,
            audience=audience or instance_id_of(api_initializer.config),
        )


@pytest.fixture
def remote(client, monkeypatch):
    # The made-up home host does not resolve; the check that real ones are public is tested on its own below.
    monkeypatch.setattr("pufferblow.api.routes.federation_join.assert_public", lambda host: None)
    person = _Remote()

    async def fetch(actor_uri: str, **_):
        if actor_uri != person.actor_uri:
            raise ValueError("unknown actor")
        stored = api_initializer.database_handler.get_activitypub_actor_by_uri(actor_uri=actor_uri)
        return stored if stored is not None else person.row

    monkeypatch.setattr(api_initializer.activitypub_manager, "fetch_remote_actor", fetch)
    return person


def _join(client: TestClient, remote: _Remote, **extra):
    return client.post("/api/v1/federation/join", json={"assertion": remote.assertion(), **extra})


def test_someone_from_another_server_joins_an_open_server_with_no_new_account(client: TestClient, remote: _Remote):
    response = _join(client, remote)
    assert response.status_code == 200, response.text
    joined = response.json()
    assert joined["status"] == "joined"
    # They are a member here and can use this server with the tokens it gave them.
    profile = client.post("/api/v1/users/profile", json={"auth_token": joined["auth_token"]})
    assert profile.status_code == 200
    assert profile.json()["user_data"]["origin_server"] == HOME
    assert client.post("/api/v1/channels/list/", json={"auth_token": joined["auth_token"]}).status_code == 200


def test_joining_twice_is_the_same_member(client: TestClient, remote: _Remote):
    first = _join(client, remote).json()
    second = _join(client, remote).json()
    assert first["user"]["user_id"] == second["user"]["user_id"]


def test_an_assertion_works_once_only(client: TestClient, remote: _Remote):
    token = remote.assertion()
    assert client.post("/api/v1/federation/join", json={"assertion": token}).status_code == 200
    replay = client.post("/api/v1/federation/join", json={"assertion": token})
    assert replay.status_code == 401 and replay.json()["error_code"] == "join.assertion_invalid"


def test_an_assertion_for_another_server_is_refused(client: TestClient, remote: _Remote):
    response = client.post("/api/v1/federation/join", json={"assertion": remote.assertion(audience="somewhere-else.example:7002")})
    assert response.status_code == 401 and response.json()["error_code"] == "join.assertion_invalid"


def test_someone_whose_home_is_blocked_cannot_join(client: TestClient, remote: _Remote):
    api_initializer.database_handler.upsert_peer(HOME, "blocked")
    response = _join(client, remote)
    assert response.status_code == 403 and response.json()["error_code"] == "join.refused"
    api_initializer.database_handler.set_federation_mode("closed")
    api_initializer.database_handler.upsert_peer(HOME, "federating")
    assert _join(client, remote).json()["error_code"] == "join.refused"


def test_an_invite_server_asks_the_visitor_for_a_code(client: TestClient, remote: _Remote):
    _, owner = _staff()
    _mode(owner, client, "invite")
    needs = _join(client, remote)
    assert needs.status_code == 403 and needs.json()["error_code"] == "join.invite_required"
    wrong = _join(client, remote, invite_code="NOTACODE1234")
    assert wrong.json()["error_code"] == "join.invite_invalid"
    assert _join(client, remote, invite_code=_code(client, owner, max_uses=1)).json()["status"] == "joined"


def test_a_request_server_keeps_the_visitor_waiting_until_approved(client: TestClient, remote: _Remote):
    _, owner = _staff()
    _mode(owner, client, "request")
    waiting = _join(client, remote, message="from the other side")
    assert waiting.status_code == 202 and waiting.json()["status"] == "pending"
    assert "auth_token" not in waiting.json()
    # No account exists here yet; the request names who asks.
    [asked] = client.get("/api/v1/server/join-requests", params={"auth_token": owner, "status": "pending"}).json()["requests"]
    assert (asked["kind"], asked["handle"], asked["home_host"]) == ("federated", f"alice@{HOME}", HOME)

    assert client.post("/api/v1/federation/join/status", json={"assertion": remote.assertion()}).json()["status"] == "pending"
    assert _join(client, remote).json()["status"] == "pending"  # asking again does not make a second request
    assert len(client.get("/api/v1/server/join-requests", params={"auth_token": owner}).json()["requests"]) == 1

    assert client.post(f"/api/v1/server/join-requests/{asked['request_id']}/approve", json={"auth_token": owner}).status_code == 200
    joined = client.post("/api/v1/federation/join/status", json={"assertion": remote.assertion()}).json()
    assert joined["status"] == "joined" and joined["auth_token"]
    assert client.post("/api/v1/users/profile", json={"auth_token": joined["auth_token"]}).status_code == 200


def test_an_approval_lets_someone_in_once(client: TestClient, remote: _Remote):
    _, owner = _staff()
    _mode(owner, client, "request")
    _join(client, remote)
    [asked] = client.get("/api/v1/server/join-requests", params={"auth_token": owner}).json()["requests"]
    client.post(f"/api/v1/server/join-requests/{asked['request_id']}/approve", json={"auth_token": owner})
    joined = client.post("/api/v1/federation/join/status", json={"assertion": remote.assertion()}).json()
    assert joined["status"] == "joined"

    # Having left, the same approval does not get them back in: they are asked about again.
    client.post("/api/v1/federation/leave", json={"auth_token": joined["auth_token"]})
    again = _join(client, remote)
    assert again.status_code == 202 and again.json()["status"] == "pending"
    [_, second] = sorted(client.get("/api/v1/server/join-requests", params={"auth_token": owner}).json()["requests"], key=lambda r: r["created_at"], reverse=True)[:2] or [None, None]
    assert client.post("/api/v1/federation/join/status", json={"assertion": remote.assertion()}).json()["status"] == "pending"


def test_someone_who_left_cannot_get_a_new_session_or_a_realtime_connection(client: TestClient, remote: _Remote):
    joined = _join(client, remote).json()
    user_id = joined["user"]["user_id"]
    assert api_initializer.user_manager.membership_error(user_id) is None
    client.post("/api/v1/federation/leave", json={"auth_token": joined["auth_token"]})
    assert api_initializer.user_manager.membership_error(user_id) == "auth.membership_denied"
    # The realtime path asks the same question as the routes.
    from pufferblow.api.errors import ApiError

    with pytest.raises(ApiError):
        api_initializer.authorizer  # noqa: B018  (the resolver below is what the socket uses)
        from pufferblow.api.principals.resolver import UserPrincipalResolver

        UserPrincipalResolver(api_initializer.user_manager, api_initializer.auth_token_manager).resolve(joined["auth_token"])


def test_a_visitor_whose_home_is_a_private_address_is_not_fetched(client: TestClient, monkeypatch):
    """The join route fetches a page from whatever address it is given, so it refuses addresses that are not public."""
    monkeypatch.delenv("PUFFERBLOW_ALLOW_PRIVATE_FEDERATION", raising=False)
    person = _Remote(host="127.0.0.1:9")
    fetched = []

    async def fetch(actor_uri: str, **_):
        fetched.append(actor_uri)
        return person.row

    monkeypatch.setattr(api_initializer.activitypub_manager, "fetch_remote_actor", fetch)
    response = client.post("/api/v1/federation/join", json={"assertion": person.assertion()})
    assert response.status_code == 401 and response.json()["error_code"] == "join.assertion_invalid"
    assert fetched == []


def test_a_denied_visitor_is_told_so(client: TestClient, remote: _Remote):
    _, owner = _staff()
    _mode(owner, client, "request")
    _join(client, remote)
    [asked] = client.get("/api/v1/server/join-requests", params={"auth_token": owner}).json()["requests"]
    client.post(f"/api/v1/server/join-requests/{asked['request_id']}/deny", json={"auth_token": owner})
    refused = client.post("/api/v1/federation/join/status", json={"assertion": remote.assertion()})
    assert refused.status_code == 403 and refused.json()["error_code"] == "auth.membership_denied"


def test_someone_known_only_from_a_direct_message_is_not_a_member(client: TestClient, remote: _Remote):
    """A person who federated (a DM, a friend request) has an entry here, but that is not joining: a private server still wants its code."""
    _, owner = _staff()
    api_initializer.activitypub_manager._ensure_remote_shadow_user(remote.row)
    _mode(owner, client, "invite")
    response = _join(client, remote)
    assert response.status_code == 403 and response.json()["error_code"] == "join.invite_required"


def test_leaving_ends_the_membership_and_the_tokens(client: TestClient, remote: _Remote):
    joined = _join(client, remote).json()
    assert client.post("/api/v1/federation/leave", json={"auth_token": joined["auth_token"]}).status_code == 200
    assert client.post("/api/v1/users/profile", json={"auth_token": joined["auth_token"]}).status_code == 403
    # Rejoining a private server then takes a code again.
    _, owner = _staff()
    _mode(owner, client, "invite")
    assert _join(client, remote).json()["error_code"] == "join.invite_required"


def test_a_local_account_has_nothing_to_leave(client: TestClient):
    person = _signup(client).json()
    assert client.post("/api/v1/federation/leave", json={"auth_token": person["auth_token"]}).status_code == 400
    assert client.post("/api/v1/users/profile", json={"auth_token": person["auth_token"]}).status_code == 200


def test_the_home_server_signs_for_its_own_people_only(client: TestClient):
    person = _signup(client).json()
    response = client.post("/api/v1/federation/assertions", json={"auth_token": person["auth_token"], "audience": "there.example:7002"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["audience"] == "there.example:7002" and body["handle"].startswith("person_")
    own = client.post("/api/v1/federation/assertions", json={"auth_token": person["auth_token"], "audience": instance_id_of(api_initializer.config)})
    assert own.status_code == 400


# ── the fetch made for a stranger's address ───────────────────────────────────


def _resolver(address: str):
    return lambda host, port: [(2, 1, 6, "", (address, port))]


@pytest.mark.asyncio
async def test_a_stranger_cannot_point_the_fetch_at_a_private_address():
    from pufferblow.api.federation.nodeinfo import UnsafeHost, fetch_public_json

    for address in ("127.0.0.1", "10.1.2.3", "169.254.169.254", "::1"):
        with pytest.raises(UnsafeHost):
            await fetch_public_json("https://evil.example/ap/users/x", resolve=_resolver(address), allow_private=False)
    with pytest.raises(UnsafeHost):
        await fetch_public_json("http://evil.example/ap/users/x", resolve=_resolver("93.184.216.34"), allow_private=False)
    with pytest.raises(UnsafeHost):
        await fetch_public_json("https://user:pw@evil.example/", resolve=_resolver("93.184.216.34"), allow_private=False)


@pytest.mark.asyncio
async def test_the_fetch_goes_to_the_address_it_checked_and_does_not_follow_redirects(monkeypatch):
    import httpx

    from pufferblow.api.federation import nodeinfo

    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((str(request.url), request.headers["host"], request.extensions.get("sni_hostname")))
        return httpx.Response(302, headers={"Location": "http://169.254.169.254/latest/meta-data"})

    real = httpx.AsyncClient
    monkeypatch.setattr(nodeinfo.httpx, "AsyncClient", lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    with pytest.raises(httpx.HTTPStatusError):
        await nodeinfo.fetch_public_json("https://home.example/ap/users/a", resolve=_resolver("93.184.216.34"), allow_private=False)
    # One request, to the address that was checked, under the real name; the redirect was not followed.
    assert seen == [("https://93.184.216.34/ap/users/a", "home.example", "home.example")]


def test_someone_who_left_is_refused_by_the_older_checks_too(client: TestClient, remote: _Remote):
    from pufferblow.api.dependencies import get_current_user_from_node_session  # noqa: F401
    from pufferblow.api.routes.system_routes.shared import extract_user

    joined = _join(client, remote).json()
    assert extract_user(joined["auth_token"]) == joined["user"]["user_id"]
    client.post("/api/v1/federation/leave", json={"auth_token": joined["auth_token"]})
    with pytest.raises(ApiError):
        extract_user(joined["auth_token"])
    refused = api_initializer.security_checks_handler.check_user(auth_token=joined["auth_token"])
    assert refused is not None and refused.status_code == 403
