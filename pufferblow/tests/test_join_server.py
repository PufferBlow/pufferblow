"""Unit tests for `UserManager.join_server` / `leave_server`.

These tests cover the validation policy in isolation — they don't
spin up a FastAPI app or a real database. The manager talks to:
  - `httpx.get` (probe of the target's server-info endpoint)
  - `database_handler.get_user` / `add_joined_server` /
    `remove_joined_server` (idempotent list mutation)

Both are stubbed so the tests exercise the manager's own logic:
  - target normalization (scheme stripping, trailing-slash trim)
  - the validation matrix (unreachable / not Pufferblow / self-join)
  - the home-instance protection for leave_server
"""

from __future__ import annotations

import types

import pytest

from pufferblow.api.user.user_manager import UserManager


class _FakeResponse:
    """Minimal stand-in for httpx.Response used by the probe."""

    def __init__(self, status_code: int, body: dict | None):
        self.status_code = status_code
        self._body = body

    def json(self):
        if self._body is None:
            raise ValueError("not json")
        return self._body


def _build_manager(probe_responses, db_stub):
    """Construct a UserManager with httpx + db calls patched.

    `probe_responses` is a list of (url-substring, response) tuples
    matched in order — the manager tries URLs in a specific
    sequence (https first for public targets, http for local),
    and this lets each test express what each candidate returns.

    `db_stub` is a SimpleNamespace impersonating database_handler
    with the methods join_server / leave_server reach for.
    """

    def fake_get(url, timeout=None):  # noqa: ARG001 — signature parity
        for needle, response in probe_responses:
            if needle in url:
                if isinstance(response, Exception):
                    raise response
                return response
        # Unmatched URL — treat as a connection failure.
        import httpx

        raise httpx.ConnectError(f"unmatched: {url}")

    # Stub the `httpx` module used inside join_server. The manager
    # imports it lazily (inside the method), so monkeypatching the
    # module attribute is the cleanest hook.
    import httpx

    fake_httpx = types.SimpleNamespace(
        get=fake_get,
        Timeout=httpx.Timeout,
        ConnectError=httpx.ConnectError,
        TimeoutException=httpx.TimeoutException,
        ReadError=httpx.ReadError,
    )

    manager = object.__new__(UserManager)
    manager.config = types.SimpleNamespace(API_HOST="home.example", API_PORT=7575)
    manager.database_handler = db_stub
    # Inject the patched httpx into the module's globals during the
    # call. We rely on the method doing `import httpx` locally — the
    # local import lands at the bottom of the call frame and reads
    # from sys.modules, so we have to swap it there for the duration.
    return manager, fake_httpx


@pytest.fixture
def patched_httpx(monkeypatch):
    """Returns a setter that installs a fake httpx module."""

    def install(fake):
        import sys

        monkeypatch.setitem(sys.modules, "httpx", fake)

    return install


# ── _normalize_target_domain ─────────────────────────────────────────


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("chat.example:7575", "chat.example:7575"),
        ("https://chat.example:7575", "chat.example:7575"),
        ("http://chat.example:7575/", "chat.example:7575"),
        ("  http://chat.example  ", "chat.example"),
        ("", ""),
    ],
)
def test_normalize_target_domain_strips_scheme_and_slashes(raw, expected):
    assert UserManager._normalize_target_domain(raw) == expected


# ── join_server ──────────────────────────────────────────────────────


def test_join_server_rejects_self(patched_httpx):
    db = types.SimpleNamespace(
        add_joined_server=lambda **_: pytest.fail("must not call db on self_join")
    )
    manager, fake = _build_manager([], db)
    patched_httpx(fake)

    ok, code, info = manager.join_server(user_id="u1", target="home.example:7575")
    assert ok is False
    assert code == "self_join"
    assert info is None


def test_join_server_rejects_invalid_target(patched_httpx):
    db = types.SimpleNamespace(add_joined_server=lambda **_: pytest.fail("no db"))
    manager, fake = _build_manager([], db)
    patched_httpx(fake)

    ok, code, _ = manager.join_server(user_id="u1", target="   ")
    assert ok is False
    assert code == "invalid_target"


def test_join_server_unreachable_when_all_probes_fail(patched_httpx):
    import httpx as real_httpx

    db = types.SimpleNamespace(add_joined_server=lambda **_: pytest.fail("no db"))
    probes = [
        # Both https and http probes raise ConnectError → unreachable.
        ("https://", real_httpx.ConnectError("down")),
        ("http://", real_httpx.ConnectError("down")),
    ]
    manager, fake = _build_manager(probes, db)
    patched_httpx(fake)

    ok, code, _ = manager.join_server(user_id="u1", target="chat.example:7575")
    assert ok is False
    assert code == "unreachable"


def test_join_server_unreachable_when_target_returns_non_json(patched_httpx):
    db = types.SimpleNamespace(add_joined_server=lambda **_: pytest.fail("no db"))
    probes = [
        ("https://", _FakeResponse(200, None)),  # raises ValueError in .json()
        ("http://", _FakeResponse(200, None)),
    ]
    manager, fake = _build_manager(probes, db)
    patched_httpx(fake)

    ok, code, _ = manager.join_server(user_id="u1", target="chat.example:7575")
    assert ok is False
    assert code == "unreachable"


def test_join_server_not_pufferblow_when_payload_lacks_server_id(patched_httpx):
    """The probe got a 200 + JSON but the payload doesn't look right.

    The server-info endpoint always carries `server_id`. A payload
    without it is either a different service (something else at that
    host) or a Pufferblow build older than the v1.0 schema. Either
    way we refuse the join with a code the client can act on.
    """
    db = types.SimpleNamespace(add_joined_server=lambda **_: pytest.fail("no db"))
    probes = [
        ("https://", _FakeResponse(200, {"server_info": {"name": "Bob's IRC"}})),
    ]
    manager, fake = _build_manager(probes, db)
    patched_httpx(fake)

    ok, code, _ = manager.join_server(user_id="u1", target="chat.example:7575")
    assert ok is False
    assert code == "not_pufferblow"


def test_join_server_succeeds_and_persists_canonical_id(patched_httpx):
    captured = {}

    def add(*, user_id, server_id):
        captured["user_id"] = user_id
        captured["server_id"] = server_id
        return [server_id]

    db = types.SimpleNamespace(add_joined_server=add)
    info_payload = {
        "server_id": "chat.example:7575",
        "server_name": "Bob's Pufferblow",
    }
    probes = [("https://", _FakeResponse(200, {"server_info": info_payload}))]
    manager, fake = _build_manager(probes, db)
    patched_httpx(fake)

    ok, code, info = manager.join_server(
        user_id="u1", target="https://chat.example:7575/"
    )
    assert ok is True
    assert code is None
    assert info == info_payload
    # Persisted with the remote's self-declared server_id, not the
    # URL the user typed.
    assert captured["server_id"] == "chat.example:7575"


def test_join_server_uses_http_only_probe_for_localhost(patched_httpx):
    """Localhost / RFC1918 targets skip the https probe.

    Operators commonly run development instances without TLS at
    127.0.0.1; trying https first means a ConnectError on every
    join attempt against those targets, slowing the flow. The
    manager short-circuits to the http probe in that case.
    """
    seen_urls: list[str] = []

    def fake_get(url, timeout=None):  # noqa: ARG001
        seen_urls.append(url)
        return _FakeResponse(
            200, {"server_info": {"server_id": "127.0.0.1:7575", "server_name": "Local"}}
        )

    import httpx as real_httpx
    import sys

    monkeypatch_target = sys.modules.setdefault
    fake_httpx = types.SimpleNamespace(
        get=fake_get,
        Timeout=real_httpx.Timeout,
        ConnectError=real_httpx.ConnectError,
        TimeoutException=real_httpx.TimeoutException,
        ReadError=real_httpx.ReadError,
    )
    patched_httpx(fake_httpx)

    db = types.SimpleNamespace(add_joined_server=lambda **_: ["127.0.0.1:7575"])
    manager = object.__new__(UserManager)
    manager.config = types.SimpleNamespace(API_HOST="home.example", API_PORT=7575)
    manager.database_handler = db

    ok, _, _ = manager.join_server(user_id="u1", target="127.0.0.1:7575")
    assert ok is True
    assert all(u.startswith("http://") for u in seen_urls)


# ── leave_server ─────────────────────────────────────────────────────


def test_leave_server_refuses_home_instance(patched_httpx):
    db = types.SimpleNamespace(
        get_user=lambda **_: types.SimpleNamespace(origin_server="chat.example:7575"),
        remove_joined_server=lambda **_: pytest.fail("must not call db"),
    )
    manager, fake = _build_manager([], db)
    patched_httpx(fake)

    ok, code = manager.leave_server(user_id="u1", target="chat.example:7575")
    assert ok is False
    assert code == "cannot_leave_home"


def test_leave_server_removes_remote_server(patched_httpx):
    removed: dict = {}

    def remove(*, user_id, server_id):
        removed["user_id"] = user_id
        removed["server_id"] = server_id
        return []

    db = types.SimpleNamespace(
        get_user=lambda **_: types.SimpleNamespace(origin_server="home.example:7575"),
        remove_joined_server=remove,
    )
    manager, fake = _build_manager([], db)
    patched_httpx(fake)

    ok, code = manager.leave_server(user_id="u1", target="https://chat.example:7575")
    assert ok is True
    assert code is None
    assert removed["server_id"] == "chat.example:7575"


def test_leave_server_returns_user_not_found_when_db_misses(patched_httpx):
    db = types.SimpleNamespace(get_user=lambda **_: None)
    manager, fake = _build_manager([], db)
    patched_httpx(fake)

    ok, code = manager.leave_server(user_id="ghost", target="chat.example:7575")
    assert ok is False
    assert code == "user_not_found"
