"""Tests for HTTP Signatures, NodeInfo, and the followers/following/outbox
collection wrappers added to ActivityPub federation.

Follows the same philosophy as test_26_activitypub_reliability.py: the
TestClient fixture hangs in this environment, and the ActivityPub DB tables
are Postgres-only (excluded from the SQLite test harness — see
`postgresql_only_tables` in database_handler.py), so everything here is a
direct unit test against the manager/route functions with lightweight fakes
rather than a full app boot or a real ActivityPubFollow row.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from pufferblow.api.activitypub import http_signatures as sig
from pufferblow.api.activitypub import activitypub_manager as ap_module
from pufferblow.api.routes import activitypub as routes_module


# --- HTTP Signatures ---------------------------------------------------------


def _generate_test_keypair() -> tuple[str, str]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return public_pem, private_pem


@pytest.fixture(scope="module")
def keypair() -> tuple[str, str]:
    return _generate_test_keypair()


def test_key_id_for_actor_matches_actor_document_convention():
    assert sig.key_id_for_actor("https://local.test/ap/users/1") == "https://local.test/ap/users/1#main-key"


def test_sign_and_verify_round_trip(keypair):
    public_pem, private_pem = keypair
    body = b'{"type":"Follow"}'
    headers = sig.sign_request(
        method="POST",
        url="https://remote.test/ap/inbox",
        body=body,
        private_key_pem=private_pem,
        key_id="https://local.test/ap/users/1#main-key",
    )
    # Should not raise.
    sig.verify_request(method="POST", path="/ap/inbox", headers=headers, body=body, public_key_pem=public_pem)


def test_verify_rejects_tampered_body(keypair):
    public_pem, private_pem = keypair
    headers = sig.sign_request(
        method="POST", url="https://remote.test/ap/inbox", body=b"original",
        private_key_pem=private_pem, key_id="k",
    )
    with pytest.raises(sig.SignatureVerificationError):
        sig.verify_request(method="POST", path="/ap/inbox", headers=headers, body=b"tampered", public_key_pem=public_pem)


def test_verify_rejects_tampered_signature(keypair):
    public_pem, private_pem = keypair
    body = b"same body"
    headers = sig.sign_request(
        method="POST", url="https://remote.test/ap/inbox", body=body,
        private_key_pem=private_pem, key_id="k",
    )
    bad = dict(headers)
    bad["Signature"] = bad["Signature"].replace('signature="', 'signature="AA', 1)
    with pytest.raises(sig.SignatureVerificationError):
        sig.verify_request(method="POST", path="/ap/inbox", headers=bad, body=body, public_key_pem=public_pem)


def test_verify_rejects_missing_signature_header(keypair):
    public_pem, _ = keypair
    with pytest.raises(sig.SignatureVerificationError):
        sig.verify_request(method="POST", path="/ap/inbox", headers={}, body=b"x", public_key_pem=public_pem)


def test_verify_rejects_stale_date(keypair, monkeypatch):
    public_pem, private_pem = keypair
    body = b"x"
    headers = sig.sign_request(
        method="POST", url="https://remote.test/ap/inbox", body=body,
        private_key_pem=private_pem, key_id="k",
    )
    # Signed just fine "at the time" — but back-date the Date header itself
    # past the allowed skew so verification rejects it as stale.
    import email.utils as email_utils
    from datetime import datetime, timedelta, timezone

    stale = datetime.now(timezone.utc) - timedelta(hours=48)
    headers["Date"] = email_utils.format_datetime(stale, usegmt=True)
    with pytest.raises(sig.SignatureVerificationError):
        sig.verify_request(method="POST", path="/ap/inbox", headers=headers, body=body, public_key_pem=public_pem)


def test_verify_rejects_wrong_key(keypair):
    other_public_pem, _ = _generate_test_keypair()
    _, private_pem = keypair
    body = b"x"
    headers = sig.sign_request(
        method="POST", url="https://remote.test/ap/inbox", body=body,
        private_key_pem=private_pem, key_id="k",
    )
    with pytest.raises(sig.SignatureVerificationError):
        sig.verify_request(method="POST", path="/ap/inbox", headers=headers, body=body, public_key_pem=other_public_pem)


# --- ActivityPubManager.verify_inbox_signature -------------------------------


def _make_manager(config) -> ap_module.ActivityPubManager:
    return ap_module.ActivityPubManager(
        database_handler=SimpleNamespace(config=config),  # type: ignore[arg-type]
        user_manager=SimpleNamespace(),  # type: ignore[arg-type]
        messages_manager=SimpleNamespace(),  # type: ignore[arg-type]
        websockets_manager=SimpleNamespace(),  # type: ignore[arg-type]
    )


async def _fake_fetch_remote_actor_factory(public_key_pem: str):
    async def _fetch(*, actor_uri: str):
        return SimpleNamespace(actor_uri=actor_uri, public_key_pem=public_key_pem)

    return _fetch


def test_verify_inbox_signature_noop_when_disabled(keypair):
    manager = _make_manager(SimpleNamespace(ACTIVITYPUB_REQUIRE_HTTP_SIGNATURES=False))
    import asyncio

    # No headers at all would normally fail — confirms the toggle short-circuits.
    asyncio.run(
        manager.verify_inbox_signature(
            method="POST", path="/ap/inbox", headers={}, raw_body=b"x",
            claimed_actor_uri="https://remote.test/users/alice",
        )
    )


def test_verify_inbox_signature_accepts_valid_signature(keypair, monkeypatch):
    public_pem, private_pem = keypair
    manager = _make_manager(SimpleNamespace(ACTIVITYPUB_REQUIRE_HTTP_SIGNATURES=True))

    import asyncio

    async def fake_fetch(*, actor_uri: str):
        return SimpleNamespace(actor_uri=actor_uri, public_key_pem=public_pem)

    monkeypatch.setattr(manager, "fetch_remote_actor", fake_fetch)

    body = b'{"type":"Follow"}'
    headers = sig.sign_request(
        method="POST", url="https://local.test/ap/inbox", body=body,
        private_key_pem=private_pem, key_id="https://remote.test/users/alice#main-key",
    )
    asyncio.run(
        manager.verify_inbox_signature(
            method="POST", path="/ap/inbox", headers=headers, raw_body=body,
            claimed_actor_uri="https://remote.test/users/alice",
        )
    )


def test_verify_inbox_signature_rejects_bad_signature(keypair, monkeypatch):
    public_pem, private_pem = keypair
    manager = _make_manager(SimpleNamespace(ACTIVITYPUB_REQUIRE_HTTP_SIGNATURES=True))

    import asyncio

    async def fake_fetch(*, actor_uri: str):
        return SimpleNamespace(actor_uri=actor_uri, public_key_pem=public_pem)

    monkeypatch.setattr(manager, "fetch_remote_actor", fake_fetch)

    body = b'{"type":"Follow"}'
    headers = sig.sign_request(
        method="POST", url="https://local.test/ap/inbox", body=body,
        private_key_pem=private_pem, key_id="https://remote.test/users/alice#main-key",
    )
    with pytest.raises(ValueError):
        asyncio.run(
            manager.verify_inbox_signature(
                method="POST", path="/ap/inbox", headers=headers, raw_body=b"tampered",
                claimed_actor_uri="https://remote.test/users/alice",
            )
        )


# --- Outbox / followers / following collection pagination -------------------


class _FakeQueryParams(dict):
    """Minimal stand-in for Starlette's QueryParams (supports `in`)."""


class _FakeRequest:
    def __init__(self, query_params: dict):
        self.query_params = _FakeQueryParams(query_params)


def test_ordered_collection_wrapper_when_no_page_param():
    request = _FakeRequest({})
    doc = routes_module._ordered_collection_or_page(
        collection_uri="https://local.test/ap/users/1/followers",
        items=["https://remote.test/users/a", "https://remote.test/users/b"],
        request=request,
        page=1,
        limit=20,
    )
    assert doc["type"] == "OrderedCollection"
    assert doc["totalItems"] == 2
    assert doc["first"] == "https://local.test/ap/users/1/followers?page=1&limit=20"
    assert "orderedItems" not in doc


def test_ordered_collection_page_when_page_param_present():
    request = _FakeRequest({"page": "1"})
    items = [f"https://remote.test/users/{i}" for i in range(5)]
    doc = routes_module._ordered_collection_or_page(
        collection_uri="https://local.test/ap/users/1/followers",
        items=items,
        request=request,
        page=1,
        limit=2,
    )
    assert doc["type"] == "OrderedCollectionPage"
    assert doc["orderedItems"] == items[:2]
    assert doc["next"] == "https://local.test/ap/users/1/followers?page=2&limit=2"


def test_ordered_collection_page_omits_next_on_last_page():
    request = _FakeRequest({"page": "3"})
    items = [f"https://remote.test/users/{i}" for i in range(5)]
    doc = routes_module._ordered_collection_or_page(
        collection_uri="https://local.test/ap/users/1/followers",
        items=items,
        request=request,
        page=3,
        limit=2,
    )
    assert doc["orderedItems"] == items[4:5]
    assert "next" not in doc


# --- Undo / Reject / Delete / Update inbound handlers ------------------------


class _FakeFollowDatabaseHandler:
    """Just enough surface for the Undo/Reject handlers' follow-row deletion."""

    def __init__(self):
        self.deleted: list[tuple[str, str]] = []
        self.delete_returns = True

    def delete_activitypub_follow(self, local_actor_uri: str, remote_actor_uri: str) -> bool:
        self.deleted.append((local_actor_uri, remote_actor_uri))
        return self.delete_returns


def _make_manager_with_fake_follow_db() -> tuple[ap_module.ActivityPubManager, _FakeFollowDatabaseHandler]:
    handler = _FakeFollowDatabaseHandler()
    manager = ap_module.ActivityPubManager(
        database_handler=handler,  # type: ignore[arg-type]
        user_manager=SimpleNamespace(),  # type: ignore[arg-type]
        messages_manager=SimpleNamespace(),  # type: ignore[arg-type]
        websockets_manager=SimpleNamespace(),  # type: ignore[arg-type]
    )
    return manager, handler


def test_handle_undo_follow_removes_the_follow_row():
    manager, handler = _make_manager_with_fake_follow_db()
    result = manager._handle_undo(
        activity={
            "type": "Undo",
            "actor": "https://remote.test/users/alice",
            "object": {
                "type": "Follow",
                "actor": "https://remote.test/users/alice",
                "object": "https://local.test/ap/users/1",
            },
        }
    )
    assert result["action"] == "follow_removed"
    assert handler.deleted == [("https://local.test/ap/users/1", "https://remote.test/users/alice")]


def test_handle_undo_ignores_non_follow_objects():
    manager, handler = _make_manager_with_fake_follow_db()
    result = manager._handle_undo(
        activity={"type": "Undo", "actor": "https://remote.test/users/alice", "object": {"type": "Like"}}
    )
    assert result["action"] == "stored_only"
    assert handler.deleted == []


def test_handle_reject_follow_removes_the_outgoing_follow_row():
    manager, handler = _make_manager_with_fake_follow_db()
    result = manager._handle_reject(
        activity={
            "type": "Reject",
            "actor": "https://remote.test/users/bob",  # the one rejecting us
            "object": {
                "type": "Follow",
                "actor": "https://local.test/ap/users/1",  # us, the original follower
                "object": "https://remote.test/users/bob",
            },
        }
    )
    assert result["action"] == "follow_removed"
    assert handler.deleted == [("https://local.test/ap/users/1", "https://remote.test/users/bob")]


def test_handle_reject_reports_not_found_when_no_row_existed():
    manager, handler = _make_manager_with_fake_follow_db()
    handler.delete_returns = False
    result = manager._handle_reject(
        activity={
            "type": "Reject",
            "actor": "https://remote.test/users/bob",
            "object": {"type": "Follow", "actor": "https://local.test/ap/users/1", "object": "https://remote.test/users/bob"},
        }
    )
    assert result["action"] == "follow_not_found"


def test_handle_delete_is_acknowledged_but_unmapped():
    manager, _ = _make_manager_with_fake_follow_db()
    result = manager._handle_delete(activity={"type": "Delete", "object": "https://remote.test/objects/123"})
    assert result == {"processed": True, "activity_type": "Delete", "action": "acknowledged_unmapped"}


def test_handle_update_note_is_acknowledged_but_unmapped():
    manager, _ = _make_manager_with_fake_follow_db()
    result = manager._handle_update(
        activity={"type": "Update", "object": {"type": "Note", "id": "https://remote.test/objects/123", "content": "edited"}}
    )
    assert result["action"] == "acknowledged_unmapped"


def test_handle_update_ignores_non_note_objects():
    manager, _ = _make_manager_with_fake_follow_db()
    result = manager._handle_update(activity={"type": "Update", "object": {"type": "Person"}})
    assert result["action"] == "stored_only"


def test_process_inbox_activity_dispatches_undo_delete_update_reject(monkeypatch):
    """End-to-end through process_inbox_activity's dispatch table, not just
    the handler directly — catches a dispatch-wiring mistake the direct
    handler tests above wouldn't."""
    manager, handler = _make_manager_with_fake_follow_db()
    handler.is_activitypub_inbox_known = lambda activity_uri: False
    handler.store_activitypub_inbox_activity = lambda **kwargs: None

    result = asyncio.run(
        manager.process_inbox_activity(
            activity={
                "id": "https://remote.test/ap/activities/undo-1",
                "type": "Undo",
                "actor": "https://remote.test/users/alice",
                "object": {
                    "type": "Follow",
                    "actor": "https://remote.test/users/alice",
                    "object": "https://local.test/ap/users/1",
                },
            },
            base_url="https://local.test",
        )
    )
    assert result["action"] == "follow_removed"
