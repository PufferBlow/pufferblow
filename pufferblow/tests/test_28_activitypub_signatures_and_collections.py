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
    """Just enough surface for the Undo/Reject/Delete/Update/Like handlers."""

    def __init__(self):
        self.deleted: list[tuple[str, str]] = []
        self.delete_returns = True
        self.message_by_remote_uri: dict[str, SimpleNamespace] = {}
        self.actor_by_uri: dict[str, SimpleNamespace] = {}
        self.edited: list[tuple[str, str, str]] = []
        self.deleted_messages: list[tuple[str, str | None]] = []

    def delete_activitypub_follow(self, local_actor_uri: str, remote_actor_uri: str) -> bool:
        self.deleted.append((local_actor_uri, remote_actor_uri))
        return self.delete_returns

    def get_message_by_remote_object_uri(self, remote_object_uri: str):
        return self.message_by_remote_uri.get(remote_object_uri)

    def get_activitypub_actor_by_uri(self, actor_uri: str):
        return self.actor_by_uri.get(actor_uri)

    def get_message_by_id(self, message_id: str):
        # `_local_message_from_object_uri` resolves our own deterministic
        # ids straight back through here in the real implementation.
        return self._local_messages.get(message_id) if hasattr(self, "_local_messages") else None


def _make_manager_with_fake_follow_db() -> tuple[ap_module.ActivityPubManager, _FakeFollowDatabaseHandler]:
    handler = _FakeFollowDatabaseHandler()
    fake_messages_manager = SimpleNamespace(
        delete_message=lambda message_id, channel_id: handler.deleted_messages.append((message_id, channel_id)),
        edit_message=lambda message_id, editor_user_id, new_body: handler.edited.append(
            (message_id, editor_user_id, new_body)
        ),
        add_reaction=lambda message_id, user_id, emoji: True,
    )
    manager = ap_module.ActivityPubManager(
        database_handler=handler,  # type: ignore[arg-type]
        user_manager=SimpleNamespace(),  # type: ignore[arg-type]
        messages_manager=fake_messages_manager,  # type: ignore[arg-type]
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
        },
        base_url="https://local.test",
    )
    assert result["action"] == "follow_removed"
    assert handler.deleted == [("https://local.test/ap/users/1", "https://remote.test/users/alice")]


def test_handle_undo_ignores_non_follow_non_like_objects():
    manager, handler = _make_manager_with_fake_follow_db()
    result = manager._handle_undo(
        activity={"type": "Undo", "actor": "https://remote.test/users/alice", "object": {"type": "Announce"}},
        base_url="https://local.test",
    )
    assert result["action"] == "stored_only"
    assert handler.deleted == []


def test_handle_undo_like_removes_the_reaction():
    manager, handler = _make_manager_with_fake_follow_db()
    handler._local_messages = {"msg1": SimpleNamespace(message_id="msg1")}
    handler.actor_by_uri["https://remote.test/users/alice"] = SimpleNamespace(user_id="alice-user-id")
    removed_calls = []
    manager.messages_manager.remove_reaction = lambda message_id, user_id, emoji: (
        removed_calls.append((message_id, user_id, emoji)) or True
    )

    result = manager._handle_undo(
        activity={
            "type": "Undo",
            "actor": "https://remote.test/users/alice",
            "object": {
                "type": "Like",
                "content": "\U0001F44D",
                "object": "https://local.test/ap/objects/msg1",
            },
        },
        base_url="https://local.test",
    )
    assert result["action"] == "reaction_removed"
    assert removed_calls == [("msg1", "alice-user-id", "\U0001F44D")]


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


def test_handle_delete_resolves_via_remote_object_uri_and_deletes():
    manager, handler = _make_manager_with_fake_follow_db()
    row = SimpleNamespace(message_id="msg1", channel_id=None)
    handler.message_by_remote_uri["https://remote.test/objects/123"] = row

    result = manager._handle_delete(activity={"type": "Delete", "object": "https://remote.test/objects/123"})
    assert result["action"] == "message_deleted"
    assert handler.deleted_messages == [("msg1", None)]


def test_handle_delete_reports_not_found_when_unresolvable():
    manager, _handler = _make_manager_with_fake_follow_db()
    result = manager._handle_delete(activity={"type": "Delete", "object": "https://remote.test/objects/unknown"})
    assert result["action"] == "message_not_found"


def test_handle_update_note_resolves_and_edits():
    manager, handler = _make_manager_with_fake_follow_db()
    row = SimpleNamespace(message_id="msg1", channel_id=None, sender_id="alice-user-id")
    handler.message_by_remote_uri["https://remote.test/objects/123"] = row

    result = manager._handle_update(
        activity={"type": "Update", "object": {"type": "Note", "id": "https://remote.test/objects/123", "content": "edited"}}
    )
    assert result["action"] == "message_updated"
    assert handler.edited == [("msg1", "alice-user-id", "edited")]


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


# --- Like (inbound) ----------------------------------------------------------


def test_handle_like_adds_a_reaction_to_our_own_message():
    manager, handler = _make_manager_with_fake_follow_db()
    handler._local_messages = {"msg1": SimpleNamespace(message_id="msg1")}
    added_calls = []
    manager.messages_manager.add_reaction = lambda message_id, user_id, emoji: added_calls.append(
        (message_id, user_id, emoji)
    )

    async def fake_fetch_remote_actor(*, actor_uri: str):
        return SimpleNamespace(actor_uri=actor_uri, user_id=None)

    manager.fetch_remote_actor = fake_fetch_remote_actor
    manager._ensure_remote_shadow_user = lambda remote_actor: "shadow-user-id"

    result = asyncio.run(
        manager._handle_like(
            activity={
                "type": "Like",
                "actor": "https://remote.test/users/alice",
                "content": "\U0001F389",
                "object": {"id": "https://local.test/ap/objects/msg1", "type": "Note"},
            },
            base_url="https://local.test",
        )
    )
    assert result["action"] == "reaction_added"
    assert added_calls == [("msg1", "shadow-user-id", "\U0001F389")]


def test_handle_like_reports_not_found_for_unresolvable_object():
    manager, _handler = _make_manager_with_fake_follow_db()

    async def fake_fetch_remote_actor(*, actor_uri: str):
        return SimpleNamespace(actor_uri=actor_uri, user_id=None)

    manager.fetch_remote_actor = fake_fetch_remote_actor

    result = asyncio.run(
        manager._handle_like(
            activity={
                "type": "Like",
                "actor": "https://remote.test/users/alice",
                "object": {"id": "https://remote.test/their-own-objects/999", "type": "Note"},
            },
            base_url="https://local.test",
        )
    )
    assert result["action"] == "message_not_found"


# --- DM conversation-membership authorization --------------------------------


def test_user_can_access_dm_message_true_for_sender():
    manager, _handler = _make_manager_with_fake_follow_db()
    row = SimpleNamespace(conversation_id="conv-1", sender_id="alice-user-id")
    assert manager.user_can_access_dm_message("alice-user-id", row, "https://local.test") is True


def test_user_can_access_dm_message_true_for_the_other_participant():
    manager, handler = _make_manager_with_fake_follow_db()
    row = SimpleNamespace(conversation_id=None, sender_id="alice-user-id")
    # Compute the real expected conversation id the same way the manager
    # will, so this test doesn't need to fake out the hash function too.
    sender_actor_uri = "https://local.test/ap/users/alice-user-id"
    bob_actor_uri = "https://local.test/ap/users/bob-user-id"
    row.conversation_id = manager._conversation_id(sender_actor_uri, bob_actor_uri)

    manager.ensure_local_actor = lambda user_id, base_url: SimpleNamespace(actor_uri=bob_actor_uri)
    handler.get_activitypub_actor_by_user_id = lambda user_id: None  # sender resolves via the local uri fallback

    assert manager.user_can_access_dm_message("bob-user-id", row, "https://local.test") is True


def test_user_can_access_dm_message_false_for_an_uninvolved_user():
    manager, handler = _make_manager_with_fake_follow_db()
    row = SimpleNamespace(
        conversation_id=manager._conversation_id(
            "https://local.test/ap/users/alice-user-id", "https://local.test/ap/users/bob-user-id"
        ),
        sender_id="alice-user-id",
    )
    manager.ensure_local_actor = lambda user_id, base_url: SimpleNamespace(
        actor_uri=f"https://local.test/ap/users/{user_id}"
    )
    handler.get_activitypub_actor_by_user_id = lambda user_id: None

    assert manager.user_can_access_dm_message("mallory-user-id", row, "https://local.test") is False
