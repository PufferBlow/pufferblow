"""The password digest used where there are no encryption keys is salted and slow, not a bare SHA-256."""

from __future__ import annotations

import hashlib

from pufferblow.api.security.password_digest import hash_password, verify_password


def test_a_digest_verifies_only_its_own_password():
    stored = hash_password("correct horse")
    assert verify_password(stored, "correct horse")
    assert not verify_password(stored, "correct horsf")
    assert not verify_password(stored, "")


def test_the_same_password_gets_a_different_digest_each_time():
    assert hash_password("same") != hash_password("same")  # a random salt per password


def test_it_is_not_a_plain_sha256_and_never_holds_the_password():
    stored = hash_password("hunter2")
    assert "hunter2" not in stored
    assert hashlib.sha256(b"hunter2").hexdigest() not in stored and stored.startswith("scrypt$")


def test_anything_that_is_not_a_digest_never_matches():
    for stored in (None, "", "plain", "scrypt$", "scrypt$!!$!!", "73l8gRjwLftklgfdXT+MdiMEjJwGPVMsyVxe16iYpk8="):
        assert not verify_password(stored, "anything")
