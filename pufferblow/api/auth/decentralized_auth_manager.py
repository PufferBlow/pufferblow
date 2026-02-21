from __future__ import annotations

import datetime
import hashlib
import hmac
import secrets
from uuid import UUID

from fastapi import HTTPException

from pufferblow.api.database.database_handler import DatabaseHandler


class DecentralizedAuthManager:
    """
    Node-aware auth flow for decentralized deployments.
    """

    def __init__(self, database_handler: DatabaseHandler) -> None:
        """Initialize the instance."""
        self.database_handler = database_handler

    @staticmethod
    def _utcnow() -> datetime.datetime:
        """Utcnow."""
        return datetime.datetime.now(datetime.timezone.utc)

    @staticmethod
    def _hash_session_token(raw_token: str) -> str:
        """Hash session token."""
        return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    @staticmethod
    def _verify_challenge_signature(
        challenge_nonce: str, signature: str, shared_secret: str
    ) -> bool:
        """Verify challenge signature."""
        expected = hmac.new(
            shared_secret.encode("utf-8"),
            challenge_nonce.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, signature)

    def issue_challenge(self, user_id: str, node_id: str, ttl_seconds: int = 120) -> dict:
        """Issue challenge."""
        try:
            UUID(str(user_id))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid user_id format") from exc

        nonce = secrets.token_urlsafe(32)
        expires_at = self._utcnow() + datetime.timedelta(seconds=ttl_seconds)
        challenge = self.database_handler.create_decentralized_auth_challenge(
            user_id=user_id,
            node_id=node_id,
            challenge_nonce=nonce,
            expires_at=expires_at,
        )

        return {
            "challenge_id": str(challenge.challenge_id),
            "challenge_nonce": challenge.challenge_nonce,
            "expires_at": challenge.expires_at.isoformat(),
        }

    def verify_challenge_and_issue_session(
        self,
        challenge_id: str,
        node_public_key: str,
        challenge_signature: str,
        shared_secret: str,
        session_ttl_hours: int = 24,
    ) -> dict:
        """Verify challenge and issue session."""
        challenge = self.database_handler.get_decentralized_auth_challenge(challenge_id)
        if challenge is None:
            raise HTTPException(status_code=404, detail="Challenge not found")
        if challenge.consumed:
            raise HTTPException(status_code=409, detail="Challenge already consumed")
        if challenge.expires_at <= self._utcnow():
            raise HTTPException(status_code=401, detail="Challenge expired")

        if not self._verify_challenge_signature(
            challenge_nonce=challenge.challenge_nonce,
            signature=challenge_signature,
            shared_secret=shared_secret,
        ):
            raise HTTPException(status_code=401, detail="Invalid challenge signature")

        self.database_handler.consume_decentralized_auth_challenge(challenge_id)

        raw_session_token = secrets.token_urlsafe(48)
        token_hash = self._hash_session_token(raw_session_token)
        expires_at = self._utcnow() + datetime.timedelta(hours=session_ttl_hours)

        session_obj = self.database_handler.create_decentralized_node_session(
            user_id=str(challenge.user_id),
            node_id=challenge.node_id,
            node_public_key=node_public_key,
            session_token_hash=token_hash,
            session_token_hint=raw_session_token[:8],
            scopes="chat:read,chat:write",
            expires_at=expires_at,
        )

        return {
            "session_id": str(session_obj.session_id),
            "session_token": raw_session_token,
            "node_id": session_obj.node_id,
            "expires_at": session_obj.expires_at.isoformat(),
            "scopes": session_obj.scopes.split(","),
        }

    def introspect_session(self, session_token: str) -> dict:
        """Introspect session."""
        token_hash = self._hash_session_token(session_token)
        session_obj = self.database_handler.get_decentralized_node_session_by_hash(
            token_hash
        )
        if session_obj is None:
            raise HTTPException(status_code=401, detail="Invalid or expired session token")

        return {
            "active": True,
            "session_id": str(session_obj.session_id),
            "user_id": str(session_obj.user_id),
            "node_id": session_obj.node_id,
            "node_public_key": session_obj.node_public_key,
            "expires_at": session_obj.expires_at.isoformat(),
            "scopes": session_obj.scopes.split(","),
        }
