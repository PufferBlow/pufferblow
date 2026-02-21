from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
import secrets
import threading
import uuid
from typing import Any

from sqlalchemy import and_, desc, func, select

from pufferblow.api.auth.auth_token_manager import AuthTokenManager
from pufferblow.api.channels.channels_manager import ChannelsManager
from pufferblow.api.database.database_handler import DatabaseHandler
from pufferblow.api.database.tables.voice_sessions import (
    VoiceJoinToken,
    VoiceSession,
    VoiceSessionEvent,
    VoiceSessionParticipant,
)
from pufferblow.api.websocket.websocket_manager import WebSocketsManager


class VoiceSessionManager:
    """Control-plane manager for SFU-based channel voice sessions."""

    def __init__(
        self,
        database_handler: DatabaseHandler,
        auth_token_manager: AuthTokenManager,
        channels_manager: ChannelsManager,
        websockets_manager: WebSocketsManager,
    ) -> None:
        """Initialize manager state and runtime config."""
        self.database_handler = database_handler
        self.auth_token_manager = auth_token_manager
        self.channels_manager = channels_manager
        self.websockets_manager = websockets_manager

        cfg = self.database_handler.config

        self.voice_backend = getattr(cfg, "VOICE_BACKEND", "sfu_v2").lower()
        self.join_token_ttl_seconds = int(
            getattr(cfg, "RTC_JOIN_TOKEN_TTL_SECONDS", 60)
        )
        self.join_secret = (
            getattr(cfg, "RTC_JOIN_SECRET", None) or self.auth_token_manager.jwt_secret
        )
        self.internal_secret = (
            getattr(cfg, "RTC_INTERNAL_SECRET", None) or self.join_secret
        )
        self.bootstrap_secret = (
            getattr(cfg, "RTC_BOOTSTRAP_SECRET", None) or self.internal_secret
        )
        self.bootstrap_signature_ttl_seconds = 120
        self._bootstrap_nonce_lock = threading.Lock()
        self._bootstrap_seen_nonces: dict[str, int] = {}
        self.signaling_url = (
            getattr(cfg, "RTC_SIGNALING_URL", None) or self._default_signaling_url()
        )

    def _instance_id(self) -> str:
        """Return canonical local instance identifier."""
        cfg = self.database_handler.config
        return f"{cfg.API_HOST}:{cfg.API_PORT}"

    def _default_signaling_url(self) -> str:
        """Build fallback public signaling url if explicit env/config is missing."""
        cfg = self.database_handler.config
        host = getattr(cfg, "API_HOST", "127.0.0.1")
        if host in {"0.0.0.0", "::"}:
            host = "127.0.0.1"
        return f"ws://{host}:8787/rtc/v1/ws"

    def _default_internal_api_base(self) -> str:
        """Build fallback internal API base URL for SFU callbacks."""
        cfg = self.database_handler.config
        host = getattr(cfg, "API_HOST", "127.0.0.1")
        if host in {"0.0.0.0", "::"}:
            host = "127.0.0.1"
        port = int(getattr(cfg, "API_PORT", 7575))
        return f"http://{host}:{port}/api/internal/v1/voice"

    def _build_ice_servers(self) -> list[dict[str, Any]]:
        """Build RTC ICE config returned to clients."""
        cfg = self.database_handler.config

        stun_raw = getattr(cfg, "RTC_STUN_SERVERS", "stun:stun.l.google.com:19302")
        stun_servers = [s.strip() for s in stun_raw.split(",") if s.strip()]

        servers: list[dict[str, Any]] = [{"urls": stun} for stun in stun_servers]

        turn_url = getattr(cfg, "TURN_URL", None)
        turn_username = getattr(cfg, "TURN_USERNAME", None)
        turn_password = getattr(cfg, "TURN_PASSWORD", None)

        if turn_url:
            turn_payload: dict[str, Any] = {"urls": turn_url}
            if turn_username:
                turn_payload["username"] = turn_username
            if turn_password:
                turn_payload["credential"] = turn_password
            servers.append(turn_payload)

        return servers

    @staticmethod
    def _b64url_encode(data: bytes) -> str:
        """Encode bytes as base64url string without padding."""
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

    @staticmethod
    def _b64url_decode(data: str) -> bytes:
        """Decode base64url string."""
        padding = "=" * (-len(data) % 4)
        return base64.urlsafe_b64decode((data + padding).encode("utf-8"))

    def _sign_join_jwt(self, signing_input: str) -> str:
        """Sign a JWT input using RTC join secret."""
        signature = hmac.new(
            self.join_secret.encode("utf-8"),
            signing_input.encode("utf-8"),
            hashlib.sha256,
        ).digest()
        return self._b64url_encode(signature)

    def _create_join_token(
        self,
        *,
        user_id: str,
        server_id: str,
        channel_id: str,
        session_id: str,
    ) -> tuple[str, dict[str, Any], datetime.datetime]:
        """Create signed one-time join JWT payload and token string."""
        now = datetime.datetime.now(datetime.timezone.utc)
        exp = now + datetime.timedelta(seconds=self.join_token_ttl_seconds)
        jti = secrets.token_hex(12)

        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "sub": str(user_id),
            "instance_id": self._instance_id(),
            "server_id": str(server_id),
            "channel_id": str(channel_id),
            "session_id": str(session_id),
            "scope": "voice:join",
            "iat": int(now.timestamp()),
            "exp": int(exp.timestamp()),
            "jti": jti,
        }

        header_segment = self._b64url_encode(
            json.dumps(header, separators=(",", ":")).encode("utf-8")
        )
        payload_segment = self._b64url_encode(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        )
        signing_input = f"{header_segment}.{payload_segment}"
        signature_segment = self._sign_join_jwt(signing_input)

        return f"{signing_input}.{signature_segment}", payload, exp

    def _decode_join_token(self, join_token: str, verify_exp: bool = True) -> dict[str, Any]:
        """Decode and validate a signed join JWT."""
        parts = join_token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid join token format")

        header_segment, payload_segment, signature_segment = parts
        signing_input = f"{header_segment}.{payload_segment}"
        expected_signature = self._sign_join_jwt(signing_input)

        if not hmac.compare_digest(signature_segment, expected_signature):
            raise ValueError("Invalid join token signature")

        payload = json.loads(self._b64url_decode(payload_segment).decode("utf-8"))

        if payload.get("scope") != "voice:join":
            raise ValueError("Invalid join token scope")

        if payload.get("instance_id") != self._instance_id():
            raise ValueError("Join token target instance mismatch")

        if verify_exp:
            now_ts = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
            if int(payload.get("exp", 0)) <= now_ts:
                raise ValueError("Join token expired")

        return payload

    def _record_session_event(
        self,
        *,
        db_session,
        session_id: str,
        user_id: str | None,
        event_type: str,
        payload: dict[str, Any] | None = None,
    ) -> None:
        """Persist voice session event row."""
        db_session.add(
            VoiceSessionEvent(
                event_id=str(uuid.uuid4()),
                session_id=str(session_id),
                user_id=str(user_id) if user_id is not None else None,
                event_type=event_type,
                payload_json=json.dumps(payload or {}),
            )
        )

    def _active_session_by_channel(self, db_session, channel_id: str) -> VoiceSession | None:
        """Load most recent active session for a channel."""
        stmt = (
            select(VoiceSession)
            .where(
                and_(
                    VoiceSession.channel_id == channel_id,
                    VoiceSession.is_active.is_(True),
                )
            )
            .order_by(desc(VoiceSession.created_at))
            .limit(1)
        )
        return db_session.execute(stmt).scalar_one_or_none()

    def create_or_join_session(
        self,
        *,
        user_id: str,
        channel_id: str,
        quality_profile: str = "balanced",
    ) -> dict[str, Any]:
        """Create or join active voice session for a channel and issue one-time join token."""
        channel = self.database_handler.get_channel_data(channel_id=channel_id)
        if channel is None:
            raise ValueError("Channel not found")

        if channel.channel_type not in {"voice", "mixed"}:
            raise ValueError("Channel does not support voice sessions")

        profile = quality_profile if quality_profile in {"low", "balanced", "high"} else "balanced"

        user = self.database_handler.get_user(user_id=user_id)
        username = user.username if user is not None else str(user_id)

        try:
            server_id = self.database_handler.get_server_id()
        except Exception:
            server_id = "unknown"

        with self.database_handler.database_session() as db_session:
            session_row = self._active_session_by_channel(db_session, channel_id)

            if session_row is None:
                session_row = VoiceSession(
                    session_id=str(uuid.uuid4()),
                    channel_id=channel_id,
                    server_id=str(server_id),
                    backend="sfu_v2",
                    quality_profile=profile,
                    signaling_url=self.signaling_url,
                    is_active=True,
                    created_by=str(user_id),
                )
                db_session.add(session_row)
                db_session.flush()

            participant_stmt = select(VoiceSessionParticipant).where(
                and_(
                    VoiceSessionParticipant.session_id == session_row.session_id,
                    VoiceSessionParticipant.user_id == str(user_id),
                )
            )
            participant = db_session.execute(participant_stmt).scalar_one_or_none()

            now = datetime.datetime.now(datetime.timezone.utc)
            if participant is None:
                participant = VoiceSessionParticipant(
                    session_id=session_row.session_id,
                    user_id=str(user_id),
                    username=username,
                    is_connected=True,
                    is_muted=False,
                    is_deafened=False,
                    is_speaking=False,
                    joined_at=now,
                    disconnected_at=None,
                )
                db_session.add(participant)
            else:
                participant.username = username
                participant.is_connected = True
                participant.disconnected_at = None

            self._record_session_event(
                db_session=db_session,
                session_id=session_row.session_id,
                user_id=str(user_id),
                event_type="participant_join_requested",
                payload={"channel_id": channel_id, "quality_profile": profile},
            )

            join_token, token_payload, token_exp = self._create_join_token(
                user_id=str(user_id),
                server_id=str(server_id),
                channel_id=channel_id,
                session_id=session_row.session_id,
            )
            join_token_hash = hashlib.sha256(join_token.encode("utf-8")).hexdigest()

            db_session.add(
                VoiceJoinToken(
                    token_id=token_payload["jti"],
                    session_id=session_row.session_id,
                    user_id=str(user_id),
                    token_hash=join_token_hash,
                    expires_at=token_exp,
                )
            )

            connected_count_stmt = select(func.count(VoiceSessionParticipant.id)).where(
                and_(
                    VoiceSessionParticipant.session_id == session_row.session_id,
                    VoiceSessionParticipant.is_connected.is_(True),
                )
            )
            participant_count = int(db_session.execute(connected_count_stmt).scalar() or 0)

            db_session.commit()

        return {
            "session_id": session_row.session_id,
            "channel_id": channel_id,
            "join_token": join_token,
            "signaling_url": session_row.signaling_url,
            "ice_servers": self._build_ice_servers(),
            "expires_at": token_exp.isoformat(),
            "participant_count": participant_count,
            "quality_profile": session_row.quality_profile,
            "backend": "sfu_v2",
        }

    def consume_join_token(self, join_token: str) -> dict[str, Any]:
        """Validate and consume one-time join token (replay-protected)."""
        payload = self._decode_join_token(join_token=join_token, verify_exp=True)
        token_hash = hashlib.sha256(join_token.encode("utf-8")).hexdigest()
        now = datetime.datetime.now(datetime.timezone.utc)

        with self.database_handler.database_session() as db_session:
            token_stmt = select(VoiceJoinToken).where(
                and_(
                    VoiceJoinToken.token_id == str(payload.get("jti")),
                    VoiceJoinToken.token_hash == token_hash,
                    VoiceJoinToken.consumed_at.is_(None),
                    VoiceJoinToken.expires_at > now,
                )
            )
            token_row = db_session.execute(token_stmt).scalar_one_or_none()
            if token_row is None:
                raise ValueError("Join token already used, unknown, or expired")

            token_row.consumed_at = now

            session_stmt = select(VoiceSession).where(
                VoiceSession.session_id == str(payload.get("session_id"))
            )
            session_row = db_session.execute(session_stmt).scalar_one_or_none()
            if session_row is None or not session_row.is_active:
                raise ValueError("Voice session is not active")

            self._record_session_event(
                db_session=db_session,
                session_id=str(payload.get("session_id")),
                user_id=str(payload.get("sub")),
                event_type="join_token_consumed",
                payload={"jti": str(payload.get("jti"))},
            )

            db_session.commit()

        return payload

    def get_session_status(self, session_id: str) -> dict[str, Any] | None:
        """Return voice session status payload for API responses."""
        with self.database_handler.database_session() as db_session:
            session_stmt = select(VoiceSession).where(VoiceSession.session_id == session_id)
            session_row = db_session.execute(session_stmt).scalar_one_or_none()
            if session_row is None:
                return None

            participants_stmt = (
                select(VoiceSessionParticipant)
                .where(VoiceSessionParticipant.session_id == session_id)
                .order_by(VoiceSessionParticipant.joined_at.asc())
            )
            participant_rows = list(db_session.execute(participants_stmt).scalars())

            participants = [
                {
                    "user_id": row.user_id,
                    "username": row.username,
                    "is_connected": row.is_connected,
                    "is_muted": row.is_muted,
                    "is_deafened": row.is_deafened,
                    "is_speaking": row.is_speaking,
                    "joined_at": row.joined_at.isoformat() if row.joined_at else None,
                    "disconnected_at": row.disconnected_at.isoformat() if row.disconnected_at else None,
                }
                for row in participant_rows
            ]

            participant_count = sum(1 for row in participant_rows if row.is_connected)

            return {
                "session_id": session_row.session_id,
                "channel_id": session_row.channel_id,
                "is_active": session_row.is_active,
                "quality_profile": session_row.quality_profile,
                "backend": session_row.backend,
                "signaling_url": session_row.signaling_url,
                "participants": participants,
                "participant_count": participant_count,
            }

    def get_active_session_for_channel(self, channel_id: str) -> dict[str, Any] | None:
        """Return active session status by channel id."""
        with self.database_handler.database_session() as db_session:
            session_row = self._active_session_by_channel(db_session, channel_id)
            if session_row is None:
                return None
            return self.get_session_status(session_id=session_row.session_id)

    def leave_session(self, *, user_id: str, session_id: str) -> dict[str, Any]:
        """Mark participant disconnected and auto-end empty sessions."""
        now = datetime.datetime.now(datetime.timezone.utc)

        with self.database_handler.database_session() as db_session:
            session_stmt = select(VoiceSession).where(VoiceSession.session_id == session_id)
            session_row = db_session.execute(session_stmt).scalar_one_or_none()
            if session_row is None:
                raise ValueError("Voice session not found")

            participant_stmt = select(VoiceSessionParticipant).where(
                and_(
                    VoiceSessionParticipant.session_id == session_id,
                    VoiceSessionParticipant.user_id == str(user_id),
                )
            )
            participant = db_session.execute(participant_stmt).scalar_one_or_none()
            if participant is None:
                raise ValueError("User is not in this voice session")

            participant.is_connected = False
            participant.is_speaking = False
            participant.disconnected_at = now

            self._record_session_event(
                db_session=db_session,
                session_id=session_id,
                user_id=str(user_id),
                event_type="participant_left",
                payload={},
            )

            connected_count_stmt = select(func.count(VoiceSessionParticipant.id)).where(
                and_(
                    VoiceSessionParticipant.session_id == session_id,
                    VoiceSessionParticipant.is_connected.is_(True),
                )
            )
            connected_count = int(db_session.execute(connected_count_stmt).scalar() or 0)

            session_ended = False
            if connected_count == 0 and session_row.is_active:
                session_row.is_active = False
                session_row.ended_at = now
                session_ended = True
                self._record_session_event(
                    db_session=db_session,
                    session_id=session_id,
                    user_id=None,
                    event_type="session_ended",
                    payload={"reason": "empty"},
                )

            db_session.commit()

            return {
                "session_id": session_id,
                "channel_id": session_row.channel_id,
                "participant_count": connected_count,
                "session_ended": session_ended,
            }

    def leave_session_by_channel(self, *, user_id: str, channel_id: str) -> dict[str, Any]:
        """Leave current active session in a given channel."""
        active = self.get_active_session_for_channel(channel_id=channel_id)
        if active is None:
            raise ValueError("No active voice session for this channel")
        return self.leave_session(user_id=user_id, session_id=active["session_id"])

    def apply_action(
        self,
        *,
        user_id: str,
        session_id: str,
        action: str,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Apply participant-side voice state changes."""
        payload = payload or {}

        allowed_actions = {
            "mute_self",
            "deafen_self",
            "set_input_device",
            "set_output_device",
        }
        if action not in allowed_actions:
            raise ValueError(f"Unsupported voice action: {action}")

        with self.database_handler.database_session() as db_session:
            participant_stmt = select(VoiceSessionParticipant).where(
                and_(
                    VoiceSessionParticipant.session_id == session_id,
                    VoiceSessionParticipant.user_id == str(user_id),
                )
            )
            participant = db_session.execute(participant_stmt).scalar_one_or_none()
            if participant is None:
                raise ValueError("User is not a participant in this session")

            if action == "mute_self":
                participant.is_muted = bool(payload.get("value", True))
                if participant.is_muted:
                    participant.is_speaking = False
            elif action == "deafen_self":
                participant.is_deafened = bool(payload.get("value", True))

            self._record_session_event(
                db_session=db_session,
                session_id=session_id,
                user_id=str(user_id),
                event_type=f"participant_action:{action}",
                payload=payload,
            )

            db_session.commit()

            return {
                "session_id": session_id,
                "user_id": str(user_id),
                "action": action,
                "is_muted": participant.is_muted,
                "is_deafened": participant.is_deafened,
                "is_speaking": participant.is_speaking,
            }

    def process_internal_event(self, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Apply state updates emitted by SFU runtime."""
        session_id = str(payload.get("session_id", ""))
        user_id = str(payload.get("user_id", "")) if payload.get("user_id") else None

        if not session_id:
            raise ValueError("Missing session_id in internal event payload")

        now = datetime.datetime.now(datetime.timezone.utc)

        with self.database_handler.database_session() as db_session:
            session_stmt = select(VoiceSession).where(VoiceSession.session_id == session_id)
            session_row = db_session.execute(session_stmt).scalar_one_or_none()
            if session_row is None:
                raise ValueError("Voice session not found")

            if event_type == "participant_joined" and user_id:
                participant_stmt = select(VoiceSessionParticipant).where(
                    and_(
                        VoiceSessionParticipant.session_id == session_id,
                        VoiceSessionParticipant.user_id == user_id,
                    )
                )
                participant = db_session.execute(participant_stmt).scalar_one_or_none()
                if participant is None:
                    participant = VoiceSessionParticipant(
                        session_id=session_id,
                        user_id=user_id,
                        username=str(payload.get("username") or user_id),
                        is_connected=True,
                        joined_at=now,
                    )
                    db_session.add(participant)
                else:
                    participant.is_connected = True
                    participant.disconnected_at = None

            elif event_type == "participant_left" and user_id:
                participant_stmt = select(VoiceSessionParticipant).where(
                    and_(
                        VoiceSessionParticipant.session_id == session_id,
                        VoiceSessionParticipant.user_id == user_id,
                    )
                )
                participant = db_session.execute(participant_stmt).scalar_one_or_none()
                if participant is not None:
                    participant.is_connected = False
                    participant.is_speaking = False
                    participant.disconnected_at = now

            elif event_type == "state_changed" and user_id:
                participant_stmt = select(VoiceSessionParticipant).where(
                    and_(
                        VoiceSessionParticipant.session_id == session_id,
                        VoiceSessionParticipant.user_id == user_id,
                    )
                )
                participant = db_session.execute(participant_stmt).scalar_one_or_none()
                if participant is not None:
                    if "is_muted" in payload:
                        participant.is_muted = bool(payload.get("is_muted"))
                    if "is_deafened" in payload:
                        participant.is_deafened = bool(payload.get("is_deafened"))
                    if "is_speaking" in payload:
                        participant.is_speaking = bool(payload.get("is_speaking"))

            elif event_type == "session_ended":
                session_row.is_active = False
                session_row.ended_at = now

                participants_stmt = select(VoiceSessionParticipant).where(
                    VoiceSessionParticipant.session_id == session_id
                )
                participants = list(db_session.execute(participants_stmt).scalars())
                for participant in participants:
                    participant.is_connected = False
                    participant.is_speaking = False
                    if participant.disconnected_at is None:
                        participant.disconnected_at = now

            self._record_session_event(
                db_session=db_session,
                session_id=session_id,
                user_id=user_id,
                event_type=f"internal:{event_type}",
                payload=payload,
            )

            db_session.commit()

            return {
                "session_id": session_id,
                "channel_id": session_row.channel_id,
                "event_type": event_type,
                "user_id": user_id,
            }

    def verify_internal_signature(self, body: bytes, signature_header: str | None) -> bool:
        """Validate HMAC signature for internal SFU->API callbacks."""
        if not signature_header:
            return False

        incoming = signature_header.strip()
        if incoming.startswith("sha256="):
            incoming = incoming.split("=", 1)[1]

        expected = hmac.new(
            self.internal_secret.encode("utf-8"), body, hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(incoming, expected)

    def _purge_stale_bootstrap_nonces(self, now_ts: int) -> None:
        """Drop stale nonce entries from in-memory replay cache."""
        stale_cutoff = now_ts - self.bootstrap_signature_ttl_seconds
        stale = [
            nonce
            for nonce, seen_ts in self._bootstrap_seen_nonces.items()
            if seen_ts <= stale_cutoff
        ]
        for nonce in stale:
            del self._bootstrap_seen_nonces[nonce]

    def verify_bootstrap_signature(
        self,
        *,
        body: bytes,
        signature_header: str | None,
        timestamp_header: str | None,
        nonce_header: str | None,
    ) -> bool:
        """
        Validate signed bootstrap config requests from SFU.
        """
        if not signature_header or not timestamp_header or not nonce_header:
            return False

        try:
            timestamp = int(timestamp_header)
        except ValueError:
            return False

        now_ts = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        if abs(now_ts - timestamp) > self.bootstrap_signature_ttl_seconds:
            return False

        nonce = nonce_header.strip()
        if not nonce:
            return False

        incoming = signature_header.strip()
        if incoming.startswith("sha256="):
            incoming = incoming.split("=", 1)[1]

        signed_payload = (
            f"{timestamp}.{nonce}.".encode("utf-8") + body
        )
        expected = hmac.new(
            self.bootstrap_secret.encode("utf-8"),
            signed_payload,
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(incoming, expected):
            return False

        with self._bootstrap_nonce_lock:
            self._purge_stale_bootstrap_nonces(now_ts=now_ts)
            if nonce in self._bootstrap_seen_nonces:
                return False
            self._bootstrap_seen_nonces[nonce] = timestamp

        return True

    def build_sfu_bootstrap_config(self) -> dict[str, Any]:
        """
        Build server-authoritative SFU runtime configuration payload.
        """
        cfg = self.database_handler.config
        return {
            "internal_api_base": getattr(
                cfg, "RTC_INTERNAL_API_BASE", self._default_internal_api_base()
            )
            or self._default_internal_api_base(),
            "internal_secret": self.internal_secret,
            "max_total_peers": int(getattr(cfg, "RTC_MAX_TOTAL_PEERS", 200)),
            "max_room_peers": int(getattr(cfg, "RTC_MAX_ROOM_PEERS", 60)),
            "room_end_grace_seconds": int(
                getattr(cfg, "RTC_ROOM_END_GRACE_SECONDS", 15)
            ),
            "internal_event_workers": int(
                getattr(cfg, "RTC_INTERNAL_EVENT_WORKERS", 4)
            ),
            "internal_event_queue_size": int(
                getattr(cfg, "RTC_INTERNAL_EVENT_QUEUE_SIZE", 4096)
            ),
            "internal_http_timeout_seconds": int(
                getattr(cfg, "RTC_INTERNAL_HTTP_TIMEOUT_SECONDS", 5)
            ),
            "ws_write_timeout_seconds": int(
                getattr(cfg, "RTC_WS_WRITE_TIMEOUT_SECONDS", 4)
            ),
            "ws_ping_interval_seconds": int(
                getattr(cfg, "RTC_WS_PING_INTERVAL_SECONDS", 20)
            ),
            "ws_pong_wait_seconds": int(
                getattr(cfg, "RTC_WS_PONG_WAIT_SECONDS", 45)
            ),
            "ws_read_limit_bytes": int(
                getattr(cfg, "RTC_WS_READ_LIMIT_BYTES", 1_048_576)
            ),
            "udp_port_min": int(getattr(cfg, "RTC_UDP_PORT_MIN", 50000)),
            "udp_port_max": int(getattr(cfg, "RTC_UDP_PORT_MAX", 50199)),
            "ice_servers": self._build_ice_servers(),
        }
