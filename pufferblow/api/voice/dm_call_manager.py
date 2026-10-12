from __future__ import annotations

import datetime
import threading
import uuid
from typing import Any

from pufferblow.api.friends.friends_manager import FriendsManager
from pufferblow.api.voice.voice_session_manager import VoiceSessionManager

_ACTIVE_STATUSES = {"ringing", "accepted"}


class DmCallManager:
    """Control-plane signaling relay for 1:1 DM voice calls.

    Pufferblow has never had DM voice calling (channel voice is SFU-only,
    per `docs/developer/architecture.md`). This adds the P2P-first path for
    exactly the 2-party case: this manager never touches media, it only
    brokers `call_invite`/`call_accept`/`call_reject`/`call_offer`/
    `call_answer`/`call_candidate`/`call_end` between the two participants
    over the existing global WebSocket stream (`WebSocketsManager.broadcast_to_user`).
    If direct `RTCPeerConnection` negotiation doesn't complete in time, the
    client falls back to `VoiceSessionManager.create_or_join_dm_fallback_session`
    — same SFU join/bootstrap path channel voice uses, including multi-instance
    selection.

    Call state is kept in-process (a dict guarded by a lock), the same
    durability tier as `WebSocketsManager`'s own connection table — a ringing
    call that outlives a server restart isn't a scenario worth persisting
    for, since the WebSocket connections themselves wouldn't survive it either.
    """

    def __init__(
        self,
        *,
        friends_manager: FriendsManager,
        voice_session_manager: VoiceSessionManager,
        ring_timeout_seconds: int = 45,
    ) -> None:
        self.friends_manager = friends_manager
        self.voice_session_manager = voice_session_manager
        self.ring_timeout_seconds = ring_timeout_seconds

        self._lock = threading.Lock()
        self._calls: dict[str, dict[str, Any]] = {}

    @staticmethod
    def _now() -> datetime.datetime:
        return datetime.datetime.now(datetime.timezone.utc)

    def _other_participant(self, call: dict[str, Any], user_id: str) -> str:
        caller_id, callee_id = call["caller_id"], call["callee_id"]
        if str(user_id) == str(caller_id):
            return callee_id
        if str(user_id) == str(callee_id):
            return caller_id
        raise ValueError("User is not a participant in this call")

    def _get_call_or_raise(self, call_id: str) -> dict[str, Any]:
        call = self._calls.get(call_id)
        if call is None:
            raise ValueError("Call not found")
        return call

    def invite(self, *, caller_id: str, callee_id: str) -> dict[str, Any]:
        """Start a call. Fails if either side has blocked the other."""
        if str(caller_id) == str(callee_id):
            raise ValueError("Cannot call yourself")

        if self.friends_manager.is_viewer_blocked_by(
            viewer_id=caller_id, target_id=callee_id
        ) or self.friends_manager.is_viewer_blocked_by(
            viewer_id=callee_id, target_id=caller_id
        ):
            # Deliberately the same generic error a blocked DM send would
            # give — no signal to the caller about which side blocked whom.
            raise ValueError("Cannot call this user")

        call_id = str(uuid.uuid4())
        now = self._now()
        with self._lock:
            self._calls[call_id] = {
                "call_id": call_id,
                "caller_id": str(caller_id),
                "callee_id": str(callee_id),
                "status": "ringing",
                "created_at": now,
                "updated_at": now,
            }

        return {
            "call_id": call_id,
            "caller_id": str(caller_id),
            "callee_id": str(callee_id),
            "status": "ringing",
        }

    def accept(self, *, call_id: str, user_id: str) -> dict[str, Any]:
        with self._lock:
            call = self._get_call_or_raise(call_id)
            if str(user_id) != str(call["callee_id"]):
                raise ValueError("Only the callee can accept this call")
            if call["status"] != "ringing":
                raise ValueError(f"Call is not ringing (status={call['status']})")
            call["status"] = "accepted"
            call["updated_at"] = self._now()
            return dict(call)

    def reject(self, *, call_id: str, user_id: str) -> dict[str, Any]:
        with self._lock:
            call = self._get_call_or_raise(call_id)
            other_user_id = self._other_participant(call, user_id)
            call["status"] = "ended"
            call["updated_at"] = self._now()
            snapshot = dict(call)
            del self._calls[call_id]
            snapshot["other_user_id"] = other_user_id
            return snapshot

    def end(self, *, call_id: str, user_id: str) -> dict[str, Any]:
        with self._lock:
            call = self._get_call_or_raise(call_id)
            other_user_id = self._other_participant(call, user_id)
            snapshot = dict(call)
            del self._calls[call_id]
            snapshot["other_user_id"] = other_user_id
            return snapshot

    def relay_signal(
        self, *, call_id: str, user_id: str, signal_type: str, payload: dict
    ) -> dict[str, Any]:
        """Validate a signaling message and return who it should be relayed to.

        `signal_type` is one of offer/answer/candidate — this manager doesn't
        interpret SDP/ICE content at all, it only enforces that the sender is
        one of the call's two participants and the call is still live.
        """
        with self._lock:
            call = self._get_call_or_raise(call_id)
            if call["status"] not in _ACTIVE_STATUSES:
                raise ValueError(f"Call is not active (status={call['status']})")
            other_user_id = self._other_participant(call, user_id)

        return {
            "call_id": call_id,
            "from_user_id": str(user_id),
            "to_user_id": other_user_id,
            "signal_type": signal_type,
            "payload": payload,
        }

    def request_sfu_fallback(
        self, *, call_id: str, user_id: str, quality_profile: str = "balanced"
    ) -> dict[str, Any]:
        """Join the SFU fallback session for a call whose P2P path failed."""
        with self._lock:
            call = self._get_call_or_raise(call_id)
            if call["status"] not in _ACTIVE_STATUSES:
                raise ValueError(f"Call is not active (status={call['status']})")
            self._other_participant(call, user_id)  # raises if not a participant

        return self.voice_session_manager.create_or_join_dm_fallback_session(
            user_id=user_id,
            call_id=call_id,
            quality_profile=quality_profile,
        )
