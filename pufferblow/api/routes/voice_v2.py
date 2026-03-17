"""Versioned SFU voice control-plane routes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from loguru import logger

from pufferblow.api.dependencies import (
    check_channel_access,
    ensure_user_not_timed_out,
    get_current_user,
)
from pufferblow.api.schemas import (
    VoiceSessionActionRequest,
    VoiceSessionCreateRequest,
    VoiceSessionLeaveRequest,
)
from pufferblow.core.bootstrap import api_initializer

router = APIRouter(prefix="/api/v2/voice")


@router.post("/channels/{channel_id}/sessions", status_code=200)
async def create_or_join_voice_session(channel_id: str, request: VoiceSessionCreateRequest):
    """Create or join active SFU voice session for a channel."""
    user_id = get_current_user(request.auth_token)
    check_channel_access(user_id=user_id, channel_id=channel_id)
    ensure_user_not_timed_out(user_id, "join voice channels")

    try:
        payload = api_initializer.voice_session_manager.create_or_join_session(
            user_id=user_id,
            channel_id=channel_id,
            quality_profile=request.quality_profile,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {
        "status_code": 200,
        **payload,
    }


@router.get("/channels/{channel_id}/participants", status_code=200)
async def get_voice_channel_participants(channel_id: str, auth_token: str):
    """Return participants in the active voice session for a channel (read-only, no join required)."""
    user_id = get_current_user(auth_token)
    check_channel_access(user_id=user_id, channel_id=channel_id)

    payload = api_initializer.voice_session_manager.get_active_session_for_channel(channel_id)
    if payload is None:
        return {
            "status_code": 200,
            "channel_id": channel_id,
            "participants": [],
            "participant_count": 0,
            "session_id": None,
        }

    return {
        "status_code": 200,
        "channel_id": channel_id,
        "participants": [p for p in payload.get("participants", []) if p.get("is_connected")],
        "participant_count": payload.get("participant_count", 0),
        "session_id": payload.get("session_id"),
    }


@router.post("/sessions/{session_id}/leave", status_code=200)
async def leave_voice_session(session_id: str, request: VoiceSessionLeaveRequest):
    """Leave voice session for current user."""
    user_id = get_current_user(request.auth_token)

    try:
        payload = api_initializer.voice_session_manager.leave_session(
            user_id=user_id,
            session_id=session_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {
        "status_code": 200,
        "message": "Voice session left successfully",
        **payload,
    }


@router.get("/sessions/{session_id}", status_code=200)
async def get_voice_session_status(session_id: str, auth_token: str):
    """Get current voice session state and participant metadata."""
    user_id = get_current_user(auth_token)
    payload = api_initializer.voice_session_manager.get_session_status(session_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="Voice session not found")

    check_channel_access(user_id=user_id, channel_id=payload["channel_id"])

    return {
        "status_code": 200,
        **payload,
    }


@router.post("/sessions/{session_id}/actions", status_code=200)
async def apply_voice_session_action(session_id: str, request: VoiceSessionActionRequest):
    """Apply self-scoped audio state actions inside a voice session."""
    user_id = get_current_user(request.auth_token)

    try:
        action_payload = api_initializer.voice_session_manager.apply_action(
            user_id=user_id,
            session_id=session_id,
            action=request.action,
            payload=request.payload,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    logger.debug(
        "VOICE_ACTION_APPLIED session_id={session_id} user_id={user_id} action={action}",
        session_id=session_id,
        user_id=user_id,
        action=request.action,
    )

    return {
        "status_code": 200,
        **action_payload,
    }
