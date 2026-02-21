"""Versioned SFU voice control-plane routes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from loguru import logger

from pufferblow.api.dependencies import check_channel_access, get_current_user
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

    try:
        payload = api_initializer.voice_session_manager.create_or_join_session(
            user_id=user_id,
            channel_id=channel_id,
            quality_profile=request.quality_profile,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    await api_initializer.websockets_manager.broadcast_to_channel(
        channel_id,
        {
            "type": "voice_session_event",
            "event_type": "participant_joined",
            "session_id": payload["session_id"],
            "channel_id": channel_id,
            "user_id": user_id,
            "participant_count": payload.get("participant_count", 0),
        },
    )

    return {
        "status_code": 200,
        **payload,
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

    await api_initializer.websockets_manager.broadcast_to_channel(
        payload["channel_id"],
        {
            "type": "voice_session_event",
            "event_type": "participant_left",
            "session_id": session_id,
            "channel_id": payload["channel_id"],
            "user_id": user_id,
            "participant_count": payload.get("participant_count", 0),
            "session_ended": payload.get("session_ended", False),
        },
    )

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

    session_payload = api_initializer.voice_session_manager.get_session_status(session_id)
    channel_id = session_payload["channel_id"] if session_payload else None

    if channel_id:
        await api_initializer.websockets_manager.broadcast_to_channel(
            channel_id,
            {
                "type": "voice_session_event",
                "event_type": "state_changed",
                "session_id": session_id,
                "channel_id": channel_id,
                "user_id": user_id,
                "action": request.action,
                "payload": request.payload,
            },
        )

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
