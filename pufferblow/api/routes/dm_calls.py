"""1:1 DM voice call signaling — P2P-first, SFU-fallback.

See `DmCallManager` for the full design rationale. This router only
validates auth and relays; it never touches media.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from pufferblow.api.dependencies import ensure_user_not_timed_out, get_current_user
from pufferblow.api.voice.dm_call_manager import CallBusy
from pufferblow.api.schemas import (
    DmCallActionRequest,
    DmCallFallbackRequest,
    DmCallInviteRequest,
    DmCallSignalRequest,
)
from pufferblow.core.bootstrap import api_initializer

router = APIRouter(prefix="/api/v1/dm-calls")


@router.post("/{callee_id}/invite", status_code=200)
async def invite_dm_call(callee_id: str, request: DmCallInviteRequest):
    """Ring another user for a 1:1 voice call."""
    user_id = get_current_user(request.auth_token)
    ensure_user_not_timed_out(user_id, "start voice calls")

    if api_initializer.database_handler.get_user(user_id=callee_id) is None:
        raise HTTPException(status_code=404, detail="User not found")

    # Calls that rang out are dropped here too, so a caller who gave up does not keep their line busy.
    for expired in api_initializer.dm_call_manager.sweep_expired():
        await api_initializer.websockets_manager.broadcast_to_user(
            expired["callee_id"], {"type": "dm_call_ended", "call_id": expired["call_id"]}
        )

    try:
        call = api_initializer.dm_call_manager.invite(
            caller_id=user_id, callee_id=callee_id
        )
    except CallBusy as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Someone already on a call is not rung, and the caller is not told why (it would reveal who is on a call).
    if call.pop("deliver", True):
        await api_initializer.websockets_manager.broadcast_to_user(
            callee_id,
            {
                "type": "dm_call_invite",
                "call_id": call["call_id"],
                "caller_id": call["caller_id"],
            },
        )

    return {"status_code": 200, **call, "ice_servers": api_initializer.voice_session_manager.ice_servers()}


@router.post("/{call_id}/accept", status_code=200)
async def accept_dm_call(call_id: str, request: DmCallActionRequest):
    """Accept an incoming DM call, signaling the caller to begin offering."""
    user_id = get_current_user(request.auth_token)

    try:
        call = api_initializer.dm_call_manager.accept(call_id=call_id, user_id=user_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    await api_initializer.websockets_manager.broadcast_to_user(
        call["caller_id"],
        {"type": "dm_call_accepted", "call_id": call_id},
    )

    return {
        "status_code": 200,
        "call_id": call_id,
        "status": call["status"],
        "ice_servers": api_initializer.voice_session_manager.ice_servers(),
    }


@router.post("/{call_id}/reject", status_code=200)
async def reject_dm_call(call_id: str, request: DmCallActionRequest):
    """Reject (or cancel) a DM call before/while it's ringing."""
    user_id = get_current_user(request.auth_token)

    try:
        call = api_initializer.dm_call_manager.reject(call_id=call_id, user_id=user_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    await api_initializer.websockets_manager.broadcast_to_user(
        call["other_user_id"],
        {"type": "dm_call_rejected", "call_id": call_id},
    )

    return {"status_code": 200, "call_id": call_id, "status": "ended"}


@router.post("/{call_id}/end", status_code=200)
async def end_dm_call(call_id: str, request: DmCallActionRequest):
    """End an in-progress DM call."""
    user_id = get_current_user(request.auth_token)

    try:
        call = api_initializer.dm_call_manager.end(call_id=call_id, user_id=user_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    await api_initializer.websockets_manager.broadcast_to_user(
        call["other_user_id"],
        {"type": "dm_call_ended", "call_id": call_id},
    )

    return {"status_code": 200, "call_id": call_id, "status": "ended"}


@router.post("/{call_id}/signal", status_code=200)
async def relay_dm_call_signal(call_id: str, request: DmCallSignalRequest):
    """Relay one SDP offer/answer or ICE candidate to the other participant."""
    user_id = get_current_user(request.auth_token)

    try:
        relayed = api_initializer.dm_call_manager.relay_signal(
            call_id=call_id,
            user_id=user_id,
            signal_type=request.signal_type,
            payload=request.payload,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    await api_initializer.websockets_manager.broadcast_to_user(
        relayed["to_user_id"],
        {
            "type": f"dm_call_{relayed['signal_type']}",
            "call_id": call_id,
            "from_user_id": relayed["from_user_id"],
            "payload": relayed["payload"],
        },
    )

    return {"status_code": 200, "call_id": call_id, "relayed": True}


@router.post("/{call_id}/fallback", status_code=200)
async def request_dm_call_sfu_fallback(call_id: str, request: DmCallFallbackRequest):
    """Join the SFU fallback session after a failed direct P2P attempt."""
    user_id = get_current_user(request.auth_token)

    try:
        payload = api_initializer.dm_call_manager.request_sfu_fallback(
            call_id=call_id,
            user_id=user_id,
            quality_profile=request.quality_profile,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {"status_code": 200, **payload}
