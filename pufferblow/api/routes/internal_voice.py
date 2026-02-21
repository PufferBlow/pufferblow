"""Internal voice callbacks from SFU runtime."""

from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Request

from pufferblow.api.schemas import InternalVoiceEventRequest, VoiceJoinTokenConsumeRequest
from pufferblow.core.bootstrap import api_initializer

router = APIRouter(prefix="/api/internal/v1/voice")


def _verify_signature_or_fail(body: bytes, signature: str | None) -> None:
    """Validate internal HMAC signature for SFU callbacks."""
    if not api_initializer.voice_session_manager.verify_internal_signature(
        body=body,
        signature_header=signature,
    ):
        raise HTTPException(status_code=401, detail="Invalid internal signature")


@router.post("/consume-join-token", status_code=200)
async def consume_join_token(request: Request):
    """Consume one-time join token and return trusted claims to SFU."""
    body = await request.body()
    signature = request.headers.get("X-Pufferblow-Signature")
    _verify_signature_or_fail(body=body, signature=signature)

    try:
        payload = VoiceJoinTokenConsumeRequest.model_validate(json.loads(body.decode("utf-8")))
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid request payload") from exc

    try:
        claims = api_initializer.voice_session_manager.consume_join_token(
            join_token=payload.join_token
        )
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    return {
        "status_code": 200,
        "claims": claims,
    }


@router.post("/events", status_code=202)
async def ingest_voice_event(request: Request):
    """Apply SFU runtime events into control-plane state."""
    body = await request.body()
    signature = request.headers.get("X-Pufferblow-Signature")
    _verify_signature_or_fail(body=body, signature=signature)

    try:
        event = InternalVoiceEventRequest.model_validate(json.loads(body.decode("utf-8")))
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid request payload") from exc

    try:
        result = api_initializer.voice_session_manager.process_internal_event(
            event_type=event.event_type,
            payload=event.payload,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {
        "status_code": 202,
        "message": "Voice event processed",
        "result": result,
    }


@router.post("/bootstrap-config", status_code=200)
async def get_sfu_bootstrap_config(request: Request):
    """Return signed, server-authoritative SFU runtime configuration."""
    body = await request.body()
    signature = request.headers.get("X-Pufferblow-Signature")
    timestamp = request.headers.get("X-Pufferblow-Timestamp")
    nonce = request.headers.get("X-Pufferblow-Nonce")

    if not api_initializer.voice_session_manager.verify_bootstrap_signature(
        body=body,
        signature_header=signature,
        timestamp_header=timestamp,
        nonce_header=nonce,
    ):
        raise HTTPException(status_code=401, detail="Invalid bootstrap signature")

    return {
        "status_code": 200,
        "config": api_initializer.voice_session_manager.build_sfu_bootstrap_config(),
    }
