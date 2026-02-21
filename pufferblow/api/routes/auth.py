from fastapi import APIRouter, exceptions

from pufferblow.api.dependencies import get_current_user
from pufferblow.api.schemas import (
    DecentralizedChallengeRequest,
    DecentralizedSessionIntrospectRequest,
    DecentralizedSessionRevokeRequest,
    DecentralizedVerifyRequest,
)
from pufferblow.core.bootstrap import api_initializer

router = APIRouter(prefix="/api/v1/auth/decentralized")


@router.post("/challenge", status_code=200)
async def issue_decentralized_challenge_route(request: DecentralizedChallengeRequest):
    """Issue decentralized challenge route."""
    user_id = get_current_user(request.auth_token)
    result = api_initializer.decentralized_auth_manager.issue_challenge(
        user_id=user_id,
        node_id=request.node_id,
    )
    return {"status_code": 200, **result}


@router.post("/verify", status_code=200)
async def verify_decentralized_challenge_route(request: DecentralizedVerifyRequest):
    """Verify decentralized challenge route."""
    result = api_initializer.decentralized_auth_manager.verify_challenge_and_issue_session(
        challenge_id=request.challenge_id,
        node_public_key=request.node_public_key,
        challenge_signature=request.challenge_signature,
        shared_secret=request.shared_secret,
    )
    return {"status_code": 200, **result}


@router.post("/introspect", status_code=200)
async def introspect_decentralized_session_route(
    request: DecentralizedSessionIntrospectRequest,
):
    """Introspect decentralized session route."""
    result = api_initializer.decentralized_auth_manager.introspect_session(
        session_token=request.session_token
    )
    return {"status_code": 200, **result}


@router.post("/revoke", status_code=200)
async def revoke_decentralized_session_route(request: DecentralizedSessionRevokeRequest):
    """Revoke decentralized session route."""
    user_id = get_current_user(request.auth_token)
    active_sessions = api_initializer.database_handler.list_active_decentralized_node_sessions(
        user_id=user_id
    )

    target = None
    for session in active_sessions:
        if str(session.session_id) == request.session_id:
            target = session
            break

    if target is None:
        raise exceptions.HTTPException(
            status_code=404,
            detail="Session not found for current user",
        )

    api_initializer.database_handler.revoke_decentralized_node_session(request.session_id)
    return {
        "status_code": 200,
        "message": "Session revoked successfully",
        "session_id": request.session_id,
    }
