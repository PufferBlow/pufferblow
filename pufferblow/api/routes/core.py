"""Core application routes."""

from __future__ import annotations

from fastapi import APIRouter, exceptions, responses

from pufferblow.api.schemas import RefreshTokenRequest
from pufferblow.core.bootstrap import api_initializer

router = APIRouter()


@router.get("/")
async def redirect_route():
    """Redirect root to API info route."""
    return responses.RedirectResponse("/api/v1/info")


@router.get("/api/v1", status_code=200)
async def home_route():
    """Redirect API root to info route."""
    return responses.RedirectResponse("/api/v1/info")


@router.get("/api/v1/info", status_code=200)
async def server_info_route():
    """Get minimal server status payload."""
    return {"status_code": 200}


@router.post("/api/v1/auth/refresh", status_code=200)
async def refresh_auth_token(request: RefreshTokenRequest):
    """Refresh an access token using a valid refresh token."""
    try:
        payload = api_initializer.auth_token_manager.validate_refresh_token(
            refresh_token=request.refresh_token
        )
    except ValueError as exc:
        raise exceptions.HTTPException(status_code=401, detail=str(exc)) from exc

    user_id = str(payload["uid"])
    user = api_initializer.database_handler.get_user(user_id=user_id)
    if user is None:
        raise exceptions.HTTPException(status_code=404, detail="User not found")

    api_initializer.auth_token_manager.revoke_refresh_token(request.refresh_token)
    session_tokens = api_initializer.auth_token_manager.issue_session_tokens(
        user_id=user_id,
        origin_server=user.origin_server,
    )

    return {
        "status_code": 200,
        "message": "Token refreshed successfully",
        "auth_token": session_tokens["access_token"],
        "refresh_token": session_tokens["refresh_token"],
        "token_type": session_tokens["token_type"],
        "auth_token_expire_time": session_tokens["access_token_expires_at"],
        "refresh_token_expire_time": session_tokens["refresh_token_expires_at"],
    }


@router.post("/api/v1/auth/revoke", status_code=200)
async def revoke_refresh_token_route(request: RefreshTokenRequest):
    """Revoke a refresh token (logout session)."""
    api_initializer.auth_token_manager.revoke_refresh_token(request.refresh_token)
    return {
        "status_code": 200,
        "message": "Refresh token revoked successfully",
    }
