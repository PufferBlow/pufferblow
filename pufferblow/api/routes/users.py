import json
import uuid

from fastapi import APIRouter, Depends, Form, UploadFile, exceptions
from loguru import logger

from pufferblow.api.database.tables.activity_audit import ActivityAudit
from pufferblow.api.dependencies import get_current_user
from pufferblow.api.logger.msgs import info
from pufferblow.api.schemas import (
    AuthTokenQuery,
    EditProfileRequest,
    ResetTokenRequest,
    SigninQuery,
    SignupRequest,
    UserProfileRequest,
)
from pufferblow.api.utils.is_able_to_update import is_able_to_update
from pufferblow.core.bootstrap import api_initializer

router = APIRouter(prefix="/api/v1/users")


@router.get("", status_code=200)
async def users_route():
    """Users route."""
    return {"status_code": 200, "description": "This is the main users route"}


@router.post("/signup", status_code=201)
async def signup_new_user(request: SignupRequest):
    """Signup new user."""
    if api_initializer.user_manager.check_username(request.username):
        raise exceptions.HTTPException(
            status_code=409,
            detail="username already exists. Please change it and try again later",
        )

    user_data = api_initializer.user_manager.sign_up(
        username=request.username, password=request.password
    )

    logger.info(info.INFO_NEW_USER_SIGNUP_SUCCESSFULLY(user=user_data))

    api_initializer.database_handler.create_activity_audit_entry(
        ActivityAudit(
            activity_id=str(uuid.uuid4()),
            activity_type="user_joined",
            user_id=str(user_data.user_id),
            title=f"User {request.username} joined the server",
            description=f"New user {request.username} has successfully registered",
            metadata_json=json.dumps(
                {
                    "username": request.username,
                    "user_id": str(user_data.user_id),
                    "joined_at": user_data.created_at.isoformat(),
                }
            ),
        )
    )

    session_tokens = api_initializer.auth_token_manager.issue_session_tokens(
        user_id=str(user_data.user_id),
        origin_server=user_data.origin_server,
    )

    return {
        "status_code": 201,
        "message": "Account created successfully",
        "auth_token": session_tokens["access_token"],
        "refresh_token": session_tokens["refresh_token"],
        "token_type": session_tokens["token_type"],
        "auth_token_expire_time": session_tokens["access_token_expires_at"],
        "refresh_token_expire_time": session_tokens["refresh_token_expires_at"],
    }


@router.get("/signin", status_code=200)
async def signin_user(query: SigninQuery = Depends()):
    """Signin user."""
    if not api_initializer.user_manager.check_username(username=query.username):
        raise exceptions.HTTPException(
            status_code=404,
            detail="The provided username does not exist or could not be found. Please make sure you have entered a valid username and try again.",
        )

    user, is_signin_successful, failure_reason = api_initializer.user_manager.sign_in(
        username=query.username, password=query.password
    )
    if not is_signin_successful:
        if failure_reason == "instance_mismatch":
            raise exceptions.HTTPException(
                status_code=403,
                detail="This account belongs to a different instance and cannot sign in on this server.",
            )
        raise exceptions.HTTPException(
            status_code=401,
            detail="The provided password is incorrect. Please try again.",
        )

    api_initializer.database_handler.create_activity_audit_entry(
        ActivityAudit(
            activity_id=str(uuid.uuid4()),
            activity_type="user_signed_in",
            user_id=str(user.user_id),
            title=f"User {query.username} signed in",
            description=f"User {query.username} successfully signed in to their account",
            metadata_json=json.dumps(
                {
                    "username": query.username,
                    "user_id": str(user.user_id),
                    "signin_method": "password",
                }
            ),
        )
    )

    session_tokens = api_initializer.auth_token_manager.issue_session_tokens(
        user_id=str(user.user_id),
        origin_server=user.origin_server,
    )
    return {
        "status_code": 200,
        "message": "Signin successfully",
        "auth_token": session_tokens["access_token"],
        "refresh_token": session_tokens["refresh_token"],
        "token_type": session_tokens["token_type"],
        "auth_token_expire_time": session_tokens["access_token_expires_at"],
        "refresh_token_expire_time": session_tokens["refresh_token_expires_at"],
    }


@router.post("/profile", status_code=200)
async def users_profile_route(request: UserProfileRequest):
    """Users profile route."""
    user_id = get_current_user(request.auth_token)
    target_user_id = request.user_id if request.user_id else user_id
    is_account_owner = api_initializer.auth_token_manager.check_users_auth_token(
        user_id=target_user_id, raw_auth_token=request.auth_token
    )
    user_data = api_initializer.user_manager.user_profile(
        user_id=target_user_id, is_account_owner=is_account_owner
    )
    return {"status_code": 200, "user_data": user_data}


@router.put("/profile", status_code=200)
async def edit_users_profile_route(request: EditProfileRequest):
    """Edit users profile route."""
    user_id = get_current_user(request.auth_token)

    if request.new_username is not None:
        if api_initializer.user_manager.check_username(username=request.new_username):
            raise exceptions.HTTPException(
                detail="username already exists. Please change it and try again later",
                status_code=409,
            )
        api_initializer.user_manager.update_username(
            user_id=user_id, new_username=request.new_username
        )
        return {"status_code": 200, "message": "username updated successfully"}

    if request.status is not None:
        try:
            normalized_status = (
                await api_initializer.websockets_manager.update_user_presence_status(
                    user_id=user_id,
                    status=request.status,
                    source="http_profile_update",
                )
            )
        except ValueError as exc:
            raise exceptions.HTTPException(status_code=422, detail=str(exc)) from exc

        return {
            "status_code": 200,
            "message": "Status updated successfully",
            "status": normalized_status,
        }

    if request.new_password is not None and request.old_password is not None:
        api_initializer.user_manager.update_user_password(
            user_id=user_id, new_password=request.new_password
        )
        return {"status_code": 200, "message": "Password updated successfully"}

    if request.about is not None:
        api_initializer.user_manager.update_user_about(user_id=user_id, new_about=request.about)
        return {"status_code": 200, "message": "About updated successfully"}

    raise exceptions.HTTPException(status_code=400, detail="No update payload was provided")


@router.post("/profile/avatar", status_code=201)
async def upload_user_avatar_route(
    auth_token: str = Form(..., description="User's authentication token"),
    file: UploadFile = Form(..., description="Avatar image file"),
):
    """Upload user avatar route."""
    user_id = get_current_user(auth_token)
    avatar_url, is_duplicate = await api_initializer.user_manager.update_user_avatar(
        user_id=user_id, avatar_file=file
    )
    return {
        "status_code": 201,
        "message": (
            "Avatar updated via existing file (duplicate detected)"
            if is_duplicate
            else "Avatar uploaded successfully"
        ),
        "avatar_url": avatar_url,
        "duplicate_status": "existing" if is_duplicate else "new",
    }


@router.post("/profile/banner", status_code=201)
async def upload_user_banner_route(
    auth_token: str = Form(..., description="User's authentication token"),
    file: UploadFile = Form(..., description="Banner image file"),
):
    """Upload user banner route."""
    user_id = get_current_user(auth_token)
    banner_url, is_duplicate = await api_initializer.user_manager.update_user_banner(
        user_id=user_id, banner_file=file
    )
    return {
        "status_code": 201,
        "message": (
            "Banner updated via existing file (duplicate detected)"
            if is_duplicate
            else "Banner uploaded successfully"
        ),
        "banner_url": banner_url,
        "duplicate_status": "existing" if is_duplicate else "new",
    }


@router.post("/profile/reset-auth-token", status_code=200)
async def reset_users_auth_token_route(request: ResetTokenRequest):
    """Reset users auth token route."""
    user_id = get_current_user(request.auth_token)
    if not api_initializer.user_manager.check_user_password(
        user_id=user_id, password=request.password
    ):
        logger.info(info.INFO_RESET_USER_AUTH_TOKEN_FAILED(user_id=user_id))
        raise exceptions.HTTPException(
            detail="Incorrect password. Please try again", status_code=404
        )

    updated_at = api_initializer.database_handler.get_auth_tokens_updated_at(user_id=user_id)
    if updated_at is not None and not is_able_to_update(updated_at=updated_at, suspend_time=2):
        logger.info(info.INFO_AUTH_TOKEN_SUSPENSION_TIME(user_id=user_id))
        raise exceptions.HTTPException(
            detail="Cannot reset authentication token. Suspension time has not elapsed.",
            status_code=403,
        )

    user = api_initializer.database_handler.get_user(user_id=user_id)
    session_tokens = api_initializer.auth_token_manager.issue_session_tokens(
        user_id=user_id,
        origin_server=user.origin_server,
    )

    return {
        "status_code": 200,
        "message": "auth_token reset successfully",
        "auth_token": session_tokens["access_token"],
        "refresh_token": session_tokens["refresh_token"],
        "token_type": session_tokens["token_type"],
        "auth_token_expire_time": session_tokens["access_token_expires_at"],
        "refresh_token_expire_time": session_tokens["refresh_token_expires_at"],
    }


@router.get("/list", status_code=200)
async def list_users_route(query: AuthTokenQuery = Depends()):
    """List users route."""
    viewer_user_id = get_current_user(query.auth_token)
    users = api_initializer.user_manager.list_users(
        viewer_user_id=viewer_user_id, auth_token=query.auth_token
    )
    return {"status_code": 200, "users": users}
