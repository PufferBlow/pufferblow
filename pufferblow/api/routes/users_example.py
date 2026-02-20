"""
User routes module (EXAMPLE - not yet integrated into main api.py).

This is an example showing how user-related routes should be extracted from api.py.
It demonstrates the use of:
- Shared dependencies for authentication
- Pydantic schemas for validation
- Proper error handling
- Clean separation of concerns

To integrate this:
1. Import this router in api.py: from pufferblow.api.routes.users_example import router as users_router
2. Include the router: api.include_router(users_router, tags=["users"])
3. Remove the corresponding routes from api.py
"""

import uuid
import json
from fastapi import APIRouter, Depends, Form, UploadFile, exceptions
from loguru import logger

from pufferblow.api.schemas import (
    SignupRequest,
    SigninQuery,
    AuthTokenQuery,
    UserProfileRequest,
    EditProfileRequest,
    ResetTokenRequest,
)
from pufferblow.api.dependencies import get_current_user
from pufferblow.api.utils.extract_user_id import extract_user_id
from pufferblow.api.utils.is_able_to_update import is_able_to_update
from pufferblow.api_initializer import api_initializer
from pufferblow.api.logger.msgs import info
from pufferblow.api.database.tables.activity_audit import ActivityAudit

import base64

# Create router for user-related endpoints
router = APIRouter(prefix="/api/v1/users")


@router.get("", status_code=200)
async def users_route():
    """Users route start point"""
    return {"status_code": 200, "description": "This is the main users route"}


@router.post("/signup", status_code=201)
async def signup_new_user(request: SignupRequest):
    """
    Signup a new user.

    Args:
        request (SignupRequest): Request body containing username and password.

    Returns:
        201 OK: If the username is available and user is signed up
        409 CONFLICT: If the username already exists
    """
    # Check if username is available
    if api_initializer.user_manager.check_username(request.username):
        raise exceptions.HTTPException(
            status_code=409,
            detail="username already exists. Please change it and try again later",
        )

    # Create the user
    user_data = api_initializer.user_manager.sign_up(
        username=request.username, password=request.password
    )

    logger.info(
        info.INFO_NEW_USER_SIGNUP_SUCCESSFULLY(
            user=user_data,
        )
    )

    # Log user signup activity
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
    """
    Sign in to an account.

    Args:
        query (SigninQuery): Query parameters with username and password

    Returns:
        200 OK: If credentials are correct
        401 UNAUTHORIZED: If password is invalid
        404 NOT FOUND: If username doesn't exist
    """
    # Check if username exists
    if not api_initializer.user_manager.check_username(username=query.username):
        raise exceptions.HTTPException(
            status_code=404,
            detail="The provided username does not exist or could not be found. Please make sure you have entered a valid username and try again.",
        )

    # Attempt sign in
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

    # Log user signin activity
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
    """
    Get user profile information.

    Args:
        request (UserProfileRequest): Request with auth_token and optional user_id

    Returns:
        200 OK: User profile data
        400 BAD REQUEST: Invalid auth_token format
        404 NOT FOUND: User not found
    """
    # Extract user ID from token using dependency
    user_id = get_current_user(request.auth_token)

    # If user_id is provided in request, use it; otherwise use the one from auth_token
    target_user_id = request.user_id if request.user_id else user_id

    # Check if viewer user owns the targeted account
    is_account_owner = api_initializer.auth_token_manager.check_users_auth_token(
        user_id=target_user_id, raw_auth_token=request.auth_token
    )

    user_data = api_initializer.user_manager.user_profile(
        user_id=target_user_id, is_account_owner=is_account_owner
    )

    return {"status_code": 200, "user_data": user_data}


@router.put("/profile", status_code=200)
async def edit_users_profile_route(request: EditProfileRequest):
    """
    Update user profile (username, status, password, about).

    Args:
        request (EditProfileRequest): Request with auth_token and fields to update

    Returns:
        200 OK: Profile updated successfully
        401 UNAUTHORIZED: Invalid password
        404 NOT FOUND: User not found
        409 CONFLICT: Username already exists
    """
    # Validate user and extract ID
    user_id = get_current_user(request.auth_token)

    # Update username
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

    # Update user's status
    if request.status is not None:
        api_initializer.user_manager.update_user_status(
            user_id=user_id, status=request.status
        )

        return {"status_code": 200, "message": "Status updated successfully"}

    # Update user's password
    if request.new_password is not None and request.old_password is not None:
        api_initializer.user_manager.update_user_password(
            user_id=user_id, new_password=request.new_password
        )

        return {"status_code": 200, "message": "Password updated successfully"}

    # Update about
    if request.about is not None:
        api_initializer.user_manager.update_user_about(
            user_id=user_id, new_about=request.about
        )
        return {"status_code": 200, "message": "About updated successfully"}


@router.post("/profile/avatar", status_code=201)
async def upload_user_avatar_route(
    auth_token: str = Form(..., description="User's authentication token"),
    file: UploadFile = Form(..., description="Avatar image file"),
):
    """
    Upload user's avatar image.

    Args:
        auth_token: User's authentication token
        file: Avatar image file

    Returns:
        201 CREATED: File uploaded successfully
        400 BAD REQUEST: File validation failed
        404 NOT FOUND: Invalid auth_token
    """
    user_id = get_current_user(auth_token)

    try:
        avatar_url, is_duplicate = (
            await api_initializer.user_manager.update_user_avatar(
                user_id=user_id, avatar_file=file
            )
        )

        message = (
            "Avatar updated via existing file (duplicate detected)"
            if is_duplicate
            else "Avatar uploaded successfully"
        )
        duplicate_status = "existing" if is_duplicate else "new"

        return {
            "status_code": 201,
            "message": message,
            "avatar_url": avatar_url,
            "duplicate_status": duplicate_status,
        }

    except exceptions.HTTPException:
        raise
    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500, detail=f"Upload failed: {str(e)}"
        )


@router.post("/profile/banner", status_code=201)
async def upload_user_banner_route(
    auth_token: str = Form(..., description="User's authentication token"),
    file: UploadFile = Form(..., description="Banner image file"),
):
    """
    Upload user's banner image.

    Args:
        auth_token: User's authentication token
        file: Banner image file

    Returns:
        201 CREATED: File uploaded successfully
        400 BAD REQUEST: File validation failed
        404 NOT FOUND: Invalid auth_token
    """
    user_id = get_current_user(auth_token)

    try:
        banner_url, is_duplicate = (
            await api_initializer.user_manager.update_user_banner(
                user_id=user_id, banner_file=file
            )
        )

        message = (
            "Banner updated via existing file (duplicate detected)"
            if is_duplicate
            else "Banner uploaded successfully"
        )
        duplicate_status = "existing" if is_duplicate else "new"

        return {
            "status_code": 201,
            "message": message,
            "banner_url": banner_url,
            "duplicate_status": duplicate_status,
        }

    except exceptions.HTTPException:
        raise
    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500, detail=f"Upload failed: {str(e)}"
        )


@router.post("/profile/reset-auth-token", status_code=200)
async def reset_users_auth_token_route(request: ResetTokenRequest):
    """
    Reset the user's auth_token.

    Args:
        request (ResetTokenRequest): Request with auth_token and password

    Returns:
        200 OK: Token reset successfully
        401 UNAUTHORIZED: Invalid password
        403 FORBIDDEN: Suspension time not elapsed
        404 NOT FOUND: User not found
    """
    user_id = extract_user_id(auth_token=request.auth_token)

    # Verify password
    if not api_initializer.user_manager.check_user_password(
        user_id=user_id, password=request.password
    ):
        logger.info(
            info.INFO_RESET_USER_AUTH_TOKEN_FAILED(
                user_id=user_id,
            )
        )

        raise exceptions.HTTPException(
            detail="Incorrect password. Please try again", status_code=404
        )

    # Check if user is suspended from resetting their auth_token
    updated_at = api_initializer.database_handler.get_auth_tokens_updated_at(
        user_id=user_id
    )
    if updated_at is not None:
        if not is_able_to_update(updated_at=updated_at, suspend_time=2):  # Two days
            logger.info(info.INFO_AUTH_TOKEN_SUSPENSION_TIME(user_id=user_id))

            raise exceptions.HTTPException(
                detail="Cannot reset authentication token. Suspension time has not elapsed.",
                status_code=403,
            )

    # Generate new auth token
    new_auth_token = f"{user_id}.{api_initializer.auth_token_manager.create_token()}"

    ciphered_auth_token, key = api_initializer.hasher.encrypt(data=new_auth_token)
    ciphered_auth_token = base64.b64encode(ciphered_auth_token).decode("ascii")

    key.user_id = user_id
    key.associated_to = "auth_token"

    api_initializer.database_handler.update_key(key)
    new_auth_token_expire_time = (
        api_initializer.auth_token_manager.create_auth_token_expire_time()
    )

    api_initializer.database_handler.update_auth_token(
        user_id=user_id,
        new_auth_token=ciphered_auth_token,
        new_auth_token_expire_time=new_auth_token_expire_time,
    )

    return {
        "status_code": 200,
        "message": "auth_token reset successfully",
        "auth_token": new_auth_token,
        "auth_token_expire_time": new_auth_token_expire_time,
    }


@router.get("/list", status_code=200)
async def list_users_route(query: AuthTokenQuery = Depends()):
    """
    Get a list of all server users.

    Args:
        query (AuthTokenQuery): Query with auth_token

    Returns:
        200 OK: List of users
        404 NOT FOUND: Invalid auth_token
    """
    viewer_user_id = get_current_user(query.auth_token)

    users = api_initializer.user_manager.list_users(
        viewer_user_id=viewer_user_id, auth_token=query.auth_token
    )

    return {"status_code": 200, "users": users}
