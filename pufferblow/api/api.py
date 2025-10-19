import sys
import asyncio
import base64
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import (
    FastAPI,
    WebSocket,
    WebSocketDisconnect,
    responses,
    exceptions,
    Body,
    Depends,
    UploadFile,
    Form,
    File
)
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

from loguru import logger

# TODO: BLock known IPs https://www.ipdeny.com/ipblocks/

# Pydantic models for request bodies and query parameters
class SignupRequest(BaseModel):
    username: str
    password: str

class SigninRequest(BaseModel):
    username: str
    password: str

class UserProfileRequest(BaseModel):
    auth_token: str = Field(min_length=1)
    user_id: str | None = None  # Optional for current user profile

class EditProfileRequest(BaseModel):
    auth_token: str
    new_username: str | None = None
    status: str | None = None
    new_password: str | None = None
    old_password: str | None = None
    about: str | None = None

class ResetTokenRequest(BaseModel):
    auth_token: str
    password: str

class ListUsersRequest(BaseModel):
    auth_token: str

class ListUsersResponse(BaseModel):
    status_code: int
    users: list[dict]  # Keep as dict for now since complex nested user structure

class ListChannelsRequest(BaseModel):
    auth_token: str

class ListChannelsResponse(BaseModel):
    status_code: int
    channels: list = []  # Keep as list for now since complex nested channel structure

class CreateChannelRequest(BaseModel):
    auth_token: str
    channel_name: str
    is_private: bool = False

class CreateChannelResponse(BaseModel):
    status_code: int
    message: str
    channel_data: dict  # Keep complex dict structure for channel data

# Query parameter models
class AuthTokenQuery(BaseModel):
    auth_token: str = Field(min_length=1)

class SigninQuery(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)

class UserProfileQuery(BaseModel):
    user_id: str = Field(min_length=1)
    auth_token: str = Field(min_length=1)

class EditProfileQuery(BaseModel):
    auth_token: str = Field(min_length=1)
    new_username: str | None = None
    status: str | None = None
    new_password: str | None = None
    old_password: str | None = None
    about: str | None = None

class ChannelOperationsQuery(BaseModel):
    auth_token: str = Field(min_length=1)
    target_user_id: str = Field(min_length=1)

class CreateChannelQuery(BaseModel):
    auth_token: str = Field(min_length=1)
    channel_name: str = Field(min_length=1)
    is_private: bool = False

class LoadMessagesQuery(BaseModel):
    auth_token: str = Field(min_length=1)
    page: int = Field(default=1, ge=1)
    messages_per_page: int = Field(default=20, ge=1, le=50)

class MessageData(BaseModel):
    """Pydantic model for individual message data"""
    message_id: str
    channel_id: str | None = None
    conversation_id: str | None = None
    sender_id: str
    message: str
    sent_at: str
    attachments: list[str] = []
    username: str

class LoadMessagesResponse(BaseModel):
    """Pydantic model for load messages API response"""
    status_code: int
    messages: list[MessageData]

class SendMessageQuery(BaseModel):
    auth_token: str = Field(min_length=1)
    message: str = Field(min_length=1)

class MessageOperationsQuery(BaseModel):
    auth_token: str = Field(min_length=1)
    message_id: str = Field(min_length=1)

# Message send request model for validation
# Note: For multipart form data with files, we need to use Form() parameters individually
# But we can use Pydantic for validation of non-file fields
class SendMessageForm(BaseModel):
    auth_token: str = Field(..., min_length=1, description="User's authentication token")
    message: str = Field("", description="Message content")

    @field_validator('auth_token')
    @classmethod
    def validate_auth_token(cls, v):
        if not v or not v.strip():
            raise ValueError('auth_token cannot be empty')
        return v.strip()

class CDNFilesRequest(BaseModel):
    auth_token: str = Field(min_length=1)
    directory: str = Field(default="uploads", min_length=1)

class CDNDeleteFileRequest(BaseModel):
    auth_token: str = Field(min_length=1)
    file_url: str = Field(min_length=1)

class CDNFileInfoRequest(BaseModel):
    auth_token: str = Field(min_length=1)
    file_url: str = Field(min_length=1)

class BlockIPRequest(BaseModel):
    auth_token: str = Field(min_length=1)
    ip: str = Field(min_length=7, max_length=45)  # IPv4/IPv6 range
    reason: str = Field(min_length=1, max_length=500)

class ServerSettingsRequest(BaseModel):
    auth_token: str = Field(min_length=1)
    server_name: str | None = None
    server_description: str | None = None
    is_private: bool | None = None
    max_users: int | None = None
    max_message_length: int | None = None

class UnblockIPRequest(BaseModel):
    auth_token: str = Field(min_length=1)
    ip: str = Field(min_length=7, max_length=45)

class RunTaskRequest(BaseModel):
    auth_token: str = Field(min_length=1)
    task_id: str = Field(min_length=1)
from contextlib import asynccontextmanager
import uuid

from pufferblow import constants

# Database table models
from pufferblow.api.database.tables.blocked_ips import BlockedIPS
from pufferblow.api.database.tables.activity_audit import ActivityAudit
from pufferblow.api_initializer import api_initializer

# Middlewares
from pufferblow.middlewares import (
    RateLimitingMiddleware,
    SecurityMiddleware
)

# Utils
from pufferblow.api.utils.extract_user_id import extract_user_id
from pufferblow.api.utils.is_able_to_update import is_able_to_update

# Log messages
from pufferblow.api.logger.msgs import (
    info
)


async def check_if_file_is_protected(file_url: str) -> bool:
    """
    Check if a file URL is currently used as a user avatar/banner or server avatar/banner.

    Args:
        file_url (str): The file URL to check

    Returns:
        bool: True if the file is currently in use as an avatar/banner
    """
    try:
        # For SQLite tests, skip protection check
        database_uri = str(api_initializer.database.batch_engine.url) if hasattr(api_initializer.database, 'batch_engine') else str(api_initializer.database.database_engine.url)
        if database_uri.startswith('sqlite://'):
            return False

        # Get all users and check their avatars/banners
        all_users = api_initializer.database_handler.get_all_users()
        for user in all_users:
            if user.avatar_url == file_url or user.banner_url == file_url:
                return True

        # Check server avatar/banner
        server_data = api_initializer.database_handler.get_server()
        if server_data.avatar_url == file_url or server_data.banner_url == file_url:
            return True

        return False
    except Exception as e:
        # Log error but don't block deletion for safety
        logger.warning(f"Error checking if file is protected: {str(e)}")
        return False


# NOTE: Background tasks. https://fastapi.tiangolo.com/tutorial/background-tasks/

@asynccontextmanager
async def lifespan(api: FastAPI):
    """ API startup handler """
    if not api_initializer.is_loaded:
        api_initializer.load_objects()

    # Start background tasks scheduler
    from pufferblow.api.background_tasks.background_tasks_manager import lifespan_background_tasks

    # Use the background tasks lifespan context
    async with lifespan_background_tasks():
        yield

# Init the API
api = FastAPI(
    lifespan=lifespan
)

# NOTE: the middleware should be added with the following order
# because fastAPI reorders them to the last middleware added to be the first,
# in our case we want the RateLimitingMiddleware to be the first middleware to run
# to protect the instace from DDOS attacks and blocked IPs, after that the SecutiryMiddleware,
# which is related to auth_token checks..., will be the second. With this order we can be assured
# that blocked IPs can't access the protected api routes. 

allowed_origins = [
    "http://localhost:5173",  # or whatever port your frontend runs on
    "http://localhost:3000",    # alternative common ports
    "http://127.0.0.1:5173",  # if accessing via 127.0.0.1
    "http://172.19.224.1:5173",  # if accessing via IP with frontend port
    "http://localhost:7575",  # API server itself
    "http://127.0.0.1:7575",   # API server on 127.0.0.1
    "https://pufferblow.space",   # Production domain
    "https://www.pufferblow.space", # Production domain with www
    "http://pufferblow.space",    # HTTP version
    "http://www.pufferblow.space" # HTTP version with www
]
api.add_middleware(SecurityMiddleware)
api.add_middleware(RateLimitingMiddleware)
api.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,  # Enable credentials for auth tokens
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

@api.get("/")
async def redirect_route():
    return responses.RedirectResponse("/api/v1/info")

@api.get("/api/v1", status_code=200)
async def home_route():
    """ Main route, redirect to /api/v1/info """
    return responses.RedirectResponse("/api/v1/info")

@api.get("/api/v1/info", status_code=200)
async def server_info_route():
    """ Server info route """
    return {
        "status_code": 200,
    }

# Users routes
@api.get("/api/v1/users", status_code=200)
async def users_route():
    """ Users route start point """
    return {
        "status_code": 200,
        "description": "This is the main users route"
    }

@api.post("/api/v1/users/signup", status_code=201)
async def signup_new_user(
    request: SignupRequest
):
    """
    Signup a new user.

    Args:
        request (SignupRequest): Request body containing username and password.

    Return:
        201 OK: If the `username` is available, and the user got signed up.
        409 CONFLICT: If the `username` is not available.
    """
    if api_initializer.user_manager.check_username(request.username):
        raise exceptions.HTTPException(
            status_code=409,
            detail="username already exists. Please change it and try again later"
        )

    user_data = api_initializer.user_manager.sign_up(
        username=request.username,
        password=request.password
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
            metadata_json=json.dumps({
                "username": request.username,
                "user_id": str(user_data.user_id),
                "joined_at": user_data.created_at
            })
        )
    )

    return {
        "status_code": 201,
        "message": "Account created successfully",
        "auth_token": user_data.raw_auth_token,
        "auth_token_expire_time": user_data.auth_token_expire_time
    }

@api.get("/api/v1/users/signin", status_code=200)
async def signin_user(query: SigninQuery = Depends()):
    """
    Signin to an account route.

    Args:
        query (SigninQuery): Query parameters containing username and password.

    Returns:
        200 OK: If the `username` and `password` are correct, and the user got signed in.
        401 UNAUTHORIZED: If the `password` is unvalid.
        404 NOT FOUND: If the `username` is unvalid.
    """
    if not api_initializer.user_manager.check_username(
        username=query.username
    ):
        raise exceptions.HTTPException(
            status_code=404,
            detail="The provided username does not exist or could not be found. Please make sure you have entered a valid username and try again."
        )

    user, is_signin_successed = api_initializer.user_manager.sign_in(
        username=query.username,
        password=query.password
    )

    if not is_signin_successed:
        raise exceptions.HTTPException(
            status_code=401,
            detail="The provided password is incorrect. Please try again."
        )

    # Log user signin activity
    api_initializer.database_handler.create_activity_audit_entry(
        ActivityAudit(
            activity_id=str(uuid.uuid4()),
            activity_type="user_signed_in",
            user_id=str(user.user_id),
            title=f"User {query.username} signed in",
            description=f"User {query.username} successfully signed in to their account",
            metadata_json=json.dumps({
                "username": query.username,
                "user_id": str(user.user_id),
                "signin_method": "password"
            })
        )
    )

    return {
        "status_code": 200,
        "message": "Signin successfully",
        "auth_token": user.auth_token
    }

@api.post("/api/v1/users/profile", status_code=200)
async def users_profile_route(request: UserProfileRequest):
    """
    Users profile management route

    Args:
        request (UserProfileRequest): Request body containing auth_token and optional user_id.

    Returns:
        200 OK: If the `user_id` of the targeted user exists and the `auth_token` is valid.
        400 BAD REQUEST: If the `auth_token` is improperly formatted.
        404 NOT FOUND: The `auth_token` is unvalid, or the `user_id` of the targeted user doesn't exists.
    """
    user_id = extract_user_id(auth_token=request.auth_token)

    # If user_id is provided in request, use it; otherwise use the one from auth_token
    target_user_id = request.user_id if request.user_id else user_id

    # Check if viewer user owns the targeted account
    is_account_owner = api_initializer.auth_token_manager.check_users_auth_token(
        user_id=target_user_id,
        raw_auth_token=request.auth_token
    )

    user_data = api_initializer.user_manager.user_profile(
        user_id=target_user_id,
        is_account_owner=is_account_owner
    )

    return {
        "status_code": 200,
        "user_data": user_data
    }

@api.put("/api/v1/users/profile", status_code=200)
async def edit_users_profile_route(request: EditProfileRequest):
    """
    Update a user's profile metadata such as status, last_seen, username and password

    Args:
        request (EditProfileRequest): Request body containing auth_token and optional update fields.

    Returns:
        200 OK: If all parameters are correct, and the data was updated successfully.
        400 BAD REQUEST: If the `auth_token` is improperly formatted.
        401 UNAUTHORIZED: If the `password` is invalid.
        404 NOT FOUND: The `auth_token` is invalid, or the `user_id` does not exist.
        409 CONFLICT: If the `username` is not available.
    """
    user_id = extract_user_id(auth_token=request.auth_token)

    # Update username
    if request.new_username is not None:
        if api_initializer.user_manager.check_username(
            username=request.new_username
        ):
            raise exceptions.HTTPException(
                detail="username already exists. Please change it and try again later",
                status_code=409
            )

        api_initializer.user_manager.update_username(
            user_id=user_id,
            new_username=request.new_username
        )

        return {
            "status_code": 200,
            "message": "username updated successfully"
        }

    # Update the user's status
    if request.status is not None:
        api_initializer.user_manager.update_user_status(
            user_id=user_id,
            status=request.status
        )

        return {
            "status_code": 200,
            "message": "Status updated successfully"
        }

    # Update the user's password
    if request.new_password is not None and request.old_password is not None:
        api_initializer.user_manager.update_user_password(
            user_id=user_id,
            new_password=request.new_password
        )

        return {
            "status_code": 200,
            "message": "Password updated successfully"
        }

    # Update about
    if request.about is not None:
        api_initializer.user_manager.update_user_about(
            user_id=user_id,
            new_about=request.about
        )
        return {
            "status_code": 200,
            "message": "About updated successfully"
        }

# File upload endpoints
@api.post("/api/v1/users/profile/avatar", status_code=201)
async def upload_user_avatar_route(
    auth_token: str = Form(..., description="User's authentication token"),
    file: UploadFile = Form(..., description="Avatar image file")
):
    """
    Upload user's avatar image

    Args:
        auth_token: User's authentication token
        file: Avatar image file

    Returns:
        201 CREATED: File uploaded successfully
        400 BAD REQUEST: File validation failed
        404 NOT FOUND: Invalid auth_token
    """
    user_id = extract_user_id(auth_token=auth_token)

    try:
        avatar_url, is_duplicate = api_initializer.user_manager.update_user_avatar(
            user_id=user_id,
            avatar_file=file
        )

        message = "Avatar updated via existing file (duplicate detected)" if is_duplicate else "Avatar uploaded successfully"
        duplicate_status = "existing" if is_duplicate else "new"

        return {
            "status_code": 201,
            "message": message,
            "avatar_url": avatar_url,
            "duplicate_status": duplicate_status
        }

    except exceptions.HTTPException:
        raise
    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500,
            detail=f"Upload failed: {str(e)}"
        )

@api.post("/api/v1/users/profile/banner", status_code=201)
async def upload_user_banner_route(
    auth_token: str = Form(..., description="User's authentication token"),
    file: UploadFile = Form(..., description="Banner image file")
):
    """
    Upload user's banner image

    Args:
        auth_token: User's authentication token
        file: Banner image file

    Returns:
        201 CREATED: File uploaded successfully
        400 BAD REQUEST: File validation failed
        404 NOT FOUND: Invalid auth_token
    """
    user_id = extract_user_id(auth_token=auth_token)

    try:
        banner_url, is_duplicate = api_initializer.user_manager.update_user_banner(
            user_id=user_id,
            banner_file=file
        )

        message = "Banner updated via existing file (duplicate detected)" if is_duplicate else "Banner uploaded successfully"
        duplicate_status = "existing" if is_duplicate else "new"

        return {
            "status_code": 201,
            "message": message,
            "banner_url": banner_url,
            "duplicate_status": duplicate_status
        }

    except exceptions.HTTPException:
        raise
    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500,
            detail=f"Upload failed: {str(e)}"
        )

@api.post("/api/v1/users/profile/reset-auth-token", status_code=200)
async def reset_users_auth_token_route(
    request: ResetTokenRequest
):
    """
    Reset the user's `auth_token`.

    Args:
        request (ResetTokenRequest): Request body containing auth_token and password.

    Returns:
        200 OK: If all parameters are correct, and the user is able to reset their `auth_token`.
        400 BAD REQUEST: If the `auth_token` is improperly formatted.
        401 UNAUTHORIZED: If the `password` is unvalid.
        403 CAN'T AUTHORIZE IT: If the user is not authorized to reset their `auth_token` because of the suspension time.
        404 NOT FOUND: The `auth_token` is unvalid, or the `user_id` of the targeted user doesn't exists, or in case the `status` is unvalid.
    """
    user_id = extract_user_id(auth_token=request.auth_token)

    if not api_initializer.user_manager.check_user_password(
        user_id=user_id,
        password=request.password
    ):
        logger.info(
            info.INFO_RESET_USER_AUTH_TOKEN_FAILED(
                user_id=user_id,
            )
        )

        raise exceptions.HTTPException(
            detail="Incorrect password. Please try again",
            status_code=404
        )

    # Check if the user is suspended from reseting their auth_token
    updated_at = api_initializer.database_handler.get_auth_tokens_updated_at(
        user_id=user_id
    )
    if updated_at is not None:
        if not is_able_to_update(
            updated_at=updated_at,
            suspend_time=2 # Two days
        ):
            logger.info(
                info.INFO_AUTH_TOKEN_SUSPENSION_TIME(
                    user_id=user_id
                )
            )

            raise exceptions.HTTPException(
                detail="Cannot reset authentication token. Suspension time has not elapsed.",
                status_code=403
            )

    new_auth_token = f"{user_id}.{api_initializer.auth_token_manager.create_token()}"

    ciphered_auth_token, key = api_initializer.hasher.encrypt(
        data=new_auth_token
    )
    ciphered_auth_token = base64.b64encode(ciphered_auth_token).decode("ascii")

    key.user_id = user_id
    key.associated_to = "auth_token"
    
    api_initializer.database_handler.update_key(key)
    new_auth_token_expire_time = api_initializer.auth_token_manager.create_auth_token_expire_time()

    api_initializer.database_handler.update_auth_token(
        user_id=user_id,
        new_auth_token=ciphered_auth_token,
        new_auth_token_expire_time=new_auth_token_expire_time
    )

    return {
        "status_code": 200,
        "message": "auth_token reset successfully",
        "auth_token": new_auth_token,
        "auth_token_expire_time": new_auth_token_expire_time
    }

@api.get("/api/v1/users/list", status_code=200)
async def list_users_route(query: AuthTokenQuery = Depends()):
    """
    Returns a list of all the users present in the server

    Args:
        request (AuthTokenQuery): Request body containing auth_token.

    Returns:
        200 OK: If the `auth_token` is valid, then a list of users metadata is returned to the user.
        400 BAD REQUEST: If the `auth_token` is improperly formatted.
        404 NOT FOUND: The `auth_token` is unvalid, or the `user_id` of the targeted user doesn't exists, or in case the `status` is unvalid.
    """
    viewer_user_id = extract_user_id(auth_token=query.auth_token)

    users = api_initializer.user_manager.list_users(
        viewer_user_id=viewer_user_id,
        auth_token=query.auth_token
    )

    return {
        "status_code": 200,
        "users": users
    }

# Server's Channels routes
@api.get("/api/v1/channels", status_code=200)
def channels_route():
    """ Channels routes """
    return {
        "status_code": 200,
        "message": "Channels route"
    }

@api.post("/api/v1/channels/list/", status_code=200)
async def list_channels_route(request: AuthTokenQuery):
    """
    Returns a list of all available channels,
    excluding private channels, unless the user
    is a server admin, the server owner, or has
    been invited to the private channel.

    Args:
        request (AuthTokenQuery): Request body containing auth_token.

    Returns:
        200 OK: If the `auth_token` is valid, then a list of channels metadata is returned to the user.
        400 BAD REQUEST: If the `auth_token` is improperly formatted.
        404 NOT FOUND: The `auth_token` is unvalid, or the `user_id` of the targeted user doesn't exists, or in case the `status` is unvalid.
    """
    user_id = extract_user_id(auth_token=request.auth_token)

    try:
        channels_list = api_initializer.channels_manager.list_channels(
            user_id=user_id
        )

        logger.info(f"Successfully retrieved {len(channels_list) if channels_list else 0} channels for user {user_id}")

        return {
            "status_code": 200,
            "channels": channels_list or []
        }
    except Exception as e:
        logger.error(f"Error retrieving channels for user {user_id}: {str(e)}")
        raise exceptions.HTTPException(
            status_code=500,
            detail="Internal server error while fetching channels"
        )

@api.post("/api/v1/channels/create/", status_code=200)
async def create_new_channel_route(request: CreateChannelRequest):
    """
    Create a new channel for the server,
    only availble for the server owner, or
    a server admin.

    Args:
        `auth_token` (str): The user's `auth_token`.
        `channel_name` (str): The name of the channel.
        `is_private` (bool, optional, default: False): Specifies whether the channel should be private or not.

    Returns:
        200 OK: If all parameters are correct, then the channel gets created.
        400 BAD REQUEST: If the `auth_token` is improperly formatted.
        403 CAN'T AUTHORIZE IT: If the user is neither the server owner nor an admin.
        404 NOT FOUND: The `auth_token` is unvalid.
        409 CONFLICT: If the `channel_name` is not available.
    """
    logger.debug(f"Channel creation request at {datetime.now():.4f}")
    logger.debug(f"Channel name: {request.channel_name}")
    logger.debug(f"Is private: {request.is_private}")

    user_id = extract_user_id(auth_token=request.auth_token)
    logger.debug(f"Extracted user_id: {user_id}")

    # Check if the user is authorized (admin or server owner)
    is_authorized = api_initializer.user_manager.is_admin(user_id=user_id) or api_initializer.user_manager.is_server_owner(user_id=user_id)
    logger.debug(f"User is authorized: {is_authorized}")

    if not is_authorized:
        logger.warning(f"Channel creation failed: User {user_id} is not authorized")
        raise exceptions.HTTPException(
            status_code=403,
            detail="Access forbidden. Only admins and server owners can create channels and manage them."
        )

    # Check if the `channel_name` has already been used or not
    channels_names = api_initializer.database_handler.get_channels_names()
    logger.debug(f"Existing channel names: {channels_names}")

    if request.channel_name in channels_names:
        logger.warning(f"Channel creation failed: Channel name '{request.channel_name}' already exists")
        raise exceptions.HTTPException(
            status_code=409,
            detail="Channel name already exists, please change it and try again."
        )

    logger.debug(f"Creating channel '{request.channel_name}' for user {user_id}")

    try:
        channel_data = api_initializer.channels_manager.create_channel(
            user_id=user_id,
            channel_name=request.channel_name,
            is_private=request.is_private
        )
        logger.info(f"Channel '{request.channel_name}' created successfully by user {user_id}")

        # Log channel creation activity
        api_initializer.database_handler.create_activity_audit_entry(
            ActivityAudit(
                activity_id=str(uuid.uuid4()),
                activity_type="channel_created",
                user_id=str(user_id),
                title=f"Channel #{request.channel_name} created",
                description=f"New {'private' if request.is_private else 'public'} channel '{request.channel_name}' was created",
                metadata_json=json.dumps({
                    "channel_name": request.channel_name,
                    "channel_id": str(channel_data.channel_id),
                    "is_private": request.is_private,
                    "created_by": str(user_id)
                })
            )
        )
    except Exception as e:
        logger.error(f"Channel creation failed: {str(e)}")
        raise

    return {
        "status_code": 200,
        "message": "Channel created successfully",
        "channel_data": channel_data.to_dict()
    }

@api.delete("/api/v1/channels/{channel_id}/delete")
async def delete_channel_route(
    auth_token: str,
    channel_id: str
):
    """ 
    Deletes a server channel, only available for
    the server owner, and the server's admins.

    Args:
        `auth_token` (str): the user's `auth_token`.
        `channel_id` (str): The channel's `channel_id`.
    
    Returns:
        200 OK: If all the parameters are correct, then the channel gets deleted.
        400 BAD REQUEST: If the `auth_token` is improperly formatted.
        403 CAN'T AUTHORIZE IT: If the user is neither the server owner nor an admin.
        404 NOT FOUND: The `auth_token` is unvalid, or the `channel_id` of the channel doesn't exists.
    """
    user_id = extract_user_id(auth_token=auth_token)

    # Check if the user is the server admin
    if not api_initializer.user_manager.is_admin(
        user_id=user_id
    ):
        raise exceptions.HTTPException(
            status_code=403,
            detail="Access forbidden. Only admins can create channels and manage them."
        )

    api_initializer.channels_manager.delete_channel(
        channel_id=channel_id
    )

    logger.info(
        info.INFO_CHANNEL_DELETED(
            user_id=user_id,
            channel_id=channel_id
        )
    )

    return {
        "status_code": 200,
        "message": f"Channel: '{channel_id}' deleted successfully"
    }

@api.put("/api/v1/channels/{channel_id}/add_user", status_code=200)
async def add_user_to_private_channel_route(
    auth_token: str,
    channel_id: str,
    to_add_user_id: str
):
    """
    Add/invite a user to a private channel.

    Args:
        `auth_token` (str): the user's `auth_token`.
        `channel_id` (str): The channel's `channel_id`.
        `to_add_user_id` (str): The targeted user's `user_id`
    
    Returns:
        200 OK: If all the parameters are correct, then the targeted user gets added/invited to the private channel.
        400 BAD REQUEST: If the `auth_token` is improperly formatted.
        403 CAN'T AUTHORIZE IT: If the user is neither the server owner nor an admin.
        404 NOT FOUND: The `auth_token` is unvalid, or the `channel_id` of the channel doesn't exists, or the `user_id` of the targeted user doesn't exists.
    """
    user_id = extract_user_id(auth_token=auth_token)

    # Check if the targeted user exists or not
    if not api_initializer.user_manager.check_user(
        user_id=to_add_user_id
    ):
        raise exceptions.HTTPException(
            detail=f"To add User ID: '{to_add_user_id}' is unvalid/not found. Please enter a valid 'user_id' and try again.",
            status_code=404
        )

    # Check if the targeted user is also an admin
    if api_initializer.user_manager.is_admin(
        user_id=to_add_user_id
    ):
        return {
            "status_code": 200,
            "message": "Skipping the operation, the targeted user is an admin."
        }

    # Check if the targeted user is the server owner
    if api_initializer.user_manager.is_server_owner(
        user_id=to_add_user_id
    ):
        return {
            "status_code": 200,
            "message": "Skipping the operation, the targeted user is the server owner."
        }

    # Check if the user is an admin or the server owner
    if not api_initializer.user_manager.is_admin(
        user_id=user_id
    ) and not api_initializer.user_manager.is_server_owner(
        user_id=user_id
    ):
        raise exceptions.HTTPException(
            status_code=403,
            detail="Access forbidden. Only admins and the server owner can create channels and manage them."
        )

    # Check if the channel is private
    if not api_initializer.channels_manager.is_private(
        channel_id=channel_id
    ):

        logger.info(
            info.INFO_CHANNEL_IS_NOT_PRIVATE(
                user_id=user_id,
                to_add_user_id=to_add_user_id,
                channel_id=channel_id
            )
        )

        raise exceptions.HTTPException(
            detail=f"Channel with Channel ID: '{channel_id}' is not private. Only private channels are allowed.",
            status_code=200
        )

    api_initializer.channels_manager.add_user_to_channel(
        user_id=user_id,
        to_add_user_id=to_add_user_id,
        channel_id=channel_id
    )

    return {
        "status_code": 200,
        "message": f"User ID: '{to_add_user_id}' added to Channel ID: '{channel_id}'"
    }

@api.delete("/api/v1/channels/{channel_id}/remove_user", status_code=200)
async def remove_user_from_channel_route(
    auth_token: str,
    channel_id: str,
    to_remove_user_id: str
):
    """
    Remove a user from a private channel
    
    Args:
        `auth_token` (str): the user's `auth_token`.
        `channel_id` (str): The channel's `channel_id`.
        `to_remove_user_id` (str): The targeted user's `user_id`
    
    Returns:
        200 OK: If all the parameters are correct, then the targeted user gets removed from the private channel.
        400 BAD REQUEST: If the `auth_token` is improperly formatted.
        403 CAN'T AUTHORIZE IT: If the user is neither the server owner nor an admin.
        404 NOT FOUND: The `auth_token` is unvalid, or the `channel_id` of the channel doesn't exists, or the `user_id` of the targeted user doesn't exists.
    """
    user_id = extract_user_id(auth_token=auth_token)

    # Check if the targeted user is an admin
    if api_initializer.user_manager.is_admin(
        user_id=to_remove_user_id
    ):

        logger.warning(
            constants.FAILD_TO_REMOVE_USER_FROM_CHANNEL_TARGETED_USER_IS_AN_ADMIN(
                user_id=user_id,
                channel_id=channel_id,
                to_remove_user_id=to_remove_user_id
            )
        )

        raise exceptions.HTTPException(
            detail=f"Error removing Admin User ID: '{to_remove_user_id}'. The user is an admin",
            status_code=403
        )

    # Check if the targeted user is the server owner
    if api_initializer.user_manager.is_server_owner(
        user_id=to_remove_user_id
    ):

        logger.warning(
            constants.FAILD_TO_REMOVE_USER_FROM_CHANNEL_TARGETED_USER_IS_SERVER_OWNER(
                user_id=user_id,
                channel_id=channel_id,
                to_remove_user_id=to_remove_user_id
            )
        )

        raise exceptions.HTTPException(
            detail=f"Error removing User ID: '{to_remove_user_id}', this user is the server owner.",
            status_code=403
        )

    # Check if the user who requested this route is an admin
    if not api_initializer.user_manager.is_admin(
        user_id=user_id
    ) and not api_initializer.user_manager.is_server_owner(
        user_id=user_id
    ):
        raise exceptions.HTTPException(
            status_code=403,
            detail="Access forbidden. Only admins and the server owner can create channels and manage them."
        )

    # Check if the channel is private
    if not api_initializer.channels_manager.is_private(
        channel_id=channel_id
    ):

        logger.info(
            info.INFO_CHANNEL_IS_NOT_PRIVATE(
                user_id=user_id,
                to_add_user_id=to_remove_user_id,
                channel_id=channel_id
            )
        )

        raise exceptions.HTTPException(
            detail=f"Channel with Channel ID: '{channel_id}' is not private. Only private channels are allowed.",
            status_code=200
        )

    api_initializer.channels_manager.remove_user_from_channel(
        user_id=user_id,
        channel_id=channel_id,
        to_remove_user_id=to_remove_user_id
    )

    return {
        "status_code": 200,
        "message": f"User ID: '{to_remove_user_id}' was successfully removed from Channel ID: '{channel_id}'"
    }

@api.get("/api/v1/channels/{channel_id}/load_messages", status_code=200, response_model=LoadMessagesResponse)
async def channel_load_messages(
    auth_token: str,
    channel_id: str,
    page: int | None = 1,
    messages_per_page: int | None = 20
):
    """
    Load a specific number of messages for a given channel. The number of messages to load is controlled by the `messages_count`
    argument, which defaults to 20 messages. We implement a lazy loading mechanism using a paging system, allowing users to
    scroll through older messages in the channel. The `page` parameter increases as the user scrolls, and each `page`
    typically contains 20 messages by default.

    Args:
        auth_token (str): The user's `auth_token`.
        channel_id (str): The channel's `channel_id` that the messages will be loaded for.
        page (int, optional, default: 1): The page number (pages start from 1 to `x` depending on how many messages a channel contains).
        messages_per_page (int, optional, default: 20): The number of messages for each page, defaults to 20, max is 50 (NOTE: Setting a very high value for `messages_per_page` may negatively impact performance).

    Returns:
        200 GOOD: If all the parameters where right, a list of messages will be returned.
        400 BAD REQUEST: If the `auth_token` is improperly formatted, or if the `messages_per_page` number exceeded the allowed maximum value.
        404 NOT FOUND: The `auth_token` is unvalid, or the `channel_id` of the channel doesn't exists.
    """
    # Check if the value of `messages_per_page` exceeded the allowed maximal value
    if messages_per_page > api_initializer.config.MAX_MESSAGES_PER_PAGE:
        raise exceptions.HTTPException(
            detail=f"`messages_per_page` number exceeded the maximal number which is '{api_initializer.config.MAX_MESSAGES_PER_PAGE}'",
            status_code=400
        )

    user_id = extract_user_id(auth_token=auth_token)

    # Check if the channel is private, if True then the user should be an admin or the server owner
    if api_initializer.channels_manager.is_private(channel_id=channel_id) and (not api_initializer.user_manager.is_server_owner(user_id=user_id) or not api_initializer.user_manager.is_admin(user_id=user_id)):
        # We return that the channel doesn't exists because it's private
        # and the user is neither an admin nor the server owner, this is
        # important if a user is doing a bruteforce for `channel_id`s to
        # know what are channels the private channels that this server have.

        raise exceptions.HTTPException(
            status_code=404,
            detail="The provided channel ID does not exist or could not be found. Please make sure you have entered a valid channel ID and try again."
        )

    messages = api_initializer.messages_manager.load_messages(
        channel_id=channel_id,
        messages_per_page=messages_per_page,
        page=page
    )

    # Convert the raw messages to Pydantic MessageData models
    message_data_list = []
    for msg in messages:
        message_data_list.append(MessageData(
            message_id=msg.get('message_id', ''),
            channel_id=msg.get('channel_id', None),
            conversation_id=msg.get('conversation_id', None),
            sender_id=msg.get('sender_id', ''),
            message=msg.get('message', ''),
            sent_at=msg.get('sent_at', ''),
            attachments=msg.get('attachments', []),
            username=msg.get('sender_username', '')
        ))

    return LoadMessagesResponse(
        status_code=200,
        messages=message_data_list
    )

@api.post("/api/v1/channels/{channel_id}/send_message")
async def channel_send_message(
    channel_id: str,
    auth_token: str = Form(..., description="User's authentication token"),
    message: str = Form("", description="Message content"),
    attachments: list[UploadFile] = Form([], description="File attachments (optional)")
):
    """
    Send a message into a server channel with optional attachments.

    Args:
        auth_token (str): The sender user's `auth_token`.
        channel_id (str): The channel's `channel_id`.
        message (str): The message to send (optional with attachments).
        attachments (list[UploadFile]): List of file attachments.

    Returns:
        201 CREATED: The message will be sent in the desired channel.
        400 BAD REQUEST: If the `auth_token` is improperly formatted, message too long, or invalid attachments.
        404 NOT FOUND: The `auth_token` is invalid, or the `channel_id` doesn't exist.
    """
    # Check if message is too long
    if sys.getsizeof(message) > api_initializer.config.MAX_MESSAGE_SIZE:
        raise exceptions.HTTPException(
            detail="the message is too long.",
            status_code=400
        )

    # Check if message is empty and no attachments
    if not message.strip() and not attachments:
        raise exceptions.HTTPException(
            detail="Either a message or attachments must be provided.",
            status_code=400
        )

    user_id = extract_user_id(auth_token=auth_token)

    # Check if the channel is private, if True then the user should be an admin or the server owner
    if api_initializer.channels_manager.is_private(channel_id=channel_id) and (not api_initializer.user_manager.is_server_owner(user_id=user_id) or not api_initializer.user_manager.is_admin(user_id=user_id)):
        # We return that the channel doesn't exists because it's private
        # and the user is neither an admin nor the server owner, this is
        # important if a user is doing a bruteforce for `channel_id`s to
        # know what are channels the private channels that this server have.

        raise exceptions.HTTPException(
            status_code=404,
            detail="The provided channel ID does not exist or could not be found. Please make sure you have entered a valid channel ID and try again."
        )

    # Handle file uploads
    attachment_urls = []
    if attachments:
        for file in attachments:
            if file.filename:
                try:
                    # Use the CDN manager to save the attachment
                    cdn_url, is_duplicate = api_initializer.cdn_manager.validate_and_save_categorized_file(
                        file=file,
                        user_id=user_id,
                        force_category="attachments",
                        check_duplicates=True
                    )
                    attachment_urls.append(cdn_url)

                    # Log attachment upload
                    try:
                        file_size = getattr(file, 'size', 0)
                        file_type = file.content_type or 'unknown'
                        activity_data = {
                            "event_type": "message_attachment",
                            "description": f"Attachment '{file.filename}' uploaded for message in channel {channel_id}",
                            "metadata": {
                                "file_url": cdn_url,
                                "file_size": file_size,
                                "file_type": file_type,
                                "channel_id": channel_id,
                                "is_duplicate": is_duplicate
                            },
                            "user_id": user_id,
                            "timestamp": datetime.utcnow().isoformat()
                        }
                        api_initializer.database_handler.create_activity(activity_data)
                    except Exception as e:
                        logger.warning(f"Failed to log attachment upload activity: {str(e)}")

                except Exception as e:
                    logger.error(f"Failed to upload attachment '{file.filename}': {str(e)}")
                    raise exceptions.HTTPException(
                        status_code=500,
                        detail=f"Failed to upload attachment '{file.filename}'. Please try again."
                    )

    # Send the message
    message_obj = api_initializer.messages_manager.send_message(
        channel_id=channel_id,
        user_id=user_id,
        message=message,
        attachments=attachment_urls
    )

    # Prepare message dict for broadcasting
    sender_user = api_initializer.user_manager.user_profile(user_id=user_id)

    # Handle sent_at field - it might be a string from database
    sent_at_value = message_obj.sent_at
    if sent_at_value:
        if isinstance(sent_at_value, str):
            # If it's already a string, parse it back to datetime first, or just use as-is
            pass
        else:
            # It's a datetime object
            sent_at_value = sent_at_value.isoformat()
    else:
        sent_at_value = None

    message_dict = {
        "message_id": str(message_obj.message_id),
        "sender_user_id": str(user_id),
        "channel_id": channel_id,
        "message": message,
        "hashed_message": message_obj.hashed_message,
        "username": sender_user["username"],
        "sender_avatar_url": sender_user.get("avatar_url"),
        "sender_status": sender_user.get("status", "offline"),
        "sender_roles": sender_user.get("roles_ids", []),
        "sent_at": sent_at_value,
        "attachments": attachment_urls
    }

    # Broadcast to all eligible users using global websocket system
    await api_initializer.websockets_manager.broadcast_to_eligible_users(channel_id, message_dict)

    return {
        "status_code": 201,
        "message": "message sent successfully",
        "message_id": str(message_obj.message_id),
        "attachments": attachment_urls
    }

@api.put("/api/v1/channels/{channel_id}/mark_message_as_read")
async def channel_mark_message_as_read(
    auth_token: str,
    channel_id: str,
    message_id: str
):
    """
    Mark a message in channel as read, this to help keep track of viewed messages
    
    Args:
        auth_token (str): The user's `auth_token`.
        channel_id (str): The channel's `channel_id`.
        message_id (str): "The message's `message_id` that should be marked as read.
    
    Returns:
        400 BAD REQUEST: If the `auth_token` is improperly formatted, or if the size of `message` exceeded the allowed size.
        404 NOT FOUND: The `auth_token` is unvalid, or the `channel_id` of the channel doesn't exists.
    """
    user_id = extract_user_id(auth_token=auth_token)

    # mark the message as read
    api_initializer.messages_manager.mark_message_as_read(
        user_id=user_id,
        message_id=message_id,
        channel_id=channel_id
    )

    return {
        "status_code": 201,
        "message": "The `message_id` was successfully mark as read"
    }

@api.delete("/api/v1/channels/{channel_id}/delete_message")
async def channel_delete_message(
    auth_token: str,
    channel_id: str,
    message_id: str
):
    """
    Delete a message from a channel in the server

    Args:
        auth_token (str): The user's `auth_token`.
        channel_id (str): The channel's `channel_id`.
        message_id (str): "The message's `message_id` that should be deleted.
    
    Returns:
        204 NO CONTENT: The message will be deleted from the channel.
        400 BAD REQUEST: If the `auth_token` is improperly formatted, or if the size of `message` exceeded the allowed size.
        404 NOT FOUND: The `auth_token` is unvalid, or the `channel_id` of the channel doesn't exists.
    """
    user_id = extract_user_id(auth_token=auth_token)
    
    # Check if the channel is private, if True then the user should be an admin or the server owner
    is_channel_private  =   api_initializer.channels_manager.is_private(channel_id=channel_id)
    is_server_owner     =   api_initializer.user_manager.is_server_owner(user_id=user_id)
    is_admin            =   api_initializer.user_manager.is_admin(user_id=user_id)
    
    if is_channel_private and (not is_server_owner or not is_admin):
        # We return that the channel doesn't exists because it's private
        # and the user is neither an admin nor the server owner, this is
        # important if a user is doing a bruteforce for `channel_id`s to
        # know what are channels the private channels that this server have.

        raise exceptions.HTTPException(
            status_code=404,
            detail="The provided channel ID does not exist or could not be found. Please make sure you have entered a valid channel ID and try again."
        )
    
    # Check if the user is the sender of the message, if not then
    # he is an admin or the server owner then he will be able to delete it
    if not api_initializer.messages_manager.check_message_sender(message_id=message_id) and (not is_server_owner or not is_admin):
        raise exceptions.HTTPException(
            detail="You are not authorized to delete this message",
            status_code=401
        )

    api_initializer.messages_manager.delete_message(
        message_id=message_id,
        channel_id=channel_id
    )

    return {
        "status_code": 204,
        "message": "The message have been deleted successfully"
    }

# CDN Upload Route (Server Owner Only)
@api.post("/api/v1/cdn/upload", status_code=201)
async def upload_cdn_file(
    auth_token: str,
    file: UploadFile = Form(..., description="File to upload"),
    directory: str = Form(..., description="Target directory (uploads, avatars, banners, etc.)")
):
    """
    Upload a file to the CDN. Server Owner only.

    Args:
        auth_token: User's authentication token
        file: File to upload
        directory: Target directory for upload

    Returns:
        201 CREATED: File uploaded successfully
        400 BAD REQUEST: File validation failed
        403 FORBIDDEN: User is not server owner
        404 NOT FOUND: Invalid auth_token
    """
    user_id = extract_user_id(auth_token=auth_token)

    # Check if user is server owner
    if not api_initializer.user_manager.is_server_owner(user_id=user_id):
        raise exceptions.HTTPException(
            status_code=403,
            detail="Access forbidden. Only the server owner can upload files to CDN."
        )

    try:
        # Validate directory name for security
        allowed_dirs = ['uploads', 'avatars', 'banners', 'attachments', 'stickers', 'gifs']
        if directory not in allowed_dirs:
            raise exceptions.HTTPException(
                status_code=400,
                detail=f"Invalid directory. Allowed: {', '.join(allowed_dirs)}"
            )

        # Use CDN manager to handle the upload with categorization if no directory specified
        cdn_url, is_duplicate = api_initializer.cdn_manager.validate_and_save_categorized_file(
            file=file,
            user_id=user_id,
            force_category=directory if directory else None,
            check_duplicates=True
        )

        # Handle both new files and duplicates - update database accordingly
        try:
            # Extract file info from URL
            from pathlib import Path
            relative_path = cdn_url[len(api_initializer.config.CDN_BASE_URL):].lstrip('/')
            file_path_obj = Path(api_initializer.config.CDN_STORAGE_PATH) / relative_path

            if file_path_obj.exists():
                # Read file to compute hash
                with open(file_path_obj, "rb") as f:
                    content = f.read()

                file_hash = api_initializer.cdn_manager.compute_file_hash(content)

                if is_duplicate:
                    # For duplicates, just increment the reference count
                    api_initializer.database_handler.increment_file_reference_count(file_hash)
                else:
                    # For new files, register and create reference
                    file_id = str(uuid.uuid4())  # Generate reference ID

                    # Register file in database
                    api_initializer.database_handler.create_file_object(
                        file_hash=file_hash,
                        ref_count=1,
                        file_path=relative_path,  # Store relative path
                        file_size=len(content),
                        mime_type=api_initializer.cdn_manager.mime_detector.from_buffer(content) or 'application/octet-stream',
                        verification_status="verified"
                    )

                # Create reference for this upload (always, for both new and duplicate files)
                reference_id = f"cdn_upload_{uuid.uuid4()}"
                api_initializer.database_handler.create_file_reference(
                    reference_id=reference_id,
                    file_hash=file_hash,
                    reference_type="cdn_upload",
                    reference_entity_id=user_id  # Owner of the upload
                )
        except Exception as e:
            # Log but don't fail the upload - file is already saved
            pass

        # Log file upload activity (both new files and duplicates)
        try:
            # Determine file size from file or URL for duplicates
            file_size = 0
            file_type = 'unknown'

            if is_duplicate and cdn_url != api_initializer.config.CDN_BASE_URL:
                # For duplicates, try to get file size from existing file
                try:
                    from pathlib import Path
                    relative_path = cdn_url[len(api_initializer.config.CDN_BASE_URL):].lstrip('/')
                    file_path_obj = Path(api_initializer.config.CDN_STORAGE_PATH) / relative_path
                    if file_path_obj.exists():
                        file_size = file_path_obj.stat().st_size
                        # Get MIME type
                        file_type = api_initializer.cdn_manager.mime_detector.from_file(str(file_path_obj)) or 'unknown'
                except Exception as e:
                    logger.warning(f"Failed to get duplicate file info: {str(e)}")
            elif 'content' in locals():
                # For new files, use the content we read
                file_size = len(content)
                file_type = mime_type or 'unknown'

            # Create activity entry for file upload (new files or duplicates)
            upload_type = "existing file reused" if is_duplicate else "new file uploaded"
            activity_data = {
                "event_type": "file_upload",
                "description": f"File '{file.filename}' {upload_type} to {directory}",
                "metadata": {
                    "file_url": cdn_url,
                    "file_size": file_size,
                    "file_type": file_type,
                    "directory": directory,
                    "uploader_id": user_id,
                    "is_duplicate": is_duplicate
                },
                "user_id": user_id,
                "timestamp": datetime.utcnow().isoformat()
            }

            # Log the activity data for debugging
            logger.info(f"Creating activity for file upload: {activity_data}")

            api_initializer.database_handler.create_activity(activity_data)

            # Update activity metrics (increment files uploaded and file size)
            try:
                # Get current day's metrics (or create if doesn't exist)
                today = datetime.utcnow().date()
                metrics = api_initializer.database_handler.calculate_daily_activity_metrics()

                if metrics:
                    # Update file count and size
                    metrics.files_uploaded += 1
                    metrics.total_file_size_mb += (file_size / (1024 * 1024)) if file_size else 0

                    # Save updated metrics
                    api_initializer.database_handler.save_activity_metrics(metrics)

            except Exception as e:
                # Log error but don't fail the upload
                logger.warning(f"Failed to update activity metrics: {str(e)}")

        except Exception as e:
            # Log error but don't fail the upload
            logger.warning(f"Failed to log file upload activity: {str(e)}")

        return {
            "status_code": 201,
            "message": "File uploaded successfully" if not is_duplicate else "Duplicate file detected, existing file returned",
            "url": cdn_url,
            "is_duplicate": is_duplicate
        }

    except exceptions.HTTPException:
        raise
    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500,
            detail=f"Upload failed: {str(e)}"
        )

# CDN Management Routes (Server Owner Only)
@api.post("/api/v1/cdn/files", status_code=200)
async def list_cdn_files_route(request: CDNFilesRequest):
    """
    List all files in a CDN directory. Server Owner only.

    Args:
        query (CDNFilesQuery): Query parameters containing auth_token and directory.

    Returns:
        200 OK: List of files with metadata
        403 FORBIDDEN: User is not server owner
        404 NOT FOUND: Invalid auth_token
    """
    user_id = extract_user_id(auth_token=request.auth_token)

    # Check if user is server owner
    if not api_initializer.user_manager.is_server_owner(user_id=user_id):
        raise exceptions.HTTPException(
            status_code=403,
            detail="Access forbidden. Only the server owner can access CDN management."
        )

    try:
        import os
        from pathlib import Path

        cdn_base = Path(api_initializer.config.CDN_STORAGE_PATH)
        all_files_info = []

        # Debug: Check what directories actually exist
        existing_dirs = []
        if cdn_base.exists():
            logger.info(f"CDN base directory exists: {cdn_base}")
            for item in cdn_base.iterdir():
                if item.is_dir():
                    existing_dirs.append(item.name)
            logger.info(f"Found existing directories: {existing_dirs}")
        else:
            logger.error(f"CDN base directory does not exist: {cdn_base}")
            existing_dirs = []

        # Handle directory mapping and also check direct directory names
        directory_map = {
            "uploads": ["images", "videos", "documents", "files", "uploads"],  # "uploads" should show general uploads + uploads dir directly
            "avatars": ["avatars"],
            "banners": ["banners"],
            "attachments": ["images", "videos", "documents"],  # attachments could be various types
            "stickers": ["stickers"],
            "gifs": ["gifs"],
            "all": None  # Show all directories when "all" is selected
        }

        if request.directory == "all":
            logger.info(f"Listing files from ALL directories: {existing_dirs}")
            # List files from all existing directories
            for sub_dir_name in existing_dirs:
                sub_dir = cdn_base / sub_dir_name
                logger.info(f"Scanning directory: {sub_dir}")
                if sub_dir.exists():
                    files_in_dir = list(sub_dir.glob("*"))
                    logger.info(f"Found {len(files_in_dir)} items in {sub_dir}")
                    for file_path in files_in_dir:
                        if file_path.is_file():
                            stat = file_path.stat()
                            all_files_info.append({
                                "filename": file_path.name,
                                "size": stat.st_size,
                                "modified": stat.st_mtime,
                                "url": f"{api_initializer.config.CDN_BASE_URL}/{sub_dir_name}/{file_path.name}",
                                "subdirectory": sub_dir_name
                            })
                else:
                    logger.warning(f"Directory does not exist: {sub_dir}")
        else:
            # Check specific directory/directories
            subdirectories = directory_map.get(request.directory, [request.directory])
            logger.info(f"Looking for directory '{request.directory}', mapped to: {subdirectories}")

            # Also check if the directory exists directly
            if Path(cdn_base / request.directory).exists():
                subdirectories.append(request.directory)
                logger.info(f"Direct directory '{request.directory}' exists, added to search list")

            # Remove duplicates
            subdirectories = list(set(subdirectories))
            logger.info(f"Final subdirectories to scan: {subdirectories}")

            for sub_dir_name in subdirectories:
                sub_dir = cdn_base / sub_dir_name
                logger.info(f"Checking subdirectory: {sub_dir}")
                if sub_dir.exists():
                    files_in_dir = list(sub_dir.glob("*"))
                    logger.info(f"Found {len(files_in_dir)} items in {sub_dir}")
                    for file_path in files_in_dir:
                        if file_path.is_file():
                            logger.debug(f"Adding file: {file_path.name}")
                            stat = file_path.stat()

                            # Detect MIME type using the CDN manager's mime detector
                            mime_type = api_initializer.cdn_manager.mime_detector.from_file(str(file_path)) or 'application/octet-stream'

                            # Try to get uploader info from activity logs (basic implementation)
                            # In a full implementation, you might want to store this in file metadata
                            uploader_username = "Unknown"
                            try:
                                # Extract uploader ID from filename if it follows the pattern
                                filename_parts = file_path.name.split('_')
                                if len(filename_parts) >= 2 and filename_parts[0] in ['server', 'user']:
                                    # For server uploads, it's by server owner, for user uploads - could be any user
                                    # For now, just use 'Server' for server uploads
                                    if filename_parts[0] == 'server':
                                        uploader_username = "Server Owner"
                                    else:
                                        uploader_username = "User"
                                else:
                                    uploader_username = "Unknown"
                            except:
                                uploader_username = "Unknown"

                            # Better MIME type detection for common file types
                            # The default mime detector might not recognize all text file types
                            file_extension = file_path.name.split('.')[-1].lower() if '.' in file_path.name else ''
                            text_extensions = [
                                'txt', 'py', 'js', 'ts', 'json', 'yml', 'yaml', 'md', 'toml',
                                'html', 'css', 'xml', 'csv', 'log', 'sh', 'bat', 'ps1', 'sql',
                                'ini', 'conf', 'cfg', 'env', 'gitignore', 'dockerignore'
                            ]

                            if mime_type == 'application/octet-stream' and file_extension in text_extensions:
                                mime_type = 'text/plain'
                            elif mime_type == 'application/octet-stream' and file_extension == 'json':
                                mime_type = 'application/json'

                            all_files_info.append({
                                "filename": file_path.name,
                                "size": stat.st_size,
                                "modified": stat.st_mtime,
                                "url": f"{api_initializer.config.CDN_BASE_URL}/{sub_dir_name}/{file_path.name}",
                                "subdirectory": sub_dir_name,
                                "type": mime_type,
                                "uploader": uploader_username
                            })
                else:
                    logger.warning(f"Subdirectory does not exist: {sub_dir}")

        logger.info(f"Total files found: {len(all_files_info)}")
        for file_info in all_files_info:
            logger.debug(f"File: {file_info['filename']} in {file_info.get('subdirectory', 'unknown')}")

        return {
            "status_code": 200,
            "directory": request.directory,
            "files": all_files_info,
            "existing_dirs": existing_dirs,  # Debug info
            "scanned_dirs": subdirectories if request.directory != "all" else existing_dirs
        }

    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500,
            detail=f"Failed to list CDN files: {str(e)}"
        )

@api.post("/api/v1/cdn/file-info", status_code=200)
async def get_cdn_file_info_route(request: CDNFileInfoRequest):
    """
    Get information about a specific CDN file. Server Owner only.

    Args:
        request (CDNFileInfoRequest): Request body containing auth_token and file_url.

    Returns:
        200 OK: File information
        403 FORBIDDEN: User is not server owner
        404 NOT FOUND: File not found or invalid auth_token
    """
    user_id = extract_user_id(auth_token=request.auth_token)

    # Check if user is server owner
    if not api_initializer.user_manager.is_server_owner(user_id=user_id):
        raise exceptions.HTTPException(
            status_code=403,
            detail="Access forbidden. Only the server owner can access CDN management."
        )

    file_info = api_initializer.cdn_manager.get_file_info(request.file_url)
    if file_info is None:
        raise exceptions.HTTPException(
            status_code=404,
            detail="File not found"
        )

    return {
        "status_code": 200,
        "file_info": {
            "url": request.file_url,
            "size": file_info.get("size"),
            "mime_type": file_info.get("mime_type"),
            "created": file_info.get("created"),
            "modified": file_info.get("modified")
        }
    }

@api.post("/api/v1/cdn/delete-file", status_code=200)
async def delete_cdn_file_route(request: CDNDeleteFileRequest):
    """
    Delete a file from the CDN. Server Owner only.
    Prevents deletion of avatar/banner files that are currently in use.

    Args:
        request (CDNDeleteFileRequest): Request body containing auth_token and file_url.

    Returns:
        200 OK: File deleted successfully
        403 FORBIDDEN: User is not server owner or trying to delete active avatar/banner
        404 NOT FOUND: File not found or invalid auth_token
        500 INTERNAL SERVER ERROR: Deletion failed
    """
    user_id = extract_user_id(auth_token=request.auth_token)

    # Check if user is server owner
    if not api_initializer.user_manager.is_server_owner(user_id=user_id):
        raise exceptions.HTTPException(
            status_code=403,
            detail="Access forbidden. Only the server owner can access CDN management."
        )

    try:
        # Check if the file is currently used as an avatar or banner
        is_protected = await check_if_file_is_protected(request.file_url)
        if is_protected:
            raise exceptions.HTTPException(
                status_code=403,
                detail="Cannot delete this file as it is currently used as a user or server avatar/banner."
            )

        deleted = api_initializer.cdn_manager.delete_file(request.file_url)
        if not deleted:
            raise exceptions.HTTPException(
                status_code=404,
                detail="File not found"
            )

        return {
            "status_code": 200,
            "message": "File deleted successfully",
            "file_url": request.file_url
        }

    except exceptions.HTTPException:
        raise
    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500,
            detail=f"Failed to delete file: {str(e)}"
        )

@api.get("/api/v1/cdn/file/{file_path:path}", status_code=200)
async def serve_cdn_file_route(file_path: str, auth_token: str = None):
    """
    Serve a CDN file directly with validation and optional authentication.

    This route provides secure access to CDN files with file validation.
    Use this when you need authenticated access to CDN files.

    Args:
        file_path: The file path relative to the CDN storage directory
        auth_token: Optional authentication token

    Returns:
        200 OK: File served
        404 NOT FOUND: File not found
        403 FORBIDDEN: Authentication required but not provided
        500 INTERNAL SERVER ERROR: Failed to serve file
    """
    from pathlib import Path
    import mimetypes

    try:
        # Verify file exists on filesystem
        cdn_storage_path = Path(api_initializer.config.CDN_STORAGE_PATH) / file_path
        if not cdn_storage_path.exists() or not cdn_storage_path.is_file():
            raise exceptions.HTTPException(
                status_code=404,
                detail="File not found"
            )

        # Optional auth check if provided
        if auth_token:
            try:
                extract_user_id(auth_token=auth_token)
            except:
                raise exceptions.HTTPException(
                    status_code=403,
                    detail="Invalid authentication token"
                )

        # Get MIME type
        content_type, _ = mimetypes.guess_type(cdn_storage_path.name)
        if not content_type:
            content_type = 'application/octet-stream'

        # Read and return file
        with open(cdn_storage_path, 'rb') as file:
            content = file.read()

        return responses.Response(
            content=content,
            media_type=content_type,
            headers={"Content-Disposition": f"inline; filename={cdn_storage_path.name}"}
        )

    except exceptions.HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to serve file {file_path}: {str(e)}")
        raise exceptions.HTTPException(
            status_code=500,
            detail="Failed to serve file"
        )

class CleanupOrphanedRequest(BaseModel):
    auth_token: str = Field(min_length=1)
    subdirectory: str = Field(default="", min_length=0)

@api.post("/api/v1/cdn/cleanup-orphaned", status_code=200)
async def cleanup_orphaned_cdn_files_route(request: CleanupOrphanedRequest):
    """
    Remove CDN files that are no longer referenced in the database. Server Owner only.

    Args:
        query (CleanupOrphanedRequest): Query parameters containing auth_token and subdirectory.

    Returns:
        200 OK: Cleanup completed
        403 FORBIDDEN: User is not server owner
        404 NOT FOUND: Invalid auth_token
        500 INTERNAL SERVER ERROR: Cleanup failed
    """
    user_id = extract_user_id(auth_token=request.auth_token)

    # Check if user is server owner
    if not api_initializer.user_manager.is_server_owner(user_id=user_id):
        raise exceptions.HTTPException(
            status_code=403,
            detail="Access forbidden. Only the server owner can access CDN management."
        )

    try:
        # Get list of referenced files from database for the specified subdirectory
        db_files = []

        # Collect avatar URLs from users
        if request.subdirectory == "avatars":
            try:
                users = api_initializer.database_handler.get_all_users()
                for user in users:
                    if user.avatar_url:
                        db_files.append(user.avatar_url)
            except Exception:
                pass  # Skip if database not available

        # Collect banner URLs from users
        elif request.subdirectory == "banners":
            try:
                users = api_initializer.database_handler.get_all_users()
                for user in users:
                    if user.banner_url:
                        db_files.append(user.banner_url)
            except Exception:
                pass  # Skip if database not available

        # Collect server avatar/banner
        elif request.subdirectory == "server":
            try:
                server_data = api_initializer.database_handler.get_server()
                if server_data.avatar_url:
                    db_files.append(server_data.avatar_url)
                if server_data.banner_url:
                    db_files.append(server_data.banner_url)
            except Exception:
                pass  # Skip if database not available

        # For other directories (uploads, images, videos, etc.), we don't have specific tracking
        # so return empty list to skip cleanup for now
        else:
            return {
                "status_code": 200,
                "message": f"Cleanup for subdirectory '{request.subdirectory}' is not yet implemented. Currently only avatars, banners, and server directories are supported."
            }

        api_initializer.cdn_manager.cleanup_orphaned_files(db_files, request.subdirectory)

        return {
            "status_code": 200,
            "message": f"Orphaned files cleanup completed for subdirectory: {request.subdirectory}"
        }

    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500,
            detail=f"Failed to cleanup orphaned files: {str(e)}"
        )

# Blocked IPs Management Routes (Server Owner Only)
@api.post("/api/v1/blocked-ips/list", status_code=200)
async def list_blocked_ips_route(request: AuthTokenQuery):
    """
    List all blocked IPs with details. Server Owner only.

    Args:
        request (AuthTokenQuery): Request body containing auth_token.

    Returns:
        200 OK: List of blocked IPs
        403 FORBIDDEN: User is not server owner
        404 NOT FOUND: Invalid auth_token
    """
    user_id = extract_user_id(auth_token=request.auth_token)

    # Check if user is server owner
    if not api_initializer.user_manager.is_server_owner(user_id=user_id):
        raise exceptions.HTTPException(
            status_code=403,
            detail="Access forbidden. Only the server owner can access blocked IP management."
        )

    try:
        blocked_ips = api_initializer.database_handler.fetch_blocked_ips()

        return {
            "status_code": 200,
            "blocked_ips": blocked_ips
        }

    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500,
            detail=f"Failed to fetch blocked IPs: {str(e)}"
        )

@api.post("/api/v1/blocked-ips/block", status_code=201)
async def block_ip_route(request: BlockIPRequest):
    """
    Add an IP address to the blocked list. Server Owner only.

    Args:
        request (BlockIPRequest): Request body containing auth_token, ip, and reason.

    Returns:
        201 CREATED: IP blocked successfully
        400 BAD REQUEST: Invalid IP format or already blocked
        403 FORBIDDEN: User is not server owner
        404 NOT FOUND: Invalid auth_token
    """
    user_id = extract_user_id(auth_token=request.auth_token)

    # Check if user is server owner
    if not api_initializer.user_manager.is_server_owner(user_id=user_id):
        raise exceptions.HTTPException(
            status_code=403,
            detail="Access forbidden. Only the server owner can manage blocked IPs."
        )

    try:
        # Check if IP is already blocked
        if api_initializer.database_handler.check_is_ip_blocked(ip=request.ip):
            raise exceptions.HTTPException(
                status_code=400,
                detail="IP address is already blocked"
            )

        # Create blocked IP object
        blocked_ip = BlockedIPS(
            ip_id=str(uuid.uuid4()),
            ip=request.ip,
            block_reason=request.reason
        )

        # Save to database
        api_initializer.database_handler.save_blocked_ip_to_blocked_ips(blocked_ip=blocked_ip)

        return {
            "status_code": 201,
            "message": f"IP {request.ip} has been blocked",
            "reason": request.reason
        }

    except exceptions.HTTPException:
        raise
    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500,
            detail=f"Failed to block IP: {str(e)}"
        )

@api.post("/api/v1/blocked-ips/unblock", status_code=200)
async def unblock_ip_route(request: UnblockIPRequest):
    """
    Remove an IP address from the blocked list. Server Owner only.

    Args:
        request (UnblockIPRequest): Request body containing auth_token and ip.

    Returns:
        200 OK: IP unblocked successfully
        400 BAD REQUEST: IP not blocked
        403 FORBIDDEN: User is not server owner
        404 NOT FOUND: Invalid auth_token
    """
    user_id = extract_user_id(auth_token=request.auth_token)

    # Check if user is server owner
    if not api_initializer.user_manager.is_server_owner(user_id=user_id):
        raise exceptions.HTTPException(
            status_code=403,
            detail="Access forbidden. Only the server owner can manage blocked IPs."
        )

    try:
        # Check if IP is blocked
        if not api_initializer.database_handler.check_is_ip_blocked(ip=request.ip):
            raise exceptions.HTTPException(
                status_code=400,
                detail="IP address is not currently blocked"
            )

        # Remove from database
        deleted = api_initializer.database_handler.delete_blocked_ip(ip=request.ip)
        if not deleted:
            raise exceptions.HTTPException(
                status_code=400,
                detail="Failed to unblock IP address"
            )

        return {
            "status_code": 200,
            "message": f"IP {request.ip} has been unblocked"
        }

    except exceptions.HTTPException:
        raise
    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500,
            detail=f"Failed to unblock IP: {str(e)}"
        )

# Background Tasks Management Routes (Server Owner Only)
@api.post("/api/v1/background-tasks/status", status_code=200)
async def get_background_tasks_status_route(request: AuthTokenQuery):
    """
    Get status of all background tasks. Server Owner only.

    Args:
        request (AuthTokenQuery): Request body containing auth_token.

    Returns:
        200 OK: Background tasks status
        403 FORBIDDEN: User is not server owner
        404 NOT FOUND: Invalid auth_token
    """
    user_id = extract_user_id(auth_token=request.auth_token)

    # Check if user is server owner
    if not api_initializer.user_manager.is_server_owner(user_id=user_id):
        raise exceptions.HTTPException(
            status_code=403,
            detail="Access forbidden. Only the server owner can access background tasks management."
        )

    try:
        if hasattr(api_initializer, 'background_tasks_manager'):
            tasks_status = api_initializer.background_tasks_manager.get_task_status()
            return {
                "status_code": 200,
                "tasks": tasks_status
            }
        else:
            return {
                "status_code": 200,
                "tasks": {},
                "message": "Background tasks manager not initialized"
            }

    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500,
            detail=f"Failed to get background tasks status: {str(e)}"
        )

@api.post("/api/v1/background-tasks/run", status_code=200)
async def run_background_task_route(request: RunTaskRequest):
    """
    Execute a background task on-demand. Server Owner only.

    Args:
        request (RunTaskRequest): Request body containing auth_token and task_id.

    Returns:
        200 OK: Task executed successfully
        400 BAD REQUEST: Task not found or failed
        403 FORBIDDEN: User is not server owner
        404 NOT FOUND: Invalid auth_token
    """
    user_id = extract_user_id(auth_token=request.auth_token)

    # Check if user is server owner
    if not api_initializer.user_manager.is_server_owner(user_id=user_id):
        raise exceptions.HTTPException(
            status_code=403,
            detail="Access forbidden. Only the server owner can execute background tasks."
        )

    try:
        if not hasattr(api_initializer, 'background_tasks_manager'):
            raise exceptions.HTTPException(
                status_code=400,
                detail="Background tasks manager not initialized"
            )

        success = await api_initializer.background_tasks_manager.run_task(request.task_id)
        if success:
            return {
                "status_code": 200,
                "message": f"Background task '{request.task_id}' executed successfully"
            }
        else:
            raise exceptions.HTTPException(
                status_code=400,
                detail=f"Background task '{request.task_id}' failed to execute"
            )

    except exceptions.HTTPException:
        raise
    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500,
            detail=f"Failed to run background task: {str(e)}"
        )

# System Information Routes (All Users)
@api.get("/api/v1/system/latest-release", status_code=200)
async def get_latest_release_route():
    """
    Get information about the latest PufferBlow release from GitHub.

    Returns:
        200 OK: Latest release information
        500 INTERNAL SERVER ERROR: Failed to fetch release information
    """
    try:
        if hasattr(api_initializer, 'background_tasks_manager'):
            latest_release = api_initializer.background_tasks_manager.get_latest_release()
            if latest_release:
                return {
                    "status_code": 200,
                    "release": latest_release
                }
            else:
                return {
                    "status_code": 200,
                    "message": "No release information available yet. Release check may still be running or hasn't completed.",
                    "release": None
                }
        else:
            return {
                "status_code": 200,
                "message": "Background tasks manager not initialized",
                "release": None
            }

    except Exception as e:
            raise exceptions.HTTPException(
            status_code=500,
            detail=f"Failed to get latest release information: {str(e)}"
        )

# System Information Routes (All Users)
@api.get("/api/v1/system/server-stats", status_code=200)
async def get_server_stats_route():
    """
    Get comprehensive server statistics.

    Returns:
        200 OK: Server statistics including users, channels, messages
        500 INTERNAL SERVER ERROR: Failed to fetch statistics
    """
    try:
        if hasattr(api_initializer, 'background_tasks_manager'):
            server_stats = api_initializer.background_tasks_manager.get_server_stats()
            if server_stats:
                return {
                    "status_code": 200,
                    "statistics": server_stats
                }
            else:
                return {
                    "status_code": 200,
                    "message": "Server statistics not yet available. Statistics update may still be running or hasn't completed.",
                    "statistics": None
                }
        else:
            return {
                "status_code": 200,
                "message": "Background tasks manager not initialized",
                "statistics": None
            }

    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500,
            detail=f"Failed to get server statistics: {str(e)}"
        )

@api.get("/api/v1/system/server-info", status_code=200)
async def get_server_info_route():
    """
    Get server configuration information including name, description, and settings.

    Returns:
        200 OK: Server information including name, description, and configuration
        500 INTERNAL SERVER ERROR: Failed to fetch server info
    """
    # Get server info from database
    server_data = api_initializer.database_handler.get_server()
    server_settings = api_initializer.database_handler.get_server_settings()

    # Format server info response
    server_info = {
        "server_name": server_data.server_name,
        "server_description": server_data.description,
        "version": getattr(api_initializer.config, 'VERSION', '1.0.0'),
        "max_users": None,  # Not stored in current schema, can be added later
        "is_private": server_settings.is_private,
        "creation_date": server_data.created_at.isoformat(),
        "avatar_url": server_data.avatar_url,
        "banner_url": server_data.banner_url,
        "welcome_message": server_data.welcome_message,
        "members_count": server_data.members_count,
        "online_members": server_data.online_members,
        # Include server settings
        "max_message_length": server_settings.max_message_length,
        "max_image_size": server_settings.max_image_size,  # MB
        "max_video_size": server_settings.max_video_size,  # MB
        "max_sticker_size": server_settings.max_sticker_size,  # MB
        "max_gif_size": server_settings.max_gif_size,  # MB
        "allowed_image_types": server_settings.allowed_images_extensions,
        "allowed_video_types": server_settings.allowed_videos_extensions,
        "allowed_file_types": server_settings.allowed_doc_extensions,
        "allowed_sticker_types": server_settings.allowed_stickers_extensions,
        "allowed_gif_types": server_settings.allowed_gif_extensions,
    }

    return {
        "status_code": 200,
        "server_info": server_info
    }

@api.post("/api/v1/system/server-usage")
async def get_server_usage_route():
    """
    Get real-time server usage statistics (CPU, RAM, I/O).

    Returns:
        200 OK: Server usage metrics
        500 INTERNAL SERVER ERROR: Failed to fetch server usage
    """
    try:
        import psutil
        import time
        import os

        # Get CPU usage
        cpu_percent = psutil.cpu_percent(interval=0.1)

        # Get memory usage - use psutil's actual system reported memory
        memory = psutil.virtual_memory()
        ram_used_gb = round(memory.used / (1024**3), 2)
        ram_total_gb = round(memory.total / (1024**3), 2)
        ram_percent = memory.percent

        # Debug memory info
        logger.info(f"Server memory: used={ram_used_gb}GB, total={ram_total_gb}GB ({ram_percent}%)");

        # Get disk I/O
        disk_io_counters = psutil.disk_io_counters()
        if disk_io_counters:
            # Calculate I/O rates over a short interval
            time.sleep(0.1)
            disk_io_counters2 = psutil.disk_io_counters()
            if disk_io_counters2 and disk_io_counters:
                read_bytes_per_sec = (disk_io_counters2.read_bytes - disk_io_counters.read_bytes) * 10
                write_bytes_per_sec = (disk_io_counters2.write_bytes - disk_io_counters.write_bytes) * 10
                disk_read_mb_per_sec = round(read_bytes_per_sec / (1024**2), 2)
                disk_write_mb_per_sec = round(write_bytes_per_sec / (1024**2), 2)
            else:
                disk_read_mb_per_sec = 0
                disk_write_mb_per_sec = 0
        else:
            disk_read_mb_per_sec = 0
            disk_write_mb_per_sec = 0

        # Get disk usage for the main storage
        disk_usage = psutil.disk_usage('/')
        storage_used_gb = round(disk_usage.used / (1024**3), 2)
        storage_total_gb = round(disk_usage.total / (1024**3), 2)
        storage_percent = disk_usage.percent

        # Get system uptime
        boot_time = psutil.boot_time()
        uptime_seconds = time.time() - boot_time

        # Format uptime
        days = int(uptime_seconds // (24 * 3600))
        hours = int((uptime_seconds % (24 * 3600)) // 3600)
        minutes = int((uptime_seconds % 3600) // 60)
        uptime_str = f"{days}d {hours}h {minutes}m"

        server_usage = {
            "cpu_percent": round(cpu_percent, 1),
            "ram_used_gb": ram_used_gb,
            "ram_total_gb": ram_total_gb,
            "ram_percent": round(ram_percent, 1),
            "disk_read_mb_per_sec": disk_read_mb_per_sec,
            "disk_write_mb_per_sec": disk_write_mb_per_sec,
            "storage_used_gb": storage_used_gb,
            "storage_total_gb": storage_total_gb,
            "storage_percent": round(storage_percent, 1),
            "uptime_seconds": round(uptime_seconds, 0),
            "uptime_formatted": uptime_str,
            "timestamp": int(time.time())
        }

        return {
            "status_code": 200,
            "server_usage": server_usage
        }

    except ImportError:
        # Fallback when psutil is not installed
        import time

        return {
            "status_code": 200,
            "server_usage": {
                "cpu_percent": 0.0,
                "ram_used_gb": 0.0,
                "ram_total_gb": 0.0,
                "ram_percent": 0.0,
                "disk_read_mb_per_sec": 0.0,
                "disk_write_mb_per_sec": 0.0,
                "storage_used_gb": 0.0,
                "storage_total_gb": 0.0,
                "storage_percent": 0.0,
                "uptime_seconds": 0,
                "uptime_formatted": "0d 0h 0m",
                "timestamp": int(time.time())
            },
            "note": "psutil not installed on server - install with: pip install psutil"
        }
    except Exception as e:
        # Fallback for any other errors
        import time

        return {
            "status_code": 200,
            "server_usage": {
                "cpu_percent": 0.0,
                "ram_used_gb": 0.0,
                "ram_total_gb": 0.0,
                "ram_percent": 0.0,
                "disk_read_mb_per_sec": 0.0,
                "disk_write_mb_per_sec": 0.0,
                "storage_used_gb": 0.0,
                "storage_total_gb": 0.0,
                "storage_percent": 0.0,
                "uptime_seconds": 0,
                "uptime_formatted": "0d 0h 0m",
                "timestamp": int(time.time())
            },
            "note": f"Server monitoring error: {str(e)}. Ensure psutil is available."
        }


@api.put("/api/v1/system/server-info", status_code=200)
async def update_server_info_route(request: ServerSettingsRequest):
    """
    Update server configuration settings. Server Owner only.

    Args:
        request (ServerSettingsRequest): Request body containing auth_token and settings to update.

    Returns:
        200 OK: Server settings updated successfully
        403 FORBIDDEN: User is not server owner
        404 NOT FOUND: Invalid auth_token
        500 INTERNAL SERVER ERROR: Failed to update settings
    """
    user_id = extract_user_id(auth_token=request.auth_token)

    # Check if user is server owner
    if not api_initializer.user_manager.is_server_owner(user_id=user_id):
        raise exceptions.HTTPException(
            status_code=403,
            detail="Access forbidden. Only the server owner can update server settings."
        )

    try:
        updated_fields = []
        server_updates = {}
        server_settings_updates = {}

        # Map requested fields to appropriate tables
        if request.server_name is not None:
            server_updates["server_name"] = request.server_name
            updated_fields.append("server_name")

        if request.server_description is not None:
            server_updates["description"] = request.server_description
            updated_fields.append("server_description")

        if request.is_private is not None:
            server_settings_updates["is_private"] = request.is_private
            updated_fields.append("is_private")

        if request.max_message_length is not None:
            server_settings_updates["max_message_length"] = request.max_message_length
            updated_fields.append("max_message_length")

        # Note: max_users is not handled yet as it's not in the current schema

        # Update Server table (server name/description)
        if server_updates:
            server_name = server_updates.get("server_name")
            server_description = server_updates.get("description")
            # Get current server data to preserve existing values
            current_server = api_initializer.database_handler.get_server()
            # Only update name and description, keep welcome message from current server
            final_server_name = server_name if server_name is not None else current_server.server_name
            final_welcome_message = current_server.welcome_message
            final_description = server_description if server_description is not None else current_server.description
            api_initializer.database_handler.update_server_values(final_server_name, final_welcome_message, final_description)

            # Log server name/description changes
            if "server_name" in server_updates:
                activity_data = {
                    "event_type": "server_settings_updated",
                    "description": f"Server name updated to '{server_name}'",
                    "metadata": {
                        "field": "server_name",
                        "new_value": server_name,
                        "setting_type": "server_info"
                    },
                    "user_id": user_id,
                    "timestamp": datetime.utcnow().isoformat()
                }
                api_initializer.database_handler.create_activity_audit_entry(
                    ActivityAudit(
                        activity_id=str(uuid.uuid4()),
                        activity_type="server_settings_updated",
                        user_id=user_id,
                        title=f"Server name updated to '{server_name}'",
                        description=f"Server name changed to '{server_name}'",
                        metadata_json=json.dumps({
                            "field": "server_name",
                            "new_value": server_name,
                            "setting_type": "server_info"
                        })
                    )
                )

            if "description" in server_updates:
                activity_data = {
                    "event_type": "server_settings_updated",
                    "description": f"Server description updated",
                    "metadata": {
                        "field": "server_description",
                        "new_value": server_description,
                        "setting_type": "server_info"
                    },
                    "user_id": user_id,
                    "timestamp": datetime.utcnow().isoformat()
                }
                api_initializer.database_handler.create_activity_audit_entry(
                    ActivityAudit(
                        activity_id=str(uuid.uuid4()),
                        activity_type="server_settings_updated",
                        user_id=user_id,
                        title=f"Server description updated",
                        description=f"Server description was updated",
                        metadata_json=json.dumps({
                            "field": "server_description",
                            "new_value": server_description,
                            "setting_type": "server_info"
                        })
                    )
                )

        # Update ServerSettings table
        if server_settings_updates:
            api_initializer.database_handler.update_server_settings(server_settings_updates)

            # Log server settings changes
            for field, new_value in server_settings_updates.items():
                field_descriptions = {
                    "is_private": "Server privacy" if new_value else "Server publicity",
                    "max_message_length": f"Maximum message length to {new_value} characters"
                }

                description = field_descriptions.get(field, f"Server setting '{field}' updated to '{new_value}'")

                api_initializer.database_handler.create_activity_audit_entry(
                    ActivityAudit(
                        activity_id=str(uuid.uuid4()),
                        activity_type="server_settings_updated",
                        user_id=user_id,
                        title=f"Server settings updated: {field}",
                        description=description,
                        metadata_json=json.dumps({
                            "field": field,
                            "new_value": new_value,
                            "setting_type": "server_settings",
                            "table": "server_settings"
                        })
                    )
                )

        return {
            "status_code": 200,
            "message": "Server settings updated successfully",
            "updated_fields": updated_fields
        }

    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500,
            detail=f"Failed to update server settings: {str(e)}"
        )

@api.post("/api/v1/system/upload-avatar", status_code=201)
async def upload_server_avatar_route(
    auth_token: str = Form(..., description="User's authentication token"),
    avatar: UploadFile = Form(..., description="Server avatar image file")
):
    """
    Upload server's avatar image. Server Owner only.
    Deletes the old avatar file to prevent storage buildup.

    Args:
        auth_token: User's authentication token
        avatar: Server avatar image file (PNG, JPEG, GIF, etc.)

    Returns:
        201 CREATED: Avatar uploaded successfully
        400 BAD REQUEST: File validation failed
        403 FORBIDDEN: User is not server owner
        404 NOT FOUND: Invalid auth_token
    """
    user_id = extract_user_id(auth_token=auth_token)

    # Check if user is server owner
    if not api_initializer.user_manager.is_server_owner(user_id=user_id):
        raise exceptions.HTTPException(
            status_code=403,
            detail="Access forbidden. Only the server owner can update server avatar."
        )

    try:
        # Get current server data to check for existing avatar
        current_server = api_initializer.database_handler.get_server()
        old_avatar_url = current_server.avatar_url

        # Delete old avatar file if it exists
        if old_avatar_url:
            try:
                # Extract relative path from the URL for deletion
                if old_avatar_url.startswith('/'):
                    # It's a local CDN URL like /api/v1/cdn/file/...
                    relative_path = old_avatar_url.replace('/api/v1/cdn/file/', '', 1)
                    full_path = Path(api_initializer.config.CDN_STORAGE_PATH) / relative_path
                    if full_path.exists():
                        full_path.unlink()
                        logger.info(f"Deleted old server avatar: {relative_path}")
                else:
                    # Try the CDN manager deletion method
                    api_initializer.cdn_manager.delete_file(old_avatar_url)
            except Exception as e:
                logger.warning(f"Failed to delete old server avatar {old_avatar_url}: {str(e)}")

        # Upload new avatar
        cdn_url, is_duplicate = api_initializer.cdn_manager.validate_and_save_categorized_file(
            file=avatar,
            user_id=user_id,
            force_category="avatars",
            check_duplicates=False
        )

        # Register file in database and create reference
        try:
            # Extract file info from URL
            relative_path = cdn_url[len(api_initializer.config.CDN_BASE_URL):].lstrip('/')
            file_path_obj = Path(api_initializer.config.CDN_STORAGE_PATH) / relative_path

            if file_path_obj.exists():
                # Read file to compute hash
                with open(file_path_obj, "rb") as f:
                    content = f.read()

                file_hash = api_initializer.cdn_manager.compute_file_hash(content)

                # Always check if file object exists and increment reference count if duplicate
                # Skip creating file object if it already exists
                existing_ref_count = api_initializer.database_handler.get_file_reference_count(file_hash)
                if existing_ref_count is not None and existing_ref_count > 0:
                    # File already exists, just increment reference count
                    api_initializer.database_handler.increment_file_reference_count(file_hash)
                else:
                    # For new files, register and create reference
                    api_initializer.database_handler.create_file_object(
                        file_hash=file_hash,
                        ref_count=1,
                        file_path=relative_path,  # Store relative path
                        file_size=len(content),
                        mime_type=api_initializer.cdn_manager.mime_detector.from_buffer(content) or 'application/octet-stream',
                        verification_status="verified"
                    )

                # Create reference for server avatar
                reference_id = f"server_avatar_{uuid.uuid4()}"
                api_initializer.database_handler.create_file_reference(
                    reference_id=reference_id,
                    file_hash=file_hash,
                    reference_type="server_avatar",
                    reference_entity_id="server"  # Server entity
                )

        except Exception as e:
            # Log error but don't fail the upload
            logger.warning(f"Failed to create file reference for server avatar: {str(e)}")

        # Update server avatar URL in database - ensure full path for proper serving
        if not cdn_url.startswith('/api/v1/cdn/file/'):
            # Convert CDN-mounted URL to API route URL for database storage
            if cdn_url.startswith('/cdn/'):
                cdn_url = cdn_url.replace('/cdn/', '/api/v1/cdn/file/', 1)
        api_initializer.database_handler.update_server_avatar_url(cdn_url)

        # Log server avatar update activity
        try:
            api_initializer.database_handler.create_activity_audit_entry(
                ActivityAudit(
                    activity_id=str(uuid.uuid4()),
                    activity_type="server_avatar_updated",
                    user_id=user_id,
                    title="Server avatar updated",
                    description=f"Server avatar was updated by user {user_id}",
                    metadata_json=json.dumps({
                        "avatar_url": cdn_url,
                        "updated_by": user_id
                    })
                )
            )
        except Exception as e:
            logger.warning(f"Failed to log server avatar update activity: {str(e)}")

        return {
            "status_code": 201,
            "message": "Server avatar uploaded successfully",
            "avatar_url": cdn_url
        }

    except exceptions.HTTPException:
        raise
    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500,
            detail=f"Avatar upload failed: {str(e)}"
        )

@api.post("/api/v1/system/upload-banner", status_code=201)
async def upload_server_banner_route(
    auth_token: str = Form(..., description="User's authentication token"),
    banner: UploadFile = Form(..., description="Server banner image file")
):
    """
    Upload server's banner image. Server Owner only.
    Deletes the old banner file to prevent storage buildup.

    Args:
        auth_token: User's authentication token
        banner: Server banner image file (PNG, JPEG, GIF, etc.)

    Returns:
        201 CREATED: Banner uploaded successfully
        400 BAD REQUEST: File validation failed
        403 FORBIDDEN: User is not server owner
        404 NOT FOUND: Invalid auth_token
    """
    user_id = extract_user_id(auth_token=auth_token)

    # Check if user is server owner
    if not api_initializer.user_manager.is_server_owner(user_id=user_id):
        raise exceptions.HTTPException(
            status_code=403,
            detail="Access forbidden. Only the server owner can update server banner."
        )

    try:
        # Get current server data to check for existing banner
        current_server = api_initializer.database_handler.get_server()
        old_banner_url = current_server.banner_url

        # Delete old banner file if it exists
        if old_banner_url:
            try:
                # Extract relative path from the URL for deletion
                if old_banner_url.startswith('/'):
                    # It's a local CDN URL like /api/v1/cdn/file/...
                    relative_path = old_banner_url.replace('/api/v1/cdn/file/', '', 1)
                    full_path = Path(api_initializer.config.CDN_STORAGE_PATH) / relative_path
                    if full_path.exists():
                        full_path.unlink()
                        logger.info(f"Deleted old server banner: {relative_path}")
                else:
                    # Try the CDN manager deletion method
                    api_initializer.cdn_manager.delete_file(old_banner_url)
            except Exception as e:
                logger.warning(f"Failed to delete old server banner {old_banner_url}: {str(e)}")

        # Upload new banner
        cdn_url, is_duplicate = api_initializer.cdn_manager.validate_and_save_categorized_file(
            file=banner,
            user_id=user_id,
            force_category="banners",
            check_duplicates=False
        )

        # Register file in database and create reference
        try:
            # Extract file info from URL
            from pathlib import Path
            relative_path = cdn_url[len(api_initializer.config.CDN_BASE_URL):].lstrip('/')
            file_path_obj = Path(api_initializer.config.CDN_STORAGE_PATH) / relative_path

            if file_path_obj.exists():
                # Read file to compute hash
                with open(file_path_obj, "rb") as f:
                    content = f.read()

                file_hash = api_initializer.cdn_manager.compute_file_hash(content)

                # Always check if file object exists and increment reference count if duplicate
                # Skip creating file object if it already exists
                existing_ref_count = api_initializer.database_handler.get_file_reference_count(file_hash)
                if existing_ref_count is not None and existing_ref_count > 0:
                    # File already exists, just increment reference count
                    api_initializer.database_handler.increment_file_reference_count(file_hash)
                else:
                    # For new files, register and create reference
                    api_initializer.database_handler.create_file_object(
                        file_hash=file_hash,
                        ref_count=1,
                        file_path=relative_path,  # Store relative path
                        file_size=len(content),
                        mime_type=api_initializer.cdn_manager.mime_detector.from_buffer(content) or 'application/octet-stream',
                        verification_status="verified"
                    )

                # Create reference for server banner
                reference_id = f"server_banner_{uuid.uuid4()}"
                api_initializer.database_handler.create_file_reference(
                    reference_id=reference_id,
                    file_hash=file_hash,
                    reference_type="server_banner",
                    reference_entity_id="server"  # Server entity
                )

        except Exception as e:
            # Log error but don't fail the upload
            logger.warning(f"Failed to create file reference for server banner: {str(e)}")

        # Update server banner URL in database - ensure full path for proper serving
        if not cdn_url.startswith('/api/v1/cdn/file/'):
            # Convert CDN-mounted URL to API route URL for database storage
            if cdn_url.startswith('/cdn/'):
                cdn_url = cdn_url.replace('/cdn/', '/api/v1/cdn/file/', 1)
        api_initializer.database_handler.update_server_banner_url(cdn_url)

        return {
            "status_code": 201,
            "message": "Server banner uploaded successfully",
            "banner_url": cdn_url
        }

    except exceptions.HTTPException:
        raise
    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500,
            detail=f"Banner upload failed: {str(e)}"
        )

# Request body models for chart endpoints
class ChartRequest(BaseModel):
    auth_token: str = Field(min_length=1)
    period: str | None = Field(default=None, description="Time period (daily, weekly, monthly, 24h, 7d)")

class UserStatusChartRequest(BaseModel):
    auth_token: str = Field(min_length=1)

@api.post("/api/v1/system/charts/user-registrations", status_code=200)
async def get_user_registration_chart_route(request: ChartRequest):
    """
    Get user registration chart data.

    Args:
        request (ChartRequest): Request body containing auth_token and optional period.

    Returns:
        200 OK: Chart data for user registrations
        500 INTERNAL SERVER ERROR: Failed to fetch chart data
    """
    try:
        user_id = extract_user_id(auth_token=request.auth_token)

        if hasattr(api_initializer, 'background_tasks_manager'):
            chart_data = api_initializer.background_tasks_manager.get_chart_data('user_registrations', request.period)
            raw_stats = api_initializer.background_tasks_manager.get_raw_stats('user_registrations', request.period)

            return {
                "status_code": 200,
                "chart_data": chart_data,
                "raw_stats": raw_stats or {}
            }
        else:
            return {
                "status_code": 200,
                "message": "Background tasks manager not initialized",
                "chart_data": {},
                "raw_stats": {}
            }

    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500,
            detail=f"Failed to get user registration chart data: {str(e)}"
        )

@api.post("/api/v1/system/charts/message-activity", status_code=200)
async def get_message_activity_chart_route(request: ChartRequest):
    """
    Get message activity chart data.

    Args:
        request (ChartRequest): Request body containing auth_token and optional period.

    Returns:
        200 OK: Chart data for message activity
        500 INTERNAL SERVER ERROR: Failed to fetch chart data
    """
    try:
        user_id = extract_user_id(auth_token=request.auth_token)

        if hasattr(api_initializer, 'background_tasks_manager'):
            chart_data = api_initializer.background_tasks_manager.get_chart_data('message_activity', request.period)
            raw_stats = api_initializer.background_tasks_manager.get_raw_stats('message_activity', request.period)

            return {
                "status_code": 200,
                "chart_data": chart_data,
                "raw_stats": raw_stats or {}
            }
        else:
            return {
                "status_code": 200,
                "message": "Background tasks manager not initialized",
                "chart_data": {},
                "raw_stats": {}
            }

    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500,
            detail=f"Failed to get message activity chart data: {str(e)}"
        )

@api.post("/api/v1/system/charts/online-users", status_code=200)
async def get_online_users_chart_route(request: ChartRequest):
    """
    Get online users chart data.

    Args:
        request (ChartRequest): Request body containing auth_token and optional period.

    Returns:
        200 OK: Chart data for online users
        500 INTERNAL SERVER ERROR: Failed to fetch chart data
    """
    try:
        user_id = extract_user_id(auth_token=request.auth_token)

        if hasattr(api_initializer, 'background_tasks_manager'):
            chart_data = api_initializer.background_tasks_manager.get_chart_data('online_users', request.period)
            raw_stats = api_initializer.background_tasks_manager.get_raw_stats('online_users', request.period)

            return {
                "status_code": 200,
                "chart_data": chart_data,
                "raw_stats": raw_stats or {}
            }
        else:
            return {
                "status_code": 200,
                "message": "Background tasks manager not initialized",
                "chart_data": {},
                "raw_stats": {}
            }

    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500,
            detail=f"Failed to get online users chart data: {str(e)}"
        )

@api.post("/api/v1/system/charts/channel-creation", status_code=200)
async def get_channel_creation_chart_route(request: ChartRequest):
    """
    Get channel creation chart data.

    Args:
        request (ChartRequest): Request body containing auth_token and optional period.

    Returns:
        200 OK: Chart data for channel creation
        500 INTERNAL SERVER ERROR: Failed to fetch chart data
    """
    try:
        user_id = extract_user_id(auth_token=request.auth_token)

        if hasattr(api_initializer, 'background_tasks_manager'):
            chart_data = api_initializer.background_tasks_manager.get_chart_data('channel_creation', request.period)
            raw_stats = api_initializer.background_tasks_manager.get_raw_stats('channel_creation', request.period)

            return {
                "status_code": 200,
                "chart_data": chart_data,
                "raw_stats": raw_stats or {}
            }
        else:
            return {
                "status_code": 200,
                "message": "Background tasks manager not initialized",
                "chart_data": {},
                "raw_stats": {}
            }

    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500,
            detail=f"Failed to get channel creation chart data: {str(e)}"
        )

@api.post("/api/v1/system/charts/user-status", status_code=200)
async def get_user_status_chart_route(request: UserStatusChartRequest):
    """
    Get user status distribution chart data.

    Args:
        request (UserStatusChartRequest): Request body containing auth_token.

    Returns:
        200 OK: Chart data for user status distribution
        500 INTERNAL SERVER ERROR: Failed to fetch chart data
    """
    try:
        user_id = extract_user_id(auth_token=request.auth_token)

        if hasattr(api_initializer, 'background_tasks_manager'):
            chart_data = api_initializer.background_tasks_manager.get_chart_data('user_status', None)
            raw_stats = api_initializer.background_tasks_manager.get_raw_stats('user_status', None)

            return {
                "status_code": 200,
                "chart_data": chart_data,
                "raw_stats": raw_stats or {}
            }
        else:
            return {
                "status_code": 200,
                "message": "Background tasks manager not initialized",
                "chart_data": {},
                "raw_stats": {}
            }

    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500,
            detail=f"Failed to get user status chart data: {str(e)}"
        )

# Request body model for recent activity
class RecentActivityRequest(BaseModel):
    auth_token: str
    limit: int = 10

# Request body model for server logs
class ServerLogsRequest(BaseModel):
    auth_token: str = Field(min_length=1)
    lines: int = Field(default=50, ge=1, le=1000)
    search: str | None = Field(default=None)
    level: str | None = Field(default=None, description="Filter by log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)")

@api.post("/api/v1/system/logs", status_code=200)
async def get_server_logs_route(request: ServerLogsRequest):
    """
    Get server logs with filtering options. Server Owner only.

    Args:
        request (ServerLogsRequest): Request body containing auth_token and filtering options.

    Returns:
        200 OK: Server logs data
        403 FORBIDDEN: User is not server owner
        404 NOT FOUND: Invalid auth_token
        500 INTERNAL SERVER ERROR: Failed to fetch logs
    """
    user_id = extract_user_id(auth_token=request.auth_token)

    # Check if user is server owner
    if not api_initializer.user_manager.is_server_owner(user_id=user_id):
        raise exceptions.HTTPException(
            status_code=403,
            detail="Access forbidden. Only the server owner can access server logs."
        )

    try:
        import os
        import glob
        from pathlib import Path

        # Get log directory (using config defined log path)
        log_dir = Path(api_initializer.config.LOGS_PATH).parent

        # Look for log files
        log_files = []
        if log_dir.exists():
            # Look for common log file patterns
            patterns = ['*.log', '*.txt', 'pufferblow*.log', 'server*.log']
            for pattern in patterns:
                log_files.extend(list(log_dir.glob(pattern)))

        if not log_files:
            # Fallback to common system log locations
            possible_paths = [
                Path('/var/log/pufferblow.log'),
                Path('/var/log/pufferblow/server.log'),
                Path('./logs/pufferblow.log'),
                Path('./logs/server.log')
            ]
            for path in possible_paths:
                if path.exists():
                    log_files.append(path)
                    break

        logs_content = []
        if log_files:
            # Read the most recent log file
            latest_log = max(log_files, key=lambda p: p.stat().st_mtime)
            try:
                with open(latest_log, 'r', encoding='utf-8', errors='replace') as f:
                    all_lines = f.readlines()

                    # Reverse to get most recent first, apply line limit
                    all_lines.reverse()
                    lines = all_lines[:request.lines]

                    # Apply filters
                    filtered_lines = []
                    for line in lines:
                        # Ensure line is a string
                        if not isinstance(line, str):
                            line = str(line)

                        # Apply search filter
                        if request.search and request.search.lower() not in line.lower():
                            continue

                        # Apply level filter
                        if request.level:
                            level_upper = request.level.upper()
                            level_found = False

                            # Check for common log level patterns
                            if level_upper == 'DEBUG' and ('DEBUG' in line.upper() or 'DBUG' in line.upper()):
                                level_found = True
                            elif level_upper == 'INFO' and ('INFO' in line.upper() or 'INF' in line.upper()):
                                level_found = True
                            elif level_upper == 'WARNING' and ('WARNING' in line.upper() or 'WARN' in line.upper()):
                                level_found = True
                            elif level_upper == 'ERROR' and ('ERROR' in line.upper() or 'ERR' in line.upper()):
                                level_found = True
                            elif level_upper == 'CRITICAL' and ('CRITICAL' in line.upper() or 'CRIT' in line.upper()):
                                level_found = True

                            if not level_found:
                                continue

                        # Inline colors using ANSI escape codes
                        colored_line = line
                        line_upper = line.upper()
                        if 'ERROR' in line_upper or 'ERR' in line_upper:
                            colored_line = f"\x1b[31m{line}\x1b[0m"  # Red for errors
                        elif 'WARNING' in line_upper or 'WARN' in line_upper:
                            colored_line = f"\x1b[33m{line}\x1b[0m"  # Yellow for warnings
                        elif 'DEBUG' in line_upper:
                            colored_line = f"\x1b[36m{line}\x1b[0m"  # Cyan for debug
                        elif 'INFO' in line_upper:
                            colored_line = f"\x1b[32m{line}\x1b[0m"  # Green for info

                        filtered_lines.append({
                            "content": colored_line.strip(),
                            "raw": line.strip()
                        })

                    logs_content = filtered_lines

                    # Log the access
                    api_initializer.database_handler.create_activity_audit_entry(
                        ActivityAudit(
                            activity_id=str(uuid.uuid4()),
                            activity_type="logs_viewed",
                            user_id=user_id,
                            title="Server logs accessed",
                            description=f"Server owner accessed logs with filters: lines={request.lines}, search='{request.search or 'None'}', level='{request.level or 'None'}'",
                            metadata_json=json.dumps({
                                "action": "logs_access",
                                "lines_requested": request.lines,
                                "search_filter": request.search,
                                "level_filter": request.level,
                                "log_file": str(latest_log)
                            })
                        )
                    )

            except Exception as e:
                logger.error(f"Failed to read log file {latest_log}: {str(e)}")
                return {
                    "status_code": 200,
                    "logs": [],
                    "message": f"Error reading log file: {str(e)}",
                    "available_log_files": [str(f) for f in log_files]
                }
        else:
            return {
                "status_code": 200,
                "logs": [],
                "message": "No log files found. Logs may not be configured or accessible.",
                "searched_paths": [
                    str(log_dir),
                    "/var/log/pufferblow.log",
                    "/var/log/pufferblow/server.log",
                    "./logs/pufferblow.log",
                    "./logs/server.log"
                ]
            }

        return {
            "status_code": 200,
            "logs": logs_content,
            "total_lines": len(logs_content),
            "filtered": bool(request.search or request.level),
            "log_file": str(log_files[0]) if log_files else None,
            "note": "Logs are displayed with ANSI color codes preserved. Latest entries appear first."
        }

    except exceptions.HTTPException:
        raise
    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500,
            detail=f"Failed to get server logs: {str(e)}"
        )

@api.post("/api/v1/system/recent-activity", status_code=200)
async def get_recent_activity_route(request: RecentActivityRequest):
    """
    Get recent activity events from the server.

    Returns:
        200 OK: Recent activity data
        500 INTERNAL SERVER ERROR: Failed to fetch

    Retrieves real activity data from the activity_audit table.
    """
    try:
        user_id = extract_user_id(auth_token=request.auth_token)

        # Check if user is admin/owner (for privacy on internal activities)
        is_admin = api_initializer.user_manager.is_admin(user_id=user_id) or api_initializer.user_manager.is_server_owner(user_id=user_id)

        # If not admin, can only see public activities
        if not is_admin:
            return {
                "status_code": 200,
                "activities": []
            }

        # Get recent activities from database
        recent_activities = api_initializer.database_handler.get_recent_activities(limit=request.limit)

        activities = []
        for activity in recent_activities:
            # Parse metadata JSON
            metadata = json.loads(activity.metadata_json) if activity.metadata_json else {}

            # Get user info for the activity
            user_info = None
            if activity.user_id:
                user_profile = api_initializer.user_manager.user_profile(activity.user_id)
                if user_profile:
                    user_info = {
                        "id": activity.user_id,
                        "username": user_profile.get('username', 'Unknown'),
                        "avatar_url": f"https://api.dicebear.com/7.x/bottts-neutral/svg?seed={activity.user_id[:8]}&backgroundColor=5865f2"
                    }

            # Format activity based on type
            activity_title = ""
            activity_description = ""
            activity_type = activity.activity_type

            if activity_type == 'file_upload':
                filename = "a file"
                if metadata.get('file_url'):
                    filename_part = metadata['file_url'].split('/')[-1]
                    if '.' in filename_part and len(filename_part.split('.')[1]) > 0:
                        filename = filename_part

                directory = metadata.get('directory', 'files')
                activity_title = f"File uploaded to {directory}"
                activity_description = f"File '{filename}' was uploaded"

            elif activity_type == 'user_joined':
                activity_title = "User joined the server"
                activity_description = "A new member joined the community"

            elif activity_type == 'channel_created':
                channel_name = metadata.get('channel_name', 'unknown channel')
                activity_title = f"Channel created: #{channel_name}"
                activity_description = f"New channel '{channel_name}' was created"

            elif activity_type == 'user_left':
                activity_title = "User left the server"
                activity_description = "A member left the community"

            elif activity_type == 'server_settings_updated':
                field = metadata.get('field', 'unknown')
                setting_type = metadata.get('setting_type', 'unknown')
                new_value = metadata.get('new_value', 'unknown')
                username = user_info.get('username', 'Unknown User') if user_info else 'Unknown User'
                activity_title = f"Server settings updated by {username}: {field}"
                activity_description = f"{username} changed {field} to '{new_value}'"

            else:
                activity_title = activity_type.replace('_', ' ').title()
                activity_description = f"System activity: {activity_type}"

            activities.append({
                "id": str(activity.activity_id),
                "type": activity_type,
                "title": activity_title,
                "description": activity_description,
                "timestamp": activity.created_at.isoformat(),
                "user": user_info,
                "metadata": metadata
            })

        return {
            "status_code": 200,
            "activities": activities
        }

    except Exception as e:
        logger.warning(f"Failed to get recent activity data: {str(e)}")
        # Fallback to empty list instead of error for better UX
        return {
            "status_code": 200,
            "activities": []
        }

# Activity Metrics Routes (Admin Only)
@api.post("/api/v1/system/activity-metrics", status_code=200)
async def get_activity_metrics_route(request: AuthTokenQuery):
    """
    Get current activity metrics for the control panel dashboard.

    Args:
        request (AuthTokenQuery): Request body containing auth_token.

    Returns:
        200 OK: Activity metrics data
        403 FORBIDDEN: User is not admin/owner
        404 NOT FOUND: Invalid auth_token
        500 INTERNAL SERVER ERROR: Failed to fetch metrics
    """
    user_id = extract_user_id(auth_token=request.auth_token)

    # Check if user is admin or owner
    if not api_initializer.user_manager.is_admin(user_id=user_id):
        raise exceptions.HTTPException(
            status_code=403,
            detail="Access forbidden. Only administrators can access activity metrics."
        )

    try:
        metrics_data = api_initializer.database_handler.get_latest_activity_metrics()

        return {
            "status_code": 200,
            "activity_metrics": metrics_data
        }

    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500,
            detail=f"Failed to get activity metrics: {str(e)}"
        )

@api.post("/api/v1/system/server-overview", status_code=200)
async def get_server_overview_route(request: AuthTokenQuery):
    """
    Get comprehensive server overview data for control panel.

    Args:
        request (AuthTokenQuery): Request body containing auth_token.

    Returns:
        200 OK: Server overview data
        403 FORBIDDEN: User is not admin/owner
        404 NOT FOUND: Invalid auth_token
        500 INTERNAL SERVER ERROR: Failed to fetch overview
    """
    user_id = extract_user_id(auth_token=request.auth_token)

    # Check if user is admin or owner
    if not api_initializer.user_manager.is_admin(user_id=user_id):
        raise exceptions.HTTPException(
            status_code=403,
            detail="Access forbidden. Only administrators can access server overview."
        )

    try:
        # Get real data from database
        total_users = api_initializer.database_handler.count_users()
        total_channels = len(api_initializer.database_handler.get_channels_names())

        # Get additional metrics
        messages_last_hour = api_initializer.database_handler.get_message_count_by_period(
            datetime.now() - timedelta(hours=1), datetime.now()
        )

        active_users = api_initializer.database_handler.get_user_status_counts()
        messages_this_period = api_initializer.database_handler.get_message_count_by_period(
            datetime.now() - timedelta(days=7), datetime.now()
        )

        return {
            "status_code": 200,
            "server_overview": {
                "total_users": total_users,
                "total_channels": total_channels,
                "messages_last_hour": messages_last_hour,
                "active_users": active_users.get('online', 0) + active_users.get('away', 0),
                "messages_this_period": messages_this_period
            }
        }

    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500,
            detail=f"Failed to get server overview: {str(e)}"
        )

# Global WebSocket used for real-time messaging across all channels
@api.websocket("/ws")
async def global_messages_websocket(websocket: WebSocket, auth_token: str):
    """
    Global WebSocket endpoint handles real-time messaging for all accessible channels.
    It establishes a single WebSocket connection that receives updates from all channels
    the user has permission to access. This replaces the per-channel websockets with
    a more efficient global approach.

    Args:
        websocket (WebSocket): WebSocket connection object.
        auth_token (str): The user's authentication token.

    Returns:
        1001 Going Away: This status code may be raised if:
            - The auth_token format or validity is invalid.
            - The user doesn't exist or authentication fails.
            - Access restrictions apply.
    """
    user_id = extract_user_id(auth_token=auth_token) if 'auth_token' in locals() else "unknown"
    logger.info(f"Global WebSocket endpoint accessed | User: {user_id}")

    # Validate auth_token format
    if not api_initializer.auth_token_manager.check_auth_token_format(auth_token=auth_token):
        logger.warning(f"Invalid auth_token format from user {user_id}")
        raise exceptions.WebSocketException(
            reason="Invalid auth_token format. Please check your authentication token.",
            code=1001
        )

    user_id = extract_user_id(auth_token=auth_token)

    # Check if the user exists
    if not api_initializer.user_manager.check_user(user_id=user_id, auth_token=auth_token):
        logger.warning(f"Authentication failed for user {user_id}")
        raise exceptions.WebSocketException(
            code=1001,
            reason="Authentication failed. Invalid or expired auth_token."
        )

    # Get user's accessible channels for global permission filtering
    accessible_channels = api_initializer.websockets_manager.get_user_accessible_channels(
        user_id=user_id,
        database_handler=api_initializer.database_handler
    )

    if not accessible_channels:
        logger.warning(f"User {user_id} has no accessible channels, denying WebSocket connection")
        raise exceptions.WebSocketException(
            code=1001,
            reason="No accessible channels found. Please contact an administrator."
        )

    # Establish global WebSocket connection with user's accessible channels
    await api_initializer.websockets_manager.connect_global(
        websocket=websocket,
        auth_token=auth_token,
        accessible_channels=accessible_channels
    )

    logger.info(f"Global WebSocket connection established | User: {user_id} | Accessible channels: {len(accessible_channels)}")

    sent_messages_ids = set()  # Track sent message IDs to avoid duplicates
    unconfirmed_messages = {}  # Track messages sent but not confirmed as read
    total_messages_sent = 0
    total_read_confirmations = 0

    MESSAGE_POLL_INTERVAL = 2  # seconds between polling for new messages

    try:
        logger.debug(f"Starting global WebSocket message loop for user {user_id} with {len(accessible_channels)} accessible channels")

        while True:
            # Handle incoming messages from client (like read confirmations)
            try:
                incoming_data = await asyncio.wait_for(websocket.receive_text(), timeout=0.1)
                if incoming_data:
                    try:
                        message_data = json.loads(incoming_data)
                        message_type = message_data.get('type', 'unknown')
                        logger.debug(f"Received client message | User: {user_id} | Type: {message_type}")

                        # Handle read confirmation
                        if message_type == "read_confirmation":
                            message_id = message_data.get("message_id")
                            channel_id = message_data.get("channel_id")  # Channel context needed
                            if message_id and channel_id and message_id in unconfirmed_messages:
                                try:
                                    api_initializer.messages_manager.mark_message_as_read(
                                        user_id=user_id,
                                        message_id=message_id,
                                        channel_id=channel_id
                                    )
                                    unconfirmed_messages.pop(message_id, None)
                                    total_read_confirmations += 1
                                    logger.debug(f"Message marked as read | User: {user_id} | Channel: {channel_id} | Message: {message_id}")

                                except Exception as e:
                                    logger.warning(f"Failed to mark message as read | User: {user_id} | Channel: {channel_id} | Message: {message_id} | Error: {str(e)}")
                            else:
                                logger.debug(f"Invalid read confirmation | User: {user_id} | Message: {message_id} | Channel: {channel_id}")

                    except json.JSONDecodeError as e:
                        logger.warning(f"Invalid JSON from client | User: {user_id} | Data: {incoming_data[:100]}... | Error: {str(e)}")

            except asyncio.TimeoutError:
                # No client message, continue with message polling
                pass

            # Poll for new messages across all accessible channels
            try:
                # Get unread message IDs for all channels
                viewed_messages_ids = api_initializer.database_handler.get_user_read_messages_ids(user_id)

                all_new_messages = []

                # Check each accessible channel for new messages
                for channel_id in accessible_channels:
                    try:
                        channel_messages = api_initializer.messages_manager.load_messages(
                            websocket=True,
                            channel_id=channel_id,
                            viewed_messages_ids=viewed_messages_ids
                        )

                        # Filter out already sent messages and add channel context
                        for message in channel_messages:
                            if isinstance(message, dict):
                                message_id = message.get("message_id")
                                if message_id and message_id not in sent_messages_ids:
                                    # Add channel context to message
                                    message["channel_id"] = channel_id
                                    all_new_messages.append(message)

                    except Exception as e:
                        logger.warning(f"Failed to load messages for channel {channel_id}: {str(e)}")
                        continue

                if not all_new_messages:
                    await asyncio.sleep(MESSAGE_POLL_INTERVAL)
                    continue

                logger.debug(f"Found {len(all_new_messages)} new messages across {len(accessible_channels)} channels for user {user_id}")

                messages_sent_this_cycle = 0

                # Send new messages to client
                for message in all_new_messages:
                    message_id = message.get("message_id")
                    channel_id = message.get("channel_id")
                    message_type = message.get("type", "message")

                    if not message_id or not channel_id:
                        continue

                    try:
                        await websocket.send_json(message)
                        sent_messages_ids.add(message_id)
                        unconfirmed_messages[message_id] = True
                        messages_sent_this_cycle += 1
                        total_messages_sent += 1

                        # Log message for debugging
                        content_preview = message.get('message', '')[:50] + "..." if len(message.get('message', '')) > 50 else message.get('message', '')
                        logger.debug(f"Sent message | User: {user_id} | Channel: {channel_id} | Type: {message_type} | Message: {message_id} | Preview: {content_preview}")

                    except Exception as e:
                        logger.error(f"Failed to send message to WebSocket client | User: {user_id} | Channel: {channel_id} | Message: {message_id} | Error: {str(e)}")

                if messages_sent_this_cycle > 0:
                    logger.info(f"Sent {messages_sent_this_cycle} messages to client | User: {user_id} | Total sent: {total_messages_sent}")

            except Exception as e:
                logger.error(f"Error during message polling for user {user_id}: {str(e)}")

            await asyncio.sleep(MESSAGE_POLL_INTERVAL)

    except WebSocketDisconnect as e:
        logger.info(f"Global WebSocket disconnected | User: {user_id} | Code: {e.code} | Reason: {e.reason or 'No reason'} | Stats: sent={total_messages_sent}, confirmed={total_read_confirmations}")
        await api_initializer.websockets_manager.disconnect(websocket)

    except Exception as e:
        logger.error(f"Unexpected global WebSocket error | User: {user_id} | Error: {str(e)}", exc_info=True)
        try:
            await api_initializer.websockets_manager.disconnect(websocket)
        except Exception as disconnect_error:
            logger.error(f"Error during WebSocket cleanup | User: {user_id} | Error: {str(disconnect_error)}")


# Keep legacy WebSocket endpoint for backwards compatibility
@api.websocket("/ws/channels/{channel_id}")
async def channels_messages_websocket_legacy(websocket: WebSocket, auth_token: str, channel_id: str):
    """
    Legacy WebSocket endpoint for backwards compatibility.
    Now routes through the global WebSocket system.
    """
    logger.warning(f"Legacy WebSocket endpoint used for channel {channel_id} - consider upgrading to /ws")

    user_id = extract_user_id(auth_token=auth_token) if 'auth_token' in locals() else "unknown"
    logger.info(f"Legacy WebSocket endpoint accessed | User: {user_id} | Channel: {channel_id}")

    # Validate inputs using legacy logic
    if not api_initializer.auth_token_manager.check_auth_token_format(auth_token=auth_token):
        raise exceptions.WebSocketException(
            reason="Bad auth_token format. Please check your auth_token and try again.",
            code=1001
        )

    user_id = extract_user_id(auth_token=auth_token)

    if not api_initializer.user_manager.check_user(user_id=user_id, auth_token=auth_token):
        raise exceptions.WebSocketException(
            code=1001,
            reason="'auth_token' expired/unvalid or 'user_id' doesn't exists. Please try again."
        )

    if not api_initializer.user_manager.is_admin(user_id=user_id) and not api_initializer.user_manager.is_server_owner(user_id=user_id):
        raise exceptions.WebSocketException(
            code=1001,
            reason="Access forbidden. Only admins and server owners can access legacy channel WebSocket endpoints."
        )

    if not api_initializer.channels_manager.check_channel(channel_id=channel_id):
        logger.info(info.INFO_CHANNEL_ID_NOT_FOUND(viewer_user_id=user_id, channel_id=channel_id))
        raise exceptions.WebSocketException(
            code=1001,
            reason="The provided channel ID does not exist or could not be found. Please make sure you have entered a valid channel ID and try again."
        )

    # Establish connection using legacy method for backwards compatibility
    api_initializer.websockets_manager.connect(
        websocket=websocket,
        auth_token=auth_token,
        channel_id=channel_id
    )

    logger.info(f"Legacy WebSocket connection established | User: {user_id} | Channel: {channel_id}")

    # Legacy message handling remains the same for compatibility
    sent_messages_ids = []
    unconfirmed_messages = {}
    total_messages_sent = 0
    total_read_confirmations = 0
    DELAY = 3

    try:
        logger.debug(f"Starting legacy WebSocket message loop for user {user_id} in channel {channel_id}")

        while True:
            try:
                incoming_data = await asyncio.wait_for(websocket.receive_text(), timeout=0.1)
                if incoming_data:
                    try:
                        message_data = json.loads(incoming_data)

                        if message_data.get("type") == "read_confirmation":
                            message_id = message_data.get("message_id")
                            if message_id and message_id in unconfirmed_messages:
                                try:
                                    api_initializer.messages_manager.mark_message_as_read(
                                        user_id=user_id,
                                        message_id=message_id,
                                        channel_id=channel_id
                                    )
                                    del unconfirmed_messages[message_id]
                                    total_read_confirmations += 1
                                    logger.debug(f"Legacy: Message marked as read | Channel: {channel_id} | User: {user_id} | Message: {message_id}")
                                except Exception as e:
                                    logger.warning(f"Legacy: Failed to mark message as read | Error: {str(e)}")

                    except json.JSONDecodeError as e:
                        logger.warning(f"Legacy: Invalid JSON received | Data: {incoming_data[:100]}... | Error: {str(e)}")

            except asyncio.TimeoutError:
                pass

            try:
                viewed_messages_ids = api_initializer.database_handler.get_user_read_messages_ids(user_id)
                latest_messages = api_initializer.messages_manager.load_messages(
                    websocket=True,
                    channel_id=channel_id,
                    viewed_messages_ids=viewed_messages_ids
                )

                if len(latest_messages) == 0:
                    await asyncio.sleep(DELAY)
                    continue

                messages_sent_this_cycle = 0

                for message in latest_messages:
                    if not isinstance(message, dict):
                        continue

                    message_id = message.get("message_id")
                    if not message_id or message_id in sent_messages_ids:
                        continue

                    try:
                        await websocket.send_json(message)
                        sent_messages_ids.append(message_id)
                        unconfirmed_messages[message_id] = True
                        messages_sent_this_cycle += 1
                        total_messages_sent += 1

                        content_preview = message.get('content', '')[:50] + "..." if len(message.get('content', '')) > 50 else message.get('content', '')
                        logger.debug(f"Legacy: Message sent | Channel: {channel_id} | User: {user_id} | Message: {message_id} | Preview: {content_preview}")

                    except Exception as e:
                        logger.error(f"Legacy: Failed to send message | Error: {str(e)}")

                if messages_sent_this_cycle > 0:
                    logger.info(f"Legacy: Sent {messages_sent_this_cycle} messages | User: {user_id} | Channel: {channel_id} | Total: {total_messages_sent}")

            except Exception as e:
                logger.error(f"Legacy: Error processing messages | Error: {str(e)}")

            await asyncio.sleep(DELAY)

    except WebSocketDisconnect as e:
        logger.info(f"Legacy WebSocket disconnected | Channel: {channel_id} | User: {user_id} | Code: {e.code} | Reason: {e.reason or 'No reason'} | Stats: sent={total_messages_sent}, confirmed={total_read_confirmations}")
        await api_initializer.websockets_manager.disconnect(websocket)

    except Exception as e:
        logger.error(f"Legacy: Unexpected WebSocket error | Error: {str(e)}", exc_info=True)
        try:
            await api_initializer.websockets_manager.disconnect(websocket)
        except Exception as disconnect_error:
            logger.error(f"Legacy: Error during cleanup | Error: {str(disconnect_error)}")


# Mount CDN static file serving
if api_initializer.is_loaded:
    api.mount(api_initializer.config.CDN_BASE_URL, StaticFiles(directory=api_initializer.config.CDN_STORAGE_PATH), name="cdn")
