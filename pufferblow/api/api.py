import sys
import asyncio
import base64
import json

from fastapi import (
    FastAPI,
    WebSocket,
    WebSocketDisconnect,
    responses,
    exceptions,
    Body,
    Depends,
    UploadFile,
    Form
)
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from loguru import logger

# Pydantic models for request bodies and query parameters
class SignupRequest(BaseModel):
    username: str
    password: str

class SigninRequest(BaseModel):
    username: str
    password: str

class UserProfileRequest(BaseModel):
    auth_token: str
    user_id: str

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

class ListChannelsRequest(BaseModel):
    auth_token: str

class CreateChannelRequest(BaseModel):
    auth_token: str
    channel_name: str
    is_private: bool = False

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

class SendMessageQuery(BaseModel):
    auth_token: str = Field(min_length=1)
    message: str = Field(min_length=1)

class MessageOperationsQuery(BaseModel):
    auth_token: str = Field(min_length=1)
    message_id: str = Field(min_length=1)

class CDNFilesQuery(BaseModel):
    auth_token: str = Field(min_length=1)
    subdirectory: str = Field(default="files", min_length=1)

class CDNDeleteFileQuery(BaseModel):
    auth_token: str = Field(min_length=1)
    file_url: str = Field(min_length=1)

class BlockIPRequest(BaseModel):
    auth_token: str = Field(min_length=1)
    ip: str = Field(min_length=7, max_length=45)  # IPv4/IPv6 range
    reason: str = Field(min_length=1, max_length=500)
from contextlib import asynccontextmanager
import uuid

from pufferblow import constants

# Database table models
from pufferblow.api.database.tables.blocked_ips import BlockedIPS
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
    "http://172.19.224.1:5173"  # if accessing via IP with frontend port
]
api.add_middleware(SecurityMiddleware)
api.add_middleware(RateLimitingMiddleware)
api.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["*"],
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
    
    return {
        "status_code": 200,
        "message": "Signin successfully",
        "auth_token": user.auth_token
    }

@api.get("/api/v1/users/profile", status_code=200)
async def users_profile_route(query: UserProfileQuery = Depends()):
    """
    Users profile management route

    Args:
        query (UserProfileQuery): Query parameters containing user_id and auth_token.

    Returns:
        200 OK: If the `user_id` of the targeted user exists and the `auth_token` is valid.
        400 BAD REQUEST: If the `auth_token` is improperly formatted.
        404 NOT FOUND: The `auth_token` is unvalid, or the `user_id` of the targeted user doesn't exists.
    """
    # Check if viewer user owns the targeted account
    is_account_owner = api_initializer.auth_token_manager.check_users_auth_token(
        user_id=query.user_id,
        raw_auth_token=query.auth_token
    )

    user_data = api_initializer.user_manager.user_profile(
        user_id=query.user_id,
        is_account_owner=is_account_owner
    )

    return {
        "status_code": 200,
        "user_data": user_data
    }

@api.put("/api/v1/users/profile", status_code=200)
async def edit_users_profile_route(query: EditProfileQuery = Depends()):
    """
    Update a user's profile metadata such as status, last_seen, username and password

    Args:
        query (EditProfileQuery): Query parameters containing auth_token and optional update fields.

    Returns:
        200 OK: If all parameters are correct, and the data was updated successfully.
        400 BAD REQUEST: If the `auth_token` is improperly formatted.
        401 UNAUTHORIZED: If the `password` is invalid.
        404 NOT FOUND: The `auth_token` is invalid, or the `user_id` does not exist.
        409 CONFLICT: If the `username` is not available.
    """
    user_id = extract_user_id(auth_token=query.auth_token)

    # Update username
    if query.new_username is not None:
        if api_initializer.user_manager.check_username(
            username=query.new_username
        ):
            raise exceptions.HTTPException(
                detail="username already exists. Please change it and try again later",
                status_code=409
            )

        api_initializer.user_manager.update_username(
            user_id=user_id,
            new_username=query.new_username
        )

        return {
            "status_code": 200,
            "message": "username updated successfully"
        }

    # Update the user's status
    if query.status is not None:
        api_initializer.user_manager.update_user_status(
            user_id=user_id,
            status=query.status
        )

        return {
            "status_code": 200,
            "message": "Status updated successfully"
        }

    # Update the user's password
    if query.new_password is not None and query.old_password is not None:
        api_initializer.user_manager.update_user_password(
            user_id=user_id,
            new_password=query.new_password
        )

        return {
            "status_code": 200,
            "message": "Password updated successfully"
        }

    # Update about
    if query.about is not None:
        api_initializer.user_manager.update_user_about(
            user_id=user_id,
            new_about=query.about
        )
        return {
            "status_code": 200,
            "message": "About updated successfully"
        }

# File upload endpoints
@api.post("/api/v1/users/profile/avatar", status_code=201)
async def upload_user_avatar_route(
    auth_token: str = Body(..., description="User's authentication token"),
    file: UploadFile = Body(..., description="Avatar image file")
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
    auth_token: str = Body(..., description="User's authentication token"),
    file: UploadFile = Body(..., description="Banner image file")
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
        "message": "auth_token rested successfully",
        "auth_token": new_auth_token,
        "auth_token_expire_time": new_auth_token_expire_time
    }

@api.get("/api/v1/users/list", status_code=200)
async def list_users_route(query: AuthTokenQuery = Depends()):
    """
    Returns a list of all the users present in the server

    Args:
        query (AuthTokenQuery): Query parameters containing auth_token.

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

@api.get("/api/v1/channels/list/", status_code=200)
async def list_channels_route(
    auth_token: str
    ):
    """
    Returns a list of all available channels,
    excluding private channels, unless the user
    is a server admin, the server owner, or has
    been invited to the private channel.
    
    Args:
        `auth_token` (str): The user's `auth_token`.
    
    Returns:
        200 OK: If the `auth_token` is valid, then a list of channels metadata is returned to the user.
        400 BAD REQUEST: If the `auth_token` is improperly formatted.
        404 NOT FOUND: The `auth_token` is unvalid, or the `user_id` of the targeted user doesn't exists, or in case the `status` is unvalid.
    """
    user_id = extract_user_id(auth_token=auth_token)

    channels_list = api_initializer.channels_manager.list_channels(
        user_id=user_id
    )

    return {
        "status_code": 200,
        "channels": channels_list
    }

@api.post("/api/v1/channels/create/", status_code=200)
async def create_new_channel_route(
    auth_token: str,
    channel_name: str,
    is_private: bool = False
):
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
    user_id = extract_user_id(auth_token=auth_token)

    # Check if the user is the server admin
    if not api_initializer.user_manager.is_admin(
        user_id=user_id
    ):
        raise exceptions.HTTPException(
            status_code=403,
            detail="Access forbidden. Only admins can create channels and manage them."
        )

    # Check if the `channel_name` has already been used or not
    channels_names = api_initializer.database_handler.get_channels_names()

    if channel_name in channels_names:
        raise exceptions.HTTPException(
            status_code=409,
            detail="Channel name already exists, please change it and try again."
        )

    channel_data = api_initializer.channels_manager.create_channel(
        user_id=user_id,
        channel_name=channel_name,
        is_private=is_private
    )

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

@api.get("/api/v1/channels/{channel_id}/load_messages", status_code=200)
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

    return {
        "status_code": 200,
        "messages": messages
    }

@api.post("/api/v1/channels/{channel_id}/send_message")
async def channel_send_message(
    auth_token: str,
    channel_id: str,
    message: str
):
    """
    Send a message into a server channel, if the channel is private and the user
    is not an admin nor the server owner then he wont be able to send the message

    Args:
        auth_token (str): The sender user's `auth_token`.
        channel_id (str): The channel's `channel_id`.
        message (str): The message to send.
    
    Returns:
        200 OK: The provided `message` will be sent in the desired channel (it's still can be deleted by the server owner and some admins).
        400 BAD REQUEST: If the `auth_token` is improperly formatted, or if the size of `message` exceeded the allowed size.
        404 NOT FOUND: The `auth_token` is unvalid, or the `channel_id` of the channel doesn't exists.
    """
    # Check if the size of the `message` exceeded the allowed size
    if sys.getsizeof(message) > api_initializer.config.MAX_MESSAGE_SIZE:
        raise exceptions.HTTPException(
            detail="the message is too long.",
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

    # Send the message
    message_obj = api_initializer.messages_manager.send_message(
        channel_id=channel_id,
        user_id=user_id,
        message=message
    )

    # Prepare message dict for broadcasting
    sender_user = api_initializer.user_manager.user_profile(user_id=user_id)
    message_dict = {
        "message_id": message_obj.message_id,
        "sender_id": user_id,
        "channel_id": channel_id,
        "raw_message": message,
        "username": sender_user["username"],
        "sent_at": message_obj.sent_at.isoformat() if message_obj.sent_at else None
    }

    # Broadcast to all websocket clients in this channel
    await api_initializer.websockets_manager.broadcast_to_channel(channel_id, message_dict)

    return {
        "status_code": 201,
        "message": "message sent succesfully"
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

# CDN Management Routes (Server Owner Only)
@api.get("/api/v1/cdn/files", status_code=200)
async def list_cdn_files_route(query: CDNFilesQuery = Depends()):
    """
    List all files in a CDN subdirectory. Server Owner only.

    Args:
        query (CDNFilesQuery): Query parameters containing auth_token and subdirectory.

    Returns:
        200 OK: List of files with metadata
        403 FORBIDDEN: User is not server owner
        404 NOT FOUND: Invalid auth_token
    """
    user_id = extract_user_id(auth_token=query.auth_token)

    # Check if user is server owner
    if not api_initializer.user_manager.is_server_owner(user_id=user_id):
        raise exceptions.HTTPException(
            status_code=403,
            detail="Access forbidden. Only the server owner can access CDN management."
        )

    try:
        import os
        from pathlib import Path

        sub_dir = Path(api_initializer.config.CDN_STORAGE_PATH) / query.subdirectory
        if not sub_dir.exists():
            return {
                "status_code": 200,
                "files": []
            }

        files_info = []
        for file_path in sub_dir.glob("*"):
            if file_path.is_file():
                stat = file_path.stat()
                files_info.append({
                    "filename": file_path.name,
                    "size": stat.st_size,
                    "modified": stat.st_mtime,
                    "url": f"{api_initializer.config.CDN_BASE_URL}/{query.subdirectory}/{file_path.name}"
                })

        return {
            "status_code": 200,
            "subdirectory": query.subdirectory,
            "files": files_info
        }

    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500,
            detail=f"Failed to list CDN files: {str(e)}"
        )

@api.get("/api/v1/cdn/file-info", status_code=200)
async def get_cdn_file_info_route(query: CDNDeleteFileQuery = Depends()):
    """
    Get information about a specific CDN file. Server Owner only.

    Args:
        query (CDNDeleteFileQuery): Query parameters containing auth_token and file_url.

    Returns:
        200 OK: File information
        403 FORBIDDEN: User is not server owner
        404 NOT FOUND: File not found or invalid auth_token
    """
    user_id = extract_user_id(auth_token=query.auth_token)

    # Check if user is server owner
    if not api_initializer.user_manager.is_server_owner(user_id=user_id):
        raise exceptions.HTTPException(
            status_code=403,
            detail="Access forbidden. Only the server owner can access CDN management."
        )

    file_info = api_initializer.cdn_manager.get_file_info(query.file_url)
    if file_info is None:
        raise exceptions.HTTPException(
            status_code=404,
            detail="File not found"
        )

    return {
        "status_code": 200,
        "file_info": {
            "url": query.file_url,
            "size": file_info.get("size"),
            "mime_type": file_info.get("mime_type"),
            "created": file_info.get("created"),
            "modified": file_info.get("modified")
        }
    }

@api.delete("/api/v1/cdn/delete-file", status_code=200)
async def delete_cdn_file_route(query: CDNDeleteFileQuery = Depends()):
    """
    Delete a file from the CDN. Server Owner only.

    Args:
        query (CDNDeleteFileQuery): Query parameters containing auth_token and file_url.

    Returns:
        200 OK: File deleted successfully
        403 FORBIDDEN: User is not server owner
        404 NOT FOUND: File not found or invalid auth_token
        500 INTERNAL SERVER ERROR: Deletion failed
    """
    user_id = extract_user_id(auth_token=query.auth_token)

    # Check if user is server owner
    if not api_initializer.user_manager.is_server_owner(user_id=user_id):
        raise exceptions.HTTPException(
            status_code=403,
            detail="Access forbidden. Only the server owner can access CDN management."
        )

    try:
        deleted = api_initializer.cdn_manager.delete_file(query.file_url)
        if not deleted:
            raise exceptions.HTTPException(
                status_code=404,
                detail="File not found"
            )

        return {
            "status_code": 200,
            "message": "File deleted successfully",
            "file_url": query.file_url
        }

    except exceptions.HTTPException:
        raise
    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500,
            detail=f"Failed to delete file: {str(e)}"
        )

@api.post("/api/v1/cdn/cleanup-orphaned", status_code=200)
async def cleanup_orphaned_cdn_files_route(query: CDNFilesQuery = Depends()):
    """
    Remove CDN files that are no longer referenced in the database. Server Owner only.

    Args:
        query (CDNFilesQuery): Query parameters containing auth_token and subdirectory.

    Returns:
        200 OK: Cleanup completed
        403 FORBIDDEN: User is not server owner
        404 NOT FOUND: Invalid auth_token
        500 INTERNAL SERVER ERROR: Cleanup failed
    """
    user_id = extract_user_id(auth_token=query.auth_token)

    # Check if user is server owner
    if not api_initializer.user_manager.is_server_owner(user_id=user_id):
        raise exceptions.HTTPException(
            status_code=403,
            detail="Access forbidden. Only the server owner can access CDN management."
        )

    try:
        # Get list of referenced files from database
        # This is a simplified implementation - in practice you'd need to collect
        # all URLs from avatars, banners, and other file references in the database
        db_files = []  # TODO: Implement logic to collect all file URLs from database

        api_initializer.cdn_manager.cleanup_orphaned_files(db_files, query.subdirectory)

        return {
            "status_code": 200,
            "message": f"Orphaned files cleanup completed for subdirectory: {query.subdirectory}"
        }

    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500,
            detail=f"Failed to cleanup orphaned files: {str(e)}"
        )

# Blocked IPs Management Routes (Server Owner Only)
@api.get("/api/v1/blocked-ips/list", status_code=200)
async def list_blocked_ips_route(query: AuthTokenQuery = Depends()):
    """
    List all blocked IPs with details. Server Owner only.

    Args:
        query (AuthTokenQuery): Query parameters containing auth_token.

    Returns:
        200 OK: List of blocked IPs
        403 FORBIDDEN: User is not server owner
        404 NOT FOUND: Invalid auth_token
    """
    user_id = extract_user_id(auth_token=query.auth_token)

    # Check if user is server owner
    if not api_initializer.user_manager.is_server_owner(user_id=user_id):
        raise exceptions.HTTPException(
            status_code=403,
            detail="Access forbidden. Only the server owner can access blocked IP management."
        )

    try:
        blocked_ips = api_initializer.database_handler.fetch_blocked_ips()

        # Format the response with full IP details
        formatted_ips = []
        for ip in blocked_ips:
            # Note: In SQLite tests, blocked_ips table is excluded, so this will return an empty list
            # In production, we'd need to get full details from database
            formatted_ips.append({
                "ip": ip,
                "reason": "Blocked due to excessive rate limit warnings",
                "blocked_at": "Recent"
            })

        return {
            "status_code": 200,
            "blocked_ips": formatted_ips
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

@api.delete("/api/v1/blocked-ips/unblock/{ip}", status_code=200)
async def unblock_ip_route(ip: str, query: AuthTokenQuery = Depends()):
    """
    Remove an IP address from the blocked list. Server Owner only.

    Args:
        ip (str): The IP address to unblock (path parameter)
        query (AuthTokenQuery): Query parameters containing auth_token.

    Returns:
        200 OK: IP unblocked successfully
        400 BAD REQUEST: IP not blocked
        403 FORBIDDEN: User is not server owner
        404 NOT FOUND: Invalid auth_token
    """
    user_id = extract_user_id(auth_token=query.auth_token)

    # Check if user is server owner
    if not api_initializer.user_manager.is_server_owner(user_id=user_id):
        raise exceptions.HTTPException(
            status_code=403,
            detail="Access forbidden. Only the server owner can manage blocked IPs."
        )

    try:
        # Check if IP is blocked
        if not api_initializer.database_handler.check_is_ip_blocked(ip=ip):
            raise exceptions.HTTPException(
                status_code=400,
                detail="IP address is not currently blocked"
            )

        # Remove from database
        deleted = api_initializer.database_handler.delete_blocked_ip(ip=ip)
        if not deleted:
            raise exceptions.HTTPException(
                status_code=400,
                detail="Failed to unblock IP address"
            )

        return {
            "status_code": 200,
            "message": f"IP {ip} has been unblocked"
        }

    except exceptions.HTTPException:
        raise
    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500,
            detail=f"Failed to unblock IP: {str(e)}"
        )

# Background Tasks Management Routes (Server Owner Only)
@api.get("/api/v1/background-tasks/status", status_code=200)
async def get_background_tasks_status_route(query: AuthTokenQuery = Depends()):
    """
    Get status of all background tasks. Server Owner only.

    Args:
        query (AuthTokenQuery): Query parameters containing auth_token.

    Returns:
        200 OK: Background tasks status
        403 FORBIDDEN: User is not server owner
        404 NOT FOUND: Invalid auth_token
    """
    user_id = extract_user_id(auth_token=query.auth_token)

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

@api.post("/api/v1/background-tasks/run/{task_id}", status_code=200)
async def run_background_task_route(task_id: str, query: AuthTokenQuery = Depends()):
    """
    Execute a background task on-demand. Server Owner only.

    Args:
        task_id (str): The task ID to run
        query (AuthTokenQuery): Query parameters containing auth_token.

    Returns:
        200 OK: Task executed successfully
        400 BAD REQUEST: Task not found or failed
        403 FORBIDDEN: User is not server owner
        404 NOT FOUND: Invalid auth_token
    """
    user_id = extract_user_id(auth_token=query.auth_token)

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

        success = await api_initializer.background_tasks_manager.run_task(task_id)
        if success:
            return {
                "status_code": 200,
                "message": f"Background task '{task_id}' executed successfully"
            }
        else:
            raise exceptions.HTTPException(
                status_code=400,
                detail=f"Background task '{task_id}' failed to execute"
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

# Query parameter models for chart endpoints
class ChartQuery(BaseModel):
    period: str | None = Field(default=None, description="Time period (daily, weekly, monthly, 24h, 7d)")

@api.get("/api/v1/system/charts/user-registrations", status_code=200)
async def get_user_registration_chart_route(query: ChartQuery = Depends()):
    """
    Get user registration chart data.

    Args:
        query (ChartQuery): Query parameters containing optional period.

    Returns:
        200 OK: Chart data for user registrations
        500 INTERNAL SERVER ERROR: Failed to fetch chart data
    """
    try:
        if hasattr(api_initializer, 'background_tasks_manager'):
            chart_data = api_initializer.background_tasks_manager.get_chart_data('user_registrations', query.period)
            return {
                "status_code": 200,
                "chart_data": chart_data
            }
        else:
            return {
                "status_code": 200,
                "message": "Background tasks manager not initialized",
                "chart_data": {}
            }

    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500,
            detail=f"Failed to get user registration chart data: {str(e)}"
        )

@api.get("/api/v1/system/charts/message-activity", status_code=200)
async def get_message_activity_chart_route(query: ChartQuery = Depends()):
    """
    Get message activity chart data.

    Args:
        query (ChartQuery): Query parameters containing optional period.

    Returns:
        200 OK: Chart data for message activity
        500 INTERNAL SERVER ERROR: Failed to fetch chart data
    """
    try:
        if hasattr(api_initializer, 'background_tasks_manager'):
            chart_data = api_initializer.background_tasks_manager.get_chart_data('message_activity', query.period)
            return {
                "status_code": 200,
                "chart_data": chart_data
            }
        else:
            return {
                "status_code": 200,
                "message": "Background tasks manager not initialized",
                "chart_data": {}
            }

    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500,
            detail=f"Failed to get message activity chart data: {str(e)}"
        )

@api.get("/api/v1/system/charts/online-users", status_code=200)
async def get_online_users_chart_route(query: ChartQuery = Depends()):
    """
    Get online users chart data.

    Args:
        query (ChartQuery): Query parameters containing optional period.

    Returns:
        200 OK: Chart data for online users
        500 INTERNAL SERVER ERROR: Failed to fetch chart data
    """
    try:
        if hasattr(api_initializer, 'background_tasks_manager'):
            chart_data = api_initializer.background_tasks_manager.get_chart_data('online_users', query.period)
            return {
                "status_code": 200,
                "chart_data": chart_data
            }
        else:
            return {
                "status_code": 200,
                "message": "Background tasks manager not initialized",
                "chart_data": {}
            }

    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500,
            detail=f"Failed to get online users chart data: {str(e)}"
        )

@api.get("/api/v1/system/charts/channel-creation", status_code=200)
async def get_channel_creation_chart_route(query: ChartQuery = Depends()):
    """
    Get channel creation chart data.

    Args:
        query (ChartQuery): Query parameters containing optional period.

    Returns:
        200 OK: Chart data for channel creation
        500 INTERNAL SERVER ERROR: Failed to fetch chart data
    """
    try:
        if hasattr(api_initializer, 'background_tasks_manager'):
            chart_data = api_initializer.background_tasks_manager.get_chart_data('channel_creation', query.period)
            return {
                "status_code": 200,
                "chart_data": chart_data
            }
        else:
            return {
                "status_code": 200,
                "message": "Background tasks manager not initialized",
                "chart_data": {}
            }

    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500,
            detail=f"Failed to get channel creation chart data: {str(e)}"
        )

@api.get("/api/v1/system/charts/user-status", status_code=200)
async def get_user_status_chart_route():
    """
    Get user status distribution chart data.

    Returns:
        200 OK: Chart data for user status distribution
        500 INTERNAL SERVER ERROR: Failed to fetch chart data
    """
    try:
        if hasattr(api_initializer, 'background_tasks_manager'):
            chart_data = api_initializer.background_tasks_manager.get_chart_data('user_status', None)
            return {
                "status_code": 200,
                "chart_data": chart_data
            }
        else:
            return {
                "status_code": 200,
                "message": "Background tasks manager not initialized",
                "chart_data": {}
            }

    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500,
            detail=f"Failed to get user status chart data: {str(e)}"
        )

# Websockets used for real-time messaging server's channels
@api.websocket("/ws/channels/{channel_id}")
async def channels_messages_websocket(websocket: WebSocket, auth_token: str, channel_id: str):
    """
    WebSocket endpoint handles the exchange of messages within channels.
    It establishes a WebSocket connection for managing message retrieval
    within the specified `channel_id` channel. If the `channel_id` channel is
    private and the user does not have permission to access it, an HTTP exception
    will be raised. However, if the user has the necessary privileges,
    they will be able to view and interact with messages within
    the `channel_id` channel.

    Args:
        websocket (Websocket): WebSocket connection object.
        auth_token (str): The user's `auth_token`.
        channel_id (str): The channel's `channel_id`.
    
    Returns:
        1001 Going Away: This status code may be raised if:
            - The `auth_token` format is not valid.
            - The `auth_token` doesn't exist or is suspended.
            - The `channel_id` doesn't exist.
            - The `channel_id` is private, and the user doesn't have privileges to view it.
    """
    api_initializer.websockets_manager.connect(
        websocket=websocket,
        auth_token=auth_token,
        channel_id=channel_id
    )

    # Check `auth_token` format and validity
    if not api_initializer.auth_token_manager.check_auth_token_format(auth_token=auth_token):
        raise exceptions.WebSocketException(
            reason="Bad auth_token format. Please check your auth_token and try again.",
            code=1001
        )

    user_id = extract_user_id(auth_token=auth_token)

    # Check if the user exists or not
    if not api_initializer.user_manager.check_user(
        user_id=user_id,
        auth_token=auth_token
    ):
        raise exceptions.WebSocketException(
            code=1001,
            reason="'auth_token' expired/unvalid or 'user_id' doesn't exists. Please try again."
        )
    
    # Check if the user who requested this route is an admin
    if not api_initializer.user_manager.is_admin(
        user_id=user_id
    ) and not api_initializer.user_manager.is_server_owner(
        user_id=user_id
    ):
        raise exceptions.WebSocketException(
            code=1001,
            reason="The provided channel ID does not exist or could not be found. Please make sure you have entered a valid channel ID and try again."
        )

    # Check if the channel exists
    if not api_initializer.channels_manager.check_channel(
        channel_id=channel_id
    ):
        logger.info(
            info.INFO_CHANNEL_ID_NOT_FOUND(
                viewer_user_id=user_id,
                channel_id=channel_id
            )
        )

        raise exceptions.WebSocketException(
            code=1001,
            reason="The provided channel ID does not exist or could not be found. Please make sure you have entered a valid channel ID and try again."
        )
    
    sent_messages_ids = []
    unconfirmed_messages = {}  # Track messages sent but not confirmed as read

    DELAY = 3 # in seconds

    try:
        while True:
            # Handle incoming read confirmations from client
            try:
                incoming_data = await asyncio.wait_for(websocket.receive_text(), timeout=0.1)
                message_data = json.loads(incoming_data) if incoming_data else {}

                # Handle read confirmation message
                if message_data.get("type") == "read_confirmation":
                    message_id = message_data.get("message_id")
                    if message_id and message_id in unconfirmed_messages:
                        try:
                            # Mark message as read using the HTTP endpoint logic
                            api_initializer.messages_manager.mark_message_as_read(
                                user_id=user_id,
                                message_id=message_id,
                                channel_id=channel_id
                            )
                            del unconfirmed_messages[message_id]  # Remove from unconfirmed
                        except Exception as e:
                            # Log error but don't crash the websocket
                            logger.warning(f"Failed to mark message as read: {message_id} - {str(e)}")

            except asyncio.TimeoutError:
                pass  # No incoming message, continue polling

            # Send new messages
            viewed_messages_ids = api_initializer.database_handler.get_user_read_messages_ids(user_id)
            latest_messages = api_initializer.messages_manager.load_messages(
                websocket=True,
                channel_id=channel_id,
                viewed_messages_ids=viewed_messages_ids
            )

            if len(latest_messages) == 0:
                await asyncio.sleep(DELAY)
                continue

            for message in latest_messages:
                message_id = message.get("message_id") if isinstance(message, dict) else None
                if message_id:
                    # Skip already sent messages
                    if message_id in sent_messages_ids:
                        continue

                    # Send message to client
                    try:
                        if isinstance(message, dict):
                            await websocket.send_json(message)
                        else:
                            await websocket.send_text(str(message))

                        sent_messages_ids.append(message_id)
                        unconfirmed_messages[message_id] = True  # Track as unconfirmed
                    except Exception as e:
                        logger.warning(f"Failed to send message to websocket: {str(e)}")

            await asyncio.sleep(DELAY)
    except WebSocketDisconnect:
        await api_initializer.websockets_manager.disconnect(websocket)


# Mount CDN static file serving
if api_initializer.is_loaded:
    api.mount(api_initializer.config.CDN_BASE_URL, StaticFiles(directory=api_initializer.config.CDN_STORAGE_PATH), name="cdn")
