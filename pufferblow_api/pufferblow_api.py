import sys
import json
import asyncio

from fastapi import (
    FastAPI,
    WebSocket,
    WebSocketDisconnect,
    responses,
    exceptions
)
from loguru import logger

from pufferblow_api import constants
from pufferblow_api.api_initializer import api_initializer

# Utils
from pufferblow_api.src.utils.extract_user_id import extract_user_id
from pufferblow_api.src.utils.is_able_to_update import is_able_to_update

# Models
from pufferblow_api.src.models.message_model import Message

# Base
from pufferblow_api.src.database.tables.declarative_base import Base

# Init PufferBlow's API
api = FastAPI()

@api.on_event("startup")
async def pufferblow_api_startup():
    """ PufferBlow's API startup handler """
    # Load all the needed objects
    api_initializer.load_objects()

    # Setup the tables (will get skipped if they already exists)
    api_initializer.database_handler.setup_tables(Base)

@api.get("/")
async def redirect_route():
    return responses.RedirectResponse("/api/v1")

@api.get("/api/v1", status_code=200)
async def home_route():
    """ Main route """
    return {
        "status_code": 200,
        "message": "Welcome to PufferBlow's api",
        "github": constants.ORG_GITHUB
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
    username: str,
    password: str
):
    """
    Signup a new user.

    Args:
        `username` (str): The user's `username` (should be unique for each user)
        `password` (str): The user's `password`.
    
    Return:
        201 OK: If the `username` is available, and the user got signed up.
        409 CONFLICT: If the `username` is not available.
    """
    # Check if the `username` already exists
    if api_initializer.user_manager.check_username(username):
        raise exceptions.HTTPException(
            detail="username already exists. Please change it and try again later",
            status_code=409
        )

    user_data = api_initializer.user_manager.sign_up(
        username=username,
        password=password
    )

    logger.info(
        constants.NEW_USER_SIGNUP_SUCCESSFULLY(
            user=user_data,
        )
    )

    return {
        "status_code": 201,
        "message": "Account created successfully",
        "auth_token": user_data.raw_auth_token,
        "auth_token_expire_time": user_data.auth_token_expire_time
    }

@api.get("/api/v1/users/profile", status_code=200)
async def users_profile_route(
    user_id: str,
    auth_token: str,
):
    """
    Users profile management route

    Args:
        `user_id` (str): The `user_id` of the target user
        `auth_token` (str): The `auth_token` of the user who requested this user's profile

    Returns:
        200 OK: If the `user_id` of the targeted user exists and the `auth_token` is valid.
        400 BAD REQUEST: If the `auth_token` is improperly formatted.
        404 NOT FOUND: The `auth_token` is unvalid, or the `user_id` of the targeted user doesn't exists.
    """
    # Check `auth_token` format and validity
    if not api_initializer.auth_token_manager.check_auth_token_format(auth_token=auth_token):
        raise exceptions.HTTPException(
            detail="Bad auth_token format. Please check your auth_token and try again.",
            status_code=400
        )

    viewer_user_id = extract_user_id(auth_token=auth_token)

    # Check the viewer `user_id`
    if not api_initializer.user_manager.check_user(
        user_id=viewer_user_id,
        auth_token=auth_token
    ):
        raise exceptions.HTTPException(
            status_code=404,
            detail="'auth_token' expired/unvalid or 'user_id' doesn't exists. Please try again."
        )

    # Check if the targeted user exists or not
    if not api_initializer.user_manager.check_user(
        user_id=user_id
    ):
        raise exceptions.HTTPException(
            status_code=404,
            detail=f"The target user's user_id='{user_id}' not found. Please make sure to pass the correct one"
        )

    # Check if viewer user owns the targeted account
    is_account_owner = api_initializer.auth_token_manager.check_users_auth_token(
        user_id=user_id,
        raw_auth_token=auth_token
    )

    user_data = api_initializer.user_manager.user_profile(
        user_id=user_id,
        is_account_owner=is_account_owner
    )

    return {
        "status_code": 200,
        "user_data": user_data
    }

@api.put("/api/v1/users/profile", status_code=200)
async def edit_users_profile_route(
    auth_token: str,
    new_username: str = None,
    status: str = None,
    new_password: str = None,
    old_password: str = None
):
    """
    Update a user's profile metadata such us status,
    last_seen, username and password

    Args:
        `auth_token` (str): The user's `auth_token`
        `new_username` (str, optional): The new `username` for the user
        `status` (str, optional): The new status for the user ["ONLINE", "OFFLINE"]
        `new_password` (str, optional): The new `password` for the user
        `old_password` (str, optional): The old `password` of the user.

    Returns:
        200 OK: If all parameters are correct, and the to update data was updated successfully.
        400 BAD REQUEST: If the `auth_token` is improperly formatted.
        401 UNAUTHORIZED: If the `password` is unvalid.
        404 NOT FOUND: The `auth_token` is unvalid, or the `user_id` of the targeted user doesn't exists, or in case the `status` is unvalid.
        409 CONFLICT: If the `username` is not available.
    """
    # Check `auth_token` format and validity
    if not api_initializer.auth_token_manager.check_auth_token_format(auth_token=auth_token):
        raise exceptions.HTTPException(
            detail=f"Bad auth_token format. Please check your auth_token and try again.",
            status_code=400
        )

    user_id = extract_user_id(auth_token=auth_token)

    # Check if the user exists or not
    if not api_initializer.user_manager.check_user(
        user_id=user_id,
        auth_token=auth_token
    ):
        raise exceptions.HTTPException(
            status_code=404,
            detail=f"'auth_token' expired/unvalid or 'user_id' doesn't exists. Please try again."
        )

    # Update username
    if new_username is not None:
        if api_initializer.user_manager.check_username(
            username=new_username
        ):
            raise exceptions.HTTPException(
                detail=f"username already exists. Please change it and try again later",
                status_code=409
            )

        api_initializer.user_manager.update_username(
            user_id=user_id,
            new_username=new_username
        )

        return {
            "status_code": 200,
            "message": "username updated successfully"
        }

    # Update the user's status
    if status is not None:
        # Check the status value
        if status not in ["online", "offline"]:
            logger.info(
                constants.USER_STATUS_UPDATE_FAILED(
                    user_id=user_id,
                    status=status
                )
            )

            raise exceptions.HTTPException(
                detail=f"status value status='{status}' not found. Accepted values ['online', 'offline']",
                status_code=404
            )

        api_initializer.user_manager.update_user_status(
            user_id=user_id,
            status=status
        )

        return {
            "status_code": 200,
            "message": "Status updated successfully"
        }

    # Udate the user's password
    if new_password is not None and old_password is not None:
        if not api_initializer.user_manager.check_user_password(
            user_id=user_id,
            password=old_password
        ):
            logger.info(
                constants.UPDATE_USER_PASSWORD_FAILED(
                    user_id=user_id
                )
            )

            raise exceptions.HTTPException(
                detail=f"Invalid password. Please try again later.",
                status_code=401
            )

        api_initializer.user_manager.update_user_password(
            user_id=user_id,
            new_password=new_password
        )

        return {
            "status_code": 200,
            "message": "Password updated successfully"
        }

@api.put("/api/v1/users/profile/reset-auth-token", status_code=200)
async def reset_users_auth_token_route(
    auth_token: str,
    password: str
):
    """
    Reset the user's `auth_token`.

    Args:
        `user_id` (str): The users's `user_id`.
        `password` (str): The user's `password`.
    
    Returns:
        200 OK: If all parameters are correct, and the user is able to reset their `auth_token`.
        400 BAD REQUEST: If the `auth_token` is improperly formatted.
        401 UNAUTHORIZED: If the `password` is unvalid.
        403 CAN'T AUTHORIZE IT: If the user is not authorized to reset their `auth_token` because of the suspension time.
        404 NOT FOUND: The `auth_token` is unvalid, or the `user_id` of the targeted user doesn't exists, or in case the `status` is unvalid.
    """
    # Check `auth_token` format and validity
    if not api_initializer.auth_token_manager.check_auth_token_format(auth_token=auth_token):
        raise exceptions.HTTPException(
            detail=f"Bad auth_token format. Please check your auth_token and try again.",
            status_code=400
        )

    user_id = extract_user_id(auth_token=auth_token)

    # Check if the user exists or not
    if not api_initializer.user_manager.check_user(
        user_id=user_id,
        auth_token=auth_token
    ):
        raise exceptions.HTTPException(
            status_code=404,
            detail=f"'auth_token' expired/unvalid or 'user_id' doesn't exists. Please try again."
        )

    if not api_initializer.user_manager.check_user_password(
        user_id=user_id,
        password=password
    ):
        logger.info(
            constants.RESET_USER_AUTH_TOKEN_FAILD(
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
                constants.AUTH_TOKEN_SUSPENSION_TIME(
                    user_id=user_id
                )
            )

            raise exceptions.HTTPException(
                detail="Cannot reset authentication token. Suspension time has not elapsed.",
                status_code=403
            )

    new_auth_token = f"{user_id}.{api_initializer.auth_token_manager.create_token()}"

    # Hashing the new auth_token and updating the existing salt value
    # with the new one
    salt = api_initializer.hasher.encrypt_with_bcrypt(
        user_id=user_id,
        data=new_auth_token
    )

    hashed_auth_token = salt.hashed_data
    new_auth_token_expire_time = api_initializer.auth_token_manager.create_auth_token_expire_time()

    api_initializer.database_handler.update_salt(
        user_id=user_id,
        associated_to="auth_token",
        new_salt_value=salt.salt_value,
        new_hashed_data=hashed_auth_token
    )

    api_initializer.database_handler.update_auth_token(
        user_id=user_id,
        new_auth_token=hashed_auth_token,
        new_auth_token_expire_time=new_auth_token_expire_time
    )

    return {
        "status_code": 200,
        "message": "auth_token rested successfully",
        "auth_token": new_auth_token,
        "auth_token_expire_time": new_auth_token_expire_time
    }

@api.get("/api/v1/users/list", status_code=200)
async def list_users_route(
    auth_token: str
):
    """
    Returns a list of all the users present in the server

    Args:
        `auth_token` (str): The user's `auth_token`.
    
    Returns:
        200 OK: If the `auth_token` is valid, then a list of users metadata is returned to the user.
        400 BAD REQUEST: If the `auth_token` is improperly formatted.
        404 NOT FOUND: The `auth_token` is unvalid, or the `user_id` of the targeted user doesn't exists, or in case the `status` is unvalid.
    """
    # Check `auth_token` format and validity
    if not api_initializer.auth_token_manager.check_auth_token_format(auth_token=auth_token):
        raise exceptions.HTTPException(
            detail=f"Bad auth_token format. Please check your auth_token and try again.",
            status_code=400
        )

    viewer_user_id = extract_user_id(auth_token=auth_token)

    # Check the viewer `user_id`
    if not api_initializer.user_manager.check_user(
        user_id=viewer_user_id,
        auth_token=auth_token
    ):
        raise exceptions.HTTPException(
            status_code=404,
            detail=f"'auth_token' expired/unvalid or 'user_id' doesn't exists. Please try again."
        )

    hashed_auth_token = api_initializer.auth_token_manager._encrypt_auth_token(
        user_id=viewer_user_id,
        auth_token=auth_token
    )

    users = api_initializer.user_manager.list_users(
        viewer_user_id=viewer_user_id,
        auth_token=auth_token
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

@api.get("/api/v1/channels/list", status_code=200)
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
    # Check `auth_token` format and validity
    if not api_initializer.auth_token_manager.check_auth_token_format(auth_token=auth_token):
        raise exceptions.HTTPException(
            detail=f"Bad auth_token format. Please check your auth_token and try again.",
            status_code=400
        )

    user_id = extract_user_id(auth_token=auth_token)

    # Check if the user exists or not
    if not api_initializer.user_manager.check_user(
        user_id=user_id,
        auth_token=auth_token
    ):
        raise exceptions.HTTPException(
            status_code=404,
            detail=f"'auth_token' expired/unvalid or 'user_id' doesn't exists. Please try again."
        )

    channels_list = api_initializer.channels_manager.list_channels(
        user_id=user_id
    )

    return {
        "status_code": 200,
        "channels": channels_list
    }

@api.post("/api/v1/channels/create", status_code=200)
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
    # Check `auth_token` format and validity
    if not api_initializer.auth_token_manager.check_auth_token_format(auth_token=auth_token):
        raise exceptions.HTTPException(
            detail=f"Bad auth_token format. Please check your auth_token and try again.",
            status_code=400
        )

    user_id = extract_user_id(auth_token=auth_token)

    # Check if the user exists or not
    if not api_initializer.user_manager.check_user(
        user_id=user_id,
        auth_token=auth_token
    ):
        raise exceptions.HTTPException(
            status_code=404,
            detail=f"'auth_token' expired/unvalid or 'user_id' doesn't exists. Please try again."
        )

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
        "channel_data": channel_data.to_json()
    }

@api.delete("/api/v1/channels/delete")
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
    # Check `auth_token` format and validity
    if not api_initializer.auth_token_manager.check_auth_token_format(auth_token=auth_token):
        raise exceptions.HTTPException(
            detail=f"Bad auth_token format. Please check your auth_token and try again.",
            status_code=400
        )

    user_id = extract_user_id(auth_token=auth_token)

    # Check if the user exists or not
    if not api_initializer.user_manager.check_user(
        user_id=user_id,
        auth_token=auth_token
    ):
        raise exceptions.HTTPException(
            status_code=404,
            detail=f"'auth_token' expired/unvalid or 'user_id' doesn't exists. Please try again."
        )

    # Check if the user is the server admin
    if not api_initializer.user_manager.is_admin(
        user_id=user_id
    ):
        raise exceptions.HTTPException(
            status_code=403,
            detail="Access forbidden. Only admins can create channels and manage them."
        )

    # Check if the channel exists
    if not api_initializer.channels_manager.check_channel(
        channel_id=channel_id
    ):
        logger.info(
            constants.CHANNEL_ID_NOT_FOUND(
                viewer_user_id=user_id,
                channel_id=channel_id
            )
        )

        raise exceptions.HTTPException(
            status_code=404,
            detail="The provided channel ID does not exist or could not be found. Please make sure you have entered a valid channel ID and try again."
        )

    api_initializer.channels_manager.delete_channel(
        channel_id=channel_id
    )

    logger.info(
        constants.CHANNEL_DELETED(
            user_id=user_id,
            channel_id=channel_id
        )
    )

    return {
        "status_code": 200,
        "message": f"Channel: '{channel_id}' deleted successfully"
    }

@api.put("/api/v1/channels/addUser", status_code=200)
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
    # Check `auth_token` format and validity
    if not api_initializer.auth_token_manager.check_auth_token_format(auth_token=auth_token):
        raise exceptions.HTTPException(
            detail=f"Bad auth_token format. Please check your auth_token and try again.",
            status_code=400
        )

    user_id = extract_user_id(auth_token=auth_token)

    # Check if the user exists or not
    if not api_initializer.user_manager.check_user(
        user_id=user_id,
        auth_token=auth_token
    ):
        raise exceptions.HTTPException(
            status_code=404,
            detail=f"'auth_token' expired/unvalid or 'user_id' doesn't exists. Please try again."
        )

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

    # Check if the channel exists
    if not api_initializer.channels_manager.check_channel(
        channel_id=channel_id
    ):
        logger.info(
            constants.CHANNEL_ID_NOT_FOUND(
                viewer_user_id=user_id,
                channel_id=channel_id
            )
        )

        raise exceptions.HTTPException(
            status_code=404,
            detail="The provided channel ID does not exist or could not be found. Please make sure you have entered a valid channel ID and try again."
        )

    # Check if the channel is private
    if not api_initializer.channels_manager.is_private(
        channel_id=channel_id
    ):

        logger.info(
            constants.CHANNEL_IS_NOT_PRIVATE(
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

@api.delete("/api/v1/channels/removeUser", status_code=200)
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
    # Check `auth_token` format and validity
    if not api_initializer.auth_token_manager.check_auth_token_format(auth_token=auth_token):
        raise exceptions.HTTPException(
            detail=f"Bad auth_token format. Please check your auth_token and try again.",
            status_code=400
        )

    user_id = extract_user_id(auth_token=auth_token)

    # Check if the user exists or not
    if not api_initializer.user_manager.check_user(
        user_id=user_id,
        auth_token=auth_token
    ):
        raise exceptions.HTTPException(
            status_code=404,
            detail=f"'auth_token' expired/unvalid or 'user_id' doesn't exists. Please try again."
        )

    # Check if the targeted user exists or not
    if not api_initializer.user_manager.check_user(
        user_id=to_remove_user_id
    ):
        raise exceptions.HTTPException(
            detail=f"To remove User ID: '{to_remove_user_id}' is unvalid/not found. Please enter a valid 'user_id' and try again.",
            status_code=404
        )

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
            detail=f"Error removing Admin User ID: '{to_remove_user_id}'. Only the server owner can remove admins from channels",
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

    # Check if the channel exists
    if not api_initializer.channels_manager.check_channel(
        channel_id=channel_id
    ):
        logger.info(
            constants.CHANNEL_ID_NOT_FOUND(
                viewer_user_id=user_id,
                channel_id=channel_id
            )
        )

        raise exceptions.HTTPException(
            status_code=404,
            detail="The provided channel ID does not exist or could not be found. Please make sure you have entered a valid channel ID and try again."
        )

    # Check if the channel is private
    if not api_initializer.channels_manager.is_private(
        channel_id=channel_id
    ):

        logger.info(
            constants.CHANNEL_IS_NOT_PRIVATE(
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

@api.get("/api/v1/channel/{channel_id}/load_messages", status_code=200)
async def channel_load_messages(auth_token: str, channel_id: str, page: int | None = 1, messages_per_page: int | None = 20):
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
    if messages_per_page > 50:
        # TODO: Add a parameter in the config to manage the allowed maximal value for `messages_per_page` 
        raise exceptions.HTTPException(
            detail="`messages_per_page` number exceeded the maximal number which is `50`",
            status_code=400
        )
    
    # Check `auth_token` format and validity
    if not api_initializer.auth_token_manager.check_auth_token_format(auth_token=auth_token):
        raise exceptions.HTTPException(
            detail=f"Bad auth_token format. Please check your auth_token and try again.",
            status_code=400
        )

    user_id = extract_user_id(auth_token=auth_token)

    # Check if the user exists or not
    if not api_initializer.user_manager.check_user(
        user_id=user_id,
        auth_token=auth_token
    ):
        raise exceptions.HTTPException(
            status_code=404,
            detail=f"'auth_token' expired/unvalid or 'user_id' doesn't exists. Please try again."
        )
    
    # Check if the channel exists
    if not api_initializer.channels_manager.check_channel(
        channel_id=channel_id
    ):
        logger.info(
            constants.CHANNEL_ID_NOT_FOUND(
                viewer_user_id=user_id,
                channel_id=channel_id
            )
        )

        raise exceptions.HTTPException(
            status_code=404,
            detail="The provided channel ID does not exist or could not be found. Please make sure you have entered a valid channel ID and try again."
        )
    
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
        "data": messages
    }

@api.post("/api/v1/channel/{channel_id}/send_message")
async def channel_send_message(auth_token: str, channel_id: str, message: str):
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
    # TODO: Add a config parameter that controlles the maximal size
    # of a message
    MAX_MESSAGE_SIZE = 1014 # 1Mb
    if sys.getsizeof(message) > MAX_MESSAGE_SIZE:
        raise exceptions.HTTPException(
            detail="the message is too long",
            status_code=400
        )

    # Check `auth_token` format and validity
    if not api_initializer.auth_token_manager.check_auth_token_format(auth_token=auth_token):
        raise exceptions.HTTPException(
            detail=f"Bad auth_token format. Please check your auth_token and try again.",
            status_code=400
        )

    user_id = extract_user_id(auth_token=auth_token)

    # Check if the user exists or not
    if not api_initializer.user_manager.check_user(
        user_id=user_id,
        auth_token=auth_token
    ):
        raise exceptions.HTTPException(
            status_code=404,
            detail=f"'auth_token' expired/unvalid or 'user_id' doesn't exists. Please try again."
        )
    
    # Check if the channel exists
    if not api_initializer.channels_manager.check_channel(
        channel_id=channel_id
    ):
        logger.info(
            constants.CHANNEL_ID_NOT_FOUND(
                viewer_user_id=user_id,
                channel_id=channel_id
            )
        )

        raise exceptions.HTTPException(
            status_code=404,
            detail="The provided channel ID does not exist or could not be found. Please make sure you have entered a valid channel ID and try again."
        )
    
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
    
    api_initializer.messages_manager.send_message(
        channel_id=channel_id,
        user_id=user_id,
        message=message
    )

    return {
        "status_code": 201,
        "message": "message sent succesfully"
    }

@api.put("/api/v1/channel/{channel_id}/mark_message_as_read")
def channel_mark_message_as_read(auth_token: str, channel_id: str, message_id: str):
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
        # Check `auth_token` format and validity
    if not api_initializer.auth_token_manager.check_auth_token_format(auth_token=auth_token):
        raise exceptions.HTTPException(
            detail=f"Bad auth_token format. Please check your auth_token and try again.",
            status_code=400
        )

    user_id = extract_user_id(auth_token=auth_token)

    # Check if the user exists or not
    if not api_initializer.user_manager.check_user(
        user_id=user_id,
        auth_token=auth_token
    ):
        raise exceptions.HTTPException(
            status_code=404,
            detail=f"'auth_token' expired/unvalid or 'user_id' doesn't exists. Please try again."
        )
    
    # Check if the channel exists
    if not api_initializer.channels_manager.check_channel(
        channel_id=channel_id
    ):
        logger.info(
            constants.CHANNEL_ID_NOT_FOUND(
                viewer_user_id=user_id,
                channel_id=channel_id
            )
        )

        raise exceptions.HTTPException(
            status_code=404,
            detail="The provided channel ID does not exist or could not be found. Please make sure you have entered a valid channel ID and try again."
        )
    
    # Check if the message exists or not
    if not api_initializer.messages_manager.check_message(message_id=message_id):
        raise exceptions.HTTPException(
            detail="The provided `message_id` is not valid or it doesn't exists, please change it and try again.",
            status_code=404
        )

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

@api.delete("/api/v1/channel/{channel_id}/delete_message")
def channel_delete_message(auth_token: str, channel_id: str, message_id: str):
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
    # Check `auth_token` format and validity
    if not api_initializer.auth_token_manager.check_auth_token_format(auth_token=auth_token):
        raise exceptions.HTTPException(
            detail=f"Bad auth_token format. Please check your auth_token and try again.",
            status_code=400
        )

    user_id = extract_user_id(auth_token=auth_token)

    # Check if the user exists or not
    if not api_initializer.user_manager.check_user(
        user_id=user_id,
        auth_token=auth_token
    ):
        raise exceptions.HTTPException(
            status_code=404,
            detail=f"'auth_token' expired/unvalid or 'user_id' doesn't exists. Please try again."
        )
    
    # Check if the channel exists
    if not api_initializer.channels_manager.check_channel(
        channel_id=channel_id
    ):
        logger.info(
            constants.CHANNEL_ID_NOT_FOUND(
                viewer_user_id=user_id,
                channel_id=channel_id
            )
        )

        raise exceptions.HTTPException(
            status_code=404,
            detail="The provided channel ID does not exist or could not be found. Please make sure you have entered a valid channel ID and try again."
        )
    
    # Check if the message exists or not
    if not api_initializer.messages_manager.check_message(message_id=message_id):
        raise exceptions.HTTPException(
            detail="The provided `message_id` is not valid or it doesn't exists, please change it and try again.",
            status_code=404
        )
    
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

# Websockets used for real-time messaging server's channels
@api.websocket("/ws/channel/{channel_id}")
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
    await api_initializer.websockets_manager.connect(
        websocket=websocket,
        auth_token=auth_token,
        channel_id=channel_id
    )

    # Check `auth_token` format and validity
    if not api_initializer.auth_token_manager.check_auth_token_format(auth_token=auth_token):
        raise exceptions.WebSocketException(
            reason=f"Bad auth_token format. Please check your auth_token and try again.",
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
            reason=f"'auth_token' expired/unvalid or 'user_id' doesn't exists. Please try again."
        )
    
    # Check if the user who requested this route is an admin
    if not api_initializer.user_manager.is_admin(
        user_id=user_id
    ) and not api_initializer.user_manager.is_server_owner(
        user_id=user_id
    ):
        raise exceptions.HTTPException(
            code=1001,
            reason="The provided channel ID does not exist or could not be found. Please make sure you have entered a valid channel ID and try again."
        )

    # Check if the channel exists
    if not api_initializer.channels_manager.check_channel(
        channel_id=channel_id
    ):
        logger.info(
            constants.CHANNEL_ID_NOT_FOUND(
                viewer_user_id=user_id,
                channel_id=channel_id
            )
        )

        raise exceptions.WebSocketException(
            code=1001,
            reason="The provided channel ID does not exist or could not be found. Please make sure you have entered a valid channel ID and try again."
        )
    
    sent_messages_ids = []

    DELAY = 3 # in seconds
    
    try:
        while True:
            viewed_messages_ids = api_initializer.database_handler.get_user_read_messages_ids(user_id=user_id)
            latest_messages = api_initializer.messages_manager.load_messages(
                websocket=True,
                channel_id=channel_id,
                viewed_messages_ids=viewed_messages_ids
            )

            if len(latest_messages) == 0:
                continue
            
            for message in latest_messages:
                # Skip sent messages
                if message["message_id"] in sent_messages_ids:
                    continue
                
                await api_initializer.websockets_manager.send_message(
                    websocket=websocket,
                    message=str(message)
                )

                sent_messages_ids.append(message["message_id"])

                await asyncio.sleep(DELAY)
    except WebSocketDisconnect:
        api_initializer.websockets_manager.disconnect(websocket)
