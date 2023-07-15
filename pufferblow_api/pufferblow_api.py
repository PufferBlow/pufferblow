from fastapi import (
    FastAPI,
    responses,
    exceptions
)
from loguru import logger

from pufferblow_api import constants

from pufferblow_api.src.hasher.hasher import Hasher
from pufferblow_api.src.user.user_manager import UserManager
from pufferblow_api.src.auth.auth_token_manager import AuthTokenManager
from pufferblow_api.src.database.database_session import DatabaseSession
from pufferblow_api.src.database.database_handler import DatabaseHandler
from pufferblow_api.src.channels.channels_manager import ChannelsManager
from pufferblow_api.src.models.pufferblow_api_config_model import PufferBlowAPIconfig

from pufferblow_api.src.utils.extract_user_id import extract_user_id
from pufferblow_api.src.utils.is_able_to_update import is_able_to_update

# Init api
api = FastAPI()

# PufferBlow-api's config data class
pufferblow_api_config = PufferBlowAPIconfig()

# Init the hasher (Responsible for encrypting and decrypting data)
hasher = Hasher()

# Init Database Connection
DATABASE_SESSION = DatabaseSession(
    supabase_url            =   pufferblow_api_config.SUPABASE_URL,
    supabase_key            =   pufferblow_api_config.SUPABASE_KEY,
    pufferblow_api_config   =   pufferblow_api_config
)

# Init Database handler
database_handler = DatabaseHandler(
    database_connection_pool    =       DATABASE_SESSION.database_connection_pool(),
    hasher                      =       hasher
)

# Init Auth tokens manager
auth_token_manager = AuthTokenManager(
    database_handler        =       database_handler,
    hasher                  =       hasher
)

# Init user manager
users_manager = UserManager(
    database_handler        =       database_handler,
    auth_token_manager      =       auth_token_manager,
    hasher                  =       hasher
)

# Init channels manager
channels_manager = ChannelsManager(
    database_handler        =       database_handler,
    auth_token_manager      =       auth_token_manager,
    hasher                  =       hasher
)

@api.get("/")
def redirect_route():
    return responses.RedirectResponse("/api/v1")

@api.get("/api/v1", status_code=200)
def home_route():
    """ Main route """
    return {
        "status_code": 200,
        "message": "Welcome to PufferBlow's api",
        "github": constants.ORG_GITHUB
    }

# Users routes
@api.get("/api/v1/users", status_code=200)
def users_route():
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
    """ Signup a new user """
    # Check if the `username` already exists
    if users_manager.check_username(username):
        raise exceptions.HTTPException(
            detail="username already exists. Please change it and try again later",
            status_code=409
        )

    user_data = users_manager.sign_up(
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
    
    Parameters:
        user_id (str): The user_id of the target user
        auth_token (str): The auth_token of the user who requested this user's profile
    
    Returns:
        dict: The User class model to json

    """
    # Check auth_token foramt and validity
    if not auth_token_manager.check_auth_token_format(auth_token=auth_token):
        raise exceptions.HTTPException(
            detail="Bad auth_token format. Please check your auth_token and try again.",
            status_code=400
        )

    viewer_user_id = extract_user_id(auth_token=auth_token)

    # Check the viewer user_id
    if not users_manager.check_user(
        user_id=viewer_user_id,
        auth_token=auth_token
    ):
        raise exceptions.HTTPException(
            status_code=404,
            detail="'auth_token' expired/unvalid or 'user_id' doesn't exists. Please try again."
        )
    
    # Check if the targeted user exists or not
    if not users_manager.check_user(
        user_id=user_id
    ):
        raise exceptions.HTTPException(
            status_code=404,
            detail=f"The target user's user_id='{user_id}' not found. Please make sure to pass the correct one"
        )
    
    hashed_auth_token = auth_token_manager._encrypt_auth_token(
        user_id=viewer_user_id,
        auth_token=auth_token
    )

    user_data = users_manager.user_profile(
        user_id=user_id,
        hashed_auth_token=hashed_auth_token
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
    """ Edits a user's profile data such as: status,
    last_seen, username and password
    
    Parameters:
        auth_token (str): The user's auth_token
        new_username (str, optional): The new username for the user
        status (str, optional): The new status for the user ["ONLINE", "OFFLINE"]
        new_password (str, optional): The new password for the user
        old_password (str, optional): The old password of the user. This is in case the ```password``` was passed 
    
    Returns:
        {
            "status_code": 201,
            "message": (str)
        }
    """
    # Check auth_token foramt and validity
    if not auth_token_manager.check_auth_token_format(auth_token=auth_token):
        raise exceptions.HTTPException(
            detail=f"Bad auth_token format. Please check your auth_token and try again.",
            status_code=400
        )

    user_id = extract_user_id(auth_token=auth_token)

    # Check if the user exists or not
    if not users_manager.check_user(
        user_id=user_id,
        auth_token=auth_token
    ):
        raise exceptions.HTTPException(
            status_code=404,
            detail=f"'auth_token' expired/unvalid or 'user_id' doesn't exists. Please try again."
        )

    # Update username
    if new_username is not None:
        if users_manager.check_username(
            username=new_username
        ):
            raise exceptions.HTTPException(
                detail=f"username already exists. Please change it and try again later",
                status_code=409
            )
        
        users_manager.update_username(
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

        users_manager.update_user_status(
            user_id=user_id,
            status=status
        )

        return {
            "status_code": 200,
            "message": "Status updated successfully"
        }

    # Udate the user's password
    if new_password is not None and old_password is not None:
        if not users_manager.check_user_password(
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

        users_manager.update_user_password(
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
    Reset the user's auth_token in case they forgot it or
    their account is being compromised by someone else.

    Parameters:
        user_id (str): The user's id
        password (str): The user's password
    """
    # Check auth_token foramt and validity
    if not auth_token_manager.check_auth_token_format(auth_token=auth_token):
        raise exceptions.HTTPException(
            detail=f"Bad auth_token format. Please check your auth_token and try again.",
            status_code=400
        )

    user_id = extract_user_id(auth_token=auth_token)

    # Check if the user exists or not
    if not users_manager.check_user(
        user_id=user_id,
        auth_token=auth_token
    ):
        raise exceptions.HTTPException(
            status_code=404,
            detail=f"'auth_token' expired/unvalid or 'user_id' doesn't exists. Please try again."
        )

    if not users_manager.check_user_password(
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
    updated_at = database_handler.get_auth_tokens_updated_at(
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

    new_auth_token = f"{user_id}.{auth_token_manager.create_token()}"

    # Hashing the new auth_token and updating the existing salt value
    # with the new one
    salt = hasher.encrypt_with_bcrypt(
        user_id=user_id,
        data=new_auth_token,
    )

    hashed_auth_token = salt.hashed_data
    new_auth_token_expire_time = auth_token_manager.auth_token_expire_time()

    database_handler.update_salt(
        user_id=user_id,
        associated_to="auth_token",
        new_salt_value=salt.salt_value,
        new_hashed_data=hashed_auth_token
    )
    
    database_handler.update_auth_token(
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
def list_users_route(
    auth_token: str
):
    """
    Returns a list of all the users present in the server
    
    Parameters:
        viewer_user_id (str): The `user_id` of the user who requested to view the users list
        auth_token (str): The viewer user's `auth_token`
    """
    # Check auth_token foramt and validity
    if not auth_token_manager.check_auth_token_format(auth_token=auth_token):
        raise exceptions.HTTPException(
            detail=f"Bad auth_token format. Please check your auth_token and try again.",
            status_code=400
        )

    viewer_user_id = extract_user_id(auth_token=auth_token)

    # Check the viewer user_id
    if not users_manager.check_user(
        user_id=viewer_user_id,
        auth_token=auth_token
    ):
        raise exceptions.HTTPException(
            status_code=404,
            detail=f"'auth_token' expired/unvalid or 'user_id' doesn't exists. Please try again."
        )

    hashed_auth_token = auth_token_manager._encrypt_auth_token(
        user_id=viewer_user_id,
        auth_token=auth_token
    )

    users = users_manager.list_users(
        viewer_user_id=viewer_user_id,
        auth_token=hashed_auth_token
    )
    
    return {
        "status_code": 200,
        "users": users
    }

# Server's Channels routes
@api.get("/api/v1/channels", status_code=200)
def channels_route():
    """ Channels route start point """
    return {
        "status_code": 200,
        "message": "Channels route"
    }

@api.get("/api/v1/channels/list", status_code=200)
def list_channels_route(
    auth_token: str
    ):
    """ Returns a list of all the available channels """
    # Check auth_token foramt and validity
    if not auth_token_manager.check_auth_token_format(auth_token=auth_token):
        raise exceptions.HTTPException(
            detail=f"Bad auth_token format. Please check your auth_token and try again.",
            status_code=400
        )

    user_id = extract_user_id(auth_token=auth_token)

    # Check if the user exists or not
    if not users_manager.check_user(
        user_id=user_id,
        auth_token=auth_token
    ):
        raise exceptions.HTTPException(
            status_code=404,
            detail=f"'auth_token' expired/unvalid or 'user_id' doesn't exists. Please try again."
        )

    channels_list = channels_manager.list_channels(
            user_id=user_id
        )

    return {
        "status_code": 200,
        "channels": channels_list 
    }

@api.put("/api/v1/channels/create", status_code=200)
def create_new_channel_route(
    # user_id: str,
    auth_token: str,
    channel_name: str,
    is_private: bool = False
):
    """
    Create new channel for the server
    
    Parameters:
        user_id (str): The ID of the user creating the channel route.
        auth_token (str): The authentication token for the user.
        channel_name (str): The name of the channel to create.
        is_private (bool, optional): Specifies whether the channel should be private or not.
            Defaults to False.
    """
        # Check auth_token foramt and validity
    if not auth_token_manager.check_auth_token_format(auth_token=auth_token):
        raise exceptions.HTTPException(
            detail=f"Bad auth_token format. Please check your auth_token and try again.",
            status_code=400
        )

    user_id = extract_user_id(auth_token=auth_token)

    # Check if the user exists or not
    if not users_manager.check_user(
        user_id=user_id,
        auth_token=auth_token
    ):
        raise exceptions.HTTPException(
            status_code=404,
            detail=f"'auth_token' expired/unvalid or 'user_id' doesn't exists. Please try again."
        )

    # Check if the user is the server admin
    if not users_manager.check_is_user_admin(
        user_id=user_id
    ):
        raise exceptions.HTTPException(
            status_code=403,
            detail="Access forbidden. Only admins can create channels and manage them."
        )
    
    # Check if the channel_name is not repeated
    channels_names = database_handler.get_channels_names()
    
    if channel_name in channels_names:
        raise exceptions.HTTPException(
            status_code=409,
            detail="Channel name already exists, please change it and try again."
        )
    
    channel_data = channels_manager.create_channel(
        user_id=user_id,
        channel_name=channel_name,
        is_private=is_private
    )

    return {
        "status_code": 200,
        "message": "Channel created successfully",
        "channel_data": channel_data.to_json()
    }
