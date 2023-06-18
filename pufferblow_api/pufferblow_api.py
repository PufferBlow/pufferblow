import os
import sys
import base64

from fastapi import (
    FastAPI,
    responses,
    exceptions
)

from loguru import logger

from pufferblow_api import constants
from pufferblow_api.src.utils.logger import (
    InterceptHandler,
    logging,
    StandaloneApplication,
    StubbedGunicornLogger,
    LOG_LEVEL,
    WORKERS,
    JSON_LOGS,
)

from pufferblow_api.src.hasher.hasher import Hasher
from pufferblow_api.src.user.user_manager import UserManager
from pufferblow_api.src.auth.auth_token_manager import AuthTokenManager
from pufferblow_api.src.database.database_session import DatabaseSession
from pufferblow_api.src.database.database_handler import DatabaseHandler
from pufferblow_api.src.models.pufferblow_api_config_model import PufferBlowAPIConfig

# Init API
API = FastAPI()

# PufferBlow-api's config data class
PUFFERBLOW_API_CONFIG = PufferBlowAPIConfig()

# Init the hasher (Responsible for encrypting and decrypting data)
HASHER = Hasher()

# Init Database Connection
DATABASE_SESSION = DatabaseSession(
    supabase_url            =   PUFFERBLOW_API_CONFIG.SUPABASE_URL,
    supabase_key            =   PUFFERBLOW_API_CONFIG.SUPABASE_KEY,
    pufferblow_api_config   =   PUFFERBLOW_API_CONFIG
)

# Init Database handler
DATABASE_HANDLER = DatabaseHandler(
    database_connection_pool    =       DATABASE_SESSION.database_connection_pool(),
    hasher                      =       HASHER
)

# Init Auth tokens manager
AUTH_TOKEN_MANAGER = AuthTokenManager(
    database_handler        =       DATABASE_HANDLER,
    hasher                  =       HASHER
)

# Init user manager
USER_MANAGER = UserManager(
    database_handler        =       DATABASE_HANDLER,
    auth_token_manager      =       AUTH_TOKEN_MANAGER,
    hasher                  =       HASHER
)

@API.get("/")
def redirect_route():
    return responses.RedirectResponse("/api/v1")

@API.get("/api/v1", status_code=200)
def home_route():
    return {
        "status_code": 200,
        "message": "Welcome to PufferBlow's API",
        "github": constants.ORG_GITHUB
    }

# Users routes
@API.get("/api/v1/users", status_code=200)
def users_route():
    """ Main users route """
    return {
        "status_code": 200,
        "description": "This is the main users route"
    }

@API.post("/api/v1/users/signup", status_code=201)
async def signup_new_user(
    username: str,
    password: str
):
    """ Signup a new user """
    # Check if the `username` already exists
    if USER_MANAGER.check_username(username):
        raise exceptions.HTTPException(
            detail=f"username already exists. Please change it and try again later",
            status_code=409
        )

    user_data = USER_MANAGER.sign_up(
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
        "user_id": user_data.user_id,
        "auth_token": user_data.raw_auth_token,
        "auth_token_expire_time": user_data.auth_token_expire_time
    }

@API.get("/api/v1/users/profile", status_code=200)
async def users_profile_route(
    user_id: str,
    auth_token: str,
    viewer_user_id: str
):
    """
    Users profile management route
    
    Parameters:
        user_id (str): The user_id of the target user
        auth_token (str): The auth_token of the user who requested this user's profile
        viewer_user_id (str): The user_id of the user who requested this user's profile
    
    Returns:
        dict: The User class model to json

    """

    # Check if the targeted user exists or not
    if not USER_MANAGER.check_user(
        user_id=user_id
    ):
        raise exceptions.HTTPException(
            status_code=404,
            detail=f"The target user's user_id='{user_id}' not found. Please make sure to pass the correct one"
        )
    
    # Check if the `user_id` of the user who requested to view the target user's profile exists or not
    if not USER_MANAGER.check_user(
        user_id=viewer_user_id,
        auth_token=auth_token
    ):
        raise exceptions.HTTPException(
            status_code=404,
            detail=f"The user requested's user_id='{viewer_user_id}' not found. Please check your 'auth_token' if it is expired/unvalid, or 'user_id'"
        )
    
    hashed_auth_token = AUTH_TOKEN_MANAGER._encrypt_auth_token(
        user_id=viewer_user_id,
        auth_token=auth_token
    )

    user_data = USER_MANAGER.user_profile(
        user_id=user_id,
        hashed_auth_token=hashed_auth_token
    )

    logger.info(
        constants.REQUEST_FOR_USER_PROFILE(
            user_data=user_data,
            viewer_user_id=viewer_user_id
        )
    )

    return {
        "status_code": 200,
        "user_data": user_data
    }

@API.put("/api/v1/users/profile", status_code=200)
async def edit_users_profile_route(
    user_id: str,
    auth_token: str,
    new_username: str = None,
    status: str = None,
    new_password: str = None,
    old_password: str = None
):
    """ Edits a user's profile data such as: status,
    last_seen, username and password
    
    Parameters:
        user_id (str): The user's id
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
    # Check if the user exists or not
    if not USER_MANAGER.check_user(
        user_id=user_id,
        auth_token=auth_token
    ):
        raise exceptions.HTTPException(
            status_code=404,
            detail=f"'auth_token' expired/unvalid or 'user_id' doesn't exists. Please try again."
        )

    # Update username
    if new_username is not None:
        if USER_MANAGER.check_username(
            username=new_username
        ):
            raise exceptions.HTTPException(
                detail=f"username already exists. Please change it and try again later",
                status_code=409
            )
        
        USER_MANAGER.update_username(
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
                constants.USER_STATUS_UPDATE_FAILD(
                    user_id=user_id,
                    status=status
                )
            )

            raise exceptions.HTTPException(
                detail=f"status value status='{status}' not found. Accepted values ['online', 'offline']",
                status_code=404
            )

        USER_MANAGER.update_user_status(
            user_id=user_id,
            status=status
        )

        return {
            "status_code": 200,
            "message": "Status updated successfully"
        }

    # Udate the user's password
    if new_password is not None and old_password is not None:
        USER_MANAGER.update_user_password(
            user_id=user_id,
            new_password=new_password,
            old_password=old_password
        )

        return {
            "status_code": 200,
            "message": "Password updated successfully"
        }

def run() -> None:
    """ Starts the API """
    INTERCEPT_HANDLER = InterceptHandler()
    # logging.basicConfig(handlers=[INTERCEPT_HANDLER], level=LOG_LEVEL)
    # logging.root.handlers = [INTERCEPT_HANDLER]
    logging.root.setLevel(LOG_LEVEL)

    SEEN = set()

    for name in [
        *logging.root.manager.loggerDict.keys(),
        "gunicorn",
        "gunicorn.access",
        "gunicorn.error",
        "uvicorn",
        "uvicorn.access",
        "uvicorn.error",
    ]:
        if name not in SEEN:
            SEEN.add(name.split(".")[0])
            logging.getLogger(name).handlers = [INTERCEPT_HANDLER]

    logger.configure(handlers=[{"sink": sys.stdout, "serialize": JSON_LOGS}])
    logger.add(PUFFERBLOW_API_CONFIG.LOGS_PATH, rotation="10 MB")
    
    OPTIONS = {
        "bind": f"{PUFFERBLOW_API_CONFIG.API_HOST}:{PUFFERBLOW_API_CONFIG.API_PORT}",
        "workers": WORKERS(PUFFERBLOW_API_CONFIG.WORKERS),
        "timeout": PUFFERBLOW_API_CONFIG.CONNECTION_TIMEOUT,
        "accesslog": "-",
        "errorlog": "-",
        "worker_class": "uvicorn.workers.UvicornWorker",
        "logger_class": StubbedGunicornLogger
    }

    StandaloneApplication(API, OPTIONS).run()
