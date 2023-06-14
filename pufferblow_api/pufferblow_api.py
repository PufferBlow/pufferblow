import os
import sys
import base64

from fastapi import (
    FastAPI,
    responses,
    exceptions
)

from gunicorn.app.base import BaseApplication
from gunicorn.glogging import Logger
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
    email: str,
    password: str
):
    """ Signup a new user """
    user_data = USER_MANAGER.sign_up(
        username=username,
        email=email,
        password=password
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
):
    """ Users profile management route """
    if user_id not in DATABASE_HANDLER.get_users_id():
        raise exceptions.HTTPException(
            status_code=404,
            detail=f"\"{user_id}\" not found. Please make sure to pass the correct one"
        )
    hashed_auth_token = AUTH_TOKEN_MANAGER._encrypt_auth_token(
        user_id=user_id,
        auth_token=auth_token
    )
    if not AUTH_TOKEN_MANAGER.token_exists(
        user_id=user_id,
        hashed_auth_token=hashed_auth_token
    ):
        raise exceptions.HTTPException(
            status_code=404,
            detail=f"\"{auth_token}\" not found, or expired. Please make sure to pass the correct one"
        )

    user_data = USER_MANAGER.user_profile(
        user_id=user_id,
        hashed_auth_token=hashed_auth_token
    )

    return {
        "status_code": 200,
        "user_data": user_data
    }

@API.put("/api/v1/users/profile", status_code=201)
async def edit_users_profile_route(
    user_id: str,
    auth_token: str,
    username: str,
    status: str,
    email: str,
    old_email: str,
    password: str,
    old_password: str
):
    """ Edits a user's profile data such as: status,
    last_seen, username, email and password
    
    Parameters:
        user_id (str): The user's id
        auth_token (str): The user's auth_token
        username (str): The new username for the user
        status (str): The new status for the user ["ONLINE", "OFFLINE"]
        email (str): The new email for the user
        password (str): The new password for the user
        old_password (str): The old password of the user. This is in case the ```password``` was passed 
    
    Returns:
        {
            "status_code": 201,
            "message": (str)
        }
    """
    pass

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
        "reload": True,
        "timeout": PUFFERBLOW_API_CONFIG.CONNECTION_TIMEOUT,
        "accesslog": "-",
        "errorlog": "-",
        "worker_class": "uvicorn.workers.UvicornWorker",
        "logger_class": StubbedGunicornLogger
    }

    StandaloneApplication(API, OPTIONS).run()
