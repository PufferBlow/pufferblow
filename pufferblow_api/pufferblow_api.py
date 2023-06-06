import os
import sys
import base64

from fastapi import (
    FastAPI,
    responses
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
from pufferblow_api.src.models.user_model import User
from pufferblow_api.src.utils.user_id_generator import user_id_generator
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
    database_connenction=DATABASE_SESSION.database_connection_session(),
    hasher=HASHER
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
    new_user = User()

    new_user.user_id                                =       user_id_generator(DATABASE_HANDLER._users_id())
    new_user.username                               =       username
    new_user.email                                  =       email
    new_user.status                                 =       "ONLINE"
    new_user.contacts                               =       []
    new_user.conversations                          =       []

    encrypted_password, encryption_key_data     =       HASHER.encrypt(password)
    new_user.password_hash                      =       base64.b64encode(encrypted_password).decode("ascii")
    encryption_key_data.associated_to           =       "password"
    encryption_key_data.user_id                 =       new_user.user_id

    DATABASE_HANDLER._save_keys(encryption_key_data)

    new_user.auth_token, new_user.auth_token_expire_time = DATABASE_HANDLER.sign_up(new_user)

    return {
        "status_code": 201,
        "message": "Account created successfully",
        "auth_token": new_user.auth_token,
        "auth_token_expire_time": new_user.auth_token_expire_time
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
