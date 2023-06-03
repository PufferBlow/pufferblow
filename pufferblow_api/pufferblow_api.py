import os
import sys

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
from pufferblow_api.src.database.database_session import DatabaseSession
from pufferblow_api.src.models.pufferblow_api_config_model import PufferBlowAPIConfig

# Init API
API = FastAPI()

# PufferBlow-api's config data class
PUFFERBLOW_API_CONFIG = PufferBlowAPIConfig()

# Init Database Connection
DATABASE_SESSION = DatabaseSession(
    username    =   PUFFERBLOW_API_CONFIG.USERNAME,
    password    =   PUFFERBLOW_API_CONFIG.PASSWORD,
    host        =   PUFFERBLOW_API_CONFIG.CASSANDRA_HOST,
    port        =   PUFFERBLOW_API_CONFIG.CASSANDRA_PORT
).session()

@API.get("/")
def redirect_route():
    return responses.RedirectResponse("/api/v1")

@API.get("/api/v1", status_code=200)
def home_route():
    return {
        "status code": 200,
        "message": "Welcome to PufferBlow's API",
        "github": constants.ORG_GITHUB
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
