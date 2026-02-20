from fastapi import FastAPI

from pufferblow.api.routes.admin import router as admin_router, set_api_initializer as set_admin_initializer
from pufferblow.api.routes.auth import router as decentralized_auth_router
from pufferblow.api.routes.channels import router as channels_router
from pufferblow.api.routes.messages import router as messages_router
from pufferblow.api.routes.storage import router as storage_router, set_api_initializer as set_storage_initializer
from pufferblow.api.routes.users import router as users_router
from pufferblow.api_initializer import api_initializer


def register_routers(api: FastAPI) -> None:
    """
    Register modular route groups on the app instance.
    """
    set_admin_initializer(api_initializer)
    set_storage_initializer(api_initializer)

    api.include_router(users_router, tags=["users"])
    api.include_router(channels_router, tags=["channels"])
    api.include_router(messages_router, tags=["messages"])
    api.include_router(storage_router, tags=["storage"])
    api.include_router(admin_router, tags=["admin"])
    api.include_router(decentralized_auth_router, tags=["decentralized-auth"])
