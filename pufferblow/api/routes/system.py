"""System management routes composed from focused modules."""

from fastapi import APIRouter

from pufferblow.api.routes.system_routes.activity import router as activity_router
from pufferblow.api.routes.system_routes.analytics import router as analytics_router
from pufferblow.api.routes.system_routes.media import router as media_router
from pufferblow.api.routes.system_routes.roles import router as roles_router
from pufferblow.api.routes.system_routes.server_runtime import router as server_runtime_router

router = APIRouter()
router.include_router(server_runtime_router)
router.include_router(media_router)
router.include_router(analytics_router)
router.include_router(activity_router)
router.include_router(roles_router)
