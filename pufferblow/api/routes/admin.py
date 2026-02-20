"""
Admin Management Routes

This module contains all admin-related endpoints including:
- Blocked IP management (list, block, unblock)
- Background tasks management (status, run)

All routes require server owner privileges.
"""

import uuid
from typing import Any

from fastapi import APIRouter, exceptions

from pufferblow.api.database.tables.blocked_ips import BlockedIPS
from pufferblow.api.dependencies import require_server_owner
from pufferblow.api.logger.logger import logger
from pufferblow.api.schemas import (
    AuthTokenQuery,
    BlockIPRequest,
    RunTaskRequest,
    UnblockIPRequest,
)

# Import api_initializer - will be set by main api.py
api_initializer = None

# Create router
router = APIRouter()


def set_api_initializer(initializer: Any) -> None:
    """Set the API initializer for this module."""
    global api_initializer
    api_initializer = initializer


# ==================== Blocked IPs Management ====================


@router.post("/api/v1/blocked-ips/list", status_code=200)
async def list_blocked_ips_route(request: AuthTokenQuery) -> dict:
    """
    List all blocked IPs with details. Server Owner only.

    Args:
        request: Request containing auth_token

    Returns:
        200 OK: List of blocked IPs
        403 FORBIDDEN: User is not server owner
        404 NOT FOUND: Invalid auth_token
    """
    user_id = require_server_owner(request.auth_token)

    try:
        blocked_ips = api_initializer.database_handler.fetch_blocked_ips()

        return {"status_code": 200, "blocked_ips": blocked_ips}

    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500, detail=f"Failed to fetch blocked IPs: {str(e)}"
        )


@router.post("/api/v1/blocked-ips/block", status_code=201)
async def block_ip_route(request: BlockIPRequest) -> dict:
    """
    Add an IP address to the blocked list. Server Owner only.

    Args:
        request: Request containing auth_token, ip, and reason

    Returns:
        201 CREATED: IP blocked successfully
        400 BAD REQUEST: Invalid IP format or already blocked
        403 FORBIDDEN: User is not server owner
        404 NOT FOUND: Invalid auth_token
    """
    user_id = require_server_owner(request.auth_token)

    try:
        # Check if IP is already blocked
        if api_initializer.database_handler.check_is_ip_blocked(ip=request.ip):
            raise exceptions.HTTPException(
                status_code=400, detail="IP address is already blocked"
            )

        # Create blocked IP object
        blocked_ip = BlockedIPS(
            ip_id=str(uuid.uuid4()), ip=request.ip, block_reason=request.reason
        )

        # Save to database
        api_initializer.database_handler.save_blocked_ip_to_blocked_ips(
            blocked_ip=blocked_ip
        )

        return {
            "status_code": 201,
            "message": f"IP {request.ip} has been blocked",
            "reason": request.reason,
        }

    except exceptions.HTTPException:
        raise
    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500, detail=f"Failed to block IP: {str(e)}"
        )


@router.post("/api/v1/blocked-ips/unblock", status_code=200)
async def unblock_ip_route(request: UnblockIPRequest) -> dict:
    """
    Remove an IP address from the blocked list. Server Owner only.

    Args:
        request: Request containing auth_token and ip

    Returns:
        200 OK: IP unblocked successfully
        400 BAD REQUEST: IP not blocked
        403 FORBIDDEN: User is not server owner
        404 NOT FOUND: Invalid auth_token
    """
    user_id = require_server_owner(request.auth_token)

    try:
        # Check if IP is blocked
        if not api_initializer.database_handler.check_is_ip_blocked(ip=request.ip):
            raise exceptions.HTTPException(
                status_code=400, detail="IP address is not currently blocked"
            )

        # Remove from database
        deleted = api_initializer.database_handler.delete_blocked_ip(ip=request.ip)
        if not deleted:
            raise exceptions.HTTPException(
                status_code=400, detail="Failed to unblock IP address"
            )

        return {"status_code": 200, "message": f"IP {request.ip} has been unblocked"}

    except exceptions.HTTPException:
        raise
    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500, detail=f"Failed to unblock IP: {str(e)}"
        )


# ==================== Background Tasks Management ====================


@router.post("/api/v1/background-tasks/status", status_code=200)
async def get_background_tasks_status_route(request: AuthTokenQuery) -> dict:
    """
    Get status of all background tasks. Server Owner only.

    Args:
        request: Request containing auth_token

    Returns:
        200 OK: Background tasks status
        403 FORBIDDEN: User is not server owner
        404 NOT FOUND: Invalid auth_token
    """
    user_id = require_server_owner(request.auth_token)

    try:
        if hasattr(api_initializer, "background_tasks_manager"):
            tasks_status = api_initializer.background_tasks_manager.get_task_status()
            return {"status_code": 200, "tasks": tasks_status}
        else:
            return {
                "status_code": 200,
                "tasks": {},
                "message": "Background tasks manager not initialized",
            }

    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500, detail=f"Failed to get background tasks status: {str(e)}"
        )


@router.post("/api/v1/background-tasks/run", status_code=200)
async def run_background_task_route(request: RunTaskRequest) -> dict:
    """
    Execute a background task on-demand. Server Owner only.

    Args:
        request: Request containing auth_token and task_id

    Returns:
        200 OK: Task executed successfully
        400 BAD REQUEST: Task not found or failed
        403 FORBIDDEN: User is not server owner
        404 NOT FOUND: Invalid auth_token
    """
    user_id = require_server_owner(request.auth_token)

    try:
        if not hasattr(api_initializer, "background_tasks_manager"):
            raise exceptions.HTTPException(
                status_code=400, detail="Background tasks manager not initialized"
            )

        success = await api_initializer.background_tasks_manager.run_task(
            request.task_id
        )
        if success:
            return {
                "status_code": 200,
                "message": f"Background task '{request.task_id}' executed successfully",
            }
        else:
            raise exceptions.HTTPException(
                status_code=400,
                detail=f"Background task '{request.task_id}' failed to execute",
            )

    except exceptions.HTTPException:
        raise
    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500, detail=f"Failed to run background task: {str(e)}"
        )
