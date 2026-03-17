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
from pufferblow.api.logger.logger import logger
from pufferblow.api.routes.system_routes.shared import require_privilege
from pufferblow.api.schemas import (
    AuthTokenQuery,
    BackupConfigRequest,
    BlockIPRequest,
    RunTaskRequest,
    ToggleTaskRequest,
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
    user_id = require_privilege(request.auth_token, "manage_blocked_ips")

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
    user_id = require_privilege(request.auth_token, "manage_blocked_ips")

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
    user_id = require_privilege(request.auth_token, "manage_blocked_ips")

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


# Human-readable metadata for built-in background tasks
_TASK_META: dict[str, dict[str, str]] = {
    "storage_cleanup": {
        "name": "Storage Cleanup",
        "description": "Remove orphaned files from storage directories that are no longer referenced in the database.",
        "schedule_label": "Every 24h",
    },
    "auth_token_cleanup": {
        "name": "Auth Token Cleanup",
        "description": "Purge expired authentication tokens from the database.",
        "schedule_label": "Every 12h",
    },
    "server_stats_update": {
        "name": "Server Stats Update",
        "description": "Recalculate server statistics and member counts.",
        "schedule_label": "Every 15m",
    },
    "chart_data_update": {
        "name": "Chart Data Update",
        "description": "Refresh dashboard chart data and analytics aggregates.",
        "schedule_label": "Every 1h",
    },
    "github_releases_check": {
        "name": "GitHub Release Check",
        "description": "Check for new PufferBlow releases on GitHub.",
        "schedule_label": "Every 6h",
    },
    "activity_metrics_update": {
        "name": "Activity Metrics Update",
        "description": "Aggregate daily activity metrics from the audit log.",
        "schedule_label": "Every 6h",
    },
    "ping_stale_cleanup": {
        "name": "Stale Ping Cleanup",
        "description": "Expire pings that have passed their timeout deadline.",
        "schedule_label": "Every 5m",
    },
    "database_backup": {
        "name": "Database Backup",
        "description": "Create a database backup file (pg_dump) or mirror the database to a secondary instance.",
        "schedule_label": "Configurable",
    },
}


@router.post("/api/v1/background-tasks/status", status_code=200)
async def get_background_tasks_status_route_enriched(request: AuthTokenQuery) -> dict:
    """Get status of all background tasks with human-readable metadata."""
    user_id = require_privilege(request.auth_token, "manage_background_tasks")

    try:
        if not hasattr(api_initializer, "background_tasks_manager"):
            return {"status_code": 200, "tasks": {}}

        raw_status = api_initializer.background_tasks_manager.get_task_status()
        enriched: dict[str, dict] = {}
        for task_id, info in raw_status.items():
            meta = _TASK_META.get(task_id, {})
            task_def = api_initializer.background_tasks_manager.tasks.get(task_id, {})
            interval_h = task_def.get("interval_hours")
            interval_m = task_def.get("interval_minutes")
            if interval_h:
                schedule_label = f"Every {interval_h}h"
            elif interval_m:
                schedule_label = f"Every {interval_m}m"
            else:
                schedule_label = "On demand"
            enriched[task_id] = {
                **info,
                "name": meta.get("name", task_id.replace("_", " ").title()),
                "description": meta.get("description", ""),
                "schedule_label": meta.get("schedule_label", schedule_label),
                "last_run": info.get("last_run").isoformat() if info.get("last_run") else None,
            }
        return {"status_code": 200, "tasks": enriched}
    except Exception as e:
        raise exceptions.HTTPException(status_code=500, detail=f"Failed to get task status: {str(e)}")


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
    user_id = require_privilege(request.auth_token, "manage_background_tasks")

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


@router.post("/api/v1/background-tasks/toggle", status_code=200)
async def toggle_background_task_route(request: ToggleTaskRequest) -> dict:
    """Enable or disable a background task."""
    require_privilege(request.auth_token, "manage_background_tasks")

    try:
        if not hasattr(api_initializer, "background_tasks_manager"):
            raise exceptions.HTTPException(status_code=400, detail="Background tasks manager not initialized")

        btm = api_initializer.background_tasks_manager
        if request.task_id not in btm.tasks:
            raise exceptions.HTTPException(status_code=404, detail=f"Task '{request.task_id}' not found")

        if request.enabled:
            btm.enable_task(request.task_id)
        else:
            btm.disable_task(request.task_id)

        return {
            "status_code": 200,
            "message": f"Task '{request.task_id}' {'enabled' if request.enabled else 'disabled'}.",
            "task_id": request.task_id,
            "enabled": request.enabled,
        }
    except exceptions.HTTPException:
        raise
    except Exception as e:
        raise exceptions.HTTPException(status_code=500, detail=f"Failed to toggle task: {str(e)}")


@router.post("/api/v1/background-tasks/backup-config", status_code=200)
async def update_backup_config_route(request: BackupConfigRequest) -> dict:
    """Update database backup configuration and re-register the backup task."""
    require_privilege(request.auth_token, "manage_background_tasks")

    try:
        config_updates = {
            "BACKUP_ENABLED": request.enabled,
            "BACKUP_MODE": request.mode,
            "BACKUP_SCHEDULE_HOURS": request.schedule_hours,
            "BACKUP_MAX_FILES": request.max_files,
        }
        if request.path:
            config_updates["BACKUP_PATH"] = request.path
        if request.mirror_dsn is not None:
            config_updates["BACKUP_MIRROR_DSN"] = request.mirror_dsn

        # Persist to runtime config (database)
        api_initializer.database_handler.update_runtime_config(
            settings_updates=config_updates,
            secret_keys={"BACKUP_MIRROR_DSN"} if request.mirror_dsn else None,
        )

        # Apply to live config object
        for key, value in config_updates.items():
            setattr(api_initializer.config, key, value)

        # Re-register backup task with new settings
        if hasattr(api_initializer, "background_tasks_manager"):
            btm = api_initializer.background_tasks_manager
            backup_func = (
                btm.mirror_database if request.mode == "mirror" else btm.create_database_backup
            )
            btm.tasks["database_backup"] = {
                **btm.tasks.get("database_backup", {}),
                "func": backup_func,
                "interval_hours": request.schedule_hours,
                "interval_minutes": None,
                "enabled": request.enabled,
            }
            import datetime as _dt
            if request.enabled:
                btm.tasks["database_backup"]["next_run"] = (
                    _dt.datetime.now() + _dt.timedelta(hours=request.schedule_hours)
                )

        return {
            "status_code": 200,
            "message": "Backup configuration updated successfully.",
            "config": config_updates,
        }
    except exceptions.HTTPException:
        raise
    except Exception as e:
        raise exceptions.HTTPException(status_code=500, detail=f"Failed to update backup config: {str(e)}")


@router.post("/api/v1/background-tasks/backup-config/get", status_code=200)
async def get_backup_config_route(request: AuthTokenQuery) -> dict:
    """Get current database backup configuration."""
    require_privilege(request.auth_token, "manage_background_tasks")

    config = api_initializer.config
    return {
        "status_code": 200,
        "config": {
            "enabled": bool(getattr(config, "BACKUP_ENABLED", False)),
            "mode": str(getattr(config, "BACKUP_MODE", "file")),
            "path": str(getattr(config, "BACKUP_PATH", "~/.pufferblow/backups")),
            "mirror_dsn": getattr(config, "BACKUP_MIRROR_DSN", None),
            "schedule_hours": int(getattr(config, "BACKUP_SCHEDULE_HOURS", 24)),
            "max_files": int(getattr(config, "BACKUP_MAX_FILES", 7)),
        },
    }
