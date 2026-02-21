"""System management routes."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, Form, UploadFile, exceptions
from loguru import logger
from pydantic import BaseModel, Field

from pufferblow.api.database.tables.activity_audit import ActivityAudit
from pufferblow.api.schemas import AuthTokenQuery, ServerSettingsRequest, UploadAuthForm
from pufferblow.api.utils.extract_user_id import extract_user_id
from pufferblow.core.bootstrap import api_initializer

router = APIRouter()


async def parse_upload_auth_form(
    auth_token: str = Form(..., description="User's authentication token"),
) -> UploadAuthForm:
    """Parse upload auth form."""
    return UploadAuthForm(auth_token=auth_token)

@router.get("/api/v1/system/latest-release", status_code=200)
async def get_latest_release_route():
    """
    Get information about the latest PufferBlow release from GitHub.

    Returns:
        200 OK: Latest release information
        500 INTERNAL SERVER ERROR: Failed to fetch release information
    """
    try:
        if hasattr(api_initializer, "background_tasks_manager"):
            latest_release = (
                api_initializer.background_tasks_manager.get_latest_release()
            )
            if latest_release:
                return {"status_code": 200, "release": latest_release}
            else:
                return {
                    "status_code": 200,
                    "message": "No release information available yet. Release check may still be running or hasn't completed.",
                    "release": None,
                }
        else:
            return {
                "status_code": 200,
                "message": "Background tasks manager not initialized",
                "release": None,
            }

    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500,
            detail=f"Failed to get latest release information: {str(e)}",
        )


# System Information Routes (All Users)
@router.get("/api/v1/system/server-stats", status_code=200)
async def get_server_stats_route():
    """
    Get comprehensive server statistics.

    Returns:
        200 OK: Server statistics including users, channels, messages
        500 INTERNAL SERVER ERROR: Failed to fetch statistics
    """
    try:
        if hasattr(api_initializer, "background_tasks_manager"):
            server_stats = api_initializer.background_tasks_manager.get_server_stats()
            if server_stats:
                return {"status_code": 200, "statistics": server_stats}
            else:
                return {
                    "status_code": 200,
                    "message": "Server statistics not yet available. Statistics update may still be running or hasn't completed.",
                    "statistics": None,
                }
        else:
            return {
                "status_code": 200,
                "message": "Background tasks manager not initialized",
                "statistics": None,
            }

    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500, detail=f"Failed to get server statistics: {str(e)}"
        )


@router.get("/api/v1/system/server-info", status_code=200)
async def get_server_info_route():
    """
    Get server configuration information including name, description, and settings.

    Returns:
        200 OK: Server information including name, description, and configuration
        500 INTERNAL SERVER ERROR: Failed to fetch server info
    """
    # Get server info from database
    server_data = api_initializer.database_handler.get_server()
    server_settings = api_initializer.database_handler.get_server_settings()

    # Format server info response
    server_info = {
        "server_name": server_data.server_name,
        "server_description": server_data.description,
        "version": getattr(api_initializer.config, "VERSION", "1.0.0"),
        "is_private": server_settings.is_private,
        "creation_date": server_data.created_at.isoformat(),
        "avatar_url": server_data.avatar_url,
        "banner_url": server_data.banner_url,
        "welcome_message": server_data.welcome_message,
        # Include server settings
        "max_message_length": server_settings.max_message_length,
        "max_image_size": server_settings.max_image_size,
        "max_video_size": server_settings.max_video_size,
        "max_sticker_size": server_settings.max_sticker_size,
        "max_gif_size": server_settings.max_gif_size,
        "allowed_image_types": server_settings.allowed_images_extensions,
        "allowed_video_types": server_settings.allowed_videos_extensions,
        "allowed_file_types": server_settings.allowed_doc_extensions,
        "allowed_sticker_types": server_settings.allowed_stickers_extensions,
        "allowed_gif_types": server_settings.allowed_gif_extensions,
    }

    return {"status_code": 200, "server_info": server_info}


@router.post("/api/v1/system/server-usage")
async def get_server_usage_route():
    """
    Get real-time server usage statistics (CPU, RAM, I/O).

    Returns:
        200 OK: Server usage metrics
        500 INTERNAL SERVER ERROR: Failed to fetch server usage
    """
    try:
        import os
        import time

        import psutil

        # Get CPU usage
        cpu_percent = psutil.cpu_percent(interval=0.1)

        # Get memory usage - use psutil's actual system reported memory
        memory = psutil.virtual_memory()
        ram_used_gb = round(memory.used / (1024**3), 2)
        ram_total_gb = round(memory.total / (1024**3), 2)
        ram_percent = memory.percent

        # Debug memory info
        logger.info(
            f"Server memory: used={ram_used_gb}GB, total={ram_total_gb}GB ({ram_percent}%)"
        )

        # Get disk I/O
        disk_io_counters = psutil.disk_io_counters()
        if disk_io_counters:
            # Calculate I/O rates over a short interval
            time.sleep(0.1)
            disk_io_counters2 = psutil.disk_io_counters()
            if disk_io_counters2 and disk_io_counters:
                read_bytes_per_sec = (
                    disk_io_counters2.read_bytes - disk_io_counters.read_bytes
                ) * 10
                write_bytes_per_sec = (
                    disk_io_counters2.write_bytes - disk_io_counters.write_bytes
                ) * 10
                disk_read_mb_per_sec = round(read_bytes_per_sec / (1024**2), 2)
                disk_write_mb_per_sec = round(write_bytes_per_sec / (1024**2), 2)
            else:
                disk_read_mb_per_sec = 0
                disk_write_mb_per_sec = 0
        else:
            disk_read_mb_per_sec = 0
            disk_write_mb_per_sec = 0

        # Get disk usage for the main storage
        disk_usage = psutil.disk_usage("/")
        storage_used_gb = round(disk_usage.used / (1024**3), 2)
        storage_total_gb = round(disk_usage.total / (1024**3), 2)
        storage_percent = disk_usage.percent

        # Get system uptime
        boot_time = psutil.boot_time()
        uptime_seconds = time.time() - boot_time

        # Format uptime
        days = int(uptime_seconds // (24 * 3600))
        hours = int((uptime_seconds % (24 * 3600)) // 3600)
        minutes = int((uptime_seconds % 3600) // 60)
        uptime_str = f"{days}d {hours}h {minutes}m"

        server_usage = {
            "cpu_percent": round(cpu_percent, 1),
            "ram_used_gb": ram_used_gb,
            "ram_total_gb": ram_total_gb,
            "ram_percent": round(ram_percent, 1),
            "disk_read_mb_per_sec": disk_read_mb_per_sec,
            "disk_write_mb_per_sec": disk_write_mb_per_sec,
            "storage_used_gb": storage_used_gb,
            "storage_total_gb": storage_total_gb,
            "storage_percent": round(storage_percent, 1),
            "uptime_seconds": round(uptime_seconds, 0),
            "uptime_formatted": uptime_str,
            "timestamp": int(time.time()),
        }

        return {"status_code": 200, "server_usage": server_usage}

    except ImportError:
        # Fallback when psutil is not installed
        import time

        return {
            "status_code": 200,
            "server_usage": {
                "cpu_percent": 0.0,
                "ram_used_gb": 0.0,
                "ram_total_gb": 0.0,
                "ram_percent": 0.0,
                "disk_read_mb_per_sec": 0.0,
                "disk_write_mb_per_sec": 0.0,
                "storage_used_gb": 0.0,
                "storage_total_gb": 0.0,
                "storage_percent": 0.0,
                "uptime_seconds": 0,
                "uptime_formatted": "0d 0h 0m",
                "timestamp": int(time.time()),
            },
            "note": "psutil not installed on server - install with: pip install psutil",
        }
    except Exception as e:
        # Fallback for any other errors
        import time

        return {
            "status_code": 200,
            "server_usage": {
                "cpu_percent": 0.0,
                "ram_used_gb": 0.0,
                "ram_total_gb": 0.0,
                "ram_percent": 0.0,
                "disk_read_mb_per_sec": 0.0,
                "disk_write_mb_per_sec": 0.0,
                "storage_used_gb": 0.0,
                "storage_total_gb": 0.0,
                "storage_percent": 0.0,
                "uptime_seconds": 0,
                "uptime_formatted": "0d 0h 0m",
                "timestamp": int(time.time()),
            },
            "note": f"Server monitoring error: {str(e)}. Ensure psutil is available.",
        }


@router.put("/api/v1/system/server-info", status_code=200)
async def update_server_info_route(request: ServerSettingsRequest):
    """
    Update server configuration settings. Server Owner only.

    Args:
        request (ServerSettingsRequest): Request body containing auth_token and settings to update.

    Returns:
        200 OK: Server settings updated successfully
        403 FORBIDDEN: User is not server owner
        404 NOT FOUND: Invalid auth_token
        500 INTERNAL SERVER ERROR: Failed to update settings
    """
    user_id = extract_user_id(auth_token=request.auth_token)

    # Check if user is server owner
    if not api_initializer.user_manager.is_server_owner(user_id=user_id):
        raise exceptions.HTTPException(
            status_code=403,
            detail="Access forbidden. Only the server owner can update server settings.",
        )

    try:
        updated_fields = []
        server_updates = {}
        server_settings_updates = {}

        # Map requested fields to appropriate tables
        if request.server_name is not None:
            server_updates["server_name"] = request.server_name
            updated_fields.append("server_name")

        if request.server_description is not None:
            server_updates["description"] = request.server_description
            updated_fields.append("server_description")

        if request.is_private is not None:
            server_settings_updates["is_private"] = request.is_private
            updated_fields.append("is_private")

        if request.max_message_length is not None:
            server_settings_updates["max_message_length"] = request.max_message_length
            updated_fields.append("max_message_length")

        # Note: max_users is not handled yet as it's not in the current schema

        # Update Server table (server name/description)
        if server_updates:
            server_name = server_updates.get("server_name")
            server_description = server_updates.get("description")
            # Get current server data to preserve existing values
            current_server = api_initializer.database_handler.get_server()
            # Only update name and description, keep welcome message from current server
            final_server_name = (
                server_name if server_name is not None else current_server.server_name
            )
            final_welcome_message = current_server.welcome_message
            final_description = (
                server_description
                if server_description is not None
                else current_server.description
            )
            api_initializer.database_handler.update_server_values(
                final_server_name, final_welcome_message, final_description
            )

            # Log server name/description changes
            if "server_name" in server_updates:
                activity_data = {
                    "event_type": "server_settings_updated",
                    "description": f"Server name updated to '{server_name}'",
                    "metadata": {
                        "field": "server_name",
                        "new_value": server_name,
                        "setting_type": "server_info",
                    },
                    "user_id": user_id,
                    "timestamp": datetime.utcnow().isoformat(),
                }
                api_initializer.database_handler.create_activity_audit_entry(
                    ActivityAudit(
                        activity_id=str(uuid.uuid4()),
                        activity_type="server_settings_updated",
                        user_id=user_id,
                        title=f"Server name updated to '{server_name}'",
                        description=f"Server name changed to '{server_name}'",
                        metadata_json=json.dumps(
                            {
                                "field": "server_name",
                                "new_value": server_name,
                                "setting_type": "server_info",
                            }
                        ),
                    )
                )

            if "description" in server_updates:
                activity_data = {
                    "event_type": "server_settings_updated",
                    "description": "Server description updated",
                    "metadata": {
                        "field": "server_description",
                        "new_value": server_description,
                        "setting_type": "server_info",
                    },
                    "user_id": user_id,
                    "timestamp": datetime.utcnow().isoformat(),
                }
                api_initializer.database_handler.create_activity_audit_entry(
                    ActivityAudit(
                        activity_id=str(uuid.uuid4()),
                        activity_type="server_settings_updated",
                        user_id=user_id,
                        title="Server description updated",
                        description="Server description was updated",
                        metadata_json=json.dumps(
                            {
                                "field": "server_description",
                                "new_value": server_description,
                                "setting_type": "server_info",
                            }
                        ),
                    )
                )

        # Update ServerSettings table
        if server_settings_updates:
            api_initializer.database_handler.update_server_settings(
                server_settings_updates
            )

            # Log server settings changes
            for field, new_value in server_settings_updates.items():
                field_descriptions = {
                    "is_private": "Server privacy" if new_value else "Server publicity",
                    "max_message_length": f"Maximum message length to {new_value} characters",
                }

                description = field_descriptions.get(
                    field, f"Server setting '{field}' updated to '{new_value}'"
                )

                api_initializer.database_handler.create_activity_audit_entry(
                    ActivityAudit(
                        activity_id=str(uuid.uuid4()),
                        activity_type="server_settings_updated",
                        user_id=user_id,
                        title=f"Server settings updated: {field}",
                        description=description,
                        metadata_json=json.dumps(
                            {
                                "field": field,
                                "new_value": new_value,
                                "setting_type": "server_settings",
                                "table": "server_settings",
                            }
                        ),
                    )
                )

        return {
            "status_code": 200,
            "message": "Server settings updated successfully",
            "updated_fields": updated_fields,
        }

    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500, detail=f"Failed to update server settings: {str(e)}"
        )


@router.post("/api/v1/system/upload-avatar", status_code=201)
async def upload_server_avatar_route(
    form_data: UploadAuthForm = Depends(parse_upload_auth_form),
    avatar: UploadFile = Form(..., description="Server avatar image file"),
):
    """
    Upload server's avatar image. Server Owner only.
    Deletes the old avatar file to prevent storage buildup.

    Args:
        auth_token: User's authentication token
        avatar: Server avatar image file (PNG, JPEG, GIF, etc.)

    Returns:
        201 CREATED: Avatar uploaded successfully
        400 BAD REQUEST: File validation failed
        403 FORBIDDEN: User is not server owner
        404 NOT FOUND: Invalid auth_token
    """
    auth_token = form_data.auth_token
    user_id = extract_user_id(auth_token=auth_token)

    # Check if user is server owner
    if not api_initializer.user_manager.is_server_owner(user_id=user_id):
        raise exceptions.HTTPException(
            status_code=403,
            detail="Access forbidden. Only the server owner can update server avatar.",
        )

    try:
        # Get current server data to check for existing avatar
        current_server = api_initializer.database_handler.get_server()
        old_avatar_url = current_server.avatar_url

        # Delete old avatar file if it exists
        if old_avatar_url:
            try:
                # Extract relative path from the URL for deletion
                if old_avatar_url.startswith("/"):
                    # It's a local CDN URL like /api/v1/cdn/file/...
                    relative_path = old_avatar_url.replace("/api/v1/cdn/file/", "", 1)
                    full_path = (
                        Path(api_initializer.config.CDN_STORAGE_PATH) / relative_path
                    )
                    if full_path.exists():
                        full_path.unlink()
                        logger.info(f"Deleted old server avatar: {relative_path}")
                else:
                    # Try the CDN manager deletion method
                    api_initializer.cdn_manager.delete_file(old_avatar_url)
            except Exception as e:
                logger.warning(
                    f"Failed to delete old server avatar {old_avatar_url}: {str(e)}"
                )

        # Upload new avatar
        cdn_url, is_duplicate = (
            await api_initializer.storage_manager.validate_and_save_categorized_file(
                file=avatar,
                user_id=user_id,
                force_category="avatars",
                check_duplicates=False,
            )
        )

        # Register file in database and create reference
        try:
            # Extract file info from URL
            relative_path = cdn_url[len(api_initializer.config.CDN_BASE_URL) :].lstrip(
                "/"
            )
            file_path_obj = (
                Path(api_initializer.config.CDN_STORAGE_PATH) / relative_path
            )

            if file_path_obj.exists():
                # Read file to compute hash
                with open(file_path_obj, "rb") as f:
                    content = f.read()

                file_hash = api_initializer.cdn_manager.compute_file_hash(content)

                # Always check if file object exists and increment reference count if duplicate
                # Skip creating file object if it already exists
                existing_ref_count = (
                    api_initializer.database_handler.get_file_reference_count(file_hash)
                )
                if existing_ref_count is not None and existing_ref_count > 0:
                    # File already exists, just increment reference count
                    api_initializer.database_handler.increment_file_reference_count(
                        file_hash
                    )
                else:
                    # For new files, register and create reference
                    api_initializer.database_handler.create_file_object(
                        file_hash=file_hash,
                        ref_count=1,
                        file_path=relative_path,  # Store relative path
                        file_size=len(content),
                        mime_type=api_initializer.cdn_manager.mime_detector.from_buffer(
                            content
                        )
                        or "application/octet-stream",
                        verification_status="verified",
                    )

                # Create reference for server avatar
                reference_id = f"server_avatar_{uuid.uuid4()}"
                api_initializer.database_handler.create_file_reference(
                    reference_id=reference_id,
                    file_hash=file_hash,
                    reference_type="server_avatar",
                    reference_entity_id="server",  # Server entity
                )

        except Exception as e:
            # Log error but don't fail the upload
            logger.warning(
                f"Failed to create file reference for server avatar: {str(e)}"
            )

        # Update server avatar URL in database - ensure full path for proper serving
        if not cdn_url.startswith("/api/v1/cdn/file/"):
            # Convert CDN-mounted URL to API route URL for database storage
            if cdn_url.startswith("/cdn/"):
                cdn_url = cdn_url.replace("/cdn/", "/api/v1/cdn/file/", 1)
        api_initializer.database_handler.update_server_avatar_url(cdn_url)

        # Log server avatar update activity
        try:
            api_initializer.database_handler.create_activity_audit_entry(
                ActivityAudit(
                    activity_id=str(uuid.uuid4()),
                    activity_type="server_avatar_updated",
                    user_id=user_id,
                    title="Server avatar updated",
                    description=f"Server avatar was updated by user {user_id}",
                    metadata_json=json.dumps(
                        {"avatar_url": cdn_url, "updated_by": user_id}
                    ),
                )
            )
        except Exception as e:
            logger.warning(f"Failed to log server avatar update activity: {str(e)}")

        return {
            "status_code": 201,
            "message": "Server avatar uploaded successfully",
            "avatar_url": cdn_url,
        }

    except exceptions.HTTPException:
        raise
    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500, detail=f"Avatar upload failed: {str(e)}"
        )


@router.post("/api/v1/system/upload-banner", status_code=201)
async def upload_server_banner_route(
    form_data: UploadAuthForm = Depends(parse_upload_auth_form),
    banner: UploadFile = Form(..., description="Server banner image file"),
):
    """
    Upload server's banner image. Server Owner only.
    Deletes the old banner file to prevent storage buildup.

    Args:
        auth_token: User's authentication token
        banner: Server banner image file (PNG, JPEG, GIF, etc.)

    Returns:
        201 CREATED: Banner uploaded successfully
        400 BAD REQUEST: File validation failed
        403 FORBIDDEN: User is not server owner
        404 NOT FOUND: Invalid auth_token
    """
    auth_token = form_data.auth_token
    user_id = extract_user_id(auth_token=auth_token)

    # Check if user is server owner
    if not api_initializer.user_manager.is_server_owner(user_id=user_id):
        raise exceptions.HTTPException(
            status_code=403,
            detail="Access forbidden. Only the server owner can update server banner.",
        )

    try:
        # Get current server data to check for existing banner
        current_server = api_initializer.database_handler.get_server()
        old_banner_url = current_server.banner_url

        # Delete old banner file if it exists
        if old_banner_url:
            try:
                # Extract relative path from the URL for deletion
                if old_banner_url.startswith("/"):
                    # It's a local CDN URL like /api/v1/cdn/file/...
                    relative_path = old_banner_url.replace("/api/v1/cdn/file/", "", 1)
                    full_path = (
                        Path(api_initializer.config.CDN_STORAGE_PATH) / relative_path
                    )
                    if full_path.exists():
                        full_path.unlink()
                        logger.info(f"Deleted old server banner: {relative_path}")
                else:
                    # Try the CDN manager deletion method
                    api_initializer.cdn_manager.delete_file(old_banner_url)
            except Exception as e:
                logger.warning(
                    f"Failed to delete old server banner {old_banner_url}: {str(e)}"
                )

        # Upload new banner
        cdn_url, is_duplicate = (
            await api_initializer.storage_manager.validate_and_save_categorized_file(
                file=banner,
                user_id=user_id,
                force_category="banners",
                check_duplicates=False,
            )
        )

        # Register file in database and create reference
        try:
            # Extract file info from URL
            from pathlib import Path

            relative_path = cdn_url[len(api_initializer.config.CDN_BASE_URL) :].lstrip(
                "/"
            )
            file_path_obj = (
                Path(api_initializer.config.CDN_STORAGE_PATH) / relative_path
            )

            if file_path_obj.exists():
                # Read file to compute hash
                with open(file_path_obj, "rb") as f:
                    content = f.read()

                file_hash = api_initializer.cdn_manager.compute_file_hash(content)

                # Always check if file object exists and increment reference count if duplicate
                # Skip creating file object if it already exists
                existing_ref_count = (
                    api_initializer.database_handler.get_file_reference_count(file_hash)
                )
                if existing_ref_count is not None and existing_ref_count > 0:
                    # File already exists, just increment reference count
                    api_initializer.database_handler.increment_file_reference_count(
                        file_hash
                    )
                else:
                    # For new files, register and create reference
                    api_initializer.database_handler.create_file_object(
                        file_hash=file_hash,
                        ref_count=1,
                        file_path=relative_path,  # Store relative path
                        file_size=len(content),
                        mime_type=api_initializer.cdn_manager.mime_detector.from_buffer(
                            content
                        )
                        or "application/octet-stream",
                        verification_status="verified",
                    )

                # Create reference for server banner
                reference_id = f"server_banner_{uuid.uuid4()}"
                api_initializer.database_handler.create_file_reference(
                    reference_id=reference_id,
                    file_hash=file_hash,
                    reference_type="server_banner",
                    reference_entity_id="server",  # Server entity
                )

        except Exception as e:
            # Log error but don't fail the upload
            logger.warning(
                f"Failed to create file reference for server banner: {str(e)}"
            )

        # Update server banner URL in database - ensure full path for proper serving
        if not cdn_url.startswith("/api/v1/cdn/file/"):
            # Convert CDN-mounted URL to API route URL for database storage
            if cdn_url.startswith("/cdn/"):
                cdn_url = cdn_url.replace("/cdn/", "/api/v1/cdn/file/", 1)
        api_initializer.database_handler.update_server_banner_url(cdn_url)

        return {
            "status_code": 201,
            "message": "Server banner uploaded successfully",
            "banner_url": cdn_url,
        }

    except exceptions.HTTPException:
        raise
    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500, detail=f"Banner upload failed: {str(e)}"
        )


# Request body models for chart endpoints
class ChartRequest(BaseModel):
    """ChartRequest class."""
    auth_token: str = Field(min_length=1)
    period: str | None = Field(
        default=None, description="Time period (daily, weekly, monthly, 24h, 7d)"
    )


class UserStatusChartRequest(BaseModel):
    """UserStatusChartRequest class."""
    auth_token: str = Field(min_length=1)


@router.post("/api/v1/system/charts/user-registrations", status_code=200)
async def get_user_registration_chart_route(request: ChartRequest):
    """
    Get user registration chart data.

    Args:
        request (ChartRequest): Request body containing auth_token and optional period.

    Returns:
        200 OK: Chart data for user registrations
        500 INTERNAL SERVER ERROR: Failed to fetch chart data
    """
    try:
        user_id = extract_user_id(auth_token=request.auth_token)

        if hasattr(api_initializer, "background_tasks_manager"):
            chart_data = api_initializer.background_tasks_manager.get_chart_data(
                "user_registrations", request.period
            )
            raw_stats = api_initializer.background_tasks_manager.get_raw_stats(
                "user_registrations", request.period
            )

            return {
                "status_code": 200,
                "chart_data": chart_data,
                "raw_stats": raw_stats or {},
            }
        else:
            return {
                "status_code": 200,
                "message": "Background tasks manager not initialized",
                "chart_data": {},
                "raw_stats": {},
            }

    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500,
            detail=f"Failed to get user registration chart data: {str(e)}",
        )


@router.post("/api/v1/system/charts/message-activity", status_code=200)
async def get_message_activity_chart_route(request: ChartRequest):
    """
    Get message activity chart data.

    Args:
        request (ChartRequest): Request body containing auth_token and optional period.

    Returns:
        200 OK: Chart data for message activity
        500 INTERNAL SERVER ERROR: Failed to fetch chart data
    """
    try:
        user_id = extract_user_id(auth_token=request.auth_token)

        if hasattr(api_initializer, "background_tasks_manager"):
            chart_data = api_initializer.background_tasks_manager.get_chart_data(
                "message_activity", request.period
            )
            raw_stats = api_initializer.background_tasks_manager.get_raw_stats(
                "message_activity", request.period
            )

            return {
                "status_code": 200,
                "chart_data": chart_data,
                "raw_stats": raw_stats or {},
            }
        else:
            return {
                "status_code": 200,
                "message": "Background tasks manager not initialized",
                "chart_data": {},
                "raw_stats": {},
            }

    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500,
            detail=f"Failed to get message activity chart data: {str(e)}",
        )


@router.post("/api/v1/system/charts/online-users", status_code=200)
async def get_online_users_chart_route(request: ChartRequest):
    """
    Get online users chart data.

    Args:
        request (ChartRequest): Request body containing auth_token and optional period.

    Returns:
        200 OK: Chart data for online users
        500 INTERNAL SERVER ERROR: Failed to fetch chart data
    """
    try:
        user_id = extract_user_id(auth_token=request.auth_token)

        if hasattr(api_initializer, "background_tasks_manager"):
            chart_data = api_initializer.background_tasks_manager.get_chart_data(
                "online_users", request.period
            )
            raw_stats = api_initializer.background_tasks_manager.get_raw_stats(
                "online_users", request.period
            )

            return {
                "status_code": 200,
                "chart_data": chart_data,
                "raw_stats": raw_stats or {},
            }
        else:
            return {
                "status_code": 200,
                "message": "Background tasks manager not initialized",
                "chart_data": {},
                "raw_stats": {},
            }

    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500, detail=f"Failed to get online users chart data: {str(e)}"
        )


@router.post("/api/v1/system/charts/channel-creation", status_code=200)
async def get_channel_creation_chart_route(request: ChartRequest):
    """
    Get channel creation chart data.

    Args:
        request (ChartRequest): Request body containing auth_token and optional period.

    Returns:
        200 OK: Chart data for channel creation
        500 INTERNAL SERVER ERROR: Failed to fetch chart data
    """
    try:
        user_id = extract_user_id(auth_token=request.auth_token)

        if hasattr(api_initializer, "background_tasks_manager"):
            chart_data = api_initializer.background_tasks_manager.get_chart_data(
                "channel_creation", request.period
            )
            raw_stats = api_initializer.background_tasks_manager.get_raw_stats(
                "channel_creation", request.period
            )

            return {
                "status_code": 200,
                "chart_data": chart_data,
                "raw_stats": raw_stats or {},
            }
        else:
            return {
                "status_code": 200,
                "message": "Background tasks manager not initialized",
                "chart_data": {},
                "raw_stats": {},
            }

    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500,
            detail=f"Failed to get channel creation chart data: {str(e)}",
        )


@router.post("/api/v1/system/charts/user-status", status_code=200)
async def get_user_status_chart_route(request: UserStatusChartRequest):
    """
    Get user status distribution chart data.

    Args:
        request (UserStatusChartRequest): Request body containing auth_token.

    Returns:
        200 OK: Chart data for user status distribution
        500 INTERNAL SERVER ERROR: Failed to fetch chart data
    """
    try:
        user_id = extract_user_id(auth_token=request.auth_token)

        if hasattr(api_initializer, "background_tasks_manager"):
            chart_data = api_initializer.background_tasks_manager.get_chart_data(
                "user_status", None
            )
            raw_stats = api_initializer.background_tasks_manager.get_raw_stats(
                "user_status", None
            )

            return {
                "status_code": 200,
                "chart_data": chart_data,
                "raw_stats": raw_stats or {},
            }
        else:
            return {
                "status_code": 200,
                "message": "Background tasks manager not initialized",
                "chart_data": {},
                "raw_stats": {},
            }

    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500, detail=f"Failed to get user status chart data: {str(e)}"
        )


# Request body model for recent activity
class RecentActivityRequest(BaseModel):
    """RecentActivityRequest class."""
    auth_token: str
    limit: int = 10


# Request body model for server logs
class ServerLogsRequest(BaseModel):
    """ServerLogsRequest class."""
    auth_token: str = Field(min_length=1)
    lines: int = Field(default=50, ge=1, le=1000)
    search: str | None = Field(default=None)
    level: str | None = Field(
        default=None,
        description="Filter by log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
    )


@router.post("/api/v1/system/logs", status_code=200)
async def get_server_logs_route(request: ServerLogsRequest):
    """
    Get server logs with filtering options. Server Owner only.

    Args:
        request (ServerLogsRequest): Request body containing auth_token and filtering options.

    Returns:
        200 OK: Server logs data
        403 FORBIDDEN: User is not server owner
        404 NOT FOUND: Invalid auth_token
        500 INTERNAL SERVER ERROR: Failed to fetch logs
    """
    user_id = extract_user_id(auth_token=request.auth_token)

    # Check if user is server owner
    if not api_initializer.user_manager.is_server_owner(user_id=user_id):
        raise exceptions.HTTPException(
            status_code=403,
            detail="Access forbidden. Only the server owner can access server logs.",
        )

    try:
        from pathlib import Path

        # Get log directory (using config defined log path)
        log_dir = Path(api_initializer.config.LOGS_PATH).parent

        # Look for log files
        log_files = []
        if log_dir.exists():
            # Look for common log file patterns
            patterns = ["*.log", "*.txt", "pufferblow*.log", "server*.log"]
            for pattern in patterns:
                log_files.extend(list(log_dir.glob(pattern)))

        if not log_files:
            # Fallback to common system log locations
            possible_paths = [
                Path("/var/log/pufferblow.log"),
                Path("/var/log/pufferblow/server.log"),
                Path("./logs/pufferblow.log"),
                Path("./logs/server.log"),
            ]
            for path in possible_paths:
                if path.exists():
                    log_files.append(path)
                    break

        logs_content = []
        if log_files:
            # Read the most recent log file
            latest_log = max(log_files, key=lambda p: p.stat().st_mtime)
            try:
                with open(latest_log, encoding="utf-8", errors="replace") as f:
                    all_lines = f.readlines()

                    # Reverse to get most recent first, apply line limit
                    all_lines.reverse()
                    lines = all_lines[: request.lines]

                    # Apply filters
                    filtered_lines = []
                    for line in lines:
                        # Ensure line is a string
                        if not isinstance(line, str):
                            line = str(line)

                        # Apply search filter
                        if (
                            request.search
                            and request.search.lower() not in line.lower()
                        ):
                            continue

                        # Apply level filter
                        if request.level:
                            level_upper = request.level.upper()
                            level_found = False

                            # Check for common log level patterns
                            if level_upper == "DEBUG" and (
                                "DEBUG" in line.upper() or "DBUG" in line.upper()
                            ):
                                level_found = True
                            elif level_upper == "INFO" and (
                                "INFO" in line.upper() or "INF" in line.upper()
                            ):
                                level_found = True
                            elif level_upper == "WARNING" and (
                                "WARNING" in line.upper() or "WARN" in line.upper()
                            ):
                                level_found = True
                            elif level_upper == "ERROR" and (
                                "ERROR" in line.upper() or "ERR" in line.upper()
                            ):
                                level_found = True
                            elif level_upper == "CRITICAL" and (
                                "CRITICAL" in line.upper() or "CRIT" in line.upper()
                            ):
                                level_found = True

                            if not level_found:
                                continue

                        # Inline colors using ANSI escape codes
                        colored_line = line
                        line_upper = line.upper()
                        if "ERROR" in line_upper or "ERR" in line_upper:
                            colored_line = f"\x1b[31m{line}\x1b[0m"  # Red for errors
                        elif "WARNING" in line_upper or "WARN" in line_upper:
                            colored_line = (
                                f"\x1b[33m{line}\x1b[0m"  # Yellow for warnings
                            )
                        elif "DEBUG" in line_upper:
                            colored_line = f"\x1b[36m{line}\x1b[0m"  # Cyan for debug
                        elif "INFO" in line_upper:
                            colored_line = f"\x1b[32m{line}\x1b[0m"  # Green for info

                        filtered_lines.append(
                            {"content": colored_line.strip(), "raw": line.strip()}
                        )

                    logs_content = filtered_lines

                    # Log the access
                    api_initializer.database_handler.create_activity_audit_entry(
                        ActivityAudit(
                            activity_id=str(uuid.uuid4()),
                            activity_type="logs_viewed",
                            user_id=user_id,
                            title="Server logs accessed",
                            description=f"Server owner accessed logs with filters: lines={request.lines}, search='{request.search or 'None'}', level='{request.level or 'None'}'",
                            metadata_json=json.dumps(
                                {
                                    "action": "logs_access",
                                    "lines_requested": request.lines,
                                    "search_filter": request.search,
                                    "level_filter": request.level,
                                    "log_file": str(latest_log),
                                }
                            ),
                        )
                    )

            except Exception as e:
                logger.error(f"Failed to read log file {latest_log}: {str(e)}")
                return {
                    "status_code": 200,
                    "logs": [],
                    "message": f"Error reading log file: {str(e)}",
                    "available_log_files": [str(f) for f in log_files],
                }
        else:
            return {
                "status_code": 200,
                "logs": [],
                "message": "No log files found. Logs may not be configured or accessible.",
                "searched_paths": [
                    str(log_dir),
                    "/var/log/pufferblow.log",
                    "/var/log/pufferblow/server.log",
                    "./logs/pufferblow.log",
                    "./logs/server.log",
                ],
            }

        return {
            "status_code": 200,
            "logs": logs_content,
            "total_lines": len(logs_content),
            "filtered": bool(request.search or request.level),
            "log_file": str(log_files[0]) if log_files else None,
            "note": "Logs are displayed with ANSI color codes preserved. Latest entries appear first.",
        }

    except exceptions.HTTPException:
        raise
    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500, detail=f"Failed to get server logs: {str(e)}"
        )


@router.post("/api/v1/system/recent-activity", status_code=200)
async def get_recent_activity_route(request: RecentActivityRequest):
    """
    Get recent activity events from the server.

    Returns:
        200 OK: Recent activity data
        500 INTERNAL SERVER ERROR: Failed to fetch

    Retrieves real activity data from the activity_audit table.
    """
    try:
        user_id = extract_user_id(auth_token=request.auth_token)

        # Check if user is admin/owner (for privacy on internal activities)
        is_admin = api_initializer.user_manager.is_admin(
            user_id=user_id
        ) or api_initializer.user_manager.is_server_owner(user_id=user_id)

        # If not admin, can only see public activities
        if not is_admin:
            return {"status_code": 200, "activities": []}

        # Get recent activities from database
        recent_activities = api_initializer.database_handler.get_recent_activities(
            limit=request.limit
        )

        activities = []
        for activity in recent_activities:
            # Parse metadata JSON
            metadata = (
                json.loads(activity.metadata_json) if activity.metadata_json else {}
            )

            # Get user info for the activity
            user_info = None
            if activity.user_id:
                user_profile = api_initializer.user_manager.user_profile(
                    activity.user_id
                )
                if user_profile:
                    user_info = {
                        "id": activity.user_id,
                        "username": user_profile.get("username", "Unknown"),
                        "avatar_url": f"https://api.dicebear.com/7.x/bottts-neutral/svg?seed={activity.user_id[:8]}&backgroundColor=5865f2",
                    }

            # Format activity based on type
            activity_title = ""
            activity_description = ""
            activity_type = activity.activity_type

            if activity_type == "file_upload":
                filename = "a file"
                if metadata.get("file_url"):
                    filename_part = metadata["file_url"].split("/")[-1]
                    if "." in filename_part and len(filename_part.split(".")[1]) > 0:
                        filename = filename_part

                directory = metadata.get("directory", "files")
                activity_title = f"File uploaded to {directory}"
                activity_description = f"File '{filename}' was uploaded"

            elif activity_type == "user_joined":
                activity_title = "User joined the server"
                activity_description = "A new member joined the community"

            elif activity_type == "channel_created":
                channel_name = metadata.get("channel_name", "unknown channel")
                activity_title = f"Channel created: #{channel_name}"
                activity_description = f"New channel '{channel_name}' was created"

            elif activity_type == "user_left":
                activity_title = "User left the server"
                activity_description = "A member left the community"

            elif activity_type == "server_settings_updated":
                field = metadata.get("field", "unknown")
                setting_type = metadata.get("setting_type", "unknown")
                new_value = metadata.get("new_value", "unknown")
                username = (
                    user_info.get("username", "Unknown User")
                    if user_info
                    else "Unknown User"
                )
                activity_title = f"Server settings updated by {username}: {field}"
                activity_description = f"{username} changed {field} to '{new_value}'"

            else:
                activity_title = activity_type.replace("_", " ").title()
                activity_description = f"System activity: {activity_type}"

            activities.append(
                {
                    "id": str(activity.activity_id),
                    "type": activity_type,
                    "title": activity_title,
                    "description": activity_description,
                    "timestamp": activity.created_at.isoformat(),
                    "user": user_info,
                    "metadata": metadata,
                }
            )

        return {"status_code": 200, "activities": activities}

    except Exception as e:
        logger.warning(f"Failed to get recent activity data: {str(e)}")
        # Fallback to empty list instead of error for better UX
        return {"status_code": 200, "activities": []}


# Activity Metrics Routes (Admin Only)
@router.post("/api/v1/system/activity-metrics", status_code=200)
async def get_activity_metrics_route(request: AuthTokenQuery):
    """
    Get current activity metrics for the control panel dashboard.

    Args:
        request (AuthTokenQuery): Request body containing auth_token.

    Returns:
        200 OK: Activity metrics data
        403 FORBIDDEN: User is not admin/owner
        404 NOT FOUND: Invalid auth_token
        500 INTERNAL SERVER ERROR: Failed to fetch metrics
    """
    user_id = extract_user_id(auth_token=request.auth_token)

    # Check if user is admin or owner
    if not api_initializer.user_manager.is_admin(user_id=user_id):
        raise exceptions.HTTPException(
            status_code=403,
            detail="Access forbidden. Only administrators can access activity metrics.",
        )

    try:
        metrics_data = api_initializer.database_handler.get_latest_activity_metrics()

        return {"status_code": 200, "activity_metrics": metrics_data}

    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500, detail=f"Failed to get activity metrics: {str(e)}"
        )


@router.post("/api/v1/system/server-overview", status_code=200)
async def get_server_overview_route(request: AuthTokenQuery):
    """
    Get comprehensive server overview data for control panel.

    Args:
        request (AuthTokenQuery): Request body containing auth_token.

    Returns:
        200 OK: Server overview data
        403 FORBIDDEN: User is not admin/owner
        404 NOT FOUND: Invalid auth_token
        500 INTERNAL SERVER ERROR: Failed to fetch overview
    """
    user_id = extract_user_id(auth_token=request.auth_token)

    # Check if user is admin or owner
    if not api_initializer.user_manager.is_admin(user_id=user_id):
        raise exceptions.HTTPException(
            status_code=403,
            detail="Access forbidden. Only administrators can access server overview.",
        )

    try:
        # Get real data from database
        total_users = api_initializer.database_handler.count_users()
        total_channels = len(api_initializer.database_handler.get_channels_names())

        # Get additional metrics
        messages_last_hour = (
            api_initializer.database_handler.get_message_count_by_period(
                datetime.now() - timedelta(hours=1), datetime.now()
            )
        )

        active_users = api_initializer.database_handler.get_user_status_counts()
        messages_this_period = (
            api_initializer.database_handler.get_message_count_by_period(
                datetime.now() - timedelta(days=7), datetime.now()
            )
        )

        return {
            "status_code": 200,
            "server_overview": {
                "total_users": total_users,
                "total_channels": total_channels,
                "messages_last_hour": messages_last_hour,
                "active_users": active_users.get("online", 0)
                + active_users.get("idle", 0)
                + active_users.get("dnd", 0)
                + active_users.get("afk", 0),
                "messages_this_period": messages_this_period,
            },
        }

    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500, detail=f"Failed to get server overview: {str(e)}"
        )



