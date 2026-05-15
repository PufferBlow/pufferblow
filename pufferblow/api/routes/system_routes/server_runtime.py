"""Server info and runtime configuration routes."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, urlopen

from fastapi import APIRouter, HTTPException

from fastapi import Body

from pufferblow.api.schemas import AuthTokenQuery, RuntimeConfigRequest, RuntimeConfigUpdateRequest, ServerSettingsRequest
from pufferblow.api.utils.appearance import (
    VALID_AVATAR_KINDS,
    VALID_BANNER_KINDS,
    generate_shuffle_seed,
    is_valid_hex_color,
)
from pufferblow.api.utils.extract_user_id import extract_user_id
from pufferblow.core.bootstrap import api_initializer

from .shared import (
    ServerState,
    get_server_state,
    log_activity,
    require_component,
    require_privilege,
)

router = APIRouter()


def _background_manager_or_none():
    if not api_initializer.is_ready("background_tasks_manager"):
        return None
    return api_initializer.background_tasks_manager


def _media_sfu_health_url() -> str | None:
    """Resolve media-sfu health endpoint from the configured signaling URL."""
    manager = getattr(api_initializer, "voice_session_manager", None)
    raw_url = None
    if manager is not None:
        raw_url = getattr(manager, "signaling_url", None)
    if not raw_url:
        config = getattr(api_initializer, "config", None)
        raw_url = getattr(config, "RTC_SIGNALING_URL", None) if config is not None else None
    if not raw_url:
        return None

    candidate = str(raw_url).strip()
    if not candidate:
        return None
    if "://" not in candidate:
        candidate = f"ws://{candidate.lstrip('/')}"

    parsed = urlsplit(candidate)
    scheme = "https" if parsed.scheme == "wss" else "http"
    return urlunsplit((scheme, parsed.netloc, "/healthz", "", ""))


def _fetch_media_sfu_health() -> dict:
    """Best-effort fetch of media-sfu /healthz for instance-level health reporting."""
    health_url = _media_sfu_health_url()
    if not health_url:
        return {
            "enabled": False,
            "status": "disabled",
            "url": None,
            "healthz": None,
            "error": "RTC signaling URL is not configured.",
        }

    try:
        request = Request(health_url, headers={"Accept": "application/json"})
        with urlopen(request, timeout=2.5) as response:
            raw_body = response.read().decode("utf-8")
            payload = json.loads(raw_body) if raw_body else {}
        return {
            "enabled": True,
            "status": "ok",
            "url": health_url,
            "healthz": payload,
            "error": None,
        }
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return {
            "enabled": True,
            "status": "error",
            "url": health_url,
            "healthz": None,
            "error": f"media-sfu returned HTTP {exc.code}: {body or exc.reason}",
        }
    except URLError as exc:
        reason = getattr(exc, "reason", exc)
        return {
            "enabled": True,
            "status": "unreachable",
            "url": health_url,
            "healthz": None,
            "error": f"media-sfu health probe failed: {reason}",
        }
    except Exception as exc:
        return {
            "enabled": True,
            "status": "error",
            "url": health_url,
            "healthz": None,
            "error": f"media-sfu health probe failed: {exc}",
        }


def build_instance_health_payload() -> dict:
    """Build a stable instance health payload including mirrored media-sfu health."""
    component_names = (
        "database_handler",
        "server_manager",
        "user_manager",
        "auth_token_manager",
        "channels_manager",
        "websockets_manager",
        "storage_manager",
        "voice_session_manager",
        "background_tasks_manager",
    )
    components = {
        name: api_initializer.is_ready(name)
        for name in component_names
    }
    server_state = get_server_state()
    media_sfu = _fetch_media_sfu_health()

    overall_status = "ok"
    if not api_initializer.is_loaded or not components.get("database_handler", False):
        overall_status = "degraded"
    if media_sfu["enabled"] and media_sfu["status"] != "ok":
        overall_status = "degraded"

    return {
        "status": overall_status,
        "api_loaded": api_initializer.is_loaded,
        "server_initialized": server_state.server is not None,
        "components": components,
        "media_sfu": media_sfu,
    }


def _build_server_info_payload(state: ServerState) -> dict:
    """Build a stable server info payload even when rows are missing."""
    server = state.server
    settings = state.settings
    config = api_initializer.config
    database_handler = require_component("database_handler")
    storage_manager = getattr(api_initializer, "storage_manager", None)
    if storage_manager is not None:
        storage_manager.update_server_limits()

    try:
        members_count = database_handler.get_server_members_count()
    except Exception:
        members_count = None

    try:
        statuses = database_handler.get_user_status_counts()
        online_members = sum(
            statuses.get(key, 0) for key in ("online", "idle", "dnd", "afk")
        )
    except Exception:
        online_members = None

    created_at = getattr(server, "created_at", None)
    voice_session_manager = getattr(api_initializer, "voice_session_manager", None)
    media_quality = (
        voice_session_manager._build_media_quality_payload()
        if voice_session_manager is not None
        else None
    )
    return {
        "server_id": getattr(server, "server_id", None),
        "server_name": getattr(server, "server_name", None) or "PufferBlow",
        "server_description": getattr(server, "description", None) or "",
        "version": getattr(config, "VERSION", "1.0.0") if config else "1.0.0",
        "max_users": None,
        "is_private": bool(getattr(settings, "is_private", False)),
        "creation_date": created_at.isoformat() if created_at else None,
        "avatar_url": getattr(server, "avatar_url", None),
        "banner_url": getattr(server, "banner_url", None),
        "welcome_message": getattr(server, "welcome_message", None),
        "members_count": members_count,
        "online_members": online_members,
        "max_message_length": getattr(settings, "max_message_length", 50_000),
        "max_image_size": getattr(
            settings, "max_image_size", getattr(storage_manager, "MAX_IMAGE_SIZE_MB", None)
        ),
        "max_video_size": getattr(
            settings, "max_video_size", getattr(storage_manager, "MAX_VIDEO_SIZE_MB", None)
        ),
        "max_sticker_size": getattr(
            settings, "max_sticker_size", getattr(storage_manager, "MAX_STICKER_SIZE_MB", None)
        ),
        "max_gif_size": getattr(
            settings, "max_gif_size", getattr(storage_manager, "MAX_GIF_SIZE_MB", None)
        ),
        "allowed_image_types": getattr(
            settings, "allowed_images_extensions", getattr(storage_manager, "IMAGE_EXTENSIONS", [])
        ),
        "allowed_video_types": getattr(
            settings, "allowed_videos_extensions", getattr(storage_manager, "VIDEO_EXTENSIONS", [])
        ),
        "allowed_file_types": getattr(
            settings, "allowed_doc_extensions", getattr(storage_manager, "DOCUMENT_EXTENSIONS", [])
        ),
        "allowed_sticker_types": getattr(
            settings, "allowed_stickers_extensions", getattr(storage_manager, "STICKER_EXTENSIONS", [])
        ),
        "allowed_gif_types": getattr(
            settings, "allowed_gif_extensions", getattr(storage_manager, "GIF_EXTENSIONS", [])
        ),
        "max_audio_size": getattr(storage_manager, "MAX_AUDIO_SIZE_MB", None),
        "max_file_size": getattr(storage_manager, "MAX_DOCUMENT_SIZE_MB", None),
        "max_total_attachment_size": getattr(
            storage_manager, "MAX_TOTAL_ATTACHMENT_SIZE_MB", None
        ),
        "allowed_audio_types": getattr(storage_manager, "AUDIO_EXTENSIONS", None),
        "rtc_media_quality": media_quality,
    }


@router.get("/api/v1/system/latest-release", status_code=200)
async def get_latest_release_route():
    """Get latest PufferBlow release information."""
    manager = _background_manager_or_none()
    if manager is None:
        return {
            "status_code": 200,
            "message": "Background tasks manager not initialized",
            "release": None,
        }

    try:
        latest_release = manager.get_latest_release()
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get latest release information: {exc}",
        ) from exc

    if latest_release:
        return {"status_code": 200, "release": latest_release}
    return {
        "status_code": 200,
        "message": "No release information available yet. Release check may still be running or hasn't completed.",
        "release": None,
    }


@router.get("/api/v1/system/server-stats", status_code=200)
async def get_server_stats_route():
    """Get server statistics snapshot."""
    manager = _background_manager_or_none()
    if manager is None:
        return {
            "status_code": 200,
            "message": "Background tasks manager not initialized",
            "statistics": None,
            "stats": None,
        }

    try:
        server_stats = manager.get_server_stats()
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get server statistics: {exc}",
        ) from exc

    if server_stats:
        return {
            "status_code": 200,
            "statistics": server_stats,
            "stats": server_stats,
        }
    return {
        "status_code": 200,
        "message": "Server statistics not yet available. Statistics update may still be running or hasn't completed.",
        "statistics": None,
        "stats": None,
    }


@router.get("/api/v1/system/server-info", status_code=200)
async def get_server_info_route():
    """Get server configuration info."""
    return {
        "status_code": 200,
        "server_info": _build_server_info_payload(get_server_state()),
    }


@router.get("/api/v1/system/instance-health", status_code=200)
async def get_instance_health_route():
    """Get instance health summary including mirrored media-sfu /healthz."""
    payload = build_instance_health_payload()
    return {
        "status_code": 200,
        "instance_health": payload,
    }


@router.post("/api/v1/system/server-usage", status_code=200)
async def get_server_usage_route():
    """Get real-time server usage statistics."""
    try:
        import time

        import psutil

        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        ram_used_gb = round(memory.used / (1024**3), 2)
        ram_total_gb = round(memory.total / (1024**3), 2)
        disk_io_counters = psutil.disk_io_counters()
        disk_read_mb_per_sec = 0.0
        disk_write_mb_per_sec = 0.0
        if disk_io_counters:
            time.sleep(0.1)
            disk_io_counters2 = psutil.disk_io_counters()
            if disk_io_counters2:
                disk_read_mb_per_sec = round(
                    ((disk_io_counters2.read_bytes - disk_io_counters.read_bytes) * 10)
                    / (1024**2),
                    2,
                )
                disk_write_mb_per_sec = round(
                    ((disk_io_counters2.write_bytes - disk_io_counters.write_bytes) * 10)
                    / (1024**2),
                    2,
                )

        disk_usage = psutil.disk_usage("/")
        uptime_seconds = time.time() - psutil.boot_time()
        days = int(uptime_seconds // (24 * 3600))
        hours = int((uptime_seconds % (24 * 3600)) // 3600)
        minutes = int((uptime_seconds % 3600) // 60)

        return {
            "status_code": 200,
            "server_usage": {
                "cpu_percent": round(cpu_percent, 1),
                "ram_used_gb": ram_used_gb,
                "ram_total_gb": ram_total_gb,
                "ram_percent": round(memory.percent, 1),
                "disk_read_mb_per_sec": disk_read_mb_per_sec,
                "disk_write_mb_per_sec": disk_write_mb_per_sec,
                "storage_used_gb": round(disk_usage.used / (1024**3), 2),
                "storage_total_gb": round(disk_usage.total / (1024**3), 2),
                "storage_percent": round(disk_usage.percent, 1),
                "uptime_seconds": round(uptime_seconds, 0),
                "uptime_formatted": f"{days}d {hours}h {minutes}m",
                "timestamp": int(time.time()),
            },
        }
    except ImportError:
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
    except Exception as exc:
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
            "note": f"Server monitoring error: {exc}. Ensure psutil is available.",
        }


@router.put("/api/v1/system/server-info", status_code=200)
async def update_server_info_route(request: ServerSettingsRequest):
    """Update server configuration settings."""
    user_id = require_privilege(request.auth_token, "manage_server_settings")
    database_handler = require_component("database_handler")

    updated_fields: list[str] = []
    server_updates: dict[str, object] = {}
    server_settings_updates: dict[str, object] = {}

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
    if request.max_image_size is not None:
        server_settings_updates["max_image_size"] = request.max_image_size
        updated_fields.append("max_image_size")
    if request.max_video_size is not None:
        server_settings_updates["max_video_size"] = request.max_video_size
        updated_fields.append("max_video_size")
    if request.max_sticker_size is not None:
        server_settings_updates["max_sticker_size"] = request.max_sticker_size
        updated_fields.append("max_sticker_size")
    if request.max_gif_size is not None:
        server_settings_updates["max_gif_size"] = request.max_gif_size
        updated_fields.append("max_gif_size")
    if request.allowed_image_types is not None:
        server_settings_updates["allowed_images_extensions"] = request.allowed_image_types
        updated_fields.append("allowed_image_types")
    if request.allowed_video_types is not None:
        server_settings_updates["allowed_videos_extensions"] = request.allowed_video_types
        updated_fields.append("allowed_video_types")
    if request.allowed_file_types is not None:
        server_settings_updates["allowed_doc_extensions"] = request.allowed_file_types
        updated_fields.append("allowed_file_types")
    if request.allowed_sticker_types is not None:
        server_settings_updates["allowed_stickers_extensions"] = request.allowed_sticker_types
        updated_fields.append("allowed_sticker_types")
    if request.allowed_gif_types is not None:
        server_settings_updates["allowed_gif_extensions"] = request.allowed_gif_types
        updated_fields.append("allowed_gif_types")

    try:
        state = get_server_state()
        if server_updates:
            current_server = state.server
            if current_server is None:
                raise HTTPException(
                    status_code=404,
                    detail="Server instance has not been initialized yet.",
                )
            database_handler.update_server_values(
                server_updates.get("server_name", current_server.server_name),
                current_server.welcome_message,
                server_updates.get("description", current_server.description),
            )

            if "server_name" in server_updates:
                log_activity(
                    activity_type="server_settings_updated",
                    user_id=user_id,
                    title=f"Server name updated to '{server_updates['server_name']}'",
                    description=f"Server name changed to '{server_updates['server_name']}'",
                    metadata={
                        "field": "server_name",
                        "new_value": server_updates["server_name"],
                        "setting_type": "server_info",
                    },
                )

            if "description" in server_updates:
                log_activity(
                    activity_type="server_settings_updated",
                    user_id=user_id,
                    title="Server description updated",
                    description="Server description was updated",
                    metadata={
                        "field": "server_description",
                        "new_value": server_updates["description"],
                        "setting_type": "server_info",
                    },
                )

        if server_settings_updates:
            database_handler.update_server_settings(server_settings_updates)
            for field, new_value in server_settings_updates.items():
                description = {
                    "is_private": "Server privacy enabled"
                    if new_value
                    else "Server privacy disabled",
                    "max_message_length": f"Maximum message length updated to {new_value} characters",
                }.get(field, f"Server setting '{field}' updated to '{new_value}'")
                log_activity(
                    activity_type="server_settings_updated",
                    user_id=user_id,
                    title=f"Server settings updated: {field}",
                    description=description,
                    metadata={
                        "field": field,
                        "new_value": new_value,
                        "setting_type": "server_settings",
                        "table": "server_settings",
                    },
                )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update server settings: {exc}",
        ) from exc

    return {
        "status_code": 200,
        "message": "Server settings updated successfully",
        "updated_fields": updated_fields,
    }


@router.put("/api/v1/system/server-appearance", status_code=200)
async def update_server_appearance_route(
    auth_token: str = Body(..., embed=True),
    avatar_kind: str | None = Body(default=None),
    banner_kind: str | None = Body(default=None),
    accent_color: str | None = Body(default=None),
    shuffle_avatar_seed: bool = Body(default=False),
):
    """Toggle the server's icon/banner mode without uploading a file.

    Same semantics as ``PUT /api/v1/users/profile/appearance`` but for
    the server row. Gated by ``manage_server_settings`` so only admins
    can flip the storefront appearance — community members shouldn't
    be able to repaint the server's banner.

    Body fields are all optional. Pass only what you want to change.
    """
    user_id = require_privilege(auth_token, "manage_server_settings")
    database_handler = require_component("database_handler")

    if avatar_kind is not None and avatar_kind not in VALID_AVATAR_KINDS:
        raise HTTPException(
            status_code=400,
            detail=f"avatar_kind must be one of {sorted(VALID_AVATAR_KINDS)}",
        )
    if banner_kind is not None and banner_kind not in VALID_BANNER_KINDS:
        raise HTTPException(
            status_code=400,
            detail=f"banner_kind must be one of {sorted(VALID_BANNER_KINDS)}",
        )
    if accent_color is not None and not is_valid_hex_color(accent_color):
        raise HTTPException(
            status_code=400,
            detail="accent_color must be a '#RRGGBB' hex string",
        )

    state = get_server_state()
    server = state.server
    if server is None:
        raise HTTPException(
            status_code=404,
            detail="Server instance has not been initialized yet.",
        )

    new_seed = generate_shuffle_seed() if shuffle_avatar_seed else None

    database_handler.update_server_appearance(
        server_id=server.server_id,
        avatar_kind=avatar_kind,
        banner_kind=banner_kind,
        accent_color=accent_color,
        avatar_seed=new_seed,
    )

    log_activity(
        activity_type="server_settings_updated",
        user_id=user_id,
        title="Server appearance updated",
        description="Server avatar/banner appearance preferences were updated",
        metadata={
            "field": "appearance",
            "avatar_kind": avatar_kind,
            "banner_kind": banner_kind,
            "accent_color": accent_color,
            "shuffled_seed": new_seed is not None,
            "setting_type": "server_appearance",
        },
    )

    return {
        "status_code": 200,
        "message": "Server appearance updated",
        "avatar_kind": avatar_kind,
        "banner_kind": banner_kind,
        "accent_color": accent_color,
        "avatar_seed": new_seed,
    }


@router.post("/api/v1/system/runtime-config", status_code=200)
async def get_runtime_config_route(request: RuntimeConfigRequest):
    """Get runtime configuration saved in database."""
    require_privilege(request.auth_token, "manage_server_settings")
    user_id = extract_user_id(auth_token=request.auth_token)
    user_manager = require_component("user_manager")
    include_secrets = bool(
        request.include_secrets and user_manager.is_server_owner(user_id=user_id)
    )
    database_handler = require_component("database_handler")
    runtime_config = database_handler.get_runtime_config(include_secrets=include_secrets)
    return {
        "status_code": 200,
        "runtime_config": runtime_config,
        "include_secrets": include_secrets,
    }


@router.put("/api/v1/system/runtime-config", status_code=200)
async def update_runtime_config_route(request: RuntimeConfigUpdateRequest):
    """Update runtime configuration values in database."""
    require_privilege(request.auth_token, "manage_server_settings")
    database_handler = require_component("database_handler")
    config_handler = require_component("config_handler")

    default_map = database_handler.get_runtime_default_map()
    allowed_keys = set(default_map.keys())
    updates = {k: v for k, v in request.settings.items() if k in allowed_keys}
    if not updates:
        raise HTTPException(status_code=400, detail="No valid runtime config keys provided.")

    secret_keys = {key for key, (_, is_secret) in default_map.items() if is_secret}
    config_handler.write_config(
        database_handler=database_handler,
        config_updates=updates,
        secret_keys=secret_keys,
    )

    if api_initializer.config is not None:
        for key, value in updates.items():
            if hasattr(api_initializer.config, key):
                setattr(api_initializer.config, key, value)

    restart_required_keys = sorted(
        key
        for key in updates.keys()
        if key
        in {
            "API_HOST",
            "API_PORT",
            "WORKERS",
            "JWT_SECRET",
            "RTC_JOIN_SECRET",
            "RTC_INTERNAL_SECRET",
            "RTC_BOOTSTRAP_SECRET",
            "RTC_UDP_PORT_MIN",
            "RTC_UDP_PORT_MAX",
        }
    )

    return {
        "status_code": 200,
        "message": "Runtime config updated successfully.",
        "updated_keys": sorted(updates.keys()),
        "restart_required_keys": restart_required_keys,
        "affected_keys": sorted(updates.keys()),
        "restart_required": bool(restart_required_keys),
    }


@router.post("/api/v1/system/activity-metrics", status_code=200)
async def get_activity_metrics_route(request: AuthTokenQuery):
    """Get current activity metrics for the control panel dashboard."""
    require_privilege(request.auth_token, "view_server_stats")
    database_handler = require_component("database_handler")
    try:
        metrics_data = database_handler.get_latest_activity_metrics()
        return {"status_code": 200, "activity_metrics": metrics_data}
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get activity metrics: {exc}",
        ) from exc


@router.post("/api/v1/system/server-overview", status_code=200)
async def get_server_overview_route(request: AuthTokenQuery):
    """Get comprehensive server overview data for control panel."""
    require_privilege(request.auth_token, "view_server_stats")
    database_handler = require_component("database_handler")

    try:
        total_users = database_handler.count_users()
        total_channels = len(database_handler.get_channels_names())
        now = datetime.now()
        messages_last_hour = database_handler.get_message_count_by_period(now - timedelta(hours=1), now)
        active_users = database_handler.get_user_status_counts()
        messages_this_period = database_handler.get_message_count_by_period(now - timedelta(days=7), now)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get server overview: {exc}",
        ) from exc

    return {
        "status_code": 200,
        "server_overview": {
            "total_users": total_users,
            "total_channels": total_channels,
            "messages_last_hour": messages_last_hour,
            "active_users": sum(
                active_users.get(key, 0) for key in ("online", "idle", "dnd", "afk")
            ),
            "messages_this_period": messages_this_period,
        },
    }
