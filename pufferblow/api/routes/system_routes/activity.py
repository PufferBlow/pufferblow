"""Logs and activity routes."""

from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException
from loguru import logger

from pufferblow.core.bootstrap import api_initializer

from .shared import (
    RecentActivityRequest,
    ServerLogsRequest,
    list_log_candidates,
    log_activity,
    require_component,
    require_privilege,
)

router = APIRouter()


def _level_matches(line: str, requested_level: str | None) -> bool:
    """Check whether a log line matches the requested level filter."""
    if not requested_level:
        return True

    line_upper = line.upper()
    level_upper = requested_level.upper()
    matches = {
        "DEBUG": ("DEBUG", "DBUG"),
        "INFO": ("INFO", "INF"),
        "WARNING": ("WARNING", "WARN"),
        "ERROR": ("ERROR", "ERR"),
        "CRITICAL": ("CRITICAL", "CRIT"),
    }
    tokens = matches.get(level_upper, ())
    return any(token in line_upper for token in tokens)


def _colorize_log_line(line: str) -> str:
    """Preserve simple ANSI coloring for log UI."""
    line_upper = line.upper()
    if "ERROR" in line_upper or "ERR" in line_upper:
        return f"\x1b[31m{line}\x1b[0m"
    if "WARNING" in line_upper or "WARN" in line_upper:
        return f"\x1b[33m{line}\x1b[0m"
    if "DEBUG" in line_upper:
        return f"\x1b[36m{line}\x1b[0m"
    if "INFO" in line_upper:
        return f"\x1b[32m{line}\x1b[0m"
    return line


@router.post("/api/v1/system/logs", status_code=200)
async def get_server_logs_route(request: ServerLogsRequest):
    """Get server logs with filtering options."""
    user_id = require_privilege(request.auth_token, "view_audit_logs")
    config = api_initializer.config
    log_files, searched_paths = list_log_candidates(
        getattr(config, "LOGS_PATH", None) if config else None
    )

    if not log_files:
        return {
            "status_code": 200,
            "logs": [],
            "message": "No log files found. Logs may not be configured or accessible.",
            "searched_paths": searched_paths,
        }

    latest_log = max(log_files, key=lambda path: path.stat().st_mtime)
    try:
        with open(latest_log, encoding="utf-8", errors="replace") as file_obj:
            lines = list(reversed(file_obj.readlines()))[: request.lines]
    except Exception as exc:
        logger.error("Failed to read log file {}: {}", latest_log, exc)
        return {
            "status_code": 200,
            "logs": [],
            "message": f"Error reading log file: {exc}",
            "available_log_files": [str(path) for path in log_files],
        }

    logs_content = []
    for line in lines:
        if request.search and request.search.lower() not in line.lower():
            continue
        if not _level_matches(line, request.level):
            continue
        stripped = line.strip()
        logs_content.append(
            {"content": _colorize_log_line(stripped), "raw": stripped}
        )

    log_activity(
        activity_type="logs_viewed",
        user_id=user_id,
        title="Server logs accessed",
        description=(
            f"Privileged user accessed logs with filters: lines={request.lines}, "
            f"search='{request.search or 'None'}', level='{request.level or 'None'}'"
        ),
        metadata={
            "action": "logs_access",
            "lines_requested": request.lines,
            "search_filter": request.search,
            "level_filter": request.level,
            "log_file": str(latest_log),
        },
    )

    return {
        "status_code": 200,
        "logs": logs_content,
        "total_lines": len(logs_content),
        "filtered": bool(request.search or request.level),
        "log_file": str(latest_log),
        "note": "Logs are displayed with ANSI color codes preserved. Latest entries appear first.",
    }


@router.post("/api/v1/system/recent-activity", status_code=200)
async def get_recent_activity_route(request: RecentActivityRequest):
    """Get recent activity events from the server."""
    try:
        user_manager = require_component("user_manager")
        database_handler = require_component("database_handler")
        require_privilege(request.auth_token, "view_audit_logs")

        recent_activities = database_handler.get_recent_activities(limit=request.limit)
        activities = []
        for activity in recent_activities:
            metadata = json.loads(activity.metadata_json) if activity.metadata_json else {}
            user_info = None
            if activity.user_id:
                profile = user_manager.user_profile(activity.user_id)
                if profile:
                    user_info = {
                        "id": activity.user_id,
                        "username": profile.get("username", "Unknown"),
                        "avatar_url": (
                            "https://api.dicebear.com/7.x/bottts-neutral/svg"
                            f"?seed={activity.user_id[:8]}&backgroundColor=5865f2"
                        ),
                    }

            title = activity.activity_type.replace("_", " ").title()
            description = f"System activity: {activity.activity_type}"
            if activity.activity_type == "file_upload":
                filename = "a file"
                if metadata.get("file_url"):
                    candidate = metadata["file_url"].split("/")[-1]
                    if "." in candidate and candidate.rsplit(".", 1)[1]:
                        filename = candidate
                directory = metadata.get("directory", "files")
                title = f"File uploaded to {directory}"
                description = f"File '{filename}' was uploaded"
            elif activity.activity_type == "user_joined":
                title = "User joined the server"
                description = "A new member joined the community"
            elif activity.activity_type == "channel_created":
                channel_name = metadata.get("channel_name", "unknown channel")
                title = f"Channel created: #{channel_name}"
                description = f"New channel '{channel_name}' was created"
            elif activity.activity_type == "user_left":
                title = "User left the server"
                description = "A member left the community"
            elif activity.activity_type == "server_settings_updated":
                field = metadata.get("field", "unknown")
                new_value = metadata.get("new_value", "unknown")
                username = user_info.get("username", "Unknown User") if user_info else "Unknown User"
                title = f"Server settings updated by {username}: {field}"
                description = f"{username} changed {field} to '{new_value}'"

            activities.append(
                {
                    "id": str(activity.activity_id),
                    "type": activity.activity_type,
                    "title": title,
                    "description": description,
                    "timestamp": activity.created_at.isoformat(),
                    "user": user_info,
                    "metadata": metadata,
                }
            )

        return {"status_code": 200, "activities": activities}
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("Failed to get recent activity data: {}", exc)
        return {"status_code": 200, "activities": []}
