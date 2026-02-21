"""
Channel routes module.

This module handles all channel-related operations including:
- Listing channels
- Creating channels
- Deleting channels
- Managing channel members (add/remove users)
- Voice channel operations
"""

import uuid
import json
from datetime import datetime
from fastapi import APIRouter, exceptions
from loguru import logger

from pufferblow.api.schemas import (
    AuthTokenQuery,
    CreateChannelRequest,
    VoiceChannelJoinResponse,
    VoiceChannelStatusResponse,
)
from pufferblow.api.dependencies import (
    get_current_user,
    require_admin,
    check_channel_access,
)
from pufferblow.core.bootstrap import api_initializer
from pufferblow.api.logger.msgs import info
from pufferblow.api.database.tables.activity_audit import ActivityAudit

# Create router for channel-related endpoints
router = APIRouter(prefix="/api/v1/channels")


@router.get("", status_code=200)
def channels_route():
    """Channels routes start point"""
    return {"status_code": 200, "message": "Channels route"}


@router.post("/list/", status_code=200)
async def list_channels_route(request: AuthTokenQuery):
    """
    Get list of all available channels.
    
    Excludes private channels unless user is admin/owner or has been invited.

    Args:
        request (AuthTokenQuery): Request with auth_token

    Returns:
        200 OK: List of channels
        404 NOT FOUND: Invalid auth_token
    """
    user_id = get_current_user(request.auth_token)

    try:
        channels_list = api_initializer.channels_manager.list_channels(user_id=user_id)

        logger.info(
            f"Successfully retrieved {len(channels_list) if channels_list else 0} channels for user {user_id}"
        )

        return {"status_code": 200, "channels": channels_list or []}
    except Exception as e:
        logger.error(f"Error retrieving channels for user {user_id}: {str(e)}")
        raise exceptions.HTTPException(
            status_code=500, detail="Internal server error while fetching channels"
        )


@router.post("/create/", status_code=200)
async def create_new_channel_route(request: CreateChannelRequest):
    """
    Create a new channel (admin/owner only).

    Args:
        request (CreateChannelRequest): Request with channel details

    Returns:
        200 OK: Channel created successfully
        403 FORBIDDEN: User is not admin/owner
        409 CONFLICT: Channel name already exists
    """
    logger.debug(f"Channel creation request at {datetime.now()}")
    logger.debug(f"Channel name: {request.channel_name}")
    logger.debug(f"Is private: {request.is_private}")

    # Require admin permission using dependency
    user_id = require_admin(request.auth_token)
    logger.debug(f"User {user_id} is authorized to create channels")

    # Check if channel name already exists
    channels_names = api_initializer.database_handler.get_channels_names()
    logger.debug(f"Existing channel names: {channels_names}")

    if request.channel_name in channels_names:
        logger.warning(
            f"Channel creation failed: Channel name '{request.channel_name}' already exists"
        )
        raise exceptions.HTTPException(
            status_code=409,
            detail="Channel name already exists, please change it and try again.",
        )

    logger.debug(f"Creating channel '{request.channel_name}' for user {user_id}")

    try:
        channel_data = api_initializer.channels_manager.create_channel(
            user_id=user_id,
            channel_name=request.channel_name,
            is_private=request.is_private,
            channel_type=request.channel_type,
        )
        logger.info(
            f"Channel '{request.channel_name}' created successfully by user {user_id}"
        )

        # Log channel creation activity
        api_initializer.database_handler.create_activity_audit_entry(
            ActivityAudit(
                activity_id=str(uuid.uuid4()),
                activity_type="channel_created",
                user_id=str(user_id),
                title=f"Channel #{request.channel_name} created",
                description=f"New {'private' if request.is_private else 'public'} channel '{request.channel_name}' was created",
                metadata_json=json.dumps(
                    {
                        "channel_name": request.channel_name,
                        "channel_id": str(channel_data.channel_id),
                        "is_private": request.is_private,
                        "created_by": str(user_id),
                    }
                ),
            )
        )
    except Exception as e:
        logger.error(f"Channel creation failed: {str(e)}")
        raise

    return {
        "status_code": 200,
        "message": "Channel created successfully",
        "channel_data": channel_data.to_dict(),
    }


@router.delete("/{channel_id}/delete")
async def delete_channel_route(auth_token: str, channel_id: str):
    """
    Delete a channel (admin/owner only).

    Args:
        auth_token: User's authentication token
        channel_id: Channel ID to delete

    Returns:
        200 OK: Channel deleted
        403 FORBIDDEN: User is not admin/owner
        404 NOT FOUND: Channel not found
    """
    # Require admin permission
    user_id = require_admin(auth_token)

    # Delete the channel
    api_initializer.channels_manager.delete_channel(channel_id=channel_id)

    logger.info(info.INFO_CHANNEL_DELETED(user_id=user_id, channel_id=channel_id))

    return {
        "status_code": 200,
        "message": f"Channel: '{channel_id}' deleted successfully",
    }


@router.put("/{channel_id}/add_user", status_code=200)
async def add_user_to_private_channel_route(
    auth_token: str, channel_id: str, to_add_user_id: str
):
    """
    Add user to private channel (admin/owner only).

    Args:
        auth_token: User's authentication token
        channel_id: Channel ID
        to_add_user_id: User ID to add

    Returns:
        200 OK: User added to channel
        403 FORBIDDEN: User is not admin/owner
        404 NOT FOUND: Channel or user not found
    """
    # Require admin permission
    user_id = require_admin(auth_token)

    # Check if targeted user exists
    if not api_initializer.user_manager.check_user(user_id=to_add_user_id):
        raise exceptions.HTTPException(
            detail=f"To add User ID: '{to_add_user_id}' is invalid/not found. Please enter a valid 'user_id' and try again.",
            status_code=404,
        )

    # Skip if targeted user is admin
    if api_initializer.user_manager.is_admin(user_id=to_add_user_id):
        return {
            "status_code": 200,
            "message": "Skipping the operation, the targeted user is an admin.",
        }

    # Skip if targeted user is server owner
    if api_initializer.user_manager.is_server_owner(user_id=to_add_user_id):
        return {
            "status_code": 200,
            "message": "Skipping the operation, the targeted user is the server owner.",
        }

    # Check if channel is private
    if not api_initializer.channels_manager.is_private(channel_id=channel_id):
        logger.info(
            info.INFO_CHANNEL_IS_NOT_PRIVATE(
                user_id=user_id, to_add_user_id=to_add_user_id, channel_id=channel_id
            )
        )

        raise exceptions.HTTPException(
            detail=f"Channel with Channel ID: '{channel_id}' is not private. Only private channels are allowed.",
            status_code=200,
        )

    # Add user to channel
    api_initializer.channels_manager.add_user_to_channel(
        user_id=user_id, to_add_user_id=to_add_user_id, channel_id=channel_id
    )

    return {
        "status_code": 200,
        "message": f"User ID: '{to_add_user_id}' added to Channel ID: '{channel_id}'",
    }


@router.delete("/{channel_id}/remove_user", status_code=200)
async def remove_user_from_channel_route(
    auth_token: str, channel_id: str, to_remove_user_id: str
):
    """
    Remove user from private channel (admin/owner only).

    Args:
        auth_token: User's authentication token
        channel_id: Channel ID
        to_remove_user_id: User ID to remove

    Returns:
        200 OK: User removed from channel
        403 FORBIDDEN: User is not admin/owner or trying to remove admin/owner
        404 NOT FOUND: Channel or user not found
    """
    # Require admin permission
    user_id = require_admin(auth_token)

    # Check if targeted user is admin
    if api_initializer.user_manager.is_admin(user_id=to_remove_user_id):
        import pufferblow.core.constants as constants

        logger.warning(
            constants.FAILD_TO_REMOVE_USER_FROM_CHANNEL_TARGETED_USER_IS_AN_ADMIN(
                user_id=user_id,
                channel_id=channel_id,
                to_remove_user_id=to_remove_user_id,
            )
        )

        raise exceptions.HTTPException(
            detail=f"Error removing Admin User ID: '{to_remove_user_id}'. The user is an admin",
            status_code=403,
        )

    # Check if targeted user is server owner
    if api_initializer.user_manager.is_server_owner(user_id=to_remove_user_id):
        import pufferblow.core.constants as constants

        logger.warning(
            constants.FAILD_TO_REMOVE_USER_FROM_CHANNEL_TARGETED_USER_IS_SERVER_OWNER(
                user_id=user_id,
                channel_id=channel_id,
                to_remove_user_id=to_remove_user_id,
            )
        )

        raise exceptions.HTTPException(
            detail=f"Error removing User ID: '{to_remove_user_id}', this user is the server owner.",
            status_code=403,
        )

    # Check if channel is private
    if not api_initializer.channels_manager.is_private(channel_id=channel_id):
        logger.info(
            info.INFO_CHANNEL_IS_NOT_PRIVATE(
                user_id=user_id, to_add_user_id=to_remove_user_id, channel_id=channel_id
            )
        )

        raise exceptions.HTTPException(
            detail=f"Channel with Channel ID: '{channel_id}' is not private. Only private channels are allowed.",
            status_code=200,
        )

    # Remove user from channel
    api_initializer.channels_manager.remove_user_from_channel(
        user_id=user_id, channel_id=channel_id, to_remove_user_id=to_remove_user_id
    )

    return {
        "status_code": 200,
        "message": f"User ID: '{to_remove_user_id}' was successfully removed from Channel ID: '{channel_id}'",
    }


# Voice Channel Routes

@router.post(
    "/{channel_id}/join-audio",
    status_code=200,
    response_model=VoiceChannelJoinResponse,
)
async def join_voice_channel_route(auth_token: str, channel_id: str):
    """
    Join a voice channel using WebRTC.

    Args:
        auth_token: User's authentication token
        channel_id: Voice channel ID

    Returns:
        200 OK: WebRTC configuration for voice channel
        400 BAD REQUEST: Voice channels disabled or invalid request
        404 NOT FOUND: Channel not found
        403 FORBIDDEN: Access denied
        409 CONFLICT: Already in another voice channel
    """
    user_id = get_current_user(auth_token)
    logger.debug(
        f"Voice channel join request | User: {user_id} | Channel: {channel_id} | Timestamp: {datetime.now().isoformat()}"
    )

    # Check if aiortc/WebRTC is available
    try:
        from pufferblow.api.webrtc.webrtc_manager import AIORTC_AVAILABLE

        if not AIORTC_AVAILABLE:
            logger.error(
                f"Voice channels unavailable | User: {user_id} | Reason: aiortc not installed"
            )
            raise exceptions.HTTPException(
                status_code=400,
                detail="Voice channels are not available - aiortc library is not installed",
            )
    except ImportError as e:
        logger.error(f"Voice channels unavailable | User: {user_id} | Reason: {str(e)}")
        raise exceptions.HTTPException(
            status_code=400,
            detail="Voice channels are not available - aiortc library is not installed",
        )

    # Check channel access
    check_channel_access(user_id, channel_id)

    # Check if user is already in another voice channel
    try:
        webrtc_manager = api_initializer.channels_manager.get_webrtc_manager_singleton()
        if hasattr(webrtc_manager, "get_user_current_channel"):
            current_channel = webrtc_manager.get_user_current_channel(user_id)
            if current_channel and current_channel != channel_id:
                logger.warning(
                    f"User already in voice channel | User: {user_id} | Requested: {channel_id} | Current: {current_channel}"
                )
                raise exceptions.HTTPException(
                    status_code=409,
                    detail=f"You're already in voice channel {current_channel}. Leave it first or use client prompt to switch.",
                )
    except exceptions.HTTPException:
        raise
    except Exception as e:
        logger.debug(f"Single channel check failed | User: {user_id} | Error: {str(e)}")

    logger.info(
        f"Voice channel WebRTC join attempt | User: {user_id} | Channel: {channel_id}"
    )

    # Join voice channel
    try:
        result = await api_initializer.channels_manager.join_voice_channel(
            user_id, channel_id
        )
        logger.debug(
            f"WebRTC manager response | User: {user_id} | Channel: {channel_id} | Result: {result}"
        )

        if "error" in result:
            logger.warning(
                f"Voice channel WebRTC join failed | User: {user_id} | Channel: {channel_id} | Error: {result['error']}"
            )
            raise exceptions.HTTPException(status_code=400, detail=result["error"])

        # Log successful join
        participant_count = result.get("participant_count", 0)
        channel_type = result.get("webrtc_config", {}).get("channel_type", "unknown")
        logger.info(
            f"Voice channel WebRTC join successful | User: {user_id} | Channel: {channel_id} | Type: {channel_type} | Participants: {participant_count}"
        )

        # Log activity
        api_initializer.database_handler.create_activity_audit_entry(
            ActivityAudit(
                activity_id=str(uuid.uuid4()),
                activity_type="voice_channel_join",
                user_id=user_id,
                title=f"Joined voice channel #{result.get('channel_name', channel_id)}",
                description=f"User joined voice channel with {participant_count} participants",
                metadata_json=json.dumps(
                    {
                        "channel_id": channel_id,
                        "channel_type": channel_type,
                        "participant_count": participant_count,
                        "action": "join_voice_channel",
                    }
                ),
            )
        )

        return {
            "status_code": 200,
            "channel_id": channel_id,
            "user_id": user_id,
            "participants": result.get("participants", 0),
            "participant_count": result.get("participant_count", 0),
            "webrtc_config": result.get("webrtc_config", {}),
        }

    except exceptions.HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"Unexpected error in voice channel join | User: {user_id} | Channel: {channel_id} | Error: {str(e)}",
            exc_info=True,
        )
        raise exceptions.HTTPException(
            status_code=500, detail="Internal server error during voice channel join"
        )


@router.post("/{channel_id}/leave-audio", status_code=200)
async def leave_voice_channel_route(auth_token: str, channel_id: str):
    """
    Leave a voice channel.

    Args:
        auth_token: User's authentication token
        channel_id: Voice channel ID

    Returns:
        200 OK: Successfully left voice channel
        404 NOT FOUND: Channel not found
    """
    user_id = get_current_user(auth_token)

    logger.info(
        f"Voice channel leave attempt | User: {user_id} | Channel: {channel_id}"
    )

    result = await api_initializer.channels_manager.leave_voice_channel(
        user_id, channel_id
    )

    if "error" in result:
        logger.warning(
            f"Voice channel leave failed | User: {user_id} | Channel: {channel_id} | Error: {result['error']}"
        )
        raise exceptions.HTTPException(status_code=400, detail=result["error"])

    logger.info(
        f"Voice channel leave successful | User: {user_id} | Channel: {channel_id}"
    )

    return {"status_code": 200, "message": "Successfully left voice channel"}


@router.get(
    "/{channel_id}/audio-status",
    status_code=200,
    response_model=VoiceChannelStatusResponse,
)
async def get_voice_channel_status_route(auth_token: str, channel_id: str):
    """
    Get voice channel status including participants.

    Args:
        auth_token: User's authentication token
        channel_id: Voice channel ID

    Returns:
        200 OK: Channel status with participants
        404 NOT FOUND: Channel not found
        403 FORBIDDEN: Access denied
    """
    user_id = get_current_user(auth_token)

    # Check channel access
    check_channel_access(user_id, channel_id)

    result = api_initializer.channels_manager.get_voice_channel_status(channel_id)

    if "error" in result:
        raise exceptions.HTTPException(status_code=404, detail=result["error"])

    return {
        "status_code": 200,
        "channel_id": channel_id,
        "room_name": result.get("room_name"),
        "participants": result.get("participants", []),
        "participant_count": result.get("participant_count", 0),
    }
