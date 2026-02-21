"""
Message routes module.

This module handles all message-related operations including:
- Loading messages (with pagination)
- Sending messages (with attachments)
- Marking messages as read
- Deleting messages
"""

import sys
import mimetypes
from datetime import datetime
from urllib.parse import urlparse
from fastapi import APIRouter, Depends, Form, UploadFile, exceptions
from loguru import logger

from pufferblow.api.schemas import (
    LoadMessagesResponse,
    MessageData,
    SendMessageForm,
)
from pufferblow.api.dependencies import get_current_user, check_channel_access
from pufferblow.core.bootstrap import api_initializer

# Create router for message-related endpoints
router = APIRouter(prefix="/api/v1/channels/{channel_id}")


def _extract_storage_hash(storage_url: str) -> str | None:
    """Extract storage hash from canonical `/storage/<hash>` style URLs."""
    if not storage_url:
        return None

    path = urlparse(storage_url).path if "://" in storage_url else storage_url
    storage_base = api_initializer.config.STORAGE_BASE_URL.rstrip("/")
    if not path.startswith(f"{storage_base}/"):
        return None

    suffix = path[len(storage_base) + 1 :]
    if "/" in suffix:
        return None
    if len(suffix) != 64:
        return None
    return suffix


def _serialize_attachment(storage_url: str) -> dict:
    """Build a client-facing attachment object from a storage URL."""
    file_hash = _extract_storage_hash(storage_url)
    if file_hash:
        file_obj = api_initializer.database_handler.get_file_object_by_hash(file_hash)
        if file_obj:
            return {
                "url": storage_url,
                "filename": file_obj.filename,
                "type": file_obj.mime_type,
                "size": file_obj.file_size,
            }

    fallback_name = (
        (urlparse(storage_url).path if "://" in storage_url else storage_url)
        .rstrip("/")
        .split("/")[-1]
        or "attachment"
    )
    guessed_type = mimetypes.guess_type(fallback_name)[0] or "application/octet-stream"
    return {
        "url": storage_url,
        "filename": fallback_name,
        "type": guessed_type,
        "size": None,
    }


# Dependency to parse form data into Pydantic model
async def parse_send_message_form(
    auth_token: str = Form(..., description="User's authentication token"),
    message: str = Form("", description="Message content"),
    sent_at: str = Form(
        "", description="ISO timestamp when message was sent by client"
    ),
    attachments: list[UploadFile] = Form([], description="File attachments (optional)"),
) -> tuple[SendMessageForm, list[UploadFile]]:
    """
    Parse multipart form data into a validated SendMessageForm.
    """
    form_data = SendMessageForm(
        auth_token=auth_token,
        message=message,
        sent_at=sent_at,
        attachments=[],
    )

    return form_data, attachments


@router.get("/load_messages", status_code=200, response_model=LoadMessagesResponse)
async def channel_load_messages(
    auth_token: str,
    channel_id: str,
    page: int | None = 1,
    messages_per_page: int | None = 20,
):
    """
    Load messages from a channel with pagination.

    Args:
        auth_token: User's authentication token
        channel_id: Channel ID
        page: Page number (default: 1)
        messages_per_page: Messages per page (default: 20, max: 50)

    Returns:
        200 OK: List of messages
        400 BAD REQUEST: Invalid parameters
        404 NOT FOUND: Channel not found or no access
    """
    # Check max messages per page limit
    if messages_per_page > api_initializer.config.MAX_MESSAGES_PER_PAGE:
        raise exceptions.HTTPException(
            detail=f"`messages_per_page` number exceeded the maximal number which is '{api_initializer.config.MAX_MESSAGES_PER_PAGE}'",
            status_code=400,
        )

    user_id = get_current_user(auth_token)

    # Check channel access (handles private channels)
    check_channel_access(user_id, channel_id)

    # Load messages
    messages = api_initializer.messages_manager.load_messages(
        channel_id=channel_id, messages_per_page=messages_per_page, page=page
    )

    # Convert raw messages to Pydantic MessageData models
    message_data_list = []
    for msg in messages:
        message_data_list.append(
            MessageData(
                message_id=msg.get("message_id", ""),
                channel_id=msg.get("channel_id", None),
                conversation_id=msg.get("conversation_id", None),
                sender_id=msg.get("sender_id", ""),
                message=msg.get("message", ""),
                sent_at=msg.get("sent_at", ""),
                attachments=msg.get("attachments", []),
                username=msg.get("sender_username", ""),
                # User profile fields for reducing frontend requests
                sender_user_id=msg.get("sender_user_id"),
                sender_avatar_url=msg.get("sender_avatar_url"),
                sender_banner_url=msg.get("sender_banner_url"),
                sender_status=msg.get("sender_status"),
                sender_roles=msg.get("sender_roles"),
                sender_about=msg.get("sender_about"),
                sender_last_seen=msg.get("sender_last_seen"),
                sender_created_at=msg.get("sender_created_at"),
            )
        )

    return LoadMessagesResponse(status_code=200, messages=message_data_list)


@router.post("/send_message")
async def channel_send_message(
    channel_id: str,
    form_data: tuple[SendMessageForm, list[UploadFile]] = Depends(
        parse_send_message_form
    ),
):
    """
    Send a message to a channel with optional attachments.

    Args:
        channel_id: Channel ID
        form_data: Validated form data and file attachments

    Returns:
        201 CREATED: Message sent successfully
        400 BAD REQUEST: Invalid message or attachments
        404 NOT FOUND: Channel not found or no access
    """
    # Unpack validated form data and attachments
    validated_form, attachments = form_data
    auth_token = validated_form.auth_token
    message = validated_form.message
    sent_at = validated_form.sent_at

    # Check message size
    if sys.getsizeof(message) > api_initializer.config.MAX_MESSAGE_SIZE:
        raise exceptions.HTTPException(
            detail="the message is too long.", status_code=400
        )

    # Check if message is empty and no attachments
    if not message.strip() and not attachments:
        raise exceptions.HTTPException(
            detail="Either a message or attachments must be provided.", status_code=400
        )

    user_id = get_current_user(auth_token)

    # Check channel access
    check_channel_access(user_id, channel_id)

    # Handle file uploads
    attachment_urls = []
    if attachments:
        for file in attachments:
            if file.filename:
                try:
                    # Use the storage manager to save the attachment
                    storage_url, is_duplicate = (
                        await api_initializer.storage_manager.validate_and_save_categorized_file(
                            file=file,
                            user_id=user_id,
                            force_category="attachments",
                            check_duplicates=True,
                        )
                    )
                    attachment_urls.append(storage_url)

                    # Log attachment upload
                    try:
                        file_size = getattr(file, "size", 0)
                        file_type = file.content_type or "unknown"
                        activity_data = {
                            "event_type": "message_attachment",
                            "description": f"Attachment '{file.filename}' uploaded for message in channel {channel_id}",
                            "metadata": {
                                "file_url": storage_url,
                                "file_size": file_size,
                                "file_type": file_type,
                                "channel_id": channel_id,
                                "is_duplicate": is_duplicate,
                            },
                            "user_id": user_id,
                            "timestamp": datetime.utcnow().isoformat(),
                        }
                        api_initializer.database_handler.create_activity(activity_data)
                    except Exception as e:
                        logger.warning(
                            f"Failed to log attachment upload activity: {str(e)}"
                        )

                except Exception as e:
                    logger.error(
                        f"Failed to upload attachment '{file.filename}': {str(e)}"
                    )
                    raise exceptions.HTTPException(
                        status_code=500,
                        detail=f"Failed to upload attachment '{file.filename}'. Please try again.",
                    )

    # Send the message
    message_obj = api_initializer.messages_manager.send_message(
        channel_id=channel_id,
        user_id=user_id,
        message=message,
        attachments=attachment_urls,
        sent_at=sent_at if sent_at.strip() else None,
    )

    # Prepare message dict for broadcasting
    sender_user = api_initializer.user_manager.user_profile(user_id=user_id)

    # Handle sent_at field
    sent_at_value = message_obj.sent_at
    if sent_at_value:
        if isinstance(sent_at_value, str):
            pass
        else:
            sent_at_value = sent_at_value.isoformat()
    else:
        sent_at_value = None

    message_dict = {
        "message_id": str(message_obj.message_id),
        "sender_user_id": str(user_id),
        "channel_id": channel_id,
        "message": message,
        "hashed_message": message_obj.hashed_message,
        "username": sender_user["username"],
        "sender_avatar_url": sender_user.get("avatar_url"),
        "sender_banner_url": sender_user.get("banner_url"),
        "sender_status": sender_user.get("status", "offline"),
        "sender_roles": sender_user.get("roles_ids", []),
        "sender_about": sender_user.get("about"),
        "sender_last_seen": sender_user.get("last_seen"),
        "sender_created_at": sender_user.get("created_at"),
        "sent_at": sent_at_value,
        "attachments": [_serialize_attachment(item) for item in attachment_urls],
    }

    # Broadcast to all eligible users using global websocket system
    await api_initializer.websockets_manager.broadcast_to_eligible_users(
        channel_id, message_dict
    )

    return {
        "status_code": 201,
        "message": "message sent successfully",
        "message_id": str(message_obj.message_id),
        "attachments": attachment_urls,
    }


@router.put("/mark_message_as_read")
async def channel_mark_message_as_read(
    auth_token: str, channel_id: str, message_id: str
):
    """
    Mark a message as read.

    Args:
        auth_token: User's authentication token
        channel_id: Channel ID
        message_id: Message ID to mark as read

    Returns:
        201 CREATED: Message marked as read
        404 NOT FOUND: Channel or message not found
    """
    user_id = get_current_user(auth_token)

    # Mark the message as read
    api_initializer.messages_manager.mark_message_as_read(
        user_id=user_id, message_id=message_id, channel_id=channel_id
    )

    return {
        "status_code": 201,
        "message": "The `message_id` was successfully mark as read",
    }


@router.delete("/delete_message")
async def channel_delete_message(auth_token: str, channel_id: str, message_id: str):
    """
    Delete a message from a channel.

    Args:
        auth_token: User's authentication token
        channel_id: Channel ID
        message_id: Message ID to delete

    Returns:
        204 NO CONTENT: Message deleted successfully
        401 UNAUTHORIZED: Not authorized to delete message
        404 NOT FOUND: Channel or message not found
    """
    user_id = get_current_user(auth_token)

    # Check channel access
    is_channel_private = api_initializer.channels_manager.is_private(
        channel_id=channel_id
    )
    is_server_owner = api_initializer.user_manager.is_server_owner(user_id=user_id)
    is_admin = api_initializer.user_manager.is_admin(user_id=user_id)

    if is_channel_private and (not is_server_owner or not is_admin):
        raise exceptions.HTTPException(
            status_code=404,
            detail="The provided channel ID does not exist or could not be found.",
        )

    # Check if user is sender or admin/owner
    if not api_initializer.messages_manager.check_message_sender(
        message_id=message_id
    ) and (not is_server_owner or not is_admin):
        raise exceptions.HTTPException(
            detail="You are not authorized to delete this message", status_code=401
        )

    # Delete the message
    api_initializer.messages_manager.delete_message(
        message_id=message_id, channel_id=channel_id
    )

    return {"status_code": 204, "message": "The message have been deleted successfully"}
