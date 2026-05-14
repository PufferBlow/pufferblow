"""
Message routes module.

This module handles all message-related operations including:
- Loading messages (with pagination)
- Sending messages (with attachments)
- Marking messages as read
- Deleting messages
"""

from datetime import datetime
from fastapi import APIRouter, Depends, Form, UploadFile, exceptions
from loguru import logger

from pufferblow.api.schemas import (
    LoadMessagesResponse,
    MessageData,
    ReactionSummary,
    SearchMessagesResponse,
    SendMessageForm,
)

SEARCH_MIN_QUERY_LENGTH = 2
SEARCH_MAX_QUERY_LENGTH = 256
SEARCH_DEFAULT_LIMIT = 20
SEARCH_MAX_LIMIT = 50
SEARCH_DEFAULT_SCAN_LIMIT = 1000
SEARCH_MAX_SCAN_LIMIT = 5000

# Reactions must be short. The DB column is 32 chars to comfortably fit
# multi-codepoint emoji like flags or skin-tone modifiers.
REACTION_EMOJI_MAX_LENGTH = 32
from pufferblow.api.dependencies import (
    check_channel_access,
    ensure_user_not_timed_out,
    get_current_user,
    require_privilege,
)
from pufferblow.core.bootstrap import api_initializer

# Create router for message-related endpoints
router = APIRouter(prefix="/api/v1/channels/{channel_id}")


def _get_message_and_attachment_policy() -> tuple[int, int]:
    """Return instance-defined message and attachment limits."""
    settings = api_initializer.database_handler.get_server_settings()
    storage_manager = api_initializer.storage_manager
    storage_manager.update_server_limits()

    max_message_length = getattr(settings, "max_message_length", None)
    if not max_message_length:
        max_message_length = api_initializer.config.MAX_MESSAGE_SIZE

    max_total_attachment_mb = getattr(
        storage_manager, "MAX_TOTAL_ATTACHMENT_SIZE_MB", 50
    )
    return int(max_message_length), int(max_total_attachment_mb)


def _measure_upload_size(file: UploadFile) -> int:
    """Measure an uploaded file without consuming its stream permanently."""
    if hasattr(file.file, "getbuffer"):
        return len(file.file.getbuffer())

    current_position = file.file.tell()
    file.file.seek(0, 2)
    size = file.file.tell()
    file.file.seek(current_position)
    return size


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
        channel_id=channel_id,
        messages_per_page=messages_per_page,
        page=page,
        viewer_user_id=user_id,
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
                reactions=msg.get("reactions", []),
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


@router.get("/search", status_code=200, response_model=SearchMessagesResponse)
async def channel_search_messages(
    auth_token: str,
    channel_id: str,
    q: str,
    limit: int | None = SEARCH_DEFAULT_LIMIT,
    scan_limit: int | None = SEARCH_DEFAULT_SCAN_LIMIT,
):
    """
    Substring search across a channel's recent messages.

    Messages are encrypted at rest, so the server decrypts up to ``scan_limit``
    most-recent messages and returns up to ``limit`` matches, newest first.
    For channels larger than ``scan_limit``, the response sets
    ``truncated_scan: true`` and only the recent window is searched. True
    full-text search across all history is a v1.1 item (see PUFFERBLOW_MVP.md).

    Args:
        auth_token: User's authentication token.
        channel_id: Channel ID.
        q: Search query (2-256 chars).
        limit: Max matches to return (default 20, max 50).
        scan_limit: Max messages to decrypt-and-scan (default 1000, max 5000).

    Returns:
        200 OK: Matches plus scan metadata.
        400 BAD REQUEST: Query out of bounds, or limits exceeded.
        404 NOT FOUND: Channel not found or no access.
    """
    normalized_query = (q or "").strip()
    if len(normalized_query) < SEARCH_MIN_QUERY_LENGTH:
        raise exceptions.HTTPException(
            detail=f"`q` must be at least {SEARCH_MIN_QUERY_LENGTH} characters.",
            status_code=400,
        )
    if len(normalized_query) > SEARCH_MAX_QUERY_LENGTH:
        raise exceptions.HTTPException(
            detail=f"`q` exceeds the {SEARCH_MAX_QUERY_LENGTH}-character maximum.",
            status_code=400,
        )

    effective_limit = limit or SEARCH_DEFAULT_LIMIT
    if effective_limit < 1 or effective_limit > SEARCH_MAX_LIMIT:
        raise exceptions.HTTPException(
            detail=f"`limit` must be between 1 and {SEARCH_MAX_LIMIT}.",
            status_code=400,
        )

    effective_scan = scan_limit or SEARCH_DEFAULT_SCAN_LIMIT
    if effective_scan < 1 or effective_scan > SEARCH_MAX_SCAN_LIMIT:
        raise exceptions.HTTPException(
            detail=f"`scan_limit` must be between 1 and {SEARCH_MAX_SCAN_LIMIT}.",
            status_code=400,
        )

    user_id = get_current_user(auth_token)
    check_channel_access(user_id, channel_id)

    matches, scanned, truncated = api_initializer.messages_manager.search_messages(
        channel_id=channel_id,
        query=normalized_query,
        scan_limit=effective_scan,
        max_results=effective_limit,
        viewer_user_id=user_id,
    )

    message_data_list = [
        MessageData(
            message_id=msg.get("message_id", ""),
            channel_id=msg.get("channel_id", None),
            conversation_id=msg.get("conversation_id", None),
            sender_id=msg.get("sender_id", ""),
            message=msg.get("message", ""),
            sent_at=msg.get("sent_at", ""),
            attachments=msg.get("attachments", []),
            username=msg.get("sender_username", ""),
            sender_user_id=msg.get("sender_user_id"),
            sender_avatar_url=msg.get("sender_avatar_url"),
            sender_banner_url=msg.get("sender_banner_url"),
            sender_status=msg.get("sender_status"),
            sender_roles=msg.get("sender_roles"),
            sender_about=msg.get("sender_about"),
            sender_last_seen=msg.get("sender_last_seen"),
            sender_created_at=msg.get("sender_created_at"),
        )
        for msg in matches
    ]

    return SearchMessagesResponse(
        status_code=200,
        messages=message_data_list,
        query=normalized_query,
        scanned=scanned,
        truncated_scan=truncated,
    )


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

    max_message_length, max_total_attachment_mb = _get_message_and_attachment_policy()

    # Check message size against instance settings
    if len(message) > max_message_length:
        raise exceptions.HTTPException(
            detail=f"Message exceeds the instance limit of {max_message_length} characters.",
            status_code=400,
        )

    # Check if message is empty and no attachments
    if not message.strip() and not attachments:
        raise exceptions.HTTPException(
            detail="Either a message or attachments must be provided.", status_code=400
        )

    user_id = require_privilege(auth_token, "send_messages")

    # Check channel access
    check_channel_access(user_id, channel_id)
    ensure_user_not_timed_out(user_id, "send messages")

    attachment_objects: list[dict] = []
    if attachments:
        total_attachment_bytes = sum(_measure_upload_size(file) for file in attachments)
        if total_attachment_bytes > max_total_attachment_mb * 1024 * 1024:
            raise exceptions.HTTPException(
                status_code=400,
                detail=(
                    "Combined attachment size exceeds the instance limit of "
                    f"{max_total_attachment_mb}MB."
                ),
            )
        for file in attachments:
            if file.filename:
                try:
                    storage_url, is_duplicate, filename, mime_type, file_size = (
                        await api_initializer.storage_manager.upload_file(
                            file=file,
                            user_id=user_id,
                            reference_type="message_attachment",
                            check_duplicates=True,
                        )
                    )
                    attachment_objects.append({
                        "url": storage_url,
                        "filename": filename,
                        "type": mime_type,
                        "size": file_size,
                    })

                    try:
                        api_initializer.database_handler.create_activity({
                            "event_type": "message_attachment",
                            "description": f"Attachment '{filename}' uploaded for message in channel {channel_id}",
                            "metadata": {
                                "file_url": storage_url,
                                "file_size": file_size,
                                "file_type": mime_type,
                                "channel_id": channel_id,
                                "is_duplicate": is_duplicate,
                            },
                            "user_id": user_id,
                            "timestamp": datetime.utcnow().isoformat(),
                        })
                    except Exception as e:
                        logger.warning(f"Failed to log attachment upload activity: {str(e)}")

                except exceptions.HTTPException:
                    raise
                except Exception as e:
                    logger.error(f"Failed to upload attachment '{file.filename}': {str(e)}")
                    raise exceptions.HTTPException(
                        status_code=500,
                        detail=f"Failed to upload attachment '{file.filename}'. Please try again.",
                    )

    message_obj = api_initializer.messages_manager.send_message(
        channel_id=channel_id,
        user_id=user_id,
        message=message,
        attachments=attachment_objects,
        sent_at=sent_at if sent_at.strip() else None,
    )

    sender_user = api_initializer.user_manager.user_profile(user_id=user_id)

    sent_at_value = message_obj.sent_at
    if sent_at_value is not None and not isinstance(sent_at_value, str):
        sent_at_value = sent_at_value.isoformat()

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
        "attachments": attachment_objects,
    }

    await api_initializer.websockets_manager.broadcast_to_eligible_users(
        channel_id, message_dict
    )

    # Mention notifications: record one per resolved recipient and push a
    # `notification_created` event to each one's WebSocket so badges update
    # in real time. Failure here must not fail the send.
    try:
        notifications = (
            api_initializer.notifications_manager.record_mentions_for_message(
                content=message,
                sender_user_id=user_id,
                channel_id=channel_id,
                message_id=str(message_obj.message_id),
            )
        )
        for notification in notifications:
            try:
                await api_initializer.websockets_manager.broadcast_to_user(
                    str(notification.user_id),
                    api_initializer.notifications_manager.serialize_for_broadcast(
                        notification
                    ),
                )
            except Exception:
                logger.exception(
                    f"Failed to broadcast notification_created to "
                    f"user_id={notification.user_id}"
                )
    except Exception:
        logger.exception(
            f"Mention-notification recording failed for "
            f"message_id={message_obj.message_id}"
        )

    return {
        "status_code": 201,
        "message": "message sent successfully",
        "message_id": str(message_obj.message_id),
        "attachments": attachment_objects,
        "message_data": message_dict,
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


@router.post("/messages/{message_id}/reactions", status_code=201)
async def channel_add_message_reaction(
    auth_token: str,
    channel_id: str,
    message_id: str,
    emoji: str,
):
    """
    Add a reaction emoji to a message.

    Idempotent: re-applying the same emoji is a no-op (returns 200 with
    ``already_present: true``). Adding a different emoji from the same user
    is allowed.
    """
    emoji_value = (emoji or "").strip()
    if not emoji_value:
        raise exceptions.HTTPException(
            detail="`emoji` cannot be empty.", status_code=400
        )
    if len(emoji_value) > REACTION_EMOJI_MAX_LENGTH:
        raise exceptions.HTTPException(
            detail=f"`emoji` exceeds the {REACTION_EMOJI_MAX_LENGTH}-character maximum.",
            status_code=400,
        )

    user_id = require_privilege(auth_token, "send_messages")
    check_channel_access(user_id, channel_id)
    ensure_user_not_timed_out(user_id, "react to messages")

    newly_added = api_initializer.messages_manager.add_reaction(
        message_id=message_id, user_id=user_id, emoji=emoji_value
    )

    summary = api_initializer.messages_manager.get_reaction_summary(
        message_id=message_id, viewer_user_id=user_id
    )

    payload = {
        "status_code": 201 if newly_added else 200,
        "already_present": not newly_added,
        "message_id": message_id,
        "channel_id": channel_id,
        "emoji": emoji_value,
        "reactions": summary,
    }

    try:
        await api_initializer.websockets_manager.broadcast_to_eligible_users(
            channel_id,
            {
                "type": "message_reaction_added",
                "message_id": message_id,
                "channel_id": channel_id,
                "user_id": str(user_id),
                "emoji": emoji_value,
                "reactions": [
                    {k: v for k, v in entry.items() if k != "viewer_reacted"}
                    for entry in summary
                ],
            },
        )
    except Exception:
        logger.exception(
            "Failed to broadcast message_reaction_added for "
            f"message_id={message_id}"
        )

    return payload


@router.delete("/messages/{message_id}/reactions", status_code=200)
async def channel_remove_message_reaction(
    auth_token: str,
    channel_id: str,
    message_id: str,
    emoji: str,
):
    """
    Remove a reaction emoji applied by the viewer from a message.

    Idempotent: removing a reaction the viewer never applied returns 200
    with ``already_absent: true``.
    """
    emoji_value = (emoji or "").strip()
    if not emoji_value:
        raise exceptions.HTTPException(
            detail="`emoji` cannot be empty.", status_code=400
        )

    user_id = get_current_user(auth_token)
    check_channel_access(user_id, channel_id)

    removed = api_initializer.messages_manager.remove_reaction(
        message_id=message_id, user_id=user_id, emoji=emoji_value
    )

    summary = api_initializer.messages_manager.get_reaction_summary(
        message_id=message_id, viewer_user_id=user_id
    )

    payload = {
        "status_code": 200,
        "already_absent": not removed,
        "message_id": message_id,
        "channel_id": channel_id,
        "emoji": emoji_value,
        "reactions": summary,
    }

    try:
        await api_initializer.websockets_manager.broadcast_to_eligible_users(
            channel_id,
            {
                "type": "message_reaction_removed",
                "message_id": message_id,
                "channel_id": channel_id,
                "user_id": str(user_id),
                "emoji": emoji_value,
                "reactions": [
                    {k: v for k, v in entry.items() if k != "viewer_reacted"}
                    for entry in summary
                ],
            },
        )
    except Exception:
        logger.exception(
            "Failed to broadcast message_reaction_removed for "
            f"message_id={message_id}"
        )

    return payload


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
    check_channel_access(user_id=user_id, channel_id=channel_id)

    is_message_sender = (
        api_initializer.messages_manager.check_message_sender(message_id=message_id)
        == user_id
    )
    can_delete_messages = api_initializer.user_manager.has_privilege(
        user_id=user_id, privilege_id="delete_messages"
    )

    if not is_message_sender and not can_delete_messages:
        raise exceptions.HTTPException(
            detail="You are not authorized to delete this message", status_code=401
        )

    # Delete the message
    api_initializer.messages_manager.delete_message(
        message_id=message_id, channel_id=channel_id
    )

    return {"status_code": 204, "message": "The message have been deleted successfully"}
