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
# Widened from 32 → 64 alongside the DB column widening so sticker
# reactions (``sticker:<36-char-uuid>`` = 43 chars) fit. Plain
# Unicode emoji are typically 1–8 codepoints / under 32 chars, so
# this raises the ceiling without lowering the floor. The 64 cap
# matches the ``message_reactions.emoji`` column width — anything
# over 64 would truncate at the DB layer.
REACTION_EMOJI_MAX_LENGTH = 64
from pufferblow.api.dependencies import (
    check_channel_access,
    get_current_user,
)
from pufferblow.core.bootstrap import api_initializer

# Create router for message-related endpoints
router = APIRouter(prefix="/api/v1/channels/{channel_id}")


def _get_message_and_attachment_policy() -> tuple[int, int]:
    """Return instance-defined message and attachment limits (shared with the command protocol)."""
    from pufferblow.api.services.policy import message_policy

    return message_policy(
        api_initializer.database_handler, api_initializer.storage_manager, api_initializer.config
    )()


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
    sticker_ids: str = Form(
        "",
        description=(
            "Comma-separated list of sticker_ids from the instance "
            "library to include on this message. The server looks up "
            "each id and synthesises the attachment dict from the "
            "sticker_url — no file re-upload."
        ),
    ),
    reply_to_message_id: str = Form(
        "", description="message_id (in the same channel) this message replies to, if any"
    ),
) -> tuple[SendMessageForm, list[UploadFile], list[str]]:
    """
    Parse multipart form data into a validated SendMessageForm.

    Returns a 3-tuple: validated form, file attachments (need
    upload), and parsed sticker_ids (already on the server, just
    need to be looked up + appended to the message's attachment
    list).
    """
    form_data = SendMessageForm(
        auth_token=auth_token,
        message=message,
        sent_at=sent_at,
        attachments=[],
        reply_to_message_id=reply_to_message_id.strip() or None,
    )
    parsed_sticker_ids = [
        sid.strip() for sid in (sticker_ids or "").split(",") if sid.strip()
    ]
    return form_data, attachments, parsed_sticker_ids


@router.get("/load_messages", status_code=200, response_model=LoadMessagesResponse)
async def channel_load_messages(
    auth_token: str,
    channel_id: str,
    page: int | None = 1,
    messages_per_page: int | None = 20,
    before_cursor: str | None = None,
):
    """Load messages from a channel.

    Two modes share this endpoint:

    * `before_cursor=<token>` — keyset pagination, O(log N + limit)
      regardless of channel size. Clients should prefer this for
      anything new. The response carries `next_cursor` which you pass
      back as `before_cursor` to fetch the next page (older messages).
      `next_cursor=None` means you reached the start of history.

    * `page=N` (legacy) — translated internally into a keyset walk so
      Postgres never sees a real `OFFSET N`. Capped depth — past
      `DatabaseHandler.MAX_OFFSET_PAGINATION_ROWS` we return 400 and
      ask the client to migrate to cursor pagination.

    Args:
        auth_token: User's authentication token.
        channel_id: Channel ID.
        page: Page number (default: 1). Ignored when `before_cursor` is set.
        messages_per_page: Page / cursor batch size (default: 20, max: 50).
        before_cursor: Opaque keyset cursor from a previous response.

    Returns:
        200 OK: List of messages (+ `next_cursor` when cursor mode).
        400 BAD REQUEST: Invalid parameters or offset depth exceeded.
        404 NOT FOUND: Channel not found or no access.
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

    next_cursor: str | None = None
    try:
        result = api_initializer.messages_manager.load_messages(
            channel_id=channel_id,
            messages_per_page=messages_per_page,
            page=page,
            viewer_user_id=user_id,
            before_cursor=before_cursor,
        )
    except ValueError as exc:
        # Raised by DatabaseHandler.fetch_channel_messages when the
        # caller pushes legacy offset pagination past its safe depth.
        raise exceptions.HTTPException(status_code=400, detail=str(exc))

    if isinstance(result, tuple):
        messages, next_cursor = result
    else:
        messages = result

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
                reply_to_message_id=msg.get("reply_to_message_id"),
                reply_to=msg.get("reply_to"),
                forwarded_from_message_id=msg.get("forwarded_from_message_id"),
            )
        )

    return LoadMessagesResponse(
        status_code=200,
        messages=message_data_list,
        next_cursor=next_cursor,
    )


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
            reply_to_message_id=msg.get("reply_to_message_id"),
            reply_to=msg.get("reply_to"),
            forwarded_from_message_id=msg.get("forwarded_from_message_id"),
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
    form_data: tuple[SendMessageForm, list[UploadFile], list[str]] = Depends(
        parse_send_message_form
    ),
):
    """
    Send a message to a channel with optional attachments.

    Args:
        channel_id: Channel ID
        form_data: Validated form data, file attachments, and
            referenced sticker_ids from the instance library.

    Returns:
        201 CREATED: Message sent successfully
        400 BAD REQUEST: Invalid message or attachments
        404 NOT FOUND: Channel not found or no access
    """
    # Unpack validated form data, file attachments, and sticker refs.
    validated_form, attachments, sticker_ids = form_data
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

    # Check if message is empty and no attachments / stickers
    if not message.strip() and not attachments and not sticker_ids:
        raise exceptions.HTTPException(
            detail="Either a message or attachments must be provided.", status_code=400
        )

    principal = api_initializer.user_principal_resolver.resolve(auth_token)
    # Fail before any upload work if the sender could not post here anyway.
    api_initializer.authorizer.require_send(principal, channel_id)

    attachment_objects: list[dict] = []
    if attachments and api_initializer.storage_manager is None:
        raise exceptions.HTTPException(
            status_code=503,
            detail="File uploads are disabled on this server.",
        )
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
                            user_id=principal.id,
                            reference_type="message_attachment",
                            check_duplicates=True,
                        )
                    )
                    # Resolve LQIP URL for image attachments so the
                    # client can paint a placeholder while the full
                    # asset streams in. Non-image attachments
                    # (videos, audio, PDFs, etc.) just get None
                    # here — the AttachmentBubble renders its
                    # type-specific placeholder for those.
                    lqip_url = None
                    if mime_type.startswith("image/") and mime_type != "image/gif":
                        from pufferblow.api.user.user_manager import (
                            _resolve_storage_lqip_url,
                        )
                        lqip_url = _resolve_storage_lqip_url(
                            storage_url, api_initializer.database_handler
                        )
                    attachment_objects.append({
                        "url": storage_url,
                        "lqip_url": lqip_url,
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
                            "user_id": principal.id,
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

    # Persisting, sticker resolution, mention notifications and the real-time event all live in
    # the shared MessageService, so this route and the WebSocket `message.create` command behave
    # identically.
    outcome = api_initializer.message_service.create(
        principal,
        channel_id,
        message,
        sticker_ids=sticker_ids,
        attachments=attachment_objects,
        sent_at=sent_at,
        reply_to_message_id=validated_form.reply_to_message_id,
    )
    await api_initializer.event_publisher.publish_all(outcome.events)

    message_dict = outcome.value["raw"]
    return {
        "status_code": 201,
        "message": "message sent successfully",
        "message_id": message_dict["message_id"],
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
