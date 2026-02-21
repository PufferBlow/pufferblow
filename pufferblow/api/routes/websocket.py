"""WebSocket routes."""

from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, exceptions
from loguru import logger

from pufferblow.api.logger.msgs import info
from pufferblow.api.utils.extract_user_id import extract_user_id
from pufferblow.core.bootstrap import api_initializer

router = APIRouter()


async def _handle_presence_update_message(
    websocket: WebSocket, user_id: str, message_data: dict
) -> bool:
    """
    Handle websocket-delivered client presence updates.

    Returns:
        bool: True if message was a presence update and has been handled.
    """
    message_type = message_data.get("type")
    if message_type not in {"user_status_changed", "status_update", "presence_update"}:
        return False

    requested_status = message_data.get("status")
    if requested_status is None:
        await websocket.send_json(
            {
                "type": "error",
                "error": "Missing status field in presence update message.",
            }
        )
        return True

    try:
        normalized_status = await api_initializer.websockets_manager.update_user_presence_status(
            user_id=user_id,
            status=requested_status,
            source="ws_client_update",
        )
        logger.debug(
            f"Presence updated from websocket | User: {user_id} | Status: {normalized_status}"
        )
    except ValueError as exc:
        await websocket.send_json({"type": "error", "error": str(exc)})
        logger.warning(
            f"Invalid presence update from websocket | User: {user_id} | Status: {requested_status} | Error: {str(exc)}"
        )

    return True


@router.websocket("/ws")
async def global_messages_websocket(websocket: WebSocket, auth_token: str):
    """
    Global WebSocket endpoint handles real-time messaging for all accessible channels.
    It establishes a single WebSocket connection that receives updates from all channels
    the user has permission to access. This replaces the per-channel websockets with
    a more efficient global approach.

    Args:
        websocket (WebSocket): WebSocket connection object.
        auth_token (str): The user's authentication token.

    Returns:
        1001 Going Away: This status code may be raised if:
            - The auth_token format or validity is invalid.
            - The user doesn't exist or authentication fails.
            - Access restrictions apply.
    """
    user_id = (
        extract_user_id(auth_token=auth_token)
        if "auth_token" in locals()
        else "unknown"
    )
    logger.info(f"Global WebSocket endpoint accessed | User: {user_id}")

    # Validate auth_token format
    if not api_initializer.auth_token_manager.check_auth_token_format(
        auth_token=auth_token
    ):
        logger.warning(f"Invalid auth_token format from user {user_id}")
        raise exceptions.WebSocketException(
            reason="Invalid auth_token format. Please check your authentication token.",
            code=1001,
        )

    user_id = extract_user_id(auth_token=auth_token)

    # Check if the user exists
    if not api_initializer.user_manager.check_user(
        user_id=user_id, auth_token=auth_token
    ):
        logger.warning(f"Authentication failed for user {user_id}")
        raise exceptions.WebSocketException(
            code=1001, reason="Authentication failed. Invalid or expired auth_token."
        )

    # Get user's accessible channels for global permission filtering
    accessible_channels = (
        api_initializer.websockets_manager.get_user_accessible_channels(
            user_id=user_id, database_handler=api_initializer.database_handler
        )
    )

    if not accessible_channels:
        logger.warning(
            f"User {user_id} has no accessible channels, denying WebSocket connection"
        )
        raise exceptions.WebSocketException(
            code=1001,
            reason="No accessible channels found. Please contact an administrator.",
        )

    # Establish global WebSocket connection with user's accessible channels
    await api_initializer.websockets_manager.connect_global(
        websocket=websocket,
        auth_token=auth_token,
        accessible_channels=accessible_channels,
    )

    logger.info(
        f"Global WebSocket connection established | User: {user_id} | Accessible channels: {len(accessible_channels)}"
    )

    sent_messages_ids = set()  # Track sent message IDs to avoid duplicates
    unconfirmed_messages = {}  # Track messages sent but not confirmed as read
    total_messages_sent = 0
    total_read_confirmations = 0

    MESSAGE_POLL_INTERVAL = 2  # seconds between polling for new messages

    try:
        logger.debug(
            f"Starting global WebSocket message loop for user {user_id} with {len(accessible_channels)} accessible channels"
        )

        while True:
            # Handle incoming messages from client (like read confirmations)
            try:
                incoming_data = await asyncio.wait_for(
                    websocket.receive_text(), timeout=0.1
                )
                if incoming_data:
                    try:
                        message_data = json.loads(incoming_data)
                        message_type = message_data.get("type", "unknown")
                        logger.debug(
                            f"Received client message | User: {user_id} | Type: {message_type}"
                        )

                        if await _handle_presence_update_message(
                            websocket=websocket, user_id=user_id, message_data=message_data
                        ):
                            continue

                        # Handle read confirmation
                        if message_type == "read_confirmation":
                            message_id = message_data.get("message_id")
                            channel_id = message_data.get(
                                "channel_id"
                            )  # Channel context needed
                            if (
                                message_id
                                and channel_id
                                and message_id in unconfirmed_messages
                            ):
                                try:
                                    api_initializer.messages_manager.mark_message_as_read(
                                        user_id=user_id,
                                        message_id=message_id,
                                        channel_id=channel_id,
                                    )
                                    unconfirmed_messages.pop(message_id, None)
                                    total_read_confirmations += 1
                                    logger.debug(
                                        f"Message marked as read | User: {user_id} | Channel: {channel_id} | Message: {message_id}"
                                    )

                                except Exception as e:
                                    logger.warning(
                                        f"Failed to mark message as read | User: {user_id} | Channel: {channel_id} | Message: {message_id} | Error: {str(e)}"
                                    )
                            else:
                                logger.debug(
                                    f"Invalid read confirmation | User: {user_id} | Message: {message_id} | Channel: {channel_id}"
                                )

                    except json.JSONDecodeError as e:
                        logger.warning(
                            f"Invalid JSON from client | User: {user_id} | Data: {incoming_data[:100]}... | Error: {str(e)}"
                        )

            except asyncio.TimeoutError:
                # No client message, continue with message polling
                pass

            # Poll for new messages across all accessible channels
            try:
                # Get unread message IDs for all channels
                viewed_messages_ids = (
                    api_initializer.database_handler.get_user_read_messages_ids(user_id)
                )

                all_new_messages = []

                # Check each accessible channel for new messages
                for channel_id in accessible_channels:
                    try:
                        channel_messages = (
                            api_initializer.messages_manager.load_messages(
                                websocket=True,
                                channel_id=channel_id,
                                viewed_messages_ids=viewed_messages_ids,
                            )
                        )

                        # Filter out already sent messages and add channel context
                        for message in channel_messages:
                            if isinstance(message, dict):
                                message_id = message.get("message_id")
                                if message_id and message_id not in sent_messages_ids:
                                    # Add channel context to message
                                    message["channel_id"] = channel_id
                                    all_new_messages.append(message)

                    except Exception as e:
                        logger.warning(
                            f"Failed to load messages for channel {channel_id}: {str(e)}"
                        )
                        continue

                if not all_new_messages:
                    await asyncio.sleep(MESSAGE_POLL_INTERVAL)
                    continue

                logger.debug(
                    f"Found {len(all_new_messages)} new messages across {len(accessible_channels)} channels for user {user_id}"
                )

                messages_sent_this_cycle = 0

                # Send new messages to client
                for message in all_new_messages:
                    message_id = message.get("message_id")
                    channel_id = message.get("channel_id")
                    message_type = message.get("type", "message")

                    if not message_id or not channel_id:
                        continue

                    try:
                        await websocket.send_json(message)
                        sent_messages_ids.add(message_id)
                        unconfirmed_messages[message_id] = True
                        messages_sent_this_cycle += 1
                        total_messages_sent += 1

                        # Log message for debugging
                        content_preview = (
                            message.get("message", "")[:50] + "..."
                            if len(message.get("message", "")) > 50
                            else message.get("message", "")
                        )
                        logger.debug(
                            f"Sent message | User: {user_id} | Channel: {channel_id} | Type: {message_type} | Message: {message_id} | Preview: {content_preview}"
                        )

                    except Exception as e:
                        logger.error(
                            f"Failed to send message to WebSocket client | User: {user_id} | Channel: {channel_id} | Message: {message_id} | Error: {str(e)}"
                        )

                if messages_sent_this_cycle > 0:
                    logger.info(
                        f"Sent {messages_sent_this_cycle} messages to client | User: {user_id} | Total sent: {total_messages_sent}"
                    )

            except Exception as e:
                logger.error(
                    f"Error during message polling for user {user_id}: {str(e)}"
                )

            await asyncio.sleep(MESSAGE_POLL_INTERVAL)

    except WebSocketDisconnect as e:
        logger.info(
            f"Global WebSocket disconnected | User: {user_id} | Code: {e.code} | Reason: {e.reason or 'No reason'} | Stats: sent={total_messages_sent}, confirmed={total_read_confirmations}"
        )
        await api_initializer.websockets_manager.disconnect(websocket)

    except Exception as e:
        logger.error(
            f"Unexpected global WebSocket error | User: {user_id} | Error: {str(e)}",
            exc_info=True,
        )
        try:
            await api_initializer.websockets_manager.disconnect(websocket)
        except Exception as disconnect_error:
            logger.error(
                f"Error during WebSocket cleanup | User: {user_id} | Error: {str(disconnect_error)}"
            )


@router.websocket("/ws/channels/{channel_id}")
async def channels_messages_websocket(
    websocket: WebSocket, auth_token: str, channel_id: str
):
    """
    Channel-scoped WebSocket endpoint.
    """
    user_id = (
        extract_user_id(auth_token=auth_token)
        if "auth_token" in locals()
        else "unknown"
    )
    logger.info(
        f"Channel WebSocket endpoint accessed | User: {user_id} | Channel: {channel_id}"
    )

    if not api_initializer.auth_token_manager.check_auth_token_format(
        auth_token=auth_token
    ):
        raise exceptions.WebSocketException(
            reason="Bad auth_token format. Please check your auth_token and try again.",
            code=1001,
        )

    user_id = extract_user_id(auth_token=auth_token)

    if not api_initializer.user_manager.check_user(
        user_id=user_id, auth_token=auth_token
    ):
        raise exceptions.WebSocketException(
            code=1001,
            reason="'auth_token' expired/unvalid or 'user_id' doesn't exists. Please try again.",
        )

    if not api_initializer.user_manager.is_admin(
        user_id=user_id
    ) and not api_initializer.user_manager.is_server_owner(user_id=user_id):
        raise exceptions.WebSocketException(
            code=1001,
            reason="Access forbidden. Only admins and server owners can access channel WebSocket endpoints.",
        )

    if not api_initializer.channels_manager.check_channel(channel_id=channel_id):
        logger.info(
            info.INFO_CHANNEL_ID_NOT_FOUND(
                viewer_user_id=user_id, channel_id=channel_id
            )
        )
        raise exceptions.WebSocketException(
            code=1001,
            reason="The provided channel ID does not exist or could not be found. Please make sure you have entered a valid channel ID and try again.",
        )

    await api_initializer.websockets_manager.connect(
        websocket=websocket, auth_token=auth_token, channel_id=channel_id
    )

    logger.info(
        f"Channel WebSocket connection established | User: {user_id} | Channel: {channel_id}"
    )

    sent_messages_ids = []
    unconfirmed_messages = {}
    total_messages_sent = 0
    total_read_confirmations = 0
    DELAY = 3

    try:
        logger.debug(
            f"Starting channel WebSocket message loop for user {user_id} in channel {channel_id}"
        )

        while True:
            try:
                incoming_data = await asyncio.wait_for(
                    websocket.receive_text(), timeout=0.1
                )
                if incoming_data:
                    try:
                        message_data = json.loads(incoming_data)
                        if await _handle_presence_update_message(
                            websocket=websocket, user_id=user_id, message_data=message_data
                        ):
                            continue

                        if message_data.get("type") == "read_confirmation":
                            message_id = message_data.get("message_id")
                            if message_id and message_id in unconfirmed_messages:
                                try:
                                    api_initializer.messages_manager.mark_message_as_read(
                                        user_id=user_id,
                                        message_id=message_id,
                                        channel_id=channel_id,
                                    )
                                    del unconfirmed_messages[message_id]
                                    total_read_confirmations += 1
                                    logger.debug(
                                        f"Message marked as read | Channel: {channel_id} | User: {user_id} | Message: {message_id}"
                                    )
                                except Exception as e:
                                    logger.warning(
                                        f"Failed to mark message as read | Error: {str(e)}"
                                    )

                    except json.JSONDecodeError as e:
                        logger.warning(
                            f"Invalid JSON received | Data: {incoming_data[:100]}... | Error: {str(e)}"
                        )

            except asyncio.TimeoutError:
                pass

            try:
                viewed_messages_ids = (
                    api_initializer.database_handler.get_user_read_messages_ids(user_id)
                )
                latest_messages = api_initializer.messages_manager.load_messages(
                    websocket=True,
                    channel_id=channel_id,
                    viewed_messages_ids=viewed_messages_ids,
                )

                if len(latest_messages) == 0:
                    await asyncio.sleep(DELAY)
                    continue

                messages_sent_this_cycle = 0

                for message in latest_messages:
                    if not isinstance(message, dict):
                        continue

                    message_id = message.get("message_id")
                    if not message_id or message_id in sent_messages_ids:
                        continue

                    try:
                        await websocket.send_json(message)
                        sent_messages_ids.append(message_id)
                        unconfirmed_messages[message_id] = True
                        messages_sent_this_cycle += 1
                        total_messages_sent += 1

                        content_preview = (
                            message.get("content", "")[:50] + "..."
                            if len(message.get("content", "")) > 50
                            else message.get("content", "")
                        )
                        logger.debug(
                            f"Message sent | Channel: {channel_id} | User: {user_id} | Message: {message_id} | Preview: {content_preview}"
                        )

                    except Exception as e:
                        logger.error(f"Failed to send message | Error: {str(e)}")

                if messages_sent_this_cycle > 0:
                    logger.info(
                        f"Sent {messages_sent_this_cycle} messages | User: {user_id} | Channel: {channel_id} | Total: {total_messages_sent}"
                    )

            except Exception as e:
                logger.error(f"Error processing messages | Error: {str(e)}")

            await asyncio.sleep(DELAY)

    except WebSocketDisconnect as e:
        logger.info(
            f"Channel WebSocket disconnected | Channel: {channel_id} | User: {user_id} | Code: {e.code} | Reason: {e.reason or 'No reason'} | Stats: sent={total_messages_sent}, confirmed={total_read_confirmations}"
        )
        await api_initializer.websockets_manager.disconnect(websocket)

    except Exception as e:
        logger.error(f"Unexpected WebSocket error | Error: {str(e)}", exc_info=True)
        try:
            await api_initializer.websockets_manager.disconnect(websocket)
        except Exception as disconnect_error:
            logger.error(f"Error during cleanup | Error: {str(disconnect_error)}")



