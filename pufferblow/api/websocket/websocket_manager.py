
from fastapi import WebSocket
from loguru import logger
from pufferblow.api.utils.extract_user_id import extract_user_id


class WebSocketsManager:
    """WebSocketManager class is responsible for managing websockets"""

    def __init__(self):
        # Active connections now store user permissions
        # Format: {websocket: {"user_id": str, "auth_token": str, "accessible_channels": list[str]}}
        self.active_connections: dict[WebSocket, dict] = {}

    @staticmethod
    def _connection_context(connection_info) -> tuple[str, str]:
        """
        Normalize connection metadata for both legacy(list) and global(dict) formats.
        Returns (user_id, channel_id_or_scope).
        """
        if isinstance(connection_info, dict):
            return (
                str(connection_info.get("user_id", "unknown")),
                "global",
            )
        if isinstance(connection_info, list) and len(connection_info) >= 2:
            auth_token, channel_id = connection_info[0], connection_info[1]
            try:
                return extract_user_id(auth_token), str(channel_id)
            except Exception:
                return ("unknown", str(channel_id))
        return ("unknown", "unknown")

    async def connect(
        self, websocket: WebSocket, auth_token: str, channel_id: str
    ) -> None:
        """
        Accept connections from a client, and stores the corresponding auth_token
        and channel_id of this clients in `active_connections`

        Args:
            websocket (WebSocket): A `WebSocket` object.
            auth_token (str): The client's `auth_token`.
            channel_id (str): The channel's `channel_id`.

        Returns:
            None.
        """
        try:
            await websocket.accept()
            self.active_connections[websocket] = [auth_token, channel_id]

            try:
                user_id = extract_user_id(auth_token)
            except Exception:
                user_id = auth_token[:8]

            logger.info(
                f"WebSocket connected | User: {user_id} | Channel: {channel_id} | Total connections: {len(self.active_connections)}"
            )
        except Exception as e:
            logger.error(
                f"WebSocket connection failed | Auth: {auth_token[:8]}... | Channel: {channel_id} | Error: {str(e)}"
            )
            raise

    async def connect_global(
        self, websocket: WebSocket, auth_token: str, accessible_channels: list[str]
    ) -> None:
        """
        Accept global WebSocket connections from a client that can receive updates
        from all accessible channels.

        Args:
            websocket (WebSocket): A `WebSocket` object.
            auth_token (str): The client's `auth_token`.
            accessible_channels (list[str]): List of channel IDs this user can access.

        Returns:
            None.
        """
        try:
            await websocket.accept()

            try:
                user_id = extract_user_id(auth_token)
            except Exception:
                user_id = auth_token[:8]

            self.active_connections[websocket] = {
                "user_id": user_id,
                "auth_token": auth_token,
                "accessible_channels": accessible_channels,
            }

            logger.info(
                f"Global WebSocket connected | User: {user_id} | Accessible channels: {len(accessible_channels)} | Total connections: {len(self.active_connections)}"
            )
        except Exception as e:
            logger.error(
                f"Global WebSocket connection failed | Auth: {auth_token[:8]}... | Error: {str(e)}"
            )
            raise

    async def disconnect(self, websocket: WebSocket) -> None:
        """
        Disconnects a client

        Args:
            websocket (WebSocket): A `WebSocket` object.

        Returns:
            None.
        """
        try:
            # Check if websocket is already closed
            if websocket.client_state != 3:  # 3 = CLOSED
                await websocket.close()

            # Get connection info before removing from active connections
            connection_info = self.active_connections.get(websocket)
            if connection_info:
                user_id, channel_id = self._connection_context(connection_info)
                logger.info(
                    f"WebSocket disconnected | User: {user_id} | Channel: {channel_id} | Remaining connections: {len(self.active_connections) - 1}"
                )

            # Remove from active connections
            if websocket in self.active_connections:
                del self.active_connections[websocket]

        except Exception as e:
            logger.error(f"WebSocket disconnect error: {str(e)}")
            # Still remove from active connections even if close failed
            if websocket in self.active_connections:
                del self.active_connections[websocket]

    async def send_message(
        self,
        message: str,
        websocket: WebSocket,
        message_type: str | None = "plain-text",
    ) -> None:
        """
        Send a message to a client using his `websocket` object

        Args:
            message (str): The message to send out to the client.
            message_type (str, optional, default: plain-text): The type of message to send. ["json", "plain-text", "bytes"]
            websocket (WebSocket): A `WebSocket` object.

        Returns:
            None.
        """
        try:
            connection_info = self.active_connections.get(websocket)
            user_id = "unknown"
            channel_id = "unknown"
            if connection_info:
                user_id, channel_id = self._connection_context(connection_info)

            message_preview = (
                str(message)[:50] + "..." if len(str(message)) > 50 else str(message)
            )

            logger.debug(
                f"WebSocket send_message | User: {user_id} | Channel: {channel_id} | Type: {message_type} | Content: {message_preview}"
            )

            if message_type == "json":
                await websocket.send_json(message)
            elif message_type == "plain-text":
                await websocket.send_text(message)
            elif message_type == "bytes":
                await websocket.send_bytes(message)

        except Exception as e:
            logger.error(f"WebSocket send_message failed | Error: {str(e)}")
            raise

    async def broadcast(self, message: str) -> None:
        """
        Broadcast a message to all the connected clients.

        Args:
            message (str): The message to send out to the clients.

        Returns:
            None.
        """
        total_connections = len(self.active_connections)
        message_preview = message[:50] + "..." if len(message) > 50 else message

        logger.info(
            f"Broadcasting to all clients | Recipients: {total_connections} | Content: {message_preview}"
        )

        sent_count = 0
        failed_count = 0

        for websocket in self.active_connections:
            try:
                await websocket.send_text(message)
                sent_count += 1
            except Exception as e:
                logger.error(f"Broadcast failed for one client: {str(e)}")
                failed_count += 1

        logger.info(
            f"Broadcast completed | Sent: {sent_count} | Failed: {failed_count}"
        )

    async def broadcast_to_channel(self, channel_id: str, message: dict) -> None:
        """
        Broadcast a message to all connected clients in a specific channel.

        Args:
            channel_id (str): The channel ID to broadcast to.
            message (dict): The message dict to send as JSON.

        Returns:
            None.
        """
        # Create a copy of active connections to avoid runtime errors if dictionary is modified during iteration
        active_connections_copy = self.active_connections.copy()

        # Count recipients first
        recipients = []
        for ws, connection_info in active_connections_copy.items():
            if isinstance(connection_info, list) and len(connection_info) >= 2:
                auth_token, ws_channel_id = connection_info[0], connection_info[1]
                if ws_channel_id == channel_id:
                    recipients.append((ws, auth_token))
        total_recipients = len(recipients)

        # Get message type info for logging
        message_type = message.get("type", "unknown")
        message_id = message.get("message_id", "unknown")
        content_preview = (
            message.get("content", "")[:50] + "..."
            if len(message.get("content", "")) > 50
            else message.get("content", "")
        )

        logger.info(
            f"Channel broadcast | Channel: {channel_id} | Recipients: {total_recipients} | Message-Type: {message_type} | ID: {message_id} | Content: {content_preview}"
        )

        if total_recipients == 0:
            logger.warning(
                f"Channel broadcast attempted but no clients connected to channel {channel_id}"
            )
            return

        sent_count = 0
        failed_count = 0

        for websocket, auth_token in recipients:
            try:
                user_id = (
                    auth_token.split(".")[0] if "." in auth_token else auth_token[:8]
                )
                logger.debug(
                    f"Sending message to user {user_id} in channel {channel_id}"
                )

                await websocket.send_json(message)
                sent_count += 1
            except Exception as e:
                logger.error(
                    f"Channel broadcast failed for one client in channel {channel_id}: {str(e)}"
                )
                failed_count += 1

        logger.info(
            f"Channel broadcast completed | Channel: {channel_id} | Sent: {sent_count} | Failed: {failed_count} | Total recipients: {total_recipients}"
        )

    async def send_personal_message(self, websocket: WebSocket, message: dict) -> None:
        """
        Send a message to a specific websocket client.

        Args:
            websocket (WebSocket): The target websocket.
            message (dict): The message dict to send as JSON.

        Returns:
            None.
        """
        try:
            # Check if websocket is still connected before sending
            if websocket.client_state != 1:  # 1 = OPEN
                logger.warning(
                    f"Cannot send personal message - websocket not in OPEN state: {websocket.client_state}"
                )
                return

            # Get user info for logging
            connection_info = self.active_connections.get(websocket)
            user_id = "unknown"
            channel_id = "unknown"
            if connection_info:
                user_id, channel_id = self._connection_context(connection_info)

            message_type = message.get("type", "unknown")
            message_preview = (
                str(message)[:50] + "..." if len(str(message)) > 50 else str(message)
            )

            logger.debug(
                f"Personal message | User: {user_id} | Channel: {channel_id} | Type: {message_type} | Content: {message_preview}"
            )

            await websocket.send_json(message)

        except Exception as e:
            # Get error logging info
            connection_info = self.active_connections.get(websocket)
            user_id = "unknown"
            if connection_info:
                user_id, _ = self._connection_context(connection_info)

            logger.error(f"Personal message failed | User: {user_id} | Error: {str(e)}")

            # Handle disconnected websockets - only if still in active connections
            if websocket in self.active_connections:
                await self.disconnect(websocket)

    async def broadcast_to_eligible_users(
        self, channel_id: str, message: dict, database_handler=None
    ) -> None:
        """
        Broadcast a message to all connected users who have permission to access the specified channel.
        This is the core method for global websocket message distribution.

        Args:
            channel_id (str): The channel ID the message is from.
            message (dict): The message dict to send as JSON.
            database_handler (DatabaseHandler, optional): Database handler for permission checks.

        Returns:
            None.
        """
        # Create a copy of active connections to avoid runtime errors if dictionary is modified during iteration
        active_connections_copy = self.active_connections.copy()

        # Get message type info for logging
        message_type = message.get("type", "unknown")
        message_id = message.get("message_id", "unknown")
        content_preview = (
            message.get("content", "")[:50] + "..."
            if len(message.get("content", "")) > 50
            else message.get("content", "")
        )

        # Count recipients and determine accessibility
        recipients = []
        total_global_connections = 0
        total_legacy_connections = 0

        for websocket, connection_info in active_connections_copy.items():
            # Check if this is a global connection (new format with user permissions)
            if isinstance(connection_info, dict) and "user_id" in connection_info:
                total_global_connections += 1
                # For global connections, check if user has access to this channel
                accessible_channels = connection_info.get("accessible_channels", [])
                if channel_id in accessible_channels:
                    recipients.append((websocket, connection_info["user_id"], "global"))
            # Handle legacy connections (old format for backwards compatibility)
            elif isinstance(connection_info, list) and len(connection_info) >= 2:
                total_legacy_connections += 1
                auth_token, connected_channel_id = (
                    connection_info[0],
                    connection_info[1],
                )
                user_id = (
                    auth_token.split(".")[0] if "." in auth_token else auth_token[:8]
                )
                # Legacy connections only receive messages for their specific channel
                if connected_channel_id == channel_id:
                    recipients.append((websocket, user_id, "legacy"))

        total_recipients = len(recipients)

        logger.info(
            f"Global broadcast | Channel: {channel_id} | Recipients: {total_recipients} | Message-Type: {message_type} | ID: {message_id} | Content: {content_preview}"
        )
        logger.debug(
            f"Connection types: {total_global_connections} global, {total_legacy_connections} legacy"
        )

        if total_recipients == 0:
            logger.warning(
                f"Global broadcast attempted but no eligible users connected for channel {channel_id}"
            )
            return

        sent_count = 0
        failed_count = 0

        for websocket, user_id, connection_type in recipients:
            try:
                logger.debug(
                    f"Sending message to user {user_id} (via {connection_type} connection) for channel {channel_id}"
                )

                await websocket.send_json(message)
                sent_count += 1
            except Exception as e:
                logger.error(
                    f"Global broadcast failed for one client in channel {channel_id}: {str(e)}"
                )
                failed_count += 1

        logger.info(
            f"Global broadcast completed | Channel: {channel_id} | Sent: {sent_count} | Failed: {failed_count} | Total recipients: {total_recipients}"
        )

    def get_user_accessible_channels(self, user_id: str, database_handler) -> list[str]:
        """
        Get a list of all channel IDs that a user can access.
        This includes public channels and private channels where the user has been invited.

        Args:
            user_id (str): The user ID to check access for.
            database_handler (DatabaseHandler): Database handler to query channel access.

        Returns:
            list[str]: List of accessible channel IDs.
        """
        try:
            # Use the existing database method to fetch user's accessible channels
            # The fetch_channels method already handles permission filtering
            channels_data = database_handler.fetch_channels(user_id)

            # Extract channel IDs from the results
            accessible_channel_ids = []
            for channel_data in channels_data:
                if hasattr(channel_data, "channel_id"):
                    accessible_channel_ids.append(channel_data.channel_id)
                elif isinstance(channel_data, tuple) and len(channel_data) > 0:
                    channel_obj = channel_data[0]
                    if hasattr(channel_obj, "channel_id"):
                        accessible_channel_ids.append(channel_obj.channel_id)

            logger.debug(
                f"User {user_id} has access to {len(accessible_channel_ids)} channels"
            )
            return accessible_channel_ids

        except Exception as e:
            logger.error(
                f"Failed to get accessible channels for user {user_id}: {str(e)}"
            )
            return []
