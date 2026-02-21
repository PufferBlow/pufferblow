from datetime import datetime, timezone
from typing import TYPE_CHECKING

from fastapi import WebSocket
from loguru import logger
from pufferblow.api.user.status import normalize_user_status
from pufferblow.api.utils.extract_user_id import extract_user_id

if TYPE_CHECKING:
    from pufferblow.api.user.user_manager import UserManager


class WebSocketsManager:
    """WebSocketManager class is responsible for managing websockets"""

    def __init__(self, user_manager: "UserManager | None" = None):
        # Format:
        # {websocket: {"user_id": str, "auth_token": str, "scope": "global"|"channel",
        #              "channel_id": str|None, "accessible_channels": list[str]}}
        """Initialize the instance."""
        self.active_connections: dict[WebSocket, dict] = {}
        self.user_manager = user_manager

    @staticmethod
    def _connection_context(connection_info) -> tuple[str, str]:
        """
        Resolve (user_id, channel_or_scope) from normalized connection metadata.
        Returns (user_id, channel_id_or_scope).
        """
        if not isinstance(connection_info, dict):
            return ("unknown", "unknown")

        user_id = str(connection_info.get("user_id", "unknown"))
        if connection_info.get("scope") == "channel":
            return (user_id, str(connection_info.get("channel_id", "unknown")))
        return (user_id, "global")

    def _count_connections_for_user(self, user_id: str) -> int:
        """Return active websocket connections count for a specific user."""
        target = str(user_id)
        return sum(
            1
            for connection_info in self.active_connections.values()
            if isinstance(connection_info, dict)
            and str(connection_info.get("user_id")) == target
        )

    @staticmethod
    def _build_presence_message(user_id: str, status: str, source: str) -> dict:
        """Build canonical status update payload for websocket clients."""
        return {
            "type": "user_status_changed",
            "user_id": str(user_id),
            "status": status,
            "source": source,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    async def _broadcast_presence_message(self, message: dict) -> None:
        """Broadcast a presence update message to all active websocket clients."""
        active_connections_copy = self.active_connections.copy()
        total_recipients = len(active_connections_copy)

        if total_recipients == 0:
            return

        sent_count = 0
        failed_count = 0

        for websocket in active_connections_copy:
            try:
                await websocket.send_json(message)
                sent_count += 1
            except Exception as exc:
                failed_count += 1
                logger.warning(
                    f"Presence broadcast failed for one connection: {str(exc)}"
                )

        logger.info(
            f"Presence broadcast completed | Type: {message.get('type')} | User: {message.get('user_id')} | Status: {message.get('status')} | Sent: {sent_count} | Failed: {failed_count}"
        )

    async def update_user_presence_status(
        self, user_id: str, status: str, source: str = "client"
    ) -> str:
        """
        Persist and broadcast a user presence status.

        Args:
            user_id (str): Target user.
            status (str): Raw status value from caller/client.
            source (str): Source marker for telemetry.

        Returns:
            str: Normalized/canonical status.

        Raises:
            ValueError: If status is invalid or user manager is not configured.
        """
        if self.user_manager is None:
            raise ValueError("User manager is not configured for presence updates.")

        normalized_status = normalize_user_status(status)
        is_changed = self.user_manager.update_user_status(
            user_id=user_id, status=normalized_status
        )

        if is_changed:
            message = self._build_presence_message(
                user_id=user_id, status=normalized_status, source=source
            )
            await self._broadcast_presence_message(message)

        return normalized_status

    async def ensure_user_online(self, user_id: str, source: str = "ws_connect") -> None:
        """
        Mark user online when they establish their first websocket connection.
        """
        if self._count_connections_for_user(user_id) != 1:
            return

        try:
            await self.update_user_presence_status(
                user_id=user_id, status="online", source=source
            )
        except Exception as exc:
            logger.warning(
                f"Failed to set user online on websocket connect | User: {user_id} | Error: {str(exc)}"
            )

    async def ensure_user_offline_if_no_connections(
        self, user_id: str, source: str = "ws_disconnect"
    ) -> None:
        """
        Mark user offline when all websocket connections are gone.
        """
        if self._count_connections_for_user(user_id) != 0:
            return

        try:
            await self.update_user_presence_status(
                user_id=user_id, status="offline", source=source
            )
        except Exception as exc:
            logger.warning(
                f"Failed to set user offline on websocket disconnect | User: {user_id} | Error: {str(exc)}"
            )

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

            try:
                user_id = extract_user_id(auth_token)
            except Exception:
                user_id = auth_token[:8]

            self.active_connections[websocket] = {
                "user_id": user_id,
                "auth_token": auth_token,
                "scope": "channel",
                "channel_id": channel_id,
                "accessible_channels": [channel_id],
            }

            logger.info(
                f"WebSocket connected | User: {user_id} | Channel: {channel_id} | Total connections: {len(self.active_connections)}"
            )
            await self.ensure_user_online(user_id=user_id, source="ws_channel_connect")
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
                "scope": "global",
                "channel_id": None,
                "accessible_channels": accessible_channels,
            }

            logger.info(
                f"Global WebSocket connected | User: {user_id} | Accessible channels: {len(accessible_channels)} | Total connections: {len(self.active_connections)}"
            )
            await self.ensure_user_online(user_id=user_id, source="ws_global_connect")
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
        connection_info = self.active_connections.get(websocket)
        user_id = None

        if connection_info:
            user_id, channel_id = self._connection_context(connection_info)
            logger.info(
                f"WebSocket disconnected | User: {user_id} | Channel: {channel_id} | Remaining connections: {len(self.active_connections) - 1}"
            )

        try:
            # Check if websocket is already closed
            if websocket.client_state != 3:  # 3 = CLOSED
                await websocket.close()
        except Exception as e:
            logger.error(f"WebSocket disconnect error: {str(e)}")
        finally:
            if websocket in self.active_connections:
                del self.active_connections[websocket]

        if user_id is not None:
            await self.ensure_user_offline_if_no_connections(
                user_id=user_id, source="ws_disconnect"
            )

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
            if not isinstance(connection_info, dict):
                continue

            scope = connection_info.get("scope")
            user_id = str(connection_info.get("user_id", "unknown"))
            if scope == "channel" and connection_info.get("channel_id") == channel_id:
                recipients.append((ws, user_id))
                continue

            if scope == "global":
                accessible_channels = connection_info.get("accessible_channels", [])
                if channel_id in accessible_channels:
                    recipients.append((ws, user_id))
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

        for websocket, user_id in recipients:
            try:
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

    async def broadcast_to_user(self, user_id: str, message: dict) -> None:
        """
        Broadcast a JSON message to all active websocket connections of one user.
        """
        active_connections_copy = self.active_connections.copy()
        recipients: list[WebSocket] = []

        for websocket, connection_info in active_connections_copy.items():
            if not isinstance(connection_info, dict):
                continue
            if str(connection_info.get("user_id")) == str(user_id):
                recipients.append(websocket)

        if not recipients:
            logger.debug(f"No websocket recipients for user {user_id}")
            return

        sent_count = 0
        failed_count = 0
        for websocket in recipients:
            try:
                await websocket.send_json(message)
                sent_count += 1
            except Exception as exc:
                failed_count += 1
                logger.error(
                    f"Failed to broadcast personal message to user {user_id}: {str(exc)}"
                )

        logger.info(
            f"Personal broadcast completed | User: {user_id} | Sent: {sent_count} | Failed: {failed_count}"
        )

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
        total_channel_connections = 0

        for websocket, connection_info in active_connections_copy.items():
            if not isinstance(connection_info, dict) or "user_id" not in connection_info:
                continue

            scope = connection_info.get("scope")
            user_id = str(connection_info.get("user_id", "unknown"))

            if scope == "global":
                total_global_connections += 1
                accessible_channels = connection_info.get("accessible_channels", [])
                if channel_id in accessible_channels:
                    recipients.append((websocket, user_id, "global"))
                continue

            if scope == "channel":
                total_channel_connections += 1
                if connection_info.get("channel_id") == channel_id:
                    recipients.append((websocket, user_id, "channel"))

        total_recipients = len(recipients)

        logger.info(
            f"Global broadcast | Channel: {channel_id} | Recipients: {total_recipients} | Message-Type: {message_type} | ID: {message_id} | Content: {content_preview}"
        )
        logger.debug(
            f"Connection types: {total_global_connections} global, {total_channel_connections} channel"
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
