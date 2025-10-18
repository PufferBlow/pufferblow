from typing import Dict
from fastapi import WebSocket
from loguru import logger

class WebSocketsManager:
    """ WebSocketManager class is responsible to maanging websockets """

    def __init__(self):
        self.active_connections: Dict[WebSocket, list[str, str]] = {}

    async def connect(self, websocket: WebSocket, auth_token: str, channel_id: str) -> None:
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

            # Extract user ID from auth token for logging (first part of JWT-like token)
            user_id = auth_token.split('.')[0] if '.' in auth_token else auth_token[:8]

            logger.info(f"WebSocket connected | User: {user_id} | Channel: {channel_id} | Total connections: {len(self.active_connections)}")
        except Exception as e:
            logger.error(f"WebSocket connection failed | Auth: {auth_token[:8]}... | Channel: {channel_id} | Error: {str(e)}")
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
                auth_token = connection_info[0]
                channel_id = connection_info[1]
                user_id = auth_token.split('.')[0] if '.' in auth_token else auth_token[:8]
                logger.info(f"WebSocket disconnected | User: {user_id} | Channel: {channel_id} | Remaining connections: {len(self.active_connections) - 1}")

            # Remove from active connections
            if websocket in self.active_connections:
                del self.active_connections[websocket]

        except Exception as e:
            logger.error(f"WebSocket disconnect error: {str(e)}")
            # Still remove from active connections even if close failed
            if websocket in self.active_connections:
                del self.active_connections[websocket]

    async def send_message(self, message: str, websocket: WebSocket, message_type: str | None = "plain-text") -> None:
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
                auth_token = connection_info[0]
                channel_id = connection_info[1]
                user_id = auth_token.split('.')[0] if '.' in auth_token else auth_token[:8]

            message_preview = str(message)[:50] + "..." if len(str(message)) > 50 else str(message)

            logger.debug(f"WebSocket send_message | User: {user_id} | Channel: {channel_id} | Type: {message_type} | Content: {message_preview}")

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

        logger.info(f"Broadcasting to all clients | Recipients: {total_connections} | Content: {message_preview}")

        sent_count = 0
        failed_count = 0

        for websocket in self.active_connections:
            try:
                await websocket.send_text(message)
                sent_count += 1
            except Exception as e:
                logger.error(f"Broadcast failed for one client: {str(e)}")
                failed_count += 1

        logger.info(f"Broadcast completed | Sent: {sent_count} | Failed: {failed_count}")

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
        recipients = [(ws, auth_token) for ws, (auth_token, ws_channel_id) in active_connections_copy.items() if ws_channel_id == channel_id]
        total_recipients = len(recipients)

        # Get message type info for logging
        message_type = message.get('type', 'unknown')
        message_id = message.get('message_id', 'unknown')
        content_preview = message.get('content', '')[:50] + "..." if len(message.get('content', '')) > 50 else message.get('content', '')

        logger.info(f"Channel broadcast | Channel: {channel_id} | Recipients: {total_recipients} | Message-Type: {message_type} | ID: {message_id} | Content: {content_preview}")

        if total_recipients == 0:
            logger.warning(f"Channel broadcast attempted but no clients connected to channel {channel_id}")
            return

        sent_count = 0
        failed_count = 0

        for websocket, auth_token in recipients:
            try:
                user_id = auth_token.split('.')[0] if '.' in auth_token else auth_token[:8]
                logger.debug(f"Sending message to user {user_id} in channel {channel_id}")

                await websocket.send_json(message)
                sent_count += 1
            except Exception as e:
                logger.error(f"Channel broadcast failed for one client in channel {channel_id}: {str(e)}")
                failed_count += 1

        logger.info(f"Channel broadcast completed | Channel: {channel_id} | Sent: {sent_count} | Failed: {failed_count} | Total recipients: {total_recipients}")

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
                logger.warning(f"Cannot send personal message - websocket not in OPEN state: {websocket.client_state}")
                return

            # Get user info for logging
            connection_info = self.active_connections.get(websocket)
            user_id = "unknown"
            channel_id = "unknown"
            if connection_info:
                auth_token = connection_info[0]
                channel_id = connection_info[1]
                user_id = auth_token.split('.')[0] if '.' in auth_token else auth_token[:8]

            message_type = message.get('type', 'unknown')
            message_preview = str(message)[:50] + "..." if len(str(message)) > 50 else str(message)

            logger.debug(f"Personal message | User: {user_id} | Channel: {channel_id} | Type: {message_type} | Content: {message_preview}")

            await websocket.send_json(message)

        except Exception as e:
            # Get error logging info
            connection_info = self.active_connections.get(websocket)
            user_id = "unknown"
            if connection_info:
                auth_token = connection_info[0]
                user_id = auth_token.split('.')[0] if '.' in auth_token else auth_token[:8]

            logger.error(f"Personal message failed | User: {user_id} | Error: {str(e)}")

            # Handle disconnected websockets - only if still in active connections
            if websocket in self.active_connections:
                await self.disconnect(websocket)
