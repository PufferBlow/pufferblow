from fastapi import WebSocket
from typing import Dict

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
        await websocket.accept()
        self.active_connections[websocket] = [auth_token, channel_id]

    async def disconnect(self, websocket: WebSocket) -> None:
        """
        Disconnects a client

        Args:
            websocket (WebSocket): A `WebSocket` object.

        Returns:
            None.
        """
        await websocket.close()
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
        if message_type == "json":
            await websocket.send_json(message)
        elif message_type == "plain-text":
            await websocket.send_text(message)
        elif message_type == "bytes":
            await websocket.send_bytes(message)

    async def broadcast(self, message: str) -> None:
        """
        Broadcast a message to all the connected clients.

        Args:
            message (str): The message to send out to the clients.

        Returns:
            None.
        """
        for connection in self.active_connections:
            await connection.send_text(message)
