import uuid
import string
import random
import base64
import hashlib
import urllib.parse

from loguru import logger

from pufferblow.api.hasher.hasher import Hasher
from pufferblow.api.auth.auth_token_manager import AuthTokenManager
from pufferblow.api.database.database_handler import DatabaseHandler

# Tables
from pufferblow.api.database.tables.messages import Messages

from pufferblow.api.user.user_manager import UserManager

class MessagesManager(object):
    """ Messages manager class """
    def __init__(self, database_handler: DatabaseHandler, auth_token_manager: AuthTokenManager, user_manager: UserManager, hasher: Hasher) -> None:
        self.database_handler        =      database_handler
        self.auth_token_manager      =      auth_token_manager
        self.user_manager            =      user_manager
        self.hasher                  =      hasher
    
    def load_messages(self, channel_id: str, messages_per_page: int | None = 20, page: int | None = 1, websocket: bool | None = False, viewed_messages_ids: list | None=None) -> list[dict]:
        """
        Load a specific messages number from a given channel's `channel_id

        Args:
            channel_id (str): The channel's `channel_id`.
            messages_per_page (int, optional, default: 20): The number of messages for each page.
            page (int, optional, default: 1): The page number (pages start from 1 to `x` depending on how many messages a channel contains).
            websocket (bool, optional, default: False): Weither the function was called from a websocket function.
            viewed_messages_ids (list, optional, default: None): Viewed messages ids by the user/client.
        
        Returns:
            list[dict]: A list of messages' metadata in dict format.
        """
        messages = None
        
        if not websocket:
            messages = self.database_handler.fetch_channel_messages(
                channel_id=channel_id,
                messages_per_page=messages_per_page,
                page=page
            )
        else:
            messages = self.database_handler.fetch_unviewed_channel_messages(
                channel_id=channel_id,
                viewed_messages_ids=viewed_messages_ids
            )

            
        messages_metadata: list[dict] = list()

        # messages is now list[tuple[Messages, Users | None]] since we joined with users
        for message_tuple in messages:
            message_data = message_tuple[0]  # The Messages object
            user_data = message_tuple[1]    # The Users object (can be None)

            # Decrypt the message
            raw_message = self.decrypt_message(
                user_id=str(message_data.sender_id),
                message_id=message_data.message_id,
                encrypted_message=base64.b64decode(message_data.hashed_message)
            )

            json_metadata_format = message_data.to_dict()
            # Replace the encrypted hashed_message with the decrypted message content
            json_metadata_format['message'] = raw_message
            # Remove the encrypted field
            json_metadata_format.pop('hashed_message', None)

            for key in ["channel_id", "conversation_id"]:
                if json_metadata_format[key] is None:
                    json_metadata_format.pop(key)

            # Add user data if available
            if user_data:
                json_metadata_format['sender_username'] = user_data.username
                json_metadata_format['sender_avatar_url'] = user_data.avatar_url
                json_metadata_format['sender_status'] = user_data.status or 'offline'
                json_metadata_format['sender_roles'] = user_data.roles_ids or []
            else:
                # Fallback for messages without user data
                json_metadata_format['sender_username'] = 'Unknown User'
                json_metadata_format['sender_avatar_url'] = None
                json_metadata_format['sender_status'] = 'offline'
                json_metadata_format['sender_roles'] = []

            # Keep the sender_user_id for backward compatibility
            json_metadata_format['sender_user_id'] = str(message_data.sender_id)

            messages_metadata.append(json_metadata_format)

        logger.debug(f"{messages = }")
        return messages_metadata

    def send_message(self, channel_id: str, user_id: str, message: str, attachments: list[str] | None = None, sent_at: str | None = None) -> Messages:
        """
        Send a message to a channel

        Args:
            channel_id (str): The channel's `channel_id`.
            user_id (str): The sender user's `user_id`.
            message (str): The message to send.
            attachments (list[str], optional): List of attachment URLs.
            sent_at (str, optional): ISO format timestamp when message was sent. If None, uses current time.

        Returns:
            Messages: The message metadata object.
        """
        message_metadata = Messages()

        message_metadata.message_id     =   self._generate_message_id(
            user_id=user_id,
            message=message[:random.choice([i for i in range(len(message))])] if message else "attachment"
        )
        message_metadata.channel_id     = channel_id
        message_metadata.sender_id      = user_id
        message_metadata.attachments    = attachments or []

        # Set sent_at timestamp if provided, otherwise use SQLAlchemy default
        if sent_at:
            try:
                from datetime import datetime
                # Parse ISO timestamp, removing timezone info to make it naive
                dt_str = sent_at.replace('Z', '').replace('+00:00', '').replace('+00', '')
                message_metadata.sent_at = datetime.fromisoformat(dt_str)
            except ValueError:
                # If parsing fails, use SQLAlchemy default (don't set sent_at)
                pass

        # Encrypt the message and get the encryption key
        message_metadata.hashed_message, encryption_key = self.encrypt_message(
            message=message,
            user_id=user_id,
            message_id=message_metadata.message_id
        )

        # Save message to the database first (so message_id exists for foreign key)
        self.database_handler.save_message(
            message=message_metadata
        )

        # Save the encryption key after we have the message record
        self.database_handler.save_keys(key=encryption_key)

        return message_metadata
    
    def delete_message(self, message_id: str, channel_id: str) -> None:
        """
        Delete a message from a channel in the server

        Args:
            message_id (str): The message's `message_id`.
            channel_id (str): The channel's `channel_id`.
        
        Returns:
            None
        """
        self.database_handler.delete_message(
            message_id=message_id,
            channel_id=channel_id
        )
    
    def mark_message_as_read(self, user_id: str, message_id: str, channel_id: str) -> None:
        """
        Mark a message as read in the `message_read_history` table in the database
        
        Args:
            auth_token (str): The user's `auth_token`.
            channel_id (str): The channel's `channel_id`.
            message_id (str): "The message's `message_id` that should be marked as read.

        Returns:
            None.
        """
        viewed_messages_ids = self.database_handler.get_user_read_messages_ids(
            user_id=user_id
        )
        
        if message_id in viewed_messages_ids:
            return
        
        self.database_handler.add_message_to_read_history(
            user_id=user_id,
            message_id=message_id
        )

    def check_message(self, message_id: str) -> bool:
        """
        Check weiher a message exists by its `message_id`
        or not

        Args:
            message_id (str): The message's `message_id`.
        
        Returns:
            None.
        """
        message_metadata = self.database_handler.get_message_metadata(
            message_id=message_id
        )

        return message_metadata is not None

    def encrypt_message(self, message: str, user_id: str, message_id: str) -> tuple[str, object]:
        """
        Encrypt a message and return the encrypted message and encryption key
        
        Args:
            message (str): The raw message.
            user_id (str): The sender user's `user_id`.
            message_id (str): The message's `message_id`.
        
        Returns:
            tuple[str, object]: (base64 encoded encrypted message, encryption key object)
        """
        encrypted_message, key = self.hasher.encrypt(
            data=message
        )

        key.user_id          =   user_id
        key.message_id       =   message_id
        key.associated_to    =   "message"

        encrypted_message = base64.b64encode(encrypted_message).decode("ascii")

        return encrypted_message, key
    
    def decrypt_message(self, user_id:str, message_id: str, encrypted_message: bytes) -> str:
        """
        Decrypt a message

        Args:
            user_id (str): The sender user's `user_id`.
            message_id (str): The message's `message_id`.
        
        Returns:
            str: The decrypted message.
        """
        key = self.database_handler.get_keys(
            user_id=user_id,
            associated_to="message",
            message_id=message_id
        )

        decrypted_message = self.hasher.decrypt(
            ciphertext=encrypted_message,
            key=key.key_value,
            iv=key.iv
        )

        return decrypted_message

    def check_message_sender(self, message_id: str) -> str:
        """
        Check the message sender

        Args:
            message_id (str): The message's `message_id`.

        Returns:
            str: The message sender's `user_id`.
        """
        message_metadata = self.database_handler.get_message_metadata(
            message_id=message_id
        )

        return str(message_metadata.sender_id)

    def _generate_message_id(self, user_id: str, message: str) -> str:
        """
        Generate a unique `message_id` based of the sender user's `user_id`
        and a slice from the original message

        Args:
            user_id (str): The sender user's `user_id`.
            message (str): A slice of the original message.
        
        Returns:
            str: The generated `user_id`.
        """
        data = f"{user_id}{message}{''.join([char for char in random.choices(string.ascii_letters)])}" # Adding random charachters to the username

        hashed_data_salt = hashlib.md5(data.encode()).hexdigest()
        generated_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, hashed_data_salt)

        return str(generated_uuid)
