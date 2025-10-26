import uuid
import hashlib

from loguru import logger

# Tables
from pufferblow.api.database.tables.channels import Channels

# Hasher
from pufferblow.api.hasher.hasher import Hasher

# AuthToken manager
from pufferblow.api.auth.auth_token_manager import AuthTokenManager

# Database handler
from pufferblow.api.database.database_handler import DatabaseHandler

# Utils
from pufferblow.api.utils.current_date import date_in_gmt

# Log messages
from pufferblow.api.logger.msgs import (
    info
)

class ChannelsManager (object):
    """ Channels manager class to manage channels """
    def __init__(self, database_handler: DatabaseHandler, auth_token_manager: AuthTokenManager,hasher: Hasher) -> None:
        self.database_handler   =     database_handler
        self.auth_token_manager =     auth_token_manager
        self.hasher             =     hasher
    
    def list_channels(self, user_id: str) -> list[dict]:
        """
        List the public channels (and private channels
        in case the user is the server owner or an admin)
        
        Args:
            `user_id` (str): The user's `user_id`.
        
        Returns:
            list[dict]: List of channels and their metadata.
        """
        channels_data = self.database_handler.fetch_channels(
            user_id=user_id
        )
        channels = []

        for channel_data in channels_data:
            channel_data = channel_data[0]

            channel_metadata_json = channel_data.to_dict()

            channels.append(channel_metadata_json)
        
        return channels

    def create_channel(self, user_id: str, channel_name: str, is_private: bool, channel_type: str = "text") -> Channels:
        """
        Create a new channel

        Args:
            `user_id` (str): The user's `user_id`.
            `channel_name` (str): The channel's `channel_name` (which is unique for each channel).
            `is_private` (bool): If it set to True then the channel is going to be private (only viewable by the server owner, admins and the users who gets added/invited to it), otherwise it will be public.
            `channel_type` (str): The type of channel - "text", "voice", or "mixed". Defaults to "text".

        Returns:
            `Channels`.
        """
        channel = Channels()

        channel.channel_id = self._generate_channel_id(
            channel_name=channel_name
        )
        channel.channel_name = channel_name
        channel.channel_type = channel_type
        channel.is_private = is_private
        channel.created_at = date_in_gmt(format="%Y-%m-%d %H:%M:%S")

        # For voice channels, generate a LiveKit room name
        if channel_type in ["voice", "mixed"]:
            from pufferblow.api_initializer import api_initializer
            if api_initializer.config.get("livekit", {}).get("voice_channels_enabled", False):
                channel.livekit_room_name = f"pufferblow_channel_{channel.channel_id}"

        self.database_handler.create_new_channel(
            user_id=user_id,
            channel=channel
        )

        return channel
    
    def delete_channel(self, channel_id: str) -> None:
        """
        Delete a server channel
        
        Args:
            `channel_id` (str): The channel's `channel_id`.
        
        Returns:
            `None`.
        """
        self.database_handler.delete_channel(
            channel_id=channel_id
        )
    
    def check_channel(self, channel_id: str) -> bool:
        """
        Check the existsing of a channel
        
        Args:
            `channel_id` (str): The channel's `channel_id`.
        
        Returns:
            bool: True if the channel exists, otherwise False.
        """
        channel_data = self.database_handler.get_channel_data(
            channel_id=channel_id
        )

        if not channel_data: # If the channel doesn't exists, `None` is returned
            return False
    
        return True
    
    def is_private(self, channel_id: str) -> bool:
        """
        Check if a channnel is private or not
        
        Args:
            `channel_id` (str): The channel's `channel_id`.
        
        Returns:
            bool: True if the channel is private, otherwise False.
        """
        channel_data = self.database_handler.get_channel_data(
            channel_id=channel_id
        )
        
        return channel_data.is_private

    def add_user_to_channel(self, user_id: str, to_add_user_id: str, channel_id: str) -> None:
        """
        Add a user to a private channel
        
        Args:
            `user_id` (str): The user's `user_id`.
            `channel_id` (str): The channel's `channel_id`.
            `to_add_user_id` (str): The targeted user's `user_id`.
        
        Returns:
            `None`.
        """
        self.database_handler.add_user_to_channel(
            channel_id=channel_id,
            to_add_user_id=to_add_user_id
        )

        logger.info(
            info.INFO_NEW_USER_ADDED_TO_PRIVATE_CHANNEL(
                user_id=user_id,
                to_add_user_id=to_add_user_id,
                channel_id=channel_id
            )
        )

    def remove_user_from_channel(self, user_id: str, to_remove_user_id: str, channel_id: str) -> None:
        """
        Remove a user from a private channel
        
        Args:
            `user_id` (str): The user's `user_id`.
            `channel_id` (str): The channel's `channel_id`.
            `to_remove_user_id` (str): The targeted user's `user_id`.
        
        Returns:
            `None`.
        """
        self.database_handler.remove_user_from_channel(
            channel_id=channel_id,
            to_remove_user_id=to_remove_user_id
        )

        logger.info(
            info.INFO_USER_REMOVED_FROM_A_PRIVATE_CHANNEL(
                user_id=user_id,
                channel_id=channel_id,
                to_remove_user_id=to_remove_user_id
            )
        )
    
    def get_channel_type(self, channel_id: str) -> str:
        """
        Get the type of a channel

        Args:
            `channel_id` (str): The channel's `channel_id`.

        Returns:
            str: The channel type ("text", "voice", or "mixed"). Defaults to "text".
        """
        channel_data = self.database_handler.get_channel_data(channel_id=channel_id)
        return channel_data.channel_type if channel_data else "text"

    def is_voice_channel(self, channel_id: str) -> bool:
        """
        Check if a channel supports voice functionality

        Args:
            `channel_id` (str): The channel's `channel_id`.

        Returns:
            bool: True if the channel supports voice (type is "voice" or "mixed").
        """
        channel_type = self.get_channel_type(channel_id)
        return channel_type in ["voice", "mixed"]

    def join_voice_channel(self, user_id: str, channel_id: str) -> dict:
        """
        Join voice channel and provide LiveKit token through API proxy.
        API acts as secure gateway to LiveKit without exposing server details.

        Args:
            `user_id` (str): The user's `user_id`.
            `channel_id` (str): The channel's `channel_id`.

        Returns:
            dict: Contains LiveKit token info through API proxy, or error message.
        """
        from pufferblow.api_initializer import api_initializer

        # Check if voice channels are enabled
        if not api_initializer.config.get("livekit", {}).get("voice_channels_enabled", False):
            return {"error": "Voice channels are not enabled"}

        # Check if channel exists and is voice-enabled
        if not self.check_channel(channel_id):
            return {"error": "Channel does not exist"}

        if not self.is_voice_channel(channel_id):
            return {"error": "Channel does not support voice"}

        # Get channel data
        channel_data = self.database_handler.get_channel_data(channel_id=channel_id)
        room_name = channel_data.livekit_room_name

        if not room_name:
            return {"error": "Voice channel not properly configured"}

        try:
            # Import LiveKit SDK for token generation
            from livekit import api

            # Get user info for token generation
            user_data = self.database_handler.get_user(user_id=user_id)
            if not user_data:
                return {"error": "User not found"}

            username = user_data.username

            # Add user to participant list
            current_participants = channel_data.participant_ids or []
            if user_id not in current_participants:
                current_participants.append(user_id)
                self.database_handler.update_channel_participants(channel_id, current_participants)

            # Initialize LiveKit API for secure token generation
            lk_api = api.LiveKitAPI(
                url=api_initializer.config["livekit"]["url"],
                api_key=api_initializer.config["livekit"]["api_key"],
                api_secret=api_initializer.config["livekit"]["api_secret"]
            )

            # Create access token
            token = api.AccessToken(
                api_key=api_initializer.config["livekit"]["api_key"],
                api_secret=api_initializer.config["livekit"]["api_secret"]
            )

            # Set up participant permissions
            token.set_identity(user_id)
            token.set_name(username)
            token.set_metadata(f"pufferblow_user:{user_id}")

            # Grant permissions based on channel type
            grant = api.VideoGrants(
                room_join=True,
                room=room_name,
                can_publish=True,
                can_subscribe=True
            )
            token.set_grants(grant)

            # Generate JWT token
            jwt_token = token.to_jwt()

            logger.info(f"User {username} ({user_id}) joined voice channel {channel_id} through API proxy")

            return {
                "token": jwt_token,
                "room_name": room_name,
                "livekit_url": api_initializer.config["livekit"]["url"],
                "proxy": True  # Indicate this is through API proxy
            }

        except Exception as e:
            logger.error(f"Failed to generate LiveKit token for user {user_id} in channel {channel_id}: {str(e)}")
            return {"error": f"Failed to join voice channel: {str(e)}"}

    def leave_voice_channel(self, user_id: str, channel_id: str) -> dict:
        """
        Handle leaving a voice channel

        Args:
            `user_id` (str): The user's `user_id`.
            `channel_id` (str): The channel's `channel_id`.

        Returns:
            dict: Success or error message.
        """
        try:
            # Remove user from participant list
            channel_data = self.database_handler.get_channel_data(channel_id=channel_id)
            if channel_data:
                current_participants = channel_data.participant_ids or []
                if user_id in current_participants:
                    current_participants.remove(user_id)
                    self.database_handler.update_channel_participants(channel_id, current_participants)

            logger.info(f"User {user_id} left voice channel {channel_id}")
            return {"success": True}

        except Exception as e:
            logger.error(f"Failed to leave voice channel for user {user_id}: {str(e)}")
            return {"error": f"Failed to leave voice channel: {str(e)}"}

    def get_voice_channel_status(self, channel_id: str) -> dict:
        """
        Get status of a voice channel including participants

        Args:
            `channel_id` (str): The channel's `channel_id`.

        Returns:
            dict: Channel status including participant info.
        """
        channel_data = self.database_handler.get_channel_data(channel_id=channel_id)
        if not channel_data:
            return {"error": "Channel not found"}

        if not self.is_voice_channel(channel_id):
            return {"error": "Not a voice channel"}

        # Get participant details
        participants = []
        if channel_data.participant_ids:
            for pid in channel_data.participant_ids:
                user_data = self.database_handler.get_user(pid)
                if user_data:
                    participants.append({
                        "user_id": pid,
                        "username": user_data.username,
                        "avatar_url": user_data.avatar_url
                    })

        return {
            "channel_id": channel_id,
            "room_name": channel_data.livekit_room_name,
            "participants": participants,
            "participant_count": len(participants)
        }

    def _generate_channel_id(self, channel_name: str) -> str:
        """
        Generate a unique `channel_id` for a
        `channel` based on it's `channel_name`

        Args:
            `channel_name` (str): The channel's `channel_name`.

        Returns:
            str: The generated `channel_id`.
        """
        hashed_channel_name = hashlib.md5(channel_name.encode()).hexdigest()
        generated_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, hashed_channel_name)

        return str(generated_uuid)
