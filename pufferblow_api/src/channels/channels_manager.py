import uuid
import hashlib

from loguru import logger

from pufferblow_api import constants
from pufferblow_api.src.hasher.hasher import Hasher
from pufferblow_api.src.models.user_model import User
from pufferblow_api.src.models.channel_model import Channel
from pufferblow_api.src.auth.auth_token_manager import AuthTokenManager
from pufferblow_api.src.database.database_handler import DatabaseHandler
from pufferblow_api.src.models.encryption_key_model import EncryptionKey

from pufferblow_api.src.utils.current_date import date_in_gmt

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
            
            channel = Channel()

            channel_metadata_json = channel.load_table_metadata(
                table_metadata=channel_data
            ) # dict formated channel's metadata

            channels.append(channel_metadata_json)
        
        return channels

    def create_channel(self, user_id: str, channel_name: str, is_private: bool) -> Channel:
        """
        Create a new channel
        
        Args:
            `user_id` (str): The user's `user_id`.
            `channel_name` (str): The channel's `channel_name` (which is unique for each channel). 
            `is_private` (bool): If it set to True then the channel is going to be private (only viewable by the server owner, admins and the users who gets added/invited to it), otherwise it will be public.
        
        Returns:
            `Channel`.
        """
        channel = Channel()
        
        channel.channel_id = self._generate_channel_id(
            channel_name=channel_name
        )
        channel.channel_name =  channel_name
        channel.is_private   =  is_private
        channel.created_at   =  date_in_gmt(format="%Y-%m-%d %H:%M:%S")

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

        if not channel_data: # If the channel doesn't exists `None` is returned
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
            constants.NEW_USER_ADDED_TO_PRIVATE_CHANNEL(
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
            constants.USER_REMOVED_FROM_A_PRIVATE_CHANNEL(
                user_id=user_id,
                channel_id=channel_id,
                to_remove_user_id=to_remove_user_id
            )
        )
    
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
