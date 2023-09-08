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
    """ Server's channels manager """

    def __init__(self, database_handler: DatabaseHandler, auth_token_manager: AuthTokenManager,hasher: Hasher) -> None:
        self.database_handler   =     database_handler
        self.auth_token_manager =     auth_token_manager
        self.hasher             =     hasher
    
    def list_channels(self, user_id: str) -> list[dict]:
        """ Returns a list of the public channels """
        channels_data = self.database_handler.fetch_channels(
            user_id=user_id
        )
        channels = []

        for channel_data in channels_data:
            channel_id      =   channel_data[0]
            channel_name    =   channel_data[1]
            messages_ids    =   channel_data[2]
            is_private      =   channel_data[3]
            allowed_users   =   channel_data[4]
            created_at      =   channel_data[5]

            channel = Channel()

            channel.channel_id      =   channel_id
            channel.channel_name    =   channel_name
            channel.messages_ids    =   messages_ids
            channel.is_private      =   is_private
            channel.allowed_users   =   allowed_users
            channel.created_at      =   created_at

            channels.append(channel.to_json())
        
        return channels

    def create_channel(self, user_id: str, channel_name: str, is_private: bool) -> Channel:
        """ Creates a new channel """
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
        """ Deletes a channel based off it `channel_id` """
        self.database_handler.delete_channel(
            channel_id=channel_id
        )
    
    def check_channel(self, user_id: str, channel_id: str) -> bool:
        """ Checks the existsing of a chennal based off it's `channel_id` """
        channel_data = self.database_handler.get_channel_data(
            user_id=user_id,
            channel_id=channel_id
        )

        if len(channel_data) == 0:
            return False
    
        return True
    
    def is_private(self, user_id: str,channel_id: str) -> bool:
        """ Checks if a channnel is private or public """
        channel_data = self.database_handler.get_channel_data(
            user_id=user_id,
            channel_id=channel_id
        )
        
        return channel_data[3] # `is_private` column value

    def add_user_to_channel(self, user_id: str, to_add_user_id: str, channel_id: str) -> None:
        """ Adds a user to a private channel """
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
        """ Removes a user from a private channel """
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
        """ Generates a unique id for a channel based on this channel's name """
        hashed_channel_name = hashlib.md5(channel_name.encode()).hexdigest()
        generated_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, hashed_channel_name)

        return str(generated_uuid)
