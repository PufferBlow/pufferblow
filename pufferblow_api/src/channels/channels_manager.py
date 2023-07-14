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
    
    def _generate_channel_id(self, channel_name: str) -> str:
        """ Generates a unique id for a channel based on this channel's name """
        hashed_channel_name = hashlib.md5(channel_name.encode()).hexdigest()
        generated_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, hashed_channel_name)

        return str(generated_uuid)
