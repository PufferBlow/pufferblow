# Channels table
from pufferblow.api.database.tables.channels import Channels

class Channel(object):
    """ Channel model """
    channel_id              :       str
    channel_name            :       str
    messages_ids            :       list[str]       =   []
    is_private              :       bool            =   False
    allowed_users           :       list[str]       =   None
    created_at              :       str

    def create_table_metadata(self) -> Channels:
        """
        Create a `Channels` table object that contains
        the current channel's metadata

        Args:
            `None`.
        
        Returns:
            Channels: A `Channels` table object.
        """
        channel = Channels(
            channel_id      =   self.channel_id,
            channel_name    =   self.channel_name,
            messages_ids    =   self.messages_ids,
            is_private      =   self.is_private,
            allowed_users   =   self.allowed_users,
            created_at      =   self.created_at,
        )

        return channel

    def load_table_metadata(self, table_metadata: Channels) -> dict:
        """
        Load metadata from a `Channels` table object into
        the `self`'s attributes

        Args:
            `table_metadata` (User): The `Channels` table object containing the metadata to load.
        
        Returns:
            dict: The metadata in dict format.
        """
        self.channel_id      =   table_metadata.channel_id
        self.channel_name    =   table_metadata.channel_name
        self.messages_ids    =   table_metadata.messages_ids
        self.is_private      =   table_metadata.is_private
        self.allowed_users   =   table_metadata.allowed_users
        self.created_at      =   table_metadata.created_at

        return self.to_dict()

    def to_dict(self) -> dict:
        """ Returns the channel data in dict format """
        return {
            "channel_id"         :   self.channel_id,
            "channel_name"       :   self.channel_name,
            "messages_ids"       :   self.messages_ids,
            "is_private"         :   self.is_private,
            "allowed_users"      :   self.allowed_users,
            "created_at"         :   self.created_at
        }

    def to_tuple(self) -> tuple:
        """ Reutns the channel data in tuple format """
        channel_data = (
            self.channel_id,
            self.channel_name,
            self.messages_ids,
            self.is_private,
            self.allowed_users,
            self.created_at
        )

        return channel_data
