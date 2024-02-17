
# Table
from pufferblow.src.database.tables.messages import Messages

class Message (object):
    """ Message model """

    message_id              :       str
    hashed_message          :       str
    raw_message             :       str  =  ""
    sender_user_id          :       str
    channel_id              :       str  =  None
    conversation_id         :       str  =  None
    sent_at                 :       str

    def create_table_metadata(self) -> Messages:
        """
        Create a `Messages` table object that contains
        the current message's metadata

        Args:
            `None`.
        
        Returns:
            Messages: A `Messages` table object.
        """
        message = Messages(
            message_id          =   self.message_id,
            hashed_message      =   self.hashed_message,
            sender_user_id      =   self.sender_user_id,
            channel_id          =   self.channel_id,
            conversation_id     =   self.conversation_id,
            sent_at             =   self.sent_at
        )

        return message

    def load_table_metadata(self, table_metadata: Messages) -> tuple:
        """
        Load metadata from a `Messages` table object into
        the `self`'s attributes

        Args:
            `table_metadata` (User): The `Messages` table object containing the metadata to load.
        
        Returns:
            tuple: The metadata formated in tuple.
        """
        self.message_id         =   table_metadata.message_id   
        self.hashed_message     =   table_metadata.hashed_message   
        self.sender_user_id     =   table_metadata.sender_user_id   
        self.channel_id         =   table_metadata.channel_id   
        self.conversation_id    =   table_metadata.conversation_id  
        self.sent_at            =   table_metadata.sent_at    

        return self.to_tuple()

    def to_json(self) -> dict:
        """ Returns the message data in json format """
        message_data = {
            "message_id"            :   self.message_id,
            "message"               :   self.raw_message,
            "sender_user_id"        :   self.sender_user_id,
            "channel_id"            :   self.channel_id,
            "conversation_id"       :   self.conversation_id,
            "sent_at"               :   self.sent_at
        }

        return message_data

    def to_tuple(self) -> tuple:
        """ Reutns the message data in tuple format """
        message_data = (
            self.message_id,
            self.hashed_message,
            self.sender_user_id,
            self.channel_id,
            self.conversation_id,
            self.sent_at
        )

        return message_data
