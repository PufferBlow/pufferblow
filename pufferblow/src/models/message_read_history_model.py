
# Tables
from pufferblow.src.database.tables.message_read_history import MessageReadHistory

class MessageReadHistoryModel(object):
    """ MessageReadHistory model """

    user_id                 :   str
    viewed_messages_ids     :   list[str]
    created_at              :   str
    updated_at              :   str = None

    def create_table_metadata(self) -> MessageReadHistory:
        """
        Create a `MessageReadHistory` table object

        Args:
            None.
        
        Returns:
            MessageReadHistory: A `MessageReadHistory` table object.
        """
        message_read_history = MessageReadHistory(
            user_id=self.user_id,
            viewed_messages_ids=self.viewed_messages_ids,
            created_at=self.created_at,
            updated_at=self.updated_at
        )

        return message_read_history
    
    def load_table_metadata(self, table_metadata: MessageReadHistory) -> dict:
        """
        Load metadata from a `MessageReadHistory` table object into
        the `self`'s attributes

        Args:
            `table_metadata` (User): The `MessageReadHistory` table object containing the metadata to load.
        
        Returns:
            tuple: The metadata in dict format.
        """
        self.user_id                =   table_metadata.user_id
        self.viewed_messages_ids    =   table_metadata.viewed_messages_ids
        self.created_at             =   table_metadata.created_at
        self.updated_at             =   table_metadata.updated_at

        return self.to_dict()
    
    def to_dict(self) -> dict:
        """ 
        Returns the MessageReadHistory metadata in dict format
        """
        return {
            "user_id": self.user_id,
            "viewed_messages_ids": self.viewed_messages_ids,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }
    
    def to_tuple(self) -> tuple:
        """
        Returns the MessageReadHistory data in tuple format 
        """
        return (
            self.user_id,
            self.viewed_messages_ids,
            self.created_at,
            self.updated_at
        )
 
