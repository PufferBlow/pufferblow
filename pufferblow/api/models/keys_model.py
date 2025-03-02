import datetime

# Keys table
from pufferblow.api.database.tables.keys import Keys

class EncryptionKey(object):
    """ Encryption key data class """ 
    key_value           :           str
    iv                  :           str
    associated_to       :           str
    user_id             :           str = None
    message_id          :           str = None
    created_at          =           datetime.date.today().strftime("%Y-%m-%d")

    def create_table_metadata(self) -> Keys:
        """
        Create a `Keys` table object that contains
        the current encryption key's metadata

        Args:
            `None`.
        
        Returns:
            Keys: A `keys` table object.
        """
        key = Keys(
            key_value       =   self.key_value,
            iv              =   self.iv,
            associated_to   =   self.associated_to,
            user_id         =   self.user_id,
            message_id      =   self.message_id,
            created_at      =   self.created_at
        )

        return key
    def load_table_metadata(self, table_metadata: Keys) -> dict:
        """
        Load metadata from a `Keys` table object into
        the `self`'s attributes

        Args:
            `table_metadata` (User): The `Keys` table object containing the metadata to load.
        
        Returns:
            dict: The metadata in dict format.
        """
        self.key_value      =   table_metadata.key_value
        self.iv             =   table_metadata.iv
        self.associated_to  =   table_metadata.associated_to
        self.user_id        =   table_metadata.user_id
        self.message_id     =   table_metadata.message_id
        self.created_at     =   table_metadata.created_at

        return self.to_dict()

    def to_dict(self) -> dict:
        """ Returns the data in dict format """
        return {
            "key_value"     :   self.key_value,
            "iv"            :   self.iv,            
            "associated_to" :   self.associated_to,
            "user_id"       :   self.user_id,
            "message_id"    :   self.message_id,
            "created_at"    :   self.created_at
        }
    
    def to_tuple(self) -> tuple:
        """ Returns the data in tuple format """
        return (
            self.key_value,
            self.iv,
            self.associated_to,
            self.user_id,
            self.message_id,
            self.created_at
        )
