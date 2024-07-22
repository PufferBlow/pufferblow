import datetime

# Keys table
from pufferblow.src.database.tables.keys import Keys

class EncryptionKey(object):
    """ Encryption key data class """ 
    key_value           :           str
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
            associated_to   =   self.associated_to,
            user_id         =   self.user_id,
            message_id      =   self.message_id,
            created_at      =   self.created_at
        )

        return key
    
    def to_dict(self) -> dict:
        """ Returns the data in dict format """
        return {
            "key_value"     :   self.key_value,
            "associated_to" :   self.associated_to,
            "user_id"       :   self.user_id,
            "message_id"    :   self.message_id,
            "created_at"    :   self.created_at
        }
    
    def to_tuple(self) -> tuple:
        """ Returns the data in tuple format """
        return (
            self.key_value,
            self.associated_to,
            self.user_id,
            self.message_id,
            self.created_at
        )

