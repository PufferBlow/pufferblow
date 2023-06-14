import json

class EncryptionKey (object):
    """ Encryption key data class """
    key_value           :           str
    salt                :           str
    associated_to       :           str
    user_id             =           None
    message_id          =           None

    def to_json(self) -> json.dumps:
        """ Returns the data in json format """
        ENCRYPTION_KEY_DATA = {
            "key_value"             :       self.key_value,
            "salt"                  :       self.salt,
            "associated_to"         :       self.associated_to,
            "user_id"               :       self.user_id,
            "message_id"            :       self.message_id
        }

        return json.dumps(
            ENCRYPTION_KEY_DATA,
            indent=4,
            default=str,
            sort_keys=True
        )
    
    def to_tuple(self) -> tuple:
        """ Returns the data in tuple format """
        return (
            self.key_value,
            self.salt,
            self.associated_to,
            self.user_id,
            self.message_id
        )
