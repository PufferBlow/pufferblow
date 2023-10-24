# Users table
from pufferblow_api.src.database.tables.users import Users

class User:
    """ User model """
    user_id                  :       str
    username                 :       str
    password_hash            :       str                    =       ""
    status                   :       str
    last_seen                :       str
    conversations            :       list                   =       []
    contacts                 :       list                   =       []
    created_at               :       str    
    raw_auth_token           :       str                    =       ""    
    encrypted_auth_token     :       str                    =       ""
    auth_token_expire_time   :       str                    =       ""
    updated_at               :       str                    =       ""
    is_admin                 :       bool                   =       False
    is_owner                 :       bool                   =       False

    def __init__(self) -> None:
        pass

    def create_table_metadata(self) -> Users:
        """ 
        Create a `Users` table object that contains
        the current user's metadata

        Args:
            `None`.
        
        Returns:
            Users: A `Users` table object.
        """
        user = Users(
            user_id                =   self.user_id,
            username               =   self.username,
            password_hash          =   self.password_hash,
            status                 =   self.status,
            last_seen              =   self.last_seen,
            conversations          =   self.conversations,
            contacts               =   self.contacts,
            created_at             =   self.created_at,
            auth_token             =   self.encrypted_auth_token,
            auth_token_expire_time =   self.auth_token_expire_time,
            updated_at             =   self.updated_at,
            is_admin               =   self.is_admin,
            is_owner               =   self.is_owner,
        )

        return user
    
    def load_table_metadata(self, table_metadata: Users) -> None:
        """
        Load metadata from a `Users` table object into
        the `self`'s attributes

        Args:
            `table_metadata` (User): The `Users` table object containing the metadata to load.
        
        Returns:
            tuple: The metadata formated in tuple.
        """
        self.user_id                 =   table_metadata.user_id
        self.username                =   table_metadata.username
        self.password_hash           =   table_metadata.password_hash
        self.status                  =   table_metadata.status
        self.last_seen               =   table_metadata.last_seen
        self.conversations           =   table_metadata.conversations
        self.contacts                =   table_metadata.contacts
        self.created_at              =   table_metadata.created_at
        self.auth_token              =   table_metadata.auth_token
        self.auth_token_expire_time  =   table_metadata.auth_token_expire_time
        self.updated_at              =   table_metadata.updated_at
        self.is_admin                =   table_metadata.is_admin
        self.is_owner                =   table_metadata.is_owner

        return self.to_tuple()
    
    def to_json(self) -> dict:
        """ Returns the user data as json """
        USER_DATA = {
            "user_id"                   :       self.user_id,
            "username"                  :       self.username,
            "password_hash"             :       self.password_hash,
            "status"                    :       self.status,
            "last_seen"                 :       self.last_seen,
            "conversations"             :       self.conversations,
            "contacts"                  :       self.contacts,
            "auth_token"                :       self.encrypted_auth_token,
            "auth_token_expire_time"    :       self.auth_token_expire_time,
            "created_at"                :       self.created_at,
            "updated_at"                :       self.updated_at,
            "is_admin"                  :       self.is_admin,
            "is_owner"                  :       self.is_owner
        }

        return USER_DATA

    def to_tuple(self) -> tuple:
        """ Reutns the user data in tuple format """
        USER_DATA = (
            self.user_id,
            self.username,
            self.password_hash,
            self.status,
            self.last_seen,
            self.conversations,
            self.contacts,
            self.encrypted_auth_token,
            self.auth_token_expire_time,
            self.created_at,
            self.updated_at,
            self.is_admin,
            self.is_owner
        )

        return USER_DATA
