# Users table
from pufferblow.api.database.tables.users import Users

class User:
    """ User model """
    user_id                  :       str
    username                 :       str
    password                 :       str                    =       ""
    about                    :       str                    =       None       
    avatar_url               :       str                    =       None
    banner_url               :       str                    =       None
    inbox_id                 :       str                    =       None
    origin_server            :       str                    =       ""
    status                   :       str
    roles_ids                :       list                   =       []
    last_seen                :       str
    joined_servers_ids       :       list                   =       []
    raw_auth_token           :       str                    =       ""    
    encrypted_auth_token     :       str                    =       ""
    auth_token_expire_time   :       str                    =       ""
    created_at               :       str    
    updated_at               :       str                    =       ""

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
            password               =   self.password,
            avatar_url             =   self.avatar_url,
            banner_url             =   self.banner_url,
            inbox_id               =   self.inbox_id,
            about                  =   self.about,
            status                 =   self.status,
            roles_ids              =   self.roles_ids,
            last_seen              =   self.last_seen,
            origin_server          =   self.origin_server,
            joined_servers_ids     =   self.joined_servers_ids,
            auth_token             =   self.encrypted_auth_token,
            auth_token_expire_time =   self.auth_token_expire_time,
            created_at             =   self.created_at,
            updated_at             =   self.updated_at,
        )

        return user
    
    def load_table_metadata(self, table_metadata: Users) -> dict:
        """
        Load metadata from a `Users` table object into
        the `self`'s attributes

        Args:
            `table_metadata` (User): The `Users` table object containing the metadata to load.
        
        Returns:
            tuple: The metadata in dict format.
        """
        self.user_id                 =   table_metadata.user_id
        self.username                =   table_metadata.username
        self.password                =   table_metadata.password
        self.avatar_url              =   table_metadata.avatar_url
        self.banner_url              =   table_metadata.banner_url
        self.status                  =   table_metadata.status
        self.last_seen               =   table_metadata.last_seen
        self.inbox_id                =   table_metadata.inbox_id
        self.roles_ids               =   table_metadata.roles_ids
        self.joined_servers_ids      =   table_metadata.joined_servers_ids
        self.created_at              =   table_metadata.created_at
        self.auth_token              =   table_metadata.auth_token
        self.auth_token_expire_time  =   table_metadata.auth_token_expire_time
        self.updated_at              =   table_metadata.updated_at

        return self.to_dict()
    
    def to_dict(self) -> dict:
        """ Returns the user data as dict """
        USER_DATA = {
            "user_id"                   :       self.user_id,
            "username"                  :       self.username,
            "password"                  :       self.password,
            "about"                     :       self.about,
            "avatar_url"                :       self.avatar_url,
            "banner_url"                :       self.banner_url,
            "status"                    :       self.status,
            "origin_server"             :       self.origin_server,
            "inbox_id"                  :       self.inbox_id,
            "roles_ids"                 :       self.roles_ids,
            "last_seen"                 :       self.last_seen,
            "joined_servers_ids"        :       self.joined_servers_ids,
            "auth_token"                :       self.encrypted_auth_token,
            "auth_token_expire_time"    :       self.auth_token_expire_time,
            "created_at"                :       self.created_at,
            "updated_at"                :       self.updated_at,
        }

        return USER_DATA

    def to_tuple(self) -> tuple:
        """ Returns the user data in tuple format """
        return (
            self.user_id,
            self.username,
            self.password,
            self.status,
            self.about,
            self.avatar_url,
            self.banner_url,
            self.origin_server,
            self.roles_ids,
            self.inbox_id,
            self.last_seen,
            self.joined_servers_ids,
            self.encrypted_auth_token,
            self.auth_token_expire_time,
            self.created_at,
            self.updated_at
        )
