
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
            "is_admin"                  :       self.is_admin
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
            self.is_admin
        )

        return USER_DATA
