import datetime

from rich import print

class User:
    """ User model """

    user_id                  :       str
    username                 :       str
    email                    :       str                    =       ""
    password_hash            :       str                    =       ""
    status                   :       str 
    last_seen                :       str
    conversations            :       list                   =       []
    contacts                 :       list                   =       []
    created_at               :       str    
    raw_auth_token           :       str                    =       ""    
    encrypted_auth_token     :       str                    =       ""
    auth_token_expire_time   :       str                    =       ""

    def to_json(self) -> dict:
        """ Returns the user data as json """
        USER_DATA = {
            "user_id"                   :       self.user_id,
            "username"                  :       self.username,
            "email"                     :       self.email,
            "password_hash"             :       self.password_hash,
            "status"                    :       self.status,
            "last_seen"                 :       self.last_seen,
            "conversations"             :       self.conversations,
            "contacts"                  :       self.contacts,
            "auth_token"                :       self.encrypted_auth_token,
            "auth_token_expire_time"    :       self.auth_token_expire_time,
            "created_at"                :       self.created_at
        }

        return USER_DATA

    def to_tuple(self) -> tuple:
        """ Reutns the user data in tuple format """
        USER_DATA = (
            self.user_id,
            self.username,
            self.email,
            self.password_hash,
            self.status,
            self.last_seen.strftime("%Y-%m-%d"),
            self.conversations,
            self.contacts,
            self.encrypted_auth_token,
            self.auth_token_expire_time.strftime("%Y-%m-%d"),
            self.created_at.strftime("%Y-%m-%d")
        )

        return USER_DATA
