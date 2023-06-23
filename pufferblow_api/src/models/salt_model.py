
class Salt (object):
    """ Salt model """

    salt_value              :       str
    hashed_data             :       str
    user_id                 :       str
    associated_to           :       str
    created_at              :       str

    def to_json(self) -> dict:
        """ Returns the salt data as json """
        salt_data = {
            "salt_value"            :   self.salt_value,
            "hashed_data"           :   self.hashed_data,
            "user_id"               :   self.user_id,
            "associated_to"         :   self.associated_to,
            "created_at"            :   self.created_at
        }

        return salt_data

    def to_tuple(self) -> tuple:
        """ Reutns the salt data in tuple format """
        salt_data = (
            self.salt_value,
            self.hashed_data,
            self.user_id,
            self.associated_to,
            self.created_at
        )

        return salt_data