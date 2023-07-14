
class Channel (object):
    """ Channel model """

    channel_id              :       str
    channel_name            :       str
    messages_ids            :       list[str]       =   []
    is_private              :       bool            =   False
    allowed_users           :       list[str]       =   None
    created_at              :       str

    def to_json(self) -> dict:
        """ Returns the channel data in json format """
        channel_data = {
            "channel_id"         :   self.channel_id,
            "channel_name"       :   self.channel_name,
            "messages_ids"       :   self.messages_ids,
            "is_private"         :   self.is_private,
            "allowed_users"      :   self.allowed_users,
            "created_at"         :   self.created_at
        }

        return channel_data

    def to_tuple(self) -> tuple:
        """ Reutns the channel data in tuple format """
        channel_data = (
            self.channel_id,
            self.channel_name,
            self.messages_ids,
            self.is_private,
            self.allowed_users,
            self.created_at
        )

        return channel_data
