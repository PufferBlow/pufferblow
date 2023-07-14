
class Message (object):
    """ Message model """

    message_id              :       str
    message_content         :       str
    sender_user_id          :       str
    channel_id              :       str = None
    conversation_id         :       str = None
    sended_at               :       str

    def to_json(self) -> dict:
        """ Returns the jmessage data in json format """
        message_data = {
            "message_id"            :   self.message_id,
            "message_content"       :   self.message_content,
            "sender_user_id"        :   self.sender_user_id,
            "channel_id"            :   self.channel_id,
            "conversation_id"       :   self.conversation_id,
            "sended_at"             :   self.sended_at
        }

        return message_data

    def to_tuple(self) -> tuple:
        """ Reutns the message data in tuple format """
        message_data = (
            self.message_id,
            self.message_content,
            self.sender_user_id,
            self.channel_id,
            self.conversation_id,
            self.sended_at
        )

        return message_data
