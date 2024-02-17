import json 

class Conversation :
    """ Conversation model """

    conversation_id         :       str
    members                 :       list
    messages_id             :       str
    started_at              :       str

    def to_json(self) -> json.dump:
        """ Returns the conversation data as json """
        CONVERSATION_DATA = {
            "conversation_id"   :       self.conversation_id,
            "members"           :       self.members,
            "messages_id"       :       self.messages_id,
            "started_at"        :       self.started_at
        }

        return json.dumps(
            CONVERSATION_DATA,
            indent=4
        )
