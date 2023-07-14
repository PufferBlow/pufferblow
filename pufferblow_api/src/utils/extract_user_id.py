
def extract_user_id(auth_token: str) -> str:
    """ Extractes the user_id from an authentication token then it returns it """
    return auth_token.split(".")[0]
