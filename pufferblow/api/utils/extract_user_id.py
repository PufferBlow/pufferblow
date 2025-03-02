
def extract_user_id(auth_token: str) -> str:
    """
    Extractes the `user_id` from an `auth_token`.

    Args:
        `auth_token` (str): A user's `auth_token`.
    
    Returns:
        str: The extracted `user_id` from the `auth_token`.
    """
    return auth_token.split(".")[0]
