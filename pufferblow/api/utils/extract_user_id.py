def extract_user_id(auth_token: str) -> str:
    """
    Extractes the `user_id` from an `auth_token`.

    Args:
        `auth_token` (str): A user's `auth_token`.

    Returns:
        str: The extracted `user_id` from the `auth_token`.
    """
    if not auth_token or auth_token.count(".") != 2:
        return ""

    try:
        from pufferblow.core.bootstrap import api_initializer

        payload = api_initializer.auth_token_manager.decode_access_token(
            auth_token, verify_exp=True
        )
        return str(payload["sub"])
    except Exception:
        return ""
