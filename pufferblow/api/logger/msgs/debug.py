"""Debug-level log message builders.

Every function in this module previously interpolated raw secret material
(auth tokens, plaintext passwords, encryption key values, hashed-but-
nonetheless-sensitive blobs) directly into the log message. That
exposes any attacker who can read the log file — or its rotated
backups in `/var/log/` — to credential replay and key extraction.

The functions are kept (and keep their original signatures) so call
sites in `user_manager.py` / `database_handler.py` don't need to
change. The bodies are rewritten to log ONLY the safe, non-secret
metadata that's useful for debugging: which user, which key
relationship, validity outcome. The secret material itself never
reaches the log surface.
"""


def DEBUG_NEW_USER_ID_GENERATED(user_id) -> str:
    """Log a freshly generated user id (non-secret)."""
    return f"Generated user_id={user_id}"


def DEBUG_NEW_AUTH_TOKEN_GENERATED(auth_token) -> str:
    """Log auth-token generation WITHOUT the token value.

    `auth_token` is intentionally not interpolated. The argument is
    accepted (and ignored) so existing call sites stay working.
    """
    _ = auth_token  # explicitly discarded — see module docstring
    return "Generated new auth token"


def DEBUG_NEW_AUTH_TOKEN_HASHED(auth_token, hashed_auth_token, key) -> str:
    """Log auth-token hashing WITHOUT token, ciphertext, or key value."""
    _ = (auth_token, hashed_auth_token, key)
    return "Hashed auth token"


def DEBUG_NEW_AUTH_TOKEN_SAVED(auth_token) -> str:
    """Log auth-token persistence WITHOUT the token value."""
    _ = auth_token
    return "Persisted new auth token"


def DEBUG_NEW_DERIVED_KEY_CREATED(user, key) -> str:
    """Log derived-key creation with user + relationship only."""
    return (
        f"Derived key created: user_id={user.user_id} "
        f"associated_to={key.associated_to}"
    )


def DEBUG_NEW_DERIVED_KEY_SAVED(key) -> str:
    """Log derived-key persistence with the relationship metadata only.

    The previous implementation called `key.to_dict()` and dropped
    the entire row into the log, including the raw key material.
    """
    return (
        f"Derived key saved: user_id={key.user_id} "
        f"associated_to={key.associated_to}"
    )


def DEBUG_DERIVED_KEY_UPDATED(key) -> str:
    """Log a derived-key rotation without exposing the new value."""
    return (
        f"Derived key rotated: user_id={key.user_id} "
        f"associated_to={key.associated_to}"
    )


def DEBUG_DERIVED_KEY_DELETED(key) -> str:
    """Log a derived-key deletion with relationship metadata only."""
    return (
        f"Derived key deleted: user_id={key.user_id} "
        f"associated_to={key.associated_to}"
    )


def DEBUG_NEW_HASH_SALT_CREATED(salt) -> str:
    """Log hash-salt creation without the salt value or hashed data."""
    return f"Hash salt created: associated_to={salt.associated_to}"


def DEBUG_NEW_HASH_SALT_SAVED(salt) -> str:
    """Log hash-salt persistence without the salt value."""
    return f"Hash salt saved: associated_to={salt.associated_to}"


def DEBUG_NEW_PASSWORD_HASHED(password, hashed_password) -> str:
    """Log password hashing WITHOUT the password or its hash.

    Hashed passwords are still credential-equivalent: an attacker who
    grabs the hash can attempt offline cracking. Neither field is
    logged.
    """
    _ = (password, hashed_password)
    return "Hashed password"


def DEBUG_USERNAME_ENCRYPTED(username, encrypted_username) -> str:
    """Log username encryption without the plaintext or ciphertext."""
    _ = (username, encrypted_username)
    return "Encrypted username"


def DEBUG_SIGN_UP_USER_START(user_id, username) -> str:
    """Log the start of a signup flow with the new user_id + username."""
    return f"Sign up start: user_id={user_id} username={username}"


def DEBUG_GET_USER_START(user_id, username) -> str:
    """Log the start of a user-fetch with the identifying inputs."""
    return f"Fetch user: user_id={user_id} username={username}"


def DEBUG_USER_FOUND(user_id, username) -> str:
    """Log a successful user lookup."""
    return f"User found: user_id={user_id} username={username}"


def DEBUG_USER_NOT_FOUND(user_id, username) -> str:
    """Log a missed user lookup."""
    return f"User not found: user_id={user_id} username={username}"


def DEBUG_USERNAME_DECRYPTED(encrypted_username, decrypted_username) -> str:
    """Log username decryption without exposing either form."""
    _ = (encrypted_username, decrypted_username)
    return "Decrypted username"


def DEBUG_VALIDATE_AUTH_TOKEN(hashed_auth_token, is_valid) -> str:
    """Log the outcome of an auth-token validation without the hash."""
    _ = hashed_auth_token
    return f"Auth token validation: valid={is_valid}"


def DEBUG_FETCH_USERS_ID(users_id) -> str:
    """Log a user-id batch fetch with the count, not the full list.

    The previous version dumped the entire list of user ids into the
    log line, which on a populous instance can be megabytes per call
    and turns the log into a noisy data export.
    """
    try:
        count = len(users_id)
    except TypeError:
        count = "?"
    return f"Fetched user ids: count={count}"


def DEBUG_FETCH_USERNAMES(usernames) -> str:
    """Log a username batch fetch with the count, not the full list."""
    try:
        count = len(usernames)
    except TypeError:
        count = "?"
    return f"Fetched usernames: count={count}"
