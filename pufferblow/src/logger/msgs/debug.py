
def DEBUG_NEW_USER_ID_GENERATED(user_id) -> str:
    msg =  f"Generated new user ID: '{user_id}'."
    return msg

def DEBUG_NEW_AUTH_TOKEN_GENERATED(auth_token) -> str:
    msg =  f"Generated new authentication token: '{auth_token}'."
    return msg

def DEBUG_NEW_AUTH_TOKEN_HASHED(auth_token, hashed_auth_token, salt) -> str:
    msg =  f"Hashed new authentication token. Auth token: '{auth_token}', Hashed token: '{hashed_auth_token}', Salt: '{salt.salt_value}'."
    return msg

def DEBUG_NEW_AUTH_TOKEN_SAVED(auth_token) -> str:
    msg =  f"Saved new authentication token, AuthToken: '{auth_token}'."
    return msg

def DEBUG_NEW_DERIVED_KEY_CREATED(user, key) -> str:
    msg =  f"Created new derived key. User ID: '{user.user_id}', Key: '{key.key_value}'."
    return msg

def DEBUG_NEW_DERIVED_KEY_SAVED(key) -> str:
    msg = f"Saved new derived key in 'keys': '{key.to_json()}'."
    return msg

def DEBUG_DERIVED_KEY_UPDATED(key) -> str:
    msg = f"Derived key updated for User ID: '{key.user_id}', associated_to: '{key.associated_to}', New Key value: '{key.key_value}'."
    return msg
    
def DEBUG_DERIVED_KEY_DELETED(key) -> str:
    msg = f"Deleted derived key from 'keys': {key.to_json()}."
    return msg
    
def DEBUG_NEW_HASH_SALT_CREATED(salt) -> str:
    msg = f"Created new hash salt. Salt: '{salt.salt_value}', Associated to: '{salt.associated_to}', Hashed data: '{salt.hashed_data}'."
    return msg
    
def DEBUG_NEW_HASH_SALT_SAVED(salt) -> str:
    msg = f"Saved new hash salt in 'salts': {salt.to_json()}."
    return msg
    
def DEBUG_NEW_PASSWORD_HASHED(password, hashed_password) -> str:
    msg = f"Hashed new password. Password: '{password}', Hashed password: '{hashed_password}'."
    return msg
    
def DEBUG_USERNAME_ENCRYPTED(username, encrypted_username) -> str:
    msg = f"Encrypted username. Username: '{username}', Encrypted username: '{encrypted_username}'."
    return msg
    
def DEBUG_USERNAME_DECRYPTED(encrypted_username, decrypted_username) -> str:
    msg = f"Decrypted username. Encrypted username: '{encrypted_username}', Decrypted username: '{decrypted_username}'."
    return msg
    
def DEBUG_VALIDATE_AUTH_TOKEN(hashed_auth_token, is_valid) -> str:
    msg = f"Validated authentication token. Hashed token: '{hashed_auth_token}', Valid: '{is_valid}'."
    return msg
    
def DEBUG_REQUEST_SALT_VALUE(user_id, salt_value, associated_to) -> str:
    msg = f"Requested salt value for hashing data. User ID: '{user_id}', Salt: '{salt_value}', Associated to: '{associated_to}'."
    return msg
    
def DEBUG_FETCH_USERS_ID(users_id) -> str:
    msg = f"Fetched user IDs. User IDs: '{users_id}'."
    return msg
    
def DEBUG_FETCH_USERNAMES(usernames) -> str:
    msg = f"Fetched usernames. Usernames: '{usernames}'."
    return msg
