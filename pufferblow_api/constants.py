import os

# PufferBlow-api info
PACKAGE_NAME = "PufferBlow-api"
VERSION      = "0.1.0"
AUTHER       = "ramsy"
GITHUB       = "https://github.com/PufferBlow/PufferBlow-api"  
ORG_GITHUB   = "https://github.com/PufferBlow"

# PufferBlow-api default config file
PUFFERBLOW_CONFIG_PATH = f"{os.environ['HOME']}/.config/pufferblow-api/config.yaml"
PUFFERBLOW_CONFIG = f"""# This is the config file for pufferblow-api
# please if you do edit this file you will need
# to restart, in order to apply the changes

api:
 - host: "0.0.0.0"
 - port: 7575
 - logs_path: {os.environ['HOME']}/pufferblow_api.log
 - workers: 7 # number of workers for guvicorn
 - connection_timeout: 60 # in seconds

supabase:
 - supabase_url: "<your supabase url>"
 - supabase_key: "<your supabase key>"
 - postregsql:
    - database_name: "<your database name>"
    - username: "<your username>"
    - password: "<your password>"
    - host: "<your database host>"
    - port: "<your database port>"
"""

# Salt and derived key associations
ASSOCIATIONS = {
    "user_id": [
        "username",
        "auth_token",
        "password",
    ],
    "message_id": [
        "message_content",
        "sender"
    ] 
}

# Logs messages
NEW_USER_SIGNUP_SUCCESSFULLY = lambda user: f"New user signed up successfully. User ID: '{user.user_id}'"
REQUEST_FOR_USER_PROFILE = lambda user_data, viewer_user_id: f"Requested user profile. Viewer: '{viewer_user_id}', Target: '{user_data['user_id']}', User Data: {user_data}"

NEW_USER_ID_GENERATED = lambda user_id: f"Generated new user ID: '{user_id}'"

NEW_AUTH_TOKEN_GENERATED = lambda auth_token: f"Generated new authentication token: '{auth_token}'"
NEW_AUTH_TOKEN_HASHED = lambda auth_token, hashed_auth_token, salt: f"Hashed new authentication token. Auth token: '{auth_token}', Hashed token: '{hashed_auth_token}', Salt: '{salt.salt_value}'"
NEW_AUTH_TOKEN_SAVED = lambda auth_token: f"Saved new authentication token in 'auth_tokens' table: {auth_token}"

NEW_DERIVED_KEY_CREATED = lambda user, key: f"Created new derived key. User ID: '{user.user_id}', Key: '{key.key_value}'"
NEW_DERIVED_KEY_SAVED = lambda key: f"Saved new derived key in 'keys': {key.to_json()}"
DERIVED_KEY_UPDATED = lambda key: f"Derived key updated for User ID: {key.user_id}, associated_to: {key.associated_to}, New Key value: {key.key_value}"
DERIVED_KEY_DELETED = lambda key: f"Deleted derived key from 'keys': {key.to_json()}"

NEW_HASH_SALT_CREATED = lambda salt: f"Created new hash salt. Salt: {salt.salt_value}, Associated to: '{salt.associated_to}', Hashed data: '{salt.hashed_data}'"
NEW_HASH_SALT_SAVED = lambda salt: f"Saved new hash salt in 'salts': {salt.to_json()}"

NEW_PASSWORD_HASHED = lambda password, hashed_password: f"Hashed new password. Password: '{password}', Hashed password: '{hashed_password}'"

USERNAME_ENCRYPTED = lambda username, encrypted_username: f"Encrypted username. Username: '{username}', Encrypted username: '{encrypted_username}'"
USERNAME_DECRYPTED = lambda encrypted_username, decrypted_username: f"Decrypted username. Encrypted username: '{encrypted_username}', Decrypted username: '{decrypted_username}'"

VALIDATE_AUTH_TOKEN = lambda hashed_auth_token, is_valid: f"Validated authentication token. Hashed token: '{hashed_auth_token}', Valid: {is_valid}"

REQUEST_SALT_VALUE = lambda user_id, salt_value, associated_to: f"Requested salt value for hashing data. User ID: '{user_id}', Salt: {salt_value}, Associated to: '{associated_to}'"

FETCH_USERS_ID = lambda users_id: f"Fetched user IDs. User IDs: {users_id}"

FETCH_USERNAMES = lambda usernames: f"Fetched usernames. Usernames: {usernames}"

UPDATE_USERNAME = lambda user_id, new_username, old_username: f"Updated username. User ID: '{user_id}', Old username: '{old_username}', New username: '{new_username}'"

UPDATE_USER_STATUS = lambda user_id, from_status, to_status: f"Updated user status. User ID: '{user_id}', From status: '{from_status}', To status: '{to_status}'"
USER_STATUS_UPDATE_SKIPPED = lambda user_id: f"Skipped status update for User ID: '{user_id}' due to passing the same status value."
USER_STATUS_UPDATE_FAILED = lambda user_id, status: f"Failed to update the status for User ID: '{user_id}'. Provided status value not found. Status: '{status}', Accepted status values: ['online', 'offline']."

UPDATE_USER_PASSWORD = lambda user_id, hashed_new_password: f"Updated password. User ID: '{user_id}', Hashed new password: '{hashed_new_password}'"
UPDATE_USER_PASSWORD_FAILED = lambda user_id: f"Failed to update the password for User ID: '{user_id}' due to an invalid old password."

RESET_USER_AUTH_TOKEN = lambda user_id, new_hashed_auth_token: f"Reseted auth_token for User ID: '{user_id}', New hashed auth_token: '{new_hashed_auth_token}'"
RESET_USER_AUTH_TOKEN_FAILD = lambda user_id: f"Faild to reset auth_token for User ID: '{user_id}' due to the incorrect password that was passed in."
AUTH_TOKEN_SUSPENSION_TIME = lambda user_id: f"Faild to reset authentication token for User ID: {user_id}. Suspension time has not elapsed"
