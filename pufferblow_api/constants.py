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
        "email",
        "password",
    ],
    "message_id": [
        "message_content",
        "sender"
    ] 
}

# Logs messages
NEW_USER_SIGNUP_SUCCESSFULLY = lambda user: f"New user signup: user_id=\"{user.user_id}\""
REQUEST_FOR_USER_PROFILE     = lambda user_data, viewer_user_id: f"User profile requested: viewer=\"{viewer_user_id}\", target=\"{user_data['user_id']}\", user_data={user_data}"

NEW_USER_ID_GENERATED = lambda user_id: f"New user_id generated: user_id=\"{user_id}\""

NEW_AUTH_TOKEN_GENERATED = lambda auth_token: f"New auth_token generated: auth_token=\"{auth_token}\""
NEW_AUTH_TOKEN_HASHED  = lambda auth_token, hashed_auth_token, salt: f"New auth_token hashed: auth_token=\"{auth_token}\", hashed_auth_token=\"{hashed_auth_token}\", salt=\"{salt.salt_value}\""
NEW_AUTH_TOKEN_SAVED   = lambda auth_token: f"New auth_token saved to \"auth_tokens\" table: {auth_token}"

NEW_DERIVED_KEY_CREATED = lambda user, key: f"New derived key created: user_id=\"{user.user_id}\", key=\"{key.key_value}\", salt=\"{key.salt}\""
NEW_DERIVED_KEY_SAVED   = lambda key: f"New derived key saved to \"keys\": {key.to_json()}"

NEW_HASH_SALT_CREATED = lambda salt: f"New salt created: salt=\"{salt.salt_value}\", associated_to=\"{salt.associated_to}\", hashed_data=\"{salt.hashed_data}\""
NEW_HASH_SALT_SAVED   = lambda salt: f"New salt saved to \"salts\": {salt.to_json()}"

NEW_PASSWORD_HASHED = lambda password, hashed_password: f"New password hashed: password=\"{password}\", hashed_password=\"{hashed_password}\""

EMAIL_ENCRYPTED = lambda email, encrypted_email: f"Email encrypted: email=\"{email}\", encrypted_email=\"{encrypted_email}\""
EMAIL_DECRYPTED = lambda encrypted_email, decrypted_email: f"Email decrypted: encrypted_email=\"{encrypted_email}\", decrypted_email=\"{decrypted_email}\""

USERNAME_ENCRYPTED = lambda username, encrypted_username: f"Username encrypted: username=\"{username}\", encrypted_username=\"{encrypted_username}\""
USERNAME_DECRYPTED = lambda encrypted_username, decrypted_username: f"Username decrypted: encrypted_username=\"{encrypted_username}\", decrypted_username=\"{decrypted_username}\""

VALIDATE_AUTH_TOKEN = lambda hashed_auth_token, is_valid: f"Validate auth_token: hashed_auth_token=\"{hashed_auth_token}\", is_valid=\"{is_valid}\""

REQUEST_SALT_VALUE = lambda user_id, salt_value, associated_to: f"Salt requested to hash some data: user_id=\"{user_id}\", salt=\"{salt_value}\", associated_to=\"{associated_to}\""

FETCH_USERS_ID = lambda users_id: f"Fetched users id: users_id={users_id}"
