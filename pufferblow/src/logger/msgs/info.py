
# Models
from pufferblow.src.models.user_model import User

def INFO_NEW_USER_SIGNUP_SUCCESSFULLY(user: User) -> str:
    msg = f"New user signed up successfully. User ID: '{user.user_id}'"
    return msg

def INFO_REQUEST_USER_PROFILE(user_data, viewer_user_id) -> str:
    msg =  f"Requested user profile. Viewer: '{viewer_user_id}', Target: '{user_data['user_id']}', User Data: {user_data}"
    return msg

def INFO_REQUEST_USERS_LIST(viewer_user_id, auth_token) -> str:
    msg =  f"Request to get the list of users by User ID: '{viewer_user_id}'."
    return msg
    
def INFO_UPDATE_USERNAME(user_id, new_username, old_username) -> str:
    msg = f"Updated username. User ID: '{user_id}', Old username: '{old_username}', New username: '{new_username}'."
    return msg
    
def INFO_UPDATE_USER_STATUS(user_id, from_status, to_status) -> str:
    msg = f"Updated user status. User ID: '{user_id}', From status: '{from_status}', To status: '{to_status}'."
    return msg
    
def INFO_USER_STATUS_UPDATE_SKIPPED(user_id) -> str:
    msg = f"Skipped status update for User ID: '{user_id}' due to passing the same status value."
    return msg
    
def INFO_USER_STATUS_UPDATE_FAILED(user_id, status) -> str:
    msg = f"Failed to update the status for User ID: '{user_id}'. Provided status value not found. Status: '{status}', Accepted status values: ['online', 'offline']."
    return msg
    
def INFO_UPDATE_USER_PASSWORD(user_id, hashed_new_password) -> str:
    msg = f"Updated password. User ID: '{user_id}', Hashed new password: '{hashed_new_password}'"
    return msg
    
def INFO_UPDATE_USER_PASSWORD_FAILED(user_id) -> str:
    msg = f"Failed to update the password for User ID: '{user_id}' due to an invalid old password."
    return msg
    
def INFO_RESET_USER_AUTH_TOKEN(user_id, new_hashed_auth_token) -> str:
    msg = f"Reseted auth_token for User ID: '{user_id}', New hashed auth_token: '{new_hashed_auth_token}'."
    return msg
    
def INFO_RESET_USER_AUTH_TOKEN_FAILED(user_id) -> str:
    msg = f"Faild to reset auth_token for User ID: '{user_id}' due to the incorrect password that was passed in."
    return msg
    
def INFO_AUTH_TOKEN_SUSPENSION_TIME(user_id) -> str:
    msg = f"Faild to reset authentication token for User ID: {user_id}. Suspension time has not elapsed."
    return msg
    
def INFO_NEW_CHANNEL_CREATED(user_id, channel_id, channel_name) -> str:
    msg = f"New channel created by User ID: '{user_id}', Channel ID: '{channel_id}', Channel Name: '{channel_name}'."
    return msg
    
def INFO_CHANNEL_DELETED(user_id, channel_id) -> str:
    msg = f"Channel ID: '{channel_id}' deleted by Admin with User ID: '{user_id}'."
    return msg
    
def INFO_REQUESTED_CHANNEL_DATA(channel_id, viewer_user_id) -> str:
    msg = f"Requested data about Channel ID: '{channel_id}' by User ID: '{viewer_user_id}'."
    return msg
    
def INFO_CHANNEL_ID_NOT_FOUND(channel_id, viewer_user_id) -> str:
    msg = f"The provided channel ID: {channel_id} by User ID: '{viewer_user_id}' was not found."
    return msg
    
def INFO_CHANNEL_IS_NOT_PRIVATE(user_id, channel_id, to_add_user_id) -> str:
    msg = f"Faild to add User ID: '{to_add_user_id}' to Channel ID: '{channel_id}' by Admin User ID: '{user_id}'. Channel is not private."
    return msg
    
def INFO_NEW_USER_ADDED_TO_PRIVATE_CHANNEL(user_id, channel_id, to_add_user_id) -> str:
    msg = f"New User ID: '{to_add_user_id}' added to Channel ID: '{channel_id}' by Admin User ID: '{user_id}'."
    return msg
    
def INFO_USER_REMOVED_FROM_A_PRIVATE_CHANNEL(user_id, channel_id, to_remove_user_id) -> str:
    msg = f"User ID: '{to_remove_user_id}' was removed from Channel ID: '{channel_id}' by Admin User ID: '{user_id}'."
    return msg

def INFO_FAILD_TO_REMOVE_USER_FROM_CHANNEL_TARGETED_USER_IS_AN_ADMIN(user_id, channel_id, to_remove_user_id) -> str:
    msg = f"Admin User ID: '{user_id}' tried to remove Admin User ID: '{to_remove_user_id}' from Channel ID: '{channel_id}'."
    return msg

def INFO_FAILD_TO_REMOVE_USER_FROM_CHANNEL_TARGETED_USER_IS_SERVER_OWNER(user_id, channel_id, to_remove_user_id) -> str:
    msg =  f"User ID: '{user_id}' tried to remove the server Admin ID: '{to_remove_user_id}' from Channel ID: '{channel_id}'."
    return msg

def CLIENT_IP_BLOCKED(client_ip: str, requests_count: int, rate_limit_warnings: int) -> str:
    msg = f"Malicious activities detected with the client IP: '{client_ip}', it have been [bold red]blocked[reset]. Number of requests is '{requests_count}' and number of rate limite warnings is '{rate_limit_warnings}'."

    return msg
