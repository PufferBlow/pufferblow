import os
import pytz
import datetime

def is_able_to_update(updated_at: str, suspend_time: int) -> bool:
    """
    Checks if the user is able to update their info or reset their
    `auth_token` based on the `updated_at`
    
    Parameters:
        updated_at (str): The value of the column `updated_at`
        suspend_time (int): How many times should pass until 
        the user is eligible to update their info or reset 
        their `auth_token`. (in days)
    
    Returns:
        bool: True if the user is eligible otherwise False
    """
    updated_at = datetime.datetime.strptime(updated_at, "%Y-%m-%d %H:%M:%S") 
    current_time = datetime.datetime.now(pytz.timezone("GMT"))

    current_time = current_time.replace(tzinfo=None)
    
    difference = current_time - updated_at

    if difference.days > suspend_time:
        return True

    return False
