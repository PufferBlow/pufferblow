import pytz
import datetime

def is_able_to_update(updated_at: datetime.datetime, suspend_time: int) -> bool:
    """
    Checks if the user is able to update their info or reset their
    `auth_token` based on the `updated_at`
    
    Args:
        `updated_at` (str): The value of the column `updated_at`.
        `suspend_time` (int): The days number that should pass until the user is eligible to update their info or reset their `auth_token`.
    
    Returns:
        bool: True if the user is eligible otherwise False.
    """
    if updated_at is None:
        return True

    current_time = datetime.datetime.now()
    
    difference = current_time - updated_at

    if difference.days > suspend_time:
        return True

    return False
