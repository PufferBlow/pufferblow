import pytz
import datetime

def date_in_gmt(format: str | None = "%Y-%m-%d %H:%M:%S") -> str:
    """
    Returns the current date in GMT timezone
    
    Args:
        `format` (str): The date format.
    
    Returns:
        str: The date in the given `format`.
    """
    return datetime.datetime.now(pytz.timezone("GMT")).strftime(format)
