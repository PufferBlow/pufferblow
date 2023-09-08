import pytz
import datetime

def date_in_gmt(format: str) -> str:
    """
    Returns the current in GMT timezone
    
    Parameters:
        format: The date format
    """
    return datetime.datetime.now(pytz.timezone("GMT")).strftime(format)
