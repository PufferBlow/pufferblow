import hashlib

def create_sha256(data: str) -> str:
    """
    Create a sha 256 of some `data`

    Args:
        data (str): The data to create sha256 of.
    
    Returns:
        str: Created sha256.
    """
    sha256 = hashlib.sha256()
    sha256.update(data.encode())

    return sha256.hexdigest()
