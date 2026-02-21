def ERROR_NO_CONFIG_FILE_FOUND(config_file_path: str) -> str:
    """ERROR NO CONFIG FILE FOUND."""
    msg = f"No configuration file was found at '{config_file_path}', please run pufferblow-api with the 'setup' command to initiat the setup process."

    return msg
