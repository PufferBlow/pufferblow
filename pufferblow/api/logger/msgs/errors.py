"""Error-level log message builders.

One-liner sentences with a clear remediation hint where one applies.
"""


def ERROR_NO_CONFIG_FILE_FOUND(config_file_path: str) -> str:
    """Log a fatal missing-config-file error with the resolved path + fix."""
    return (
        f"No configuration file at {config_file_path!r}. "
        "Run `pufferblow setup` to initialize one."
    )
