"""Package-wide constants for the PufferBlow server runtime."""

import os
import platform

from rich import print

PACKAGE_NAME = "pufferblow"
VERSION = "0.0.1-beta"
AUTHOR = "ramsy0dev"
ORG_GITHUB = "https://github.com/pufferblow"
REPO_GITHUB = "https://github.com/pufferblow/pufferblow"

BANNER = f"""
                  ___  ___            _     _
                 / __)/ __)          | |   | |
     ____  _   _| |__| |__ ____  ____| | _ | | ___  _ _ _
    |  _ \\| | | |  __)  __) _  )/ ___) || \\| |/ _ \\| | | |
    | | | | |_| | |  | | ( (/ /| |   | |_) ) | |_| | | | |
    | | |_/\\____|_|  |_|  \\____)_|   |____/|_|\\___/ \\____|
    |_|
                 Made with love by '{AUTHOR}'
        - Escape surveillance and gain anonymity -
"""


def banner() -> None:
    """Render the package banner in the terminal."""
    print(BANNER)


CURRENT_PLATFORM = platform.system()

if CURRENT_PLATFORM == "Windows":
    HOME = os.environ["USERPROFILE"]
    SLASH = "\\"
else:
    HOME = os.environ["HOME"]
    SLASH = "/"
