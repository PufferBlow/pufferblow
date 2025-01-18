import os

import platform

from rich import print

# Package info
PACKAGE_NAME    =   "pufferblow"
VERSION         =   "0.0.1-beta"
AUTHOR          =   "ramsy0dev"
ORG_GITHUB      =   "https://github.com/pufferblow"
REPO_GITHUB     =   "https://github.com/pufferblow/pufferblow"

BANNER = f"""
                  ___  ___            _     _
                 / __)/ __)          | |   | |
     ____  _   _| |__| |__ ____  ____| | _ | | ___  _ _ _
    |  _ \\| | | |  __)  __) _  )/ ___) || \\| |/ _ \\| | | |
    | | | | |_| | |  | | ( (/ /| |   | |_) ) | |_| | | | |
    | | |_/\\____|_|  |_|  \\____)_|   |____/|_|\\___/ \\____|
    |_|
                 Made with [bold red]❤️[reset] by [bold bright_green]'{AUTHOR}'[reset]
        - Escape [bold red]surveillance[reset] and gain [bold green]anonymity[reset] -
"""

def banner() -> None: print(BANNER)

# The $HOME path
if platform.system() == "Windows":
    HOME = os.environ["USERPROFILE"]
    SLASH = "\\"
else:
    HOME = os.environ["HOME"]
    SLASH = "/"
