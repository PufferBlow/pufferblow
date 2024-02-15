import os

from rich import print

# Package info
PACKAGE_NAME    =   "pufferblow-api"
VERSION         =   "0.0.1-beta"
AUTHER          =   "ramsy0dev"
ORG_GITHUB      =   "https://github.com/PufferBlow"
REPO_GITHUB     =   "https://github.com/PufferBlow/pufferblow-api"

BANNER = """
                  ___  ___            _     _
                 / __)/ __)          | |   | |
     ____  _   _| |__| |__ ____  ____| | _ | | ___  _ _ _ 
    |  _ \| | | |  __)  __) _  )/ ___) || \| |/ _ \| | | |
    | | | | |_| | |  | | ( (/ /| |   | |_) ) | |_| | | | |
    | ||_/ \____|_|  |_|  \____)_|   |____/|_|\___/ \____|
    |_|                                                   
                 Made with [bold red]❤️[reset] by [bold bright_green]'ramsy0dev'[reset]
        - Escape [bold red]surveillance[reset] and gain [bold green]anonymity[reset] -
"""

def banner() -> None: print(BANNER)

# The $HOME path
HOME = os.environ["HOME"]

# Log levels
INFO        =   0
DEBUG       =   1
ERROR       =   2
CRITICAL    =   3

log_level_map = {
    INFO: "INFO",
    DEBUG: "DEBUG",
    ERROR: "ERROR",
    CRITICAL: "CRITICAL"
}
