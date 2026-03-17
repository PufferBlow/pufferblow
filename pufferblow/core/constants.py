"""Package-wide constants for the PufferBlow server runtime."""

import os
import platform

PACKAGE_NAME = "pufferblow"
VERSION = "0.0.1-beta"
AUTHOR = "ramsy0dev"
ORG_GITHUB = "https://github.com/pufferblow"
REPO_GITHUB = "https://github.com/pufferblow/pufferblow"

BANNER = f"""[bold cyan]
  ____         __  __          ____  _
 |  _ \\ _   _ / _|/ _| ___ _ _| __ )| | _____      __
 | |_) || | | |  _|  _|/ _ \\ '__| _ \\| |/ _ \\ \\ /\\ / /
 |  __/ | |_| | | | | |  __/ |  | |_) | | (_) \\ V  V /
 |_|     \\__,_|_| |_|  \\___|_|  |____/|_|\\___/  \\_/\\_/
[/bold cyan][dim]  v{VERSION}  ·  {AUTHOR}  ·  Escape surveillance, gain anonymity.[/dim]
"""


def banner() -> None:
    """Render the package banner in the terminal."""
    from rich import print as rprint

    rprint(BANNER)


CURRENT_PLATFORM = platform.system()

if CURRENT_PLATFORM == "Windows":
    HOME = os.environ["USERPROFILE"]
    SLASH = "\\"
else:
    HOME = os.environ["HOME"]
    SLASH = "/"
