"""Package-wide constants for the PufferBlow server runtime."""

import os
import platform

PACKAGE_NAME = "pufferblow"
VERSION = "1.0.0"
AUTHOR = "ramsy0dev"
ORG_GITHUB = "https://github.com/pufferblow"
REPO_GITHUB = "https://github.com/pufferblow/pufferblow"

# ASCII rendering of the Pufferblow brand mark: 8 spokes radiating from a
# centered ring with a dot. Mirrors the SVG used by the web and desktop
# clients (8 spokes + ring + dot) so the CLI's first impression matches
# the rest of the surface. Replaces the previous block-letter
# `PufferBlow` art, which had no relationship to any other logo we ship.
BANNER = f"""[bold cyan]
              \\   |   /
               \\  |  /
                \\ | /
        --------( * )--------
                / | \\
               /  |  \\
              /   |   \\
[/bold cyan][bold]      Pufferblow[/bold]  [dim]v{VERSION}[/dim]
"""


def banner() -> None:
    """Render the package banner in the terminal."""
    from rich import print as rprint

    rprint(BANNER)


CURRENT_PLATFORM = platform.system()

# PUFFERBLOW_HOME overrides where ~/.pufferblow lives, independent of
# USERPROFILE/HOME. Needed because overriding USERPROFILE/HOME itself (the
# obvious way to isolate config dirs, e.g. for running two instances side by
# side) also hijacks Poetry's own cache/venv location on that same
# variable, breaking `poetry run`. See devp.federation.toml / the
# federation test harness for the motivating case.
_home_override = os.environ.get("PUFFERBLOW_HOME", "").strip()
if _home_override:
    HOME = _home_override
    SLASH = "\\" if CURRENT_PLATFORM == "Windows" else "/"
elif CURRENT_PLATFORM == "Windows":
    HOME = os.environ["USERPROFILE"]
    SLASH = "\\"
else:
    HOME = os.environ["HOME"]
    SLASH = "/"
