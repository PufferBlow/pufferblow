"""Package-wide constants for the PufferBlow server runtime."""

import os
import platform

PACKAGE_NAME = "pufferblow"
VERSION = "1.0.0"
AUTHOR = "ramsy0dev"
ORG_GITHUB = "https://github.com/pufferblow"
REPO_GITHUB = "https://github.com/pufferblow/pufferblow"



def banner(command: str | None = None) -> None:
    """Render the launch screen: the glyph mark beside a short summary (see `cli/glyph.py`)."""
    from pufferblow.cli.glyph import print_splash

    summary = [("platform", platform.system())]
    if command:
        summary.insert(0, ("command", command))
    print_splash(summary, version=VERSION)


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
