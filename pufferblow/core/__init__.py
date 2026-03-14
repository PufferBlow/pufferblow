"""Core runtime exports for the PufferBlow server package."""

from pufferblow.core.constants import (
    AUTHOR,
    BANNER,
    CURRENT_PLATFORM,
    HOME,
    ORG_GITHUB,
    PACKAGE_NAME,
    REPO_GITHUB,
    SLASH,
    VERSION,
    banner,
)


def __getattr__(name: str):
    """Lazy-load bootstrap exports to avoid import cycles during package import."""
    if name in {"APIInitializer", "api_initializer"}:
        from pufferblow.core.bootstrap import APIInitializer, api_initializer

        exports = {
            "APIInitializer": APIInitializer,
            "api_initializer": api_initializer,
        }
        return exports[name]
    raise AttributeError(name)


__all__ = [
    "APIInitializer",
    "api_initializer",
    "AUTHOR",
    "BANNER",
    "CURRENT_PLATFORM",
    "HOME",
    "ORG_GITHUB",
    "PACKAGE_NAME",
    "REPO_GITHUB",
    "SLASH",
    "VERSION",
    "banner",
]
