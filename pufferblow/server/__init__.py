"""Server application namespace."""

from __future__ import annotations


def __getattr__(name: str):
    """Lazy-load the ASGI app export to avoid circular imports during bootstrap."""
    if name == "api":
        from pufferblow.server.app import api

        return api
    raise AttributeError(name)

__all__ = ["api"]

