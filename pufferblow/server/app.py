"""ASGI app export for server process runners.

Re-applies logger configuration on import via
`maybe_configure_server_logging_from_env`. This is a no-op except in
one case: when `pufferblow serve --dev` has forwarded log preferences
through env vars and uvicorn has spawned a fresh worker subprocess
that doesn't share the parent's loguru sinks. Without this, every
reload-driven restart silently downgrades the log format to loguru's
bare default for the duration of the worker's life.
"""

from pufferblow.cli.common import maybe_configure_server_logging_from_env

maybe_configure_server_logging_from_env()

from pufferblow.api.api import api  # noqa: E402  intentional import after logger setup

__all__ = ["api"]

