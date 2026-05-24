"""Error-handling contract for the PufferBlow API.

Public surface:

  * ``ApiError`` — raise from anywhere in the route / manager stack
    with a stable ``error_code`` and the global handler converts it
    to the documented envelope.
  * ``ErrorCode`` — enum-like namespace of every code the server can
    return. Third-party clients pin against these names; renames are
    a wire break and require a new code + deprecation cycle.
  * ``register_error_handlers(app)`` — wires FastAPI exception
    handlers so the envelope is emitted for every error class the
    server raises (``ApiError``, ``HTTPException``, validation
    errors, the manager-level domain exceptions, and the
    catch-all unhandled ``Exception``).

The complete error-code reference lives in ``docs/ERROR_CODES.md``
at the repo root; it's normative for clients.
"""

from pufferblow.api.errors.codes import ErrorCode, ERROR_REGISTRY, get_error_spec
from pufferblow.api.errors.exceptions import ApiError
from pufferblow.api.errors.handlers import register_error_handlers

__all__ = [
    "ApiError",
    "ErrorCode",
    "ERROR_REGISTRY",
    "get_error_spec",
    "register_error_handlers",
]
