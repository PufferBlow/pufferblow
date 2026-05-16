"""
Export the Pufferblow API's OpenAPI schema to disk.

Run during the docs build so the rendered API reference always matches the
shipped code. The script imports the FastAPI app and dumps its
auto-generated ``app.openapi()`` payload as JSON.

Usage::

    poetry run python scripts/export_openapi.py
    poetry run python scripts/export_openapi.py docs/developer/openapi.json
    poetry run python scripts/export_openapi.py --pretty

The default output path is ``docs/developer/openapi.json``. The docs build
(MkDocs + mkdocs-render-swagger-plugin) loads this file and renders Swagger
UI at /developer/api-reference/.

Importing the FastAPI app triggers the same module-level imports the real
server uses, but ``app.openapi()`` does not run the lifespan handler — so
this script doesn't require a working database. It does, however, require
all import-time dependencies (loguru, sqlalchemy, etc.) to be installed,
so run it from inside the poetry env.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

DEFAULT_OUTPUT = Path("docs") / "developer" / "openapi.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument(
        "output",
        nargs="?",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Path to write the JSON to (default: {DEFAULT_OUTPUT}).",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print the JSON. Default is compact, which keeps diffs sane.",
    )
    args = parser.parse_args(argv)

    # Importing the app exercises the same module-level path FastAPI uses
    # at boot. If this fails, the server itself can't start either —
    # which is a useful early signal for CI.
    try:
        from pufferblow.api.api import api  # noqa: WPS433 (intentional late import)
    except Exception as exc:  # pragma: no cover - import-time failure
        print(f"error: failed to import pufferblow.api.api: {exc}", file=sys.stderr)
        return 1

    schema = api.openapi()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    indent = 2 if args.pretty else None
    args.output.write_text(
        json.dumps(schema, indent=indent, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
