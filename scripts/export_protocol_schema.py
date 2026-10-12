"""Regenerate docs/protocol/v1/schema.json from the pydantic models (the source of truth)."""

import json
from pathlib import Path

from pufferblow.api.protocol.envelopes import protocol_json_schema

target = Path(__file__).resolve().parents[1] / "docs" / "protocol" / "v1" / "schema.json"
target.write_text(json.dumps(protocol_json_schema(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(f"wrote {target}")
