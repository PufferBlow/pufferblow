#!/usr/bin/env python
"""Runs every scenario in `scenarios/`, in order, against the two instances
devp.federation.toml brings up — the organized entry point that replaced
the old single-file `driver.py`.

Run via devp (`devp ctl start federation-driver`) once both `pufferblow-a`
and `pufferblow-b` show ready, or directly:

    poetry run python pufferblow/tests/federation_test/run_all.py

Exits non-zero if any check failed. Scenarios run in a deliberate order —
`identity` and `follow` first (so a signature/discovery regression fails
fast and legibly instead of as a confusing cascade of DM failures further
down), the rest in roughly the order a real conversation would hit them.

Known, documented gaps this harness does NOT treat as failures (see the
relevant `activitypub_manager.py` docstrings for why):
  * An inbound Update/Delete/Like can only ever target a message that WE
    (this instance) originally sent — never something the peer authored
    and sent to us. `scenarios/dm_reactions.py` only exercises the
    direction that actually resolves.

`voice_channel.py` and `voice_calls_p2p.py` are same-instance-only (voice
isn't federated at all — see `docs/developer/architecture.md`) and only
exercise the control-plane REST surface. Neither opens a real WebRTC/SFU
connection or a WebSocket client, so "a signal was relayed" is checked via
the control plane's own acceptance of the request, not independently
verified delivery — see each file's module docstring.
"""

from __future__ import annotations

import sys
from pathlib import Path

# scenarios/*.py import `common`/`topology` as flat, non-relative modules —
# this is a loose collection of scripts, not an installed package, so the
# directory they live in needs to be on sys.path before anything under it
# is imported.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import Reporter, wait_for_health, INSTANCE_A, INSTANCE_B  # noqa: E402
from topology import sign_in_all  # noqa: E402
from scenarios import (  # noqa: E402
    identity,
    follow,
    dm_basic,
    dm_attachments,
    dm_replies,
    dm_reactions,
    forwarding,
    voice_channel,
    voice_calls_p2p,
)

SCENARIOS = (
    identity,
    follow,
    dm_basic,
    dm_attachments,
    dm_replies,
    dm_reactions,
    forwarding,
    voice_channel,
    voice_calls_p2p,
)


def main() -> int:
    print("=== Pufferblow <-> Pufferblow federation test suite ===")
    reporter = Reporter()

    wait_for_health(reporter, INSTANCE_A, "Instance A")
    wait_for_health(reporter, INSTANCE_B, "Instance B")

    print("\nSigning up/in every test user...")
    sign_in_all()

    for scenario in SCENARIOS:
        scenario.run(reporter)

    return reporter.summarize()


if __name__ == "__main__":
    raise SystemExit(main())
