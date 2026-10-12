"""NodeInfo + WebFinger — the discovery surface a real peer checks before
trusting an instance at all. See docs/operator/federation.md."""

from __future__ import annotations

import httpx

from common import Reporter
from topology import ALICE, BOB


def run(reporter: Reporter) -> None:
    reporter.section("Identity: NodeInfo + WebFinger")

    for user in (ALICE, BOB):
        discovery = httpx.get(f"{user.base_url}/.well-known/nodeinfo", timeout=5.0)
        reporter.check(f"{user.base_url}: /.well-known/nodeinfo", discovery.status_code == 200)

        doc = httpx.get(f"{user.base_url}/nodeinfo/2.0", timeout=5.0)
        reporter.check(
            f"{user.base_url}: /nodeinfo/2.0 reports activitypub",
            doc.status_code == 200 and "activitypub" in doc.json().get("protocols", []),
            doc.text,
        )

        wf = httpx.get(
            f"{user.base_url}/.well-known/webfinger",
            params={"resource": f"acct:{user.handle}"},
            timeout=5.0,
        )
        reporter.check(f"{user.base_url}: webfinger resolves {user.username}", wf.status_code == 200, wf.text)
