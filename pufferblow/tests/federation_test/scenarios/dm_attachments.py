"""DM with attachments, federated alice@A -> bob@B.

Uses a bare URL string rather than a real upload — the attachments list
accepts either shape (DirectMessageSendRequest.attachments), and what this
is actually checking is that the attachment metadata round-trips through
send -> federated Create(Note) -> inbound Create -> load, not that file
storage works (that's covered elsewhere, not a federation concern).
"""

from __future__ import annotations

import httpx

from common import Reporter
from topology import ALICE, BOB

_ATTACHMENT_URL = "https://example.test/storage/fake-federation-test-image.png"


def run(reporter: Reporter) -> None:
    reporter.section("DM with attachments (alice@A -> bob@B)")

    resp = httpx.post(
        f"{ALICE.base_url}/api/v1/dms/send",
        json={
            "auth_token": ALICE.auth_token,
            "peer": BOB.handle,
            "message": "check out this attachment",
            "attachments": [{"url": _ATTACHMENT_URL, "filename": "fake-federation-test-image.png", "type": "image/png"}],
        },
        timeout=15.0,
    )
    reporter.check("alice sends a DM with an attachment", resp.status_code == 201, resp.text)
    message_id = resp.json().get("result", {}).get("message_id", "")

    bob_messages = httpx.get(
        f"{BOB.base_url}/api/v1/dms/messages", params={"auth_token": BOB.auth_token, "peer": ALICE.handle}, timeout=10.0
    ).json()
    sent = next((m for m in bob_messages.get("messages", []) if m.get("message") == "check out this attachment"), None)
    reporter.check("bob received the attachment-bearing DM", sent is not None, str(bob_messages))
    if sent is not None:
        urls = [a.get("url") for a in (sent.get("attachments") or [])]
        reporter.check("the attachment URL round-tripped to bob", _ATTACHMENT_URL in urls, str(urls))

    httpx.request(
        "DELETE", f"{ALICE.base_url}/api/v1/dms/messages/{message_id}", params={"auth_token": ALICE.auth_token}, timeout=15.0
    )
