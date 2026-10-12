"""Shared plumbing for the federation test scenarios under `scenarios/`.

Nothing here talks to the database or imports `pufferblow` — these are pure
HTTP-client helpers against the two running instances devp.federation.toml
brings up (or whatever `INSTANCE_A`/`INSTANCE_B` are pointed at). Keeping
this import-light means a scenario module can be run and iterated on
without booting any part of the actual application.
"""

from __future__ import annotations

import base64
import json
import time

import httpx

INSTANCE_A = "http://127.0.0.1:7001"
INSTANCE_B = "http://127.0.0.1:7002"

_PASS = "PASS"
_FAIL = "FAIL"


class Reporter:
    """Accumulates PASS/FAIL checks across every scenario module.

    One instance is created by `run_all.py` and threaded through every
    scenario function, so a single run produces one combined pass/fail
    tally no matter how many scenario modules contributed to it.
    """

    def __init__(self) -> None:
        self.failures: list[str] = []
        self.total: int = 0

    def check(self, label: str, condition: bool, detail: str = "") -> bool:
        self.total += 1
        status = _PASS if condition else _FAIL
        print(f"[{status}] {label}" + (f" — {detail}" if detail and not condition else ""))
        if not condition:
            self.failures.append(label)
        return condition

    def section(self, title: str) -> None:
        print(f"\n--- {title} ---")

    def summarize(self) -> int:
        print()
        if self.failures:
            print(f"=== {len(self.failures)}/{self.total} check(s) FAILED ===")
            for name in self.failures:
                print(f"  - {name}")
            return 1
        print(f"=== All {self.total} checks passed ===")
        return 0


def decode_jwt_sub(token: str) -> str:
    """Pull the `sub` claim out of a JWT without verifying it.

    Local throwaway instances we just booted ourselves — not a security
    boundary — so skipping verification just to read the user_id keeps
    this dependency-free (no need to boot a full pufferblow runtime).
    """
    try:
        payload_b64 = token.split(".")[1]
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        return str(payload["sub"])
    except Exception:
        return ""


def wait_for_health(reporter: Reporter, base_url: str, label: str, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = httpx.get(f"{base_url}/healthz", timeout=2.0)
            if resp.status_code == 200 and resp.json().get("database", {}).get("connected"):
                reporter.check(f"{label} is healthy ({base_url})", True)
                return
        except Exception as exc:
            last_error = exc
        time.sleep(1.0)
    reporter.check(f"{label} became healthy within {timeout:g}s", False, str(last_error or "timed out"))
    raise SystemExit(1)


def signup_or_signin(base_url: str, username: str, password: str) -> tuple[str, str]:
    """Returns (auth_token, user_id). Treats a 409 (already signed up from a
    previous run against instances that weren't recreated) as success via signin."""
    resp = httpx.post(
        f"{base_url}/api/v1/users/signup", json={"username": username, "password": password}, timeout=10.0
    )
    if resp.status_code == 409:
        resp = httpx.get(
            f"{base_url}/api/v1/users/signin",
            params={"username": username, "password": password},
            timeout=10.0,
        )
    if resp.status_code not in (200, 201):
        raise RuntimeError(f"signup/signin failed for {username}@{base_url}: {resp.status_code} {resp.text}")
    body = resp.json()
    token = body["auth_token"]
    return token, decode_jwt_sub(token)


def handle_for(base_url: str, username: str) -> str:
    """`user@host:port` handle for WebFinger/remote_handle purposes."""
    return f"{username}@{base_url.split('://', 1)[1]}"
