# Security Policy

## Supported versions

Pufferblow is in the **`0.x` beta** series. We don't yet maintain
parallel release branches — security fixes land on `main` and are
included in the next release. If you're running an older tagged
build, the supported response is "upgrade to the latest tag."

| Version    | Supported               |
| ---------- | ----------------------- |
| `0.x`      | Yes — fixes on `main`   |
| pre-`0.x`  | No                      |

A stable `1.0` will introduce a real support window; this table will
be updated when that happens.

## Reporting a vulnerability

**Do not open a public issue** for a suspected vulnerability. GitHub
issues are world-readable and put other instances at risk while the
fix is in flight.

Two ways to report privately, pick whichever you prefer:

1. **GitHub Security Advisory** (preferred) —
   [Report a vulnerability](https://github.com/PufferBlow/pufferblow/security/advisories/new).
   This creates a private thread visible only to maintainers and to
   you.
2. **Email** — `security@pufferblow.space`. Encrypt with our PGP
   key if you can; we'll respond from the same address.

Include in your report:

- A description of the issue and the impact you observed.
- Steps to reproduce, ideally a minimal proof-of-concept.
- The commit SHA or release tag you're testing against.
- Your preferred name / handle for the eventual credit line (or
  "anonymous" if you'd rather not be named).

## What to expect

- **Acknowledgement** within **3 business days**.
- **Triage decision** (accepted / not-a-vulnerability / duplicate)
  within **10 business days**, including a target fix window.
- For accepted reports we coordinate a disclosure date with you.
  The default is **30 days** from triage; we may extend that for
  complex fixes or shorten it if the issue is being actively
  exploited.
- Once the fix is released, you're credited in the release notes
  and the advisory unless you asked to remain anonymous.

## What is in scope

- The Pufferblow API server (`pufferblow/`)
- The `media-sfu` voice/screen-share server (`media-sfu/`)
- The official client (`client/`) — Electron + web
- The `pypufferblow` SDK (`pypufferblow/`)
- Default `docker-compose.prod.server.yml` and our published images

Out of scope:

- Vulnerabilities in upstream dependencies that aren't reachable
  through Pufferblow code paths (please report those upstream).
- Misconfigurations of self-hosted instances (e.g. running with
  `DEBUG=true`, missing TLS) where the fix is "configure it
  correctly per `ADMIN.md` / the docs."
- Social-engineering attacks against instance operators.

Thanks for taking the time to report responsibly.
