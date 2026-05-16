# What v1.0 Does and Doesn't Do

A plain-English contract with everyone running, evaluating, or
auditing a Pufferblow server. The point of this doc is to spare you
the trial-and-error of figuring out which marketing-page bullet points
are real today and which are roadmap.

If this file says "deferred to v1.1," it doesn't ship in v1.0. Don't
plan on it; don't tell users they have it.

---

## What v1.0 ships

### Messaging & community

- ✅ Email/password accounts.
- ✅ Servers, channels (text + voice + threads), invite links.
- ✅ Roles with 26 granular privileges (per-server + per-channel
  overrides).
- ✅ 1:1 direct messages (group DMs are partial — see below).
- ✅ Message edit, delete, reply, reactions (emoji), markdown, file
  uploads (images, video, generic files; S3-compatible or local
  storage backends).
- ✅ Server-side channel search (substring, scan-capped, returns
  newest matches first). Indexed by Postgres FTS is **not** what's
  shipping here — see Search below.
- ✅ First-class notification rows for mentions, persisted server-
  side, with mark-as-read and badge counts.

### Voice / video

- ✅ Voice channels via a separate Pion-based Go SFU
  (`media-sfu`). Tested to 1000 peers per instance.
- ✅ Opus audio, VP8/VP9 video at a configurable default profile
  (720p target). Bitrate is configured, not adaptive — see below.
- ✅ Screen share — picks a screen via the browser's native chooser
  (single screen, no per-window selection). Includes system audio if
  the user opts in at the picker. Track-to-user binding goes through
  the SFU's screen_share_started/stopped broadcasts; other peers'
  shared screens render as video tiles above the participant grid.
- ✅ PLI / FIR forwarding so receivers can ask the publisher for a
  fresh keyframe after packet loss.

### Federation

- 🟡 ActivityPub for cross-instance DMs and follow / accept flows.
  Works for typical loads; outbound delivery now retries with
  exponential backoff on 5xx/network errors and inbox replays are
  de-duplicated.
- ⚠️ Real-time chat across instances has noticeable extra latency
  vs. local. This is a property of ActivityPub-over-HTTP, not a bug
  on our end.
- 🟡 Identity portability — `username@instance.tld` works.
- ⬜ Public instance discovery directory is not shipped; expect to
  hand-list known instances yourself for v1.0.

### Self-hosting

- ✅ One-command Docker Compose stack
  (`docker-compose.prod.server.yml`) covering API + SFU + coturn +
  Postgres. See [DOCKER_PRODUCTION.md](DOCKER_PRODUCTION.md) for the
  flow and `.env.server.example` for the variables you must set.
- ✅ Healthchecked startup order: media-sfu waits on the API's
  `/readyz` so the bootstrap handshake doesn't race.
- ✅ CLI admin tool (`pufferblow setup`, `pufferblow serve`,
  `--backup`).
- ⚠️ Bring-your-own TURN. STUN-only works for users on home/office
  NAT; users behind carrier-grade NAT or strict corporate firewalls
  will fail to join voice without TURN. The bundled coturn service
  in the Compose stack handles this if you set the credentials.

### Desktop / web client

- ✅ Electron + React desktop client for Windows, Linux (AppImage,
  deb, rpm), and macOS-pending-CI-verification.
- ✅ Tray badge with real OS-native unread count (Windows overlay
  icon, macOS dock badge, Linux tooltip).
- ✅ Tray menu: open/hide, unread row, mute/unmute notifications
  (persisted across launches), quit.
- ✅ Single-instance lock — launching a second copy foregrounds the
  first instead of corrupting storage state.
- ✅ Multi-account / multi-instance switcher.
- ✅ Auto-update via electron-updater + GitHub Releases.
- ✅ Web client at parity from the same React Router codebase.

### Security

- ✅ SQL-injection signature detection on privileged query
  parameters with progressive IP blocking.
- ✅ Sliding-window rate limiting with auth / upload / message
  endpoint tiers.
- ✅ Storage backend with SSE-encrypted-at-rest on S3 paths.
- ✅ Transport: TLS-only (see "What v1.0 deliberately doesn't do"
  below for what "TLS-only" excludes).

---

## What v1.0 deliberately doesn't do

These are real gaps. They're either v1.1 work or out-of-scope. If
your threat model or product hinge on any of them, v1.0 is not for
you yet.

### E2EE is not in v1.0

The pufferblow API currently writes message ciphertext to disk
keyed against per-message keys stored in the same database. **That
is at-rest encryption, not end-to-end.** Anyone with database
access (you, your DBA, a stolen backup) can decrypt every message
by joining the messages and keys tables. We don't ship this as
"E2EE" because doing so would lie to users about who can read
their messages.

Real E2EE for DMs (Signal Double Ratchet + key verification +
multi-device sync + encrypted backup) is the headline v1.1 feature.
The architecture changes required mean we cannot ship a halfway
version in v1.0.

For channels (group chat), E2EE is even harder. Matrix took years
to ship Megolm; we are not pretending we have something equivalent.
v1.0 channel messages are TLS-in-transit + at-rest cipher only.

**If you tell users their messages are E2EE today, you are
misleading them.**

### Search is substring, not FTS

The earlier plan said "Postgres FTS for v1." That assumed plaintext
messages on disk. Because messages are encrypted at rest, the
server-side search path decrypts up to a configurable scan window
(default 1000 newest messages) and substring-matches in process.

Practical implications:

- ✅ Fast and useful for normal channels.
- ❌ A channel with 100k+ messages won't find old matches outside
  the scan window. The response sets `truncated_scan: true` when
  this happens.
- ❌ No relevance ranking. Matches come back newest-first.

Real FTS lands when either (a) we change the at-rest encryption
model, or (b) we add a separate encrypted-but-searchable index
(homomorphic / blind-token searchable encryption is a v1.1+
research item, not a v1.1 commitment).

### Group DMs are partial

1:1 DMs work end-to-end. Multi-user DMs (a Discord-style "group
DM" surface) is missing some UI plumbing and isn't a release
blocker.

### Voice: no bitrate adaptation

The SFU forwards the publisher's stream to all receivers at the
publisher's configured bitrate. Receivers on slower connections get
the same stream as everyone else.

Concretely: REMB / TWCC pass-through to throttle a publisher down
when one receiver is on a slow link is not in v1.0. PLI / FIR for
keyframe recovery IS forwarded, so receivers recover after packet
loss — they just can't ask the publisher to send less data.

Full per-receiver simulcast / SVC is a v1.1+ architecture item.

### Other v1.1+ items

These are deliberately out of scope. Tracking them, not building
them, in v1.0:

- OAuth login.
- Native mobile apps (the web client is mobile-responsive; React
  Native / native Swift / Kotlin clients are post-v1).
- Helm chart for Kubernetes (Docker Compose is the only supported
  prod deployment for v1.0).
- Animated avatars, server themes, custom badges, animated banners,
  sound packs.
- Public instance discovery directory.
- HTTP Signatures on outbound ActivityPub (we send unsigned today;
  some strict remote servers will reject these). The signing
  infrastructure is a v1.1 hardening item.

---

## Versioning and the v1.0 ship line

v1.0 is the first numbered, stability-committed release. Up to that
point, breaking changes can happen at any time.

After v1.0:

- Database migrations will be reversible and committed under a
  migration tool.
- HTTP API surface changes follow semver — breaking changes go
  through a deprecation window.
- The Compose stack `.env.server.example` is part of the API
  contract; renaming a variable counts as a breaking change.

Until v1.0, none of those guarantees apply. If you're running a beta
build in production, pin to a specific commit and read the release
notes before upgrading.

---

## How to verify what your instance has

```bash
# What version is the API claiming?
curl -s http://localhost:7575/healthz | python -m json.tool

# Is the SFU reachable from the API's perspective?
curl -s http://localhost:7575/readyz | python -m json.tool

# Are ICE servers configured?
docker compose logs pufferblow-media-sfu | grep "ICE server configured"
```

If any of those fail, the v1.0 ship caveats above don't apply
because the deployment isn't actually serving v1.0 yet.
