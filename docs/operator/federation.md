# Pufferblow — Federation Operator Guide

What federates today, how to debug it when it stops working, and what
to tell users about latency. Pufferblow speaks ActivityPub for
cross-instance DMs and the follow/accept social graph. It does NOT do
real-time channel federation at scale — see "Latency expectations"
below for the honest version of what users will see.

For the user-facing contract see [V1_0_CAVEATS.md](../../V1_0_CAVEATS.md).
For deployment basics see [Docker](docker.md).

---

## What's federated in v1.0

| Capability                                     | Status | Notes                                                      |
| ---------------------------------------------- | ------ | ---------------------------------------------------------- |
| WebFinger discovery (`@user@instance.tld`)     | ✅      | Standard `acct:` resource.                                 |
| Actor document (`/ap/users/{user_id}`)         | ✅      | Person type with public key, inbox, outbox.                |
| Inbox / shared inbox                           | ✅      | `/ap/users/{id}/inbox` + `/ap/inbox`.                      |
| Follow / Accept flow                           | ✅      | Auto-accepts incoming follows (no approval UI in v1.0).    |
| Direct messages across instances               | ✅      | Wraps DM payloads as ActivityPub Create+Note.              |
| Outbound delivery retry                        | ✅      | Exponential backoff on 5xx / network errors.               |
| Inbound replay dedup                           | ✅      | UNIQUE constraint on remote activity URIs.                 |
| HTTP Signatures (inbound verification)         | ⚠️      | **Not enforced in v1.0.** Hardening item for v1.1.         |
| HTTP Signatures (outbound signing)             | ⚠️      | **Not yet sent.** Some strict remotes will 401 you.        |
| Instance blocklist / allowlist                 | ⬜      | Not in v1.0. Manual DB-level blocking only.                |
| Cross-instance moderation (Flag, Block)        | ⬜      | Not in v1.0.                                               |
| Real-time channel federation                   | ⬜      | Not attempted — see "Latency expectations."                |

If the `⚠️` items are blockers for your threat model, defer running a
publicly-federated instance until v1.1. The unsigned outbound case in
particular means a future Mastodon/Misskey can decide to drop your
activities without notice.

---

## Latency expectations

ActivityPub-over-HTTP is asynchronous. Every cross-instance message
delivery is:

```
local user → local API → outbox row → background delivery worker
                                    → HTTP POST to remote inbox
                                    → remote API processes → remote user
```

Practical numbers an operator should plan for:

- **Same continent, both instances healthy:** 1–4 seconds end-to-end.
- **Different continents:** 2–8 seconds.
- **Remote instance slow / overloaded:** seconds to minutes; the
  outbox queue handles retries automatically.
- **Remote instance offline:** the delivery worker retries with
  exponential backoff (30s → 2m → 10m → 1h → 6h, up to 5 attempts).
  After that, the row sits in `dead_letter_federation` for manual
  inspection.

This is qualitatively different from local channel chat (which goes
through the WebSocket gateway and lands in milliseconds). Users will
notice. Document the difference in your community's onboarding.

---

## TURN — required for voice

WebRTC peer connections need a TURN relay to traverse symmetric NAT.
Bundled `coturn` works for most cases; substitute your own if you
prefer.

```env
# .env
PUFFERBLOW_TURN_HOST=turn.your-instance.tld
PUFFERBLOW_TURN_PORT=3478
PUFFERBLOW_TURN_USERNAME=changeme-username
PUFFERBLOW_TURN_PASSWORD=$(openssl rand -base64 24)
```

Make those values match `config.toml`'s `[voice]` section — the API
hands them to clients in the `ice_servers` bootstrap response, and a
mismatch produces silent join failures (the WS connects, the offer is
sent, ICE candidates never pair).

Quick test from outside your network:

```bash
# Replace host/user/pass:
turnutils_uclient -u changeme-username -w 'the-password' -y turn.your-instance.tld
```

A working TURN replies within a second. A `401` means the credentials
don't match. A timeout means port 3478 isn't open at your firewall.

---

## Healthchecks for federation

Both endpoints return JSON; both are safe to hit unauthenticated.

| Endpoint    | Tells you                                                              |
| ----------- | ---------------------------------------------------------------------- |
| `/healthz`  | API process is alive.                                                  |
| `/readyz`   | Database connected, managers wired, SFU bootstrap reachable.           |

There is no dedicated `/federation/healthz` in v1.0. To get a "remote
peer reachable" signal:

```bash
# Resolve and fetch a remote actor:
curl -s https://your-instance.tld/api/v1/federation/resolve?handle=test@mastodon.social

# Expected: actor URI + display name + avatar. A 504 means your
# instance couldn't reach mastodon.social — DNS, firewall, or
# outbound HTTPS is broken.
```

---

## Local two-instance test harness

`devp.federation.toml` (repo root, run with [devp](https://github.com/thefr0gg/devp))
brings up two fully isolated Pufferblow instances — own Postgres, own
memcached, own `~/.pufferblow` config dir — federating with each other over
plain HTTP on `127.0.0.1:7001` and `127.0.0.1:7002`. This is the thing to
reach for when changing anything in `pufferblow/api/activitypub/`: it
exercises HTTP Signatures, WebFinger, NodeInfo, Follow/Accept/Undo/Reject,
and DM Create/Update/Delete against a genuinely separate process and RSA
keypair, not a mock — the gap unit tests can't close (see
`test_26_activitypub_reliability.py`'s and `test_28_activitypub_signatures_and_collections.py`'s
own docstrings on why they stop short of that).

```bash
devp -c devp.federation.toml
# once both pufferblow-a and pufferblow-b show ready:
devp ctl start federation-driver
```

### Layout

```
pufferblow/tests/federation_test/
  bootstrap_instance.py   -- one-shot: server row, owner-privileged admin
                             account, a seed channel+message (used by the
                             channel-to-DM forwarding scenario)
  common.py               -- Reporter (PASS/FAIL accumulation), HTTP
                             helpers (signup/signin, health wait, JWT decode)
  topology.py             -- the user roster: ALICE/BOB (cross-instance
                             pair), CAROL/DAVE (second pair, + CAROL shares
                             an instance with ALICE for local-delivery
                             coverage), ADMIN_A/ADMIN_B
  scenarios/
    identity.py            -- NodeInfo + WebFinger
    follow.py               -- Follow/Accept/collections/Undo, two pairs
    dm_basic.py              -- send/edit/delete, federated AND local-delivery
    dm_attachments.py       -- DM with an attachment, federated
    dm_replies.py            -- reply threading, federated both directions
    dm_reactions.py          -- Like/Undo(Like) reactions on a DM message
    forwarding.py            -- DM-to-DM and channel-to-DM forwarding
    voice_channel.py         -- channel voice join/leave/participants/
                                mute, same-instance only (not federated)
    voice_calls_p2p.py       -- 1:1 DM call invite/accept/reject/signal/
                                end + SFU fallback, same-instance only
  run_all.py               -- entry point: runs every scenario in order
                               against a shared Reporter, exits non-zero
                               on any failure
```

Each scenario module is a plain `run(reporter)` function and can be run on
its own for faster iteration while working on one feature — add a `sys.path`
entry for `pufferblow/tests/federation_test/` (same as `run_all.py` does) and call
`scenarios.dm_reactions.run(Reporter())` directly after `topology.sign_in_all()`.

Two things this harness deliberately does NOT assert, because they're
known, documented gaps rather than bugs (see the relevant
`activitypub_manager.py` docstrings):

  * An inbound Update/Delete/Like can only ever target a message that WE
    (this instance) originally sent — never something the peer authored.
    `scenarios/dm_reactions.py` only exercises the direction that resolves.
  * Forwarding and replies both work end-to-end — including the trickier
    "reply to something the peer sent you" direction, now that
    `remote_object_uri` is tracked on inbound Creates.
  * `voice_channel.py`/`voice_calls_p2p.py` only exercise the control-plane
    REST surface — no real WebRTC/SFU connection or WebSocket client is
    opened, so signal relay is checked by the control plane accepting the
    request, not by independently verified delivery.

To point the harness at a real third-party server instead of your own
second instance, skip `devp.federation.toml` and follow the "resolve a
remote actor" smoke test above against that server's handle directly.

---

## Debugging a stuck outbox

Cross-instance delivery state lives in `activitypub_outbox_activities`.
The row shape includes `delivery_status`, `attempts`, `last_attempt_at`,
`next_attempt_at`, and the full payload.

```sql
-- 20 most recent outbound activities, with status:
SELECT activity_uri, target_inbox, delivery_status, attempts,
       last_attempt_at, next_attempt_at
FROM activitypub_outbox_activities
ORDER BY created_at DESC LIMIT 20;

-- Stuck (multiple failures, still pending):
SELECT activity_uri, target_inbox, attempts, last_attempt_at
FROM activitypub_outbox_activities
WHERE delivery_status = 'pending' AND attempts >= 3
ORDER BY last_attempt_at;

-- Dead-lettered (gave up):
SELECT * FROM activitypub_outbox_activities
WHERE delivery_status = 'failed';
```

Manually retry a dead-lettered row by resetting it:

```sql
UPDATE activitypub_outbox_activities
SET delivery_status = 'pending', attempts = 0, next_attempt_at = NOW()
WHERE activity_uri = 'https://your-instance.tld/ap/activities/<uuid>';
```

The background worker picks it up on its next sweep (default every 60s).

---

## Debugging a rejected inbound activity

Inbound activities arrive at `/ap/users/{user_id}/inbox` or
`/ap/inbox` and are stored in `activitypub_inbox_activities`. A failure
here usually means one of:

1. The remote sent malformed JSON-LD → look for a 400 in the API logs.
2. The remote claimed to be an actor we can't fetch → look for a
   404/5xx on the `fetch_remote_actor` path.
3. The activity's `object.id` is already stored (duplicate from
   retry) → silently 200ed by design; check the inbox table to confirm.

```sql
-- Recent inbound, newest first:
SELECT remote_activity_uri, activity_type, actor_uri, received_at, processed
FROM activitypub_inbox_activities
ORDER BY received_at DESC LIMIT 20;

-- Unprocessed (still in the queue):
SELECT * FROM activitypub_inbox_activities WHERE NOT processed;
```

If a remote keeps re-sending a `Follow` and we keep accepting:
remember v1.0 auto-accepts every follow. The approval-UI flow is
v1.1. To block a specific follower today, delete their row from
`activitypub_follows` AND add a domain-level block.

---

## Domain-level blocking (the manual fallback)

v1.0 has no admin UI for instance blocklists. To block a hostile
instance until v1.1 ships the proper feature, do it at the network
layer:

```bash
# On the API host, drop traffic from a domain you've blocklisted at
# the application layer:
iptables -A INPUT -s $(dig +short bad-instance.tld | head -1) -j DROP
```

For finer control, run the API behind a reverse proxy (nginx, Caddy)
and add a domain blocklist there — easier to manage across IPs and
survives instance restarts.

---

## Cache invalidation

Remote actor records are cached for 1 hour and refreshed on first
access after that. If a remote rotates their RSA key (some Mastodon
instances do this), you'll see signature-verification failures for the
duration of the cache TTL.

Force a refresh:

```sql
UPDATE activitypub_actors
SET fetched_at = NOW() - INTERVAL '2 hours'
WHERE actor_uri = 'https://mastodon.social/users/them';
```

The next federated activity from that actor re-fetches the actor doc
and pulls the new key.

---

## Things that look broken but are by design

- **Federated DM appears with a 5-second delay vs local DM.** Yes.
  ActivityPub is async. See "Latency expectations."
- **A remote user's avatar / display name takes a minute to update on
  your instance.** The remote actor doc is cached for an hour. Refresh
  forcibly with the SQL above if you need it sooner.
- **Following someone on a Pleroma instance shows them as followed
  but no posts appear.** Pleroma doesn't push outbox items to
  followers automatically — that's a Pleroma config choice on the
  remote side, not a Pufferblow bug.
- **An old followee's profile shows "deleted account."** The remote
  actor returned 410 Gone on our last fetch. Their server marked them
  deleted. Pufferblow honors that and keeps the marker.


## Naming an instance that is not where it listens

An instance is known by `host:port` (the host in every `name@host`), and by default that is the address it listens
on. Behind a container or a proxy those differ. Set the public name separately:

```toml
[server]
api_host = "0.0.0.0"
api_port = 7575
public_host = "chat.example.org:443"   # or PUFFERBLOW_PUBLIC_HOST
public_scheme = "https"                # or PUFFERBLOW_PUBLIC_SCHEME (http for local test setups)
```

The public name is fixed when the instance is first set up, as the listening address always was.
