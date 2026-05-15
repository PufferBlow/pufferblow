# Pufferblow MVP Plan — v1.0 (Full Vision)

> **Scope chosen:** Option B from the strategy conversation — full vision MVP including
> text, voice/video, federation, E2EE, and customization. This document is honest about
> what that means in time, scope, and risk. It is not a "lean MVP." It is a plan for
> building the thing you actually want to build, with eyes open about the cost.

---

## 0. Preamble — read this every time motivation drops

You picked the full-vision MVP, then (2026-05-12) cut E2EE and related crypto out
to v1.1 once the actual code state was honest. That brings v1.0 down to **~5–6
months of solo work** from the cut date — targeting **2026-11-12** to ship. Every
successful chat platform that shipped at this scope had a team. You don't. The
plan below works *only* if you accept three things:

1. **No new projects until this ships.** Weavero, the C HTTP library, the gaming
   forum — paused. If you start a new project in week 8 because Pufferblow is hard,
   v1.0 will not exist. Decide this now or pick a different scope.
2. **Distribution work starts now, not at launch.** You will build an audience
   in parallel with building the product. If you don't, v1.0 ships to nobody.
3. **Customization is not the wedge.** Animated avatars and custom profiles are great
   v1 *retention* features. They are not why anyone switches off Discord. The wedge
   is privacy, ownership, self-hostability, and federation. Build for that audience.
   Customization is what keeps them.

If any of these three feel wrong, stop and pick Option A (lean MVP) instead.

---

## 1. Positioning

**Pufferblow is a self-hostable, federated, end-to-end-encrypted chat platform for
communities that want to own their data and identity.**

Target users, in order of priority:

1. **Self-hosters** who already run their own services (Mastodon, Nextcloud, Plex,
   Jellyfin). Technically literate. Evangelize on HN, Lobsters, r/selfhosted.
2. **Privacy-conscious communities** that got burned by Discord ToS or data scandals.
3. **Indie creators / small communities** that want custom identity (the avatars
   pitch) and don't want to be one of 10M Discord servers.

Not targeting: mass-market Discord refugees, gaming communities at large, enterprise.
Those are Matrix's audience, Slack's audience, or unwinnable.

**Honest competitive landscape:**

- **Matrix/Element** — closest competitor. ~100k DAU. Mature federation, mature E2EE.
  Your edge: better UX, better customization, modern stack. Their edge: 10 years of
  protocol work and an installed base.
- **Revolt** — closest in spirit (Discord-clone, customization-heavy). No federation,
  no E2EE. Your edge: federation + E2EE. Their edge: ~3 years of head start, working
  product, real users.
- **Discord itself** — not your competitor. You will not pull users from Discord at
  v1. You will pull users from "I want to leave Discord but Matrix is ugly" and
  "I'm tired of running a Revolt server with no federation."

**One-sentence pitch (use this everywhere):**

> Pufferblow is what Discord would be if you owned your server, your data, and your
> identity — and could federate with friends on other instances.

---

## 2. v1.0 Scope (Ship Cut)

This is what "shipping v1.0" means after the 2026-05-12 scope cut. Status reflects
the codebase as of that date. Anything not on this list — including E2EE, encrypted
backup, and multi-device key sync — is **v1.1+** (see §8).

Status legend: ✅ done · 🟡 partial · ⬜ not started · ⏭️ deferred to v1.1

### Core Platform

- ✅ **User accounts** — email/password, JWT, bcrypt hashing
- ⏭️ **OAuth** — deferred to v1.1
- ✅ **Servers / communities** — create, join, leave, invite links
- ✅ **Channels** — text channels, voice channels, threads within text channels
- ✅ **Roles & permissions** — 26 granular privileges per-server + channel overrides
- 🟡 **Direct messages** — 1:1 working; group DMs partial
- ✅ **Message features** — edit, delete, reply, react, mentions, markdown
- ✅ **File uploads** — images, video, generic files; S3/local storage
- 🟡 **Search** — server-side substring search done (scan-capped, decrypts in-process; no Postgres FTS — messages are encrypted at rest); client UI not wired (punchlist C5)
- 🟡 **Notifications** — backend events partial; desktop push not wired (S3 + C7)

### Voice / Video

- 🟡 **Voice channels** — SFU works; client integration incomplete (C4). Voice presence/disconnect cleanup runs through `voice_session_manager.leave_all_active_sessions_for_user` on WS disconnect.
- 🟡 **Video** — same integration gap as voice
- 🟡 **Screen share** — UI exists, no active-call integration (rolled into C4)
- 🟡 **Quality** — Opus audio working; VP8/VP9 720p target, no bitrate adaptation yet (M2)
- ✅ **Go SFU** — Pion-based, TOML config, stress-tested to 1000 peers

### E2EE — **deferred to v1.1**

E2EE DMs (Double Ratchet), key verification UI, multi-device key sync (SSSS),
and encrypted message backup are all **out of v1.0 scope** as of the 2026-05-12
scope cut. See §8.

> **v1.0 transport security:** all messages — DMs and channels — are TLS-only.
> This must be stated clearly in user-facing docs (punchlist D3). If a user's
> threat model requires E2EE, v1.0 is not for them; wait for v1.1.

### Federation

- 🟡 **ActivityPub for cross-instance DMs and server discovery** — basics work; reliability pass needed (S5)
- 🟡 **Server-to-server federation** — partial impl
- 🟡 **Identity portability** — username@instance.tld working
- ⬜ **Instance discovery directory** — not started; minimum viable list is acceptable for v1.0

> **Critical caveat:** Federation for *real-time chat* (vs. asynchronous like
> Mastodon) is unsolved at scale. Matrix's solution is heavyweight and slow.
> Your v1 will likely be: federation works for DMs and joining remote servers,
> but real-time message delivery between instances may have noticeable latency.
> Be honest about this in docs (D3).

### Customization

Only items already built or trivially close to it ship in v1.0. New customization
features are **deferred to v1.1**.

- 🟡 **Avatars (static)** — done; animated GIF/WebP/APNG support is v1.1
- ✅ **Custom profiles** — banner, bio, status, pronouns
- 🟡 **Profile themes** — dark/light only; accent color is v1.1
- ⏭️ **Server themes** — deferred to v1.1
- 🟡 **Custom emoji** — backend exists; picker integration is part of punchlist (C2 surface)
- ⏭️ **Custom badges** — deferred to v1.1
- ⏭️ **Animated banners and profile effects** — deferred to v1.1
- ⏭️ **Sound packs** — deferred to v1.1

> **Reality check:** Customization is the v1.1 retention story, not the v1.0 wedge.
> Hard line: no new customization features land in v1.0 beyond what's already on
> disk or trivially completing the punchlist surface.

### Self-Hosting

- 🟡 **Docker Compose deployment** — exists; needs end-to-end verification (D1)
- ⏭️ **Helm chart for Kubernetes** — deferred to v1.1
- 🟡 **Documentation** — partial; admin/backup/federation guides needed (D2)
- 🟡 **CLI admin tool** — partial

### Desktop Client (Electron)

- ✅ **Electron + React + TypeScript**
- ✅ **Cross-platform** — Windows NSIS/MSI, Linux AppImage/deb/rpm; macOS pending verification
- ✅ **Auto-update** — electron-updater via GitHub Releases
- 🟡 **System tray + notifications** — tray ok; desktop push not wired (C7)
- 🟡 **Multi-account** — session store ready; no UI switcher (C6)

### Web Client

- ✅ **Same React Router 7 + TS codebase** — shared with Electron
- 🟡 **PWA support** — needs verification
- 🟡 **Mobile-responsive** — needs verification; native mobile is v2
 
---

## 3. Timeline (Post Scope-Cut, 2026-05-12)

Working ~30 hours/week on Pufferblow, with no other major projects. The original
20-month estimate assumed a from-scratch start. The codebase is much further along
than that — instance ~70%, client ~65%, SFU ~85%, SDK ~80%. After deferring E2EE
and related crypto work to v1.1, what's left is integration glue, a couple of
genuinely missing pieces, and beta polish.

| Phase | What lands | Duration | Cumulative |
|---|---|---|---|
| **1. Integration punchlist** | Close concrete server/client TODOs (rate limit, reactions, GIF, device select, search API, notifications) | 6 weeks | W6 |
| **2. Voice/video end-to-end** | Client ↔ SFU integration, screen share, device selection, bitrate | 4 weeks | W10 |
| **3. Federation edge cases** | ActivityPub cross-instance DM reliability, identity portability hardening | 3 weeks | W13 |
| **4. Closed beta** | 20–50 alpha users from existing audience, weekly builds, bug bashing | 4 weeks | W17 |
| **5. v1.0 polish & launch** | Beta fix-up, docs (admin/federation/honest-caveats), HN/Lobsters/r/selfhosted push | 4 weeks | W21 |

**Honest total: ~21 weeks (5 months).** Add 20% slip factor = **6 months**.
Target ship date: **2026-11-12**.

This assumes:
- You don't get sick, change jobs, or have life events
- The deferred-to-v1.1 list (E2EE, key sync, encrypted backup) stays deferred
- Federation reliability pass doesn't surface a protocol-level bug requiring redesign
- Voice client/SFU integration completes inside the 4-week window (biggest single risk)

**Crypto deliberately omitted from v1.0.** Adding it back means +12–16 weeks
minimum and a different ship date.

---

## 4. Tech Stack (Locked-in)

### Backend
- **Python 3.12 + FastAPI** — your existing stack
- **PostgreSQL 16** — primary store; users, servers, channels, messages, metadata
- **Object storage** — S3-compatible (MinIO for self-host, R2/S3 for hosted)
- **Redis** — pub/sub for real-time, session cache, rate limiting
- **WebSocket gateway** — FastAPI + custom protocol or use Centrifugo if friction
- **ActivityPub** — Python implementation, likely build your own thin layer; existing
  libs (bovine, etc.) are not built for real-time chat

### Voice/Video
- **Go SFU** — your existing work; Pion-based
- **TOML-only config** — per your prior decision

### Client
- **Electron + React + TypeScript** — per your decision (changed from Tauri)
- **State management** — Zustand or Redux Toolkit; pick one and stick
- **Styling** — Tailwind + CSS variables for theming
- **Build** — Vite for the renderer, electron-builder for packaging

### Crypto
- **libsignal** (Rust, with Node/Python bindings) — don't roll your own Double Ratchet

### Infra
- **Self-host target:** Docker Compose for single-node; Helm for k8s
- **Hosted instance (optional):** Hetzner or similar; one VM to start

### What you should NOT use
- ❌ A new language or framework you haven't used before. No Rust backend, no
  Bun, no Deno. Boring choices only.
- ❌ A custom database. Postgres handles this.
- ❌ A custom voice protocol. WebRTC + your SFU is the path.

---

## 5. Distribution Plan (Starts Month 1, Not Month 18)

This is the part that determines whether v1.0 ships to 50 users or 5,000.

### Weeks 1–13: Build in public, build an audience (parallel with punchlist + voice + federation phases)

- **Devlog blog** on the Pufferblow domain — 1 post/week, technical depth.
  Topics: "Why we picked ActivityPub for chat," "Why E2EE is deferred to v1.1
  (honestly)," "Building a Pion SFU at 1000 peers." Builds SEO and credibility
  with the self-host/privacy audience.
- **Twitter/Mastodon presence** — post progress, screenshots, technical bits.
  Aim for 300–500 followers in the self-host niche before launch.
- **r/selfhosted, r/privacy, r/Matrix, r/PrivacyTools** — participate authentically
  for the duration. Become known.
- **HN dev presence** — comment thoughtfully on chat/privacy/federation threads.
  Don't promote. Build name recognition.

### Weeks 13–17: Closed beta

- Recruit 20–50 testers from the audience you've built
- Private Discord (yes, Discord — your users are still there) for feedback
- Weekly builds; weekly feedback notes
- Iterate hard on what testers actually use
- First "Show HN: Pufferblow beta" post — calibrate for "honest progress update,"
  not "launch announcement"

### Weeks 17–21: v1.0 launch

- **Show HN** with the technical depth from the devlog
- **r/selfhosted launch post** with a Docker Compose one-liner
- **Mastodon thread** breaking down the federation design
- **YouTube video** — 10-minute "Pufferblow vs. Matrix vs. Revolt" technical
  comparison
- **Reach out to self-host newsletter authors** — Awesome-Selfhosted, Self-Hosted
  Podcast, Selfh.st

**Realistic v1.0 launch result:** 500–2,000 signups in week 1. 100–300 active
users after month 1. 50–150 daily active after month 3. This is a *success* at
this scope (a smaller scope without E2EE may underperform with the privacy crowd
specifically — set expectations accordingly). Anyone telling you to expect more
is lying to you.

---

## 6. The 4 Questions You Need to Answer

I asked these in our conversation and you didn't answer. Answer them here before
you write more code. Edit this file and fill them in.

### Q1: Who is Pufferblow for, in one sentence, that isn't "everyone tired of Discord"?

> *Your answer:*

### Q2: What does Pufferblow do that Matrix/Revolt/Element don't?

> *Your answer:*

### Q3: What does "shipping v1.0" mean concretely? (number of users, features done,
> hosted instance live, etc.)

> *Your answer:*

### Q4: Realistically — how much of the current codebase is usable for v1.0? What
> percentage of v1.0 scope is already built?

> *Your answer:*

You should be able to answer these in 30 minutes. If you can't, the project
isn't strategically defined yet and that's the most important problem to fix
before more code.

---

## 7. Risk Register

Things that will probably kill this project if not addressed. In rough order of
likelihood.

| Risk | Likelihood | Mitigation |
|---|---|---|
| You start a new project at month 6 and Pufferblow stalls | **High** | Public commitment + devlog accountability. Tell people the timeline. |
| Federation protocol design takes 6 months longer than planned | **High** | Use existing ActivityPub spec strictly; don't invent. Accept that real-time-over-AP is limited. |
| E2EE multi-device sync surfaces hard bugs | **High** | Use libsignal. Don't implement Double Ratchet from scratch. Reduce scope if needed. |
| Burnout at month 10 from solo grinding | **Medium-High** | Build the audience in parallel; positive feedback from real users sustains motivation. |
| Electron bundle size / performance becomes a meme | **Medium** | Profile early. Native modules where it matters. Accept the tradeoff for ecosystem maturity. |
| Customization scope creep eats 6 months | **Medium** | Hard 8-week cap on customization for v1.0. |
| Matrix / Revolt ship the same features first | **Medium** | You're not racing them. You're building for users they're not serving well. |
| Legal / abuse / moderation issues on hosted instance | **Medium** | Don't run a hosted instance for v1.0. Self-host only. Punt abuse policy to v2. |
| Apple/Google reject mobile apps | **Low** | No mobile native in v1.0. PWA only. |

---

## 8. What "v1.1+" looks like (so you stop adding to v1.0)

These are good ideas. They are not v1.0. Write them down and stop thinking about them.

**Deferred from v1.0 by the 2026-05-12 scope cut (top of v1.1 queue):**

- **E2EE DMs** — Signal Double Ratchet via libsignal (Rust bindings). The single largest deferred feature; ~3–4 weeks of focused work.
- **Key verification UI** — safety numbers / QR codes between users
- **Multi-device key sync** — SSSS or equivalent so E2EE actually works across desktop + web/mobile
- **Encrypted message backup** — so users don't lose history on device loss
- **Animated avatars (GIF/WebP/APNG), server themes, custom badges, animated banners, sound packs** — the "dream features" customization stack; v1.1 retention layer
- **OAuth login**
- **Helm chart for Kubernetes self-host**

**Other v1.1+ ideas:**

- E2EE for server channels (group ratchet, MLS, or Megolm-like)
- Native mobile apps (React Native or native)
- Bridges to other platforms (Matrix bridge, IRC bridge, etc.)
- Bots and webhook API
- Slash commands and app integrations
- Voice channel persistent threads
- Stage channels / large broadcast voice
- Server analytics and admin dashboards
- Hosted SaaS tier with paid plans
- Marketplace for themes/emoji/sound packs
- AI moderation tooling
- Translation
- Stickers and animated reactions
- Profile achievements / badge marketplace

Each of these is a real project. Each adds 1–6 months. None of them are why
your first 1,000 users showed up. Ship v1.0 first.

---

## 9. The Commitment Section

Sign and date this if you're actually doing Option B.

> I, r0d, commit to:
>
> 1. No new ambitious platform projects until Pufferblow v1.0 ships (~2026-11-12).
> 2. Weekly devlog posts starting the week the scope cut was made (2026-05-12).
> 3. Reviewing this plan at the end of every month and updating progress honestly.
> 4. If at the end of the integration punchlist (W6) the trajectory looks wrong,
>    cutting *more* scope rather than slipping the ship date or abandoning.
> 5. Answering the 4 questions in section 6 within one week of writing this.
>
> Signed: ____________________
> Date: ______________________

---

## 10. Final note

This plan is honest. It says 5–6 months from the 2026-05-12 scope cut to ship,
because most of the surface is already built. It says E2EE is deferred to v1.1
because shipping nothing is worse than shipping plaintext-with-TLS and being
honest about it. It says customization is not the wedge. It says federation is
unsolved for real-time. None of that means the project shouldn't exist. It just
means the version that ships in ~November 2026 will be a real thing that 50–500
people use daily, not a Discord killer.

That's still a win. Most chat platforms never get there.

But you have to actually ship.
