# Client (web + desktop)

Pufferblow ships an official client built with React Router v7 +
TypeScript, packaged as an Electron desktop app for Windows,
macOS, and Linux. The same React tree runs in the browser at
`localhost:5173` during development and from a built static
bundle in production.

The client lives in its own repo:
[`PufferBlow/client`](https://github.com/PufferBlow/client).
This page documents the integration points that matter to
**server developers** and to anyone building an alternative
client.

!!! note "Audience"
    This is server-side context for client behavior. If you're
    building the client itself, the client repo's own README +
    `CONTRIBUTING.md` are the right starting point.

## What the client expects from the server

A Pufferblow client points at a **home instance** by hostname
and uses standard REST + WebSocket endpoints. There's nothing
proprietary in the wire protocol — anything that speaks the
documented API is a valid client.

- **REST API** at `http://<host>:7575/api/v1/*` plus
  `/api/v2/voice/*`. See the
  [API reference](api-reference.md).
- **WebSocket fanout** at `ws://<host>:7575/ws` (all channels)
  and `ws://<host>:7575/ws/channels/{channel_id}` (one channel).
- **Static media** at `http://<host>:7575/storage/{file_hash}`,
  decrypted on the fly by `StorageManager`.
- **Voice signaling** at `ws://<host>:8787/rtc/v1/ws` (via the
  `media-sfu` sidecar), bootstrapped through an HMAC-signed
  internal call.

CORS origins are explicitly allowlisted in `config.toml`. The
default config includes `http://localhost:5173` so the dev
client can connect; production deployments should set this to
whatever real origin you serve the client from.

## Desktop-only features

The Electron build adds a few capabilities that aren't present
in the browser build. Server developers should be aware of
these so they don't accidentally regress them:

### Deep links (`pufferblow://`)

The desktop app registers itself as the OS handler for the
`pufferblow://` URL scheme. Clicking a link in a browser or
chat opens the app and routes to the matching screen.

Recognised forms (parsed in
`client/app/services/deepLink.ts`):

```
pufferblow://m/<message_id>       → /m/<message_id>
pufferblow://dashboard            → /dashboard
pufferblow://settings             → /settings
pufferblow://control-panel        → /control-panel
pufferblow://login                → /login
```

Unknown hosts are rejected by an allow-list parser so a stray
URL can't navigate into an attacker-chosen path. Server-side
implication: nothing — the server doesn't need to know which
deep-link forms are recognised, and there's no protocol
negotiation. The client just routes locally.

### Auto-update

The desktop app uses `electron-updater` against a generic
release feed (default: `https://releases.pufferblow.space`).
Update bundles are downloaded in the background and applied on
next launch unless the user clicks "Restart now."

Server-side implication: none today. The release feed is
hosted separately from any Pufferblow instance. If you're
running your own client distribution, swap the feed URL in
`electron-builder.yml`.

### Native notifications and tray

Notifications go through the renderer's `Notification` API
(the same one browsers use) so the desktop and web paths share
suppression logic. The desktop build adds:

- A system tray icon with show/hide/quit.
- A "Mute notifications" toggle that persists across restarts.
- Unread badge on the dock (macOS) or taskbar overlay
  (Windows).

The mute toggle is a renderer-side flag and doesn't reach the
server — pings are still delivered as WebSocket events; the
client just chooses whether to surface them.

## Voice DSP wiring

The client supports user-configurable audio settings that
affect what the server actually receives over WebRTC:

- **Echo cancellation / noise suppression / auto gain** — wired
  into `getUserMedia` constraints. Apply on call connect and
  on every mid-call device swap.
- **Mic gain (input volume)** — implemented as a Web Audio
  `GainNode` in the local audio graph
  (`mic → MediaStreamSource → GainNode → MediaStreamDestination
  → PeerConnection`). Clamped to 0–200 %, unity at 100.
- **Push-to-talk** — the client gates the audio track's
  `enabled` flag based on a global keydown/keyup listener; mute
  always wins over PTT.
- **Audio quality preset** — caps RTCRtpSender bitrate at
  `min(server profile, user preset)`. The server's
  `quality_profile` (from `media_quality.audio.profiles`)
  stays the upper bound.

Server-side implication: these are negotiated entirely between
the client, the SFU, and the user's hardware. The server
provides the bootstrap (TURN credentials, quality profile, ICE
servers) and stays out of the path. Anyone building an
alternative client should mirror the bitrate-clamp logic so
servers can enforce per-tier limits.

## Renderer cache

The client persists its React Query cache to `localStorage`
under the key `PUFFERBLOW_QUERY_CACHE` with a 24-hour TTL. On
boot the cache hydrates instantly so channels and server info
appear without a network round-trip; stale entries refetch in
the background once the 5-minute `staleTime` expires.

Server-side implication: API responses are cached on the
client per query key. If your route returns something
sensitive that should never be stored, set a short
`Cache-Control` directive and document that the client should
not persist it. The current implementation persists every
query result by default — that's a known trade-off favouring
"feels instant" over "always fresh."

## Building an alternative client

There's nothing client-specific in the protocol. Any client
that speaks the documented REST + WebSocket surfaces is a
valid one. The Python SDK
([pypufferblow](sdk.md)) is one example; a CLI bot, a TUI, or
a mobile client would all sit on the same API. The reference
client demonstrates the patterns to copy — auth refresh,
WebSocket reconnect, presence updates, voice bootstrap — but
none of them are *required* by the server.

If you're considering building one, the things to get right:

1. **Refresh-token rotation.** Every refresh returns a new
   refresh token; the old one is invalidated. Persist
   atomically so you don't lose the new token if a write
   fails mid-rotation.
2. **WebSocket reconnect with backoff.** The server expects
   you to come back; it doesn't push notifications when
   you're disconnected. Reconnect with exponential backoff
   and re-subscribe on connect.
3. **Origin-server lock.** Sign-in is locked to the user's
   home instance. Clients that present themselves as
   multi-instance should display the home instance clearly so
   users don't think they're typing credentials into the
   wrong place.

## Cross-repo links

- Source: [`PufferBlow/client`](https://github.com/PufferBlow/client)
- Issues: [`PufferBlow/client/issues`](https://github.com/PufferBlow/client/issues)
- Releases (Electron installers): [`PufferBlow/client/releases`](https://github.com/PufferBlow/client/releases)
- Python SDK (the obvious example alternative client):
  [`PufferBlow/pypufferblow`](https://github.com/PufferBlow/pypufferblow)
