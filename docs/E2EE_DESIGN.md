# End-to-End Encryption for Direct Messages — Design

## Problem

PufferBlow's current DM encryption uses a server-side keypair: the
instance encrypts each message body with a key it owns (the `Keys`
table). An operator with database access can decrypt the entire
DM history of every user on their instance. In a federated
environment, the operator hosting the conversation can equally read
both sides — even when neither user is "on their instance" in the
classical sense, because the conversation_id is computed from the
two actor URIs and the home instance of EITHER party gets to see
the plaintext on read.

This is the wrong threat model for DMs. The user expectation —
matching iMessage, Signal, WhatsApp — is that **the server cannot
decrypt your DMs, full stop**. Even a compromised or malicious
operator.

This document is the design for moving DMs to true E2EE using
asymmetric (PGP-style) keypairs. It's a normative reference for
implementation across multiple PRs.

---

## Goals

1. **Server cannot decrypt DM bodies.** Plaintext exists only on
   the sender's client and the recipient's client.
2. **Federation-compatible.** A DM from Alice on instance A to Bob
   on instance B works without either operator being able to read
   it.
3. **Backwards compatible.** Existing non-E2EE DMs continue to
   render. New DMs between two users with keypairs upgrade
   automatically.
4. **Recoverable enough.** Users get a clear recovery story when
   they lose their private key (which is, intentionally, "you
   can't recover the messages — only future ones become readable
   once a new key is published").
5. **Attachments encrypted too.** A DM body is encrypted but a
   shared image is plaintext on storage = leaky design. Both must
   be encrypted.

## Non-goals (for v1)

- **Group DMs.** v1 is 1:1 only — group key management is a
  significant additional design problem (Sender Keys, MLS, etc.)
  and not in scope.
- **Forward secrecy via ratcheting** (Signal Protocol). We use
  PGP-style static keypairs first; the schema is designed to
  allow rotation later but rotation isn't shipped in v1.
- **Hiding metadata.** Sender, recipient, timestamp,
  conversation_id, and attachment URLs remain visible to the
  operator. Just the BODY and attachment BYTES are protected.
- **Server-aided sync of message history across devices.** The
  user's private key lives on one device unless they explicitly
  export it. Multi-device support is a follow-up that needs its
  own design (likely: each device gets its own keypair + the
  sender encrypts to N recipients).

---

## Threat model

### What this design protects against

- **Honest-but-curious operator.** They have full database
  access but won't tamper with the public-key distribution layer.
  Cannot decrypt DM bodies or attachments.
- **Operator coerced to hand over user data.** They can hand over
  ciphertext + metadata; the bodies remain encrypted.
- **Cross-instance read in federation.** Neither home instance
  can read DMs they aren't a party to.

### What this design does NOT protect against

- **Active operator who tampers with public-key distribution.**
  If the server lies about Bob's public key (returns the
  operator's key instead), the operator can MITM. Solving this
  requires out-of-band key verification (QR code, safety number)
  — a follow-up.
- **Compromised client.** If the user's device is compromised
  (malware, keylogger), the private key is exposed and all past +
  future DMs are readable. Standard E2EE limitation.
- **Endpoint discovery.** Sender + recipient identity are still
  in plaintext. An operator can see who DMs whom and when.

---

## Cryptographic choices

### Asymmetric primitive

**Curve25519 / X25519** (via `nacl.public.PrivateKey` on the
server, `tweetnacl` or `@noble/curves` on the client) — modern,
fast, side-channel-resistant. Smaller key sizes than RSA-2048 and
faster operations.

Why not literal PGP / RFC 4880? PGP's wire format is heavy
(armoured blocks, packet tags, OpenPGP extensions for a thousand
features we don't need). For a chat surface we want a compact
sealed-box wrapper. X25519 + crypto_box_seal gives us "PGP-
shaped" semantics (publish a public key, anyone encrypts to it,
only the holder of the private key decrypts) in a much smaller
package.

### Sealed boxes (per-message envelope)

Per message: a fresh symmetric key (XChaCha20-Poly1305, 256-bit)
encrypts the body; the symmetric key is sealed-box-wrapped with
the recipient's public key. The result is a single opaque blob
the client sends.

```
ciphertext = XChaCha20-Poly1305_encrypt(body, message_key, nonce)
sealed_key = crypto_box_seal(message_key, recipient_pubkey)
wire_payload = {
  version: 1,
  recipient_key_fingerprint: <hex>,
  sealed_key: <base64>,
  nonce: <base64>,
  ciphertext: <base64>,
}
```

The sender encrypts twice — once for the recipient, once for
themselves (so they can read their own sent history). Two
sealed_keys in the payload.

### Attachments

Same envelope, applied to the file bytes BEFORE upload to
`/api/v1/storage/upload`. The storage URL points to encrypted
bytes; the client unwraps via the same sealed key delivered with
the message. Filename and MIME are encrypted alongside the body
(they leak via the storage hash otherwise — at least the
extension does).

---

## Schema additions

### `user_e2ee_keys`

One row per user — the canonical public key everyone encrypts
against.

```python
class UserE2eeKeys(Base):
    __tablename__ = "user_e2ee_keys"
    user_id: UUID  # FK users
    public_key: str       # base64 X25519 public key
    key_fingerprint: str  # SHA-256 of the public key, hex
    algorithm: str        # "x25519-sealed-box-v1"
    created_at: datetime
    updated_at: datetime
    # Rotation isn't implemented in v1 but the column is here so
    # the schema doesn't break when rotation lands.
    superseded_by: str | None  # fingerprint of replacement key
```

### `messages.encryption_envelope`

New nullable JSON column. NULL = legacy server-encrypted message
(read via existing decrypt path). Non-NULL = E2EE message; the
server stores the envelope opaquely and never decrypts it.

```python
encryption_envelope: dict | None  # JSON
```

When this is set, `hashed_message` carries the ciphertext blob
(base64) — same column, different semantic. Easier than adding a
separate column and migrating reads.

### `dm_conversation_settings.e2ee_required`

Boolean, default false. When true: the route rejects any DM
attempt that isn't E2EE-shaped. Lets a user say "I never want
plain DMs in this conversation again."

---

## Wire format additions

### New endpoints

```
POST /api/v1/users/me/e2ee_keys
  body: { public_key, algorithm }
  → publishes the viewer's public key. Idempotent — same key
    posted twice is a no-op. A NEW key revokes the old.

GET  /api/v1/users/{user_id}/e2ee_keys
  → { public_key, key_fingerprint, algorithm, created_at }
    or 404 if the user has no key yet.

GET  /api/v1/users/me/e2ee_keys
  → same as above but for the viewer; saves a client-side
    lookup loop.
```

### Federation

When a remote user is in a DM, the local instance needs their
public key. The home instance of that user serves it via the
existing ActivityPub actor document — extended with a
`pufferblow:e2eePublicKey` field. The local instance caches it
on the actor row (existing `activitypub_actors` table).

When a public key changes, the federation layer fans out a
WebFinger-style refresh event (or just lets the cache expire
naturally over the existing actor-refresh interval). Out of scope
for v1: real-time key revocation across federation.

### Send shape

`POST /api/v1/dms/send` gets an optional `encryption_envelope`
field. When present:

- `message` is empty (or contains a hint like `[encrypted]` for
  legacy client fallback)
- `encryption_envelope` is the JSON payload described above
- Server stores it opaquely and never inspects the body

Mixed conversations (one user has a key, the other doesn't) fall
back to the legacy server-encrypted send. The sender's client
decides per-message based on the recipient's key availability.

---

## Client key management

### Generation

On first DM open (or on sign-in for new accounts), the client:

1. Generates a Curve25519 keypair locally via WebCrypto / noble.
2. Stores the private key in IndexedDB under an
   AES-GCM-encrypted wrapper. The wrapping key is derived from
   the user's password (PBKDF2, 600k iterations) at sign-in
   and held in memory only.
3. Publishes the public key via `POST /me/e2ee_keys`.

The private key NEVER leaves the device.

### Decryption

On message read, the client:

1. Inspects `encryption_envelope`. If null, decrypt as legacy.
2. Looks up its own sealed_key copy in the envelope by the
   sender's fingerprint check.
3. Unwraps the symmetric key via crypto_box_seal_open.
4. Decrypts the body.

### Recovery

If the user loses their private key (clears storage, switches
device without exporting), they:

- Generate a new keypair.
- Publish the new public key (server keeps the old one with
  `superseded_by` set for ~30 days so in-flight messages still
  decrypt).
- **All historical messages encrypted to the old key become
  unreadable.** This is the documented contract. New messages
  are immediately readable.

Export / import flow (encrypted private-key blob + passphrase) is
an explicit Settings action. v1 ships without auto-cloud-backup —
that's a follow-up after the core flow is stable.

---

## Migration path

1. **Phase 0 (current)** — All DMs server-encrypted. No keypairs.
2. **Phase 1** — Schema + endpoints land. Existing users get keys
   on first sign-in after the feature ships. New DMs upgrade
   to E2EE when both parties have keys; mixed pairs stay
   server-encrypted with a UI hint ("This DM is not end-to-end
   encrypted — your peer hasn't enabled it yet").
3. **Phase 2** — Attachment encryption. Storage-side changes to
   serve ciphertext blobs; client wraps before upload, unwraps
   on render.
4. **Phase 3** — Federation key distribution stabilises. Remote
   keys are fetched lazily, cached on the actor row, refreshed
   on miss.
5. **Phase 4** — Conversation setting `e2ee_required` ships,
   plus the export/import flow.

Each phase is a multi-PR effort. **No part of this design ships
without dedicated security review** — both code review focused
on cryptographic correctness and operational review focused on
key-management UX.

---

## Operator concerns

### Compliance / moderation

Operators frequently need to act on reports (harassment,
spam-in-DMs). E2EE means the operator can't read the reported
DM. The mitigation:

- The reporter's client includes the decrypted body + sender
  identity in the report payload (signed by the reporter's
  key). The operator sees what the reporter saw, with
  cryptographic proof that the message originated from the
  stated sender.
- Operators see ciphertext + metadata directly. No-content
  enforcement (e.g. ban after N reports of spam in DMs) works
  on metadata alone.

### Storage

Storage cost is similar — ciphertext is the same size as
plaintext plus ~80 bytes of envelope overhead per message. The
private-key blob in IndexedDB is ~100 bytes.

---

## Open questions (resolve before implementation)

1. **Multi-device.** Should v1 support multiple devices per user?
   If yes, the sender needs N recipient public keys (one per
   device). Decision: **No.** v1 is one-device-per-user. Multi-
   device is a follow-up with its own design.

2. **Key verification UX.** How do users verify they're encrypting
   to the real Bob, not the operator's MITM? Decision: **safety
   numbers** (Signal-style) in a follow-up. v1 trusts the
   server's key distribution.

3. **Key rotation cadence.** Annual? Per-incident? Decision: **on
   demand** for v1 — user-initiated only. The schema supports
   rotation; the UX doesn't push it.

4. **Attachment thumbnails.** Server-generated LQIPs reveal a
   blurred preview of the encrypted image. Decision: **drop LQIPs
   for E2EE attachments** — client generates a tiny thumbnail
   locally before encrypting, ships it as a second sealed
   envelope alongside the full attachment. Display behaviour
   matches today (blur → full).

---

## Implementation order

Listed in dependency order; each item is a separate PR with its
own review:

1. Schema: `user_e2ee_keys` table + `messages.encryption_envelope`
   column. Migrations. No behaviour change yet.
2. Public-key endpoints (`GET/POST /api/v1/users/me/e2ee_keys` +
   per-user public-key fetch).
3. Client key generation + secure storage (IndexedDB + PBKDF2-
   wrapped).
4. Client encrypt-on-send path for DM bodies. Server stays
   opaque to the envelope.
5. Client decrypt-on-read path.
6. Federation actor-document extension to surface remote public
   keys; cache on actor rows.
7. Attachment encryption (upload-side wrap + render-side unwrap).
8. `e2ee_required` setting + UI affordances.
9. Safety-number verification UI (Signal-style).
10. Key-export / import / recovery flows.

**Item 1 is unblocking — start there.** Items 2 + 3 + 4 + 5 must
ship together (a half-implemented E2EE is worse than none — a
user who sees the lock icon expects it to mean something).

---

## Status

**This document is a design proposal, not an implemented feature.**
Nothing in the production code today encrypts end-to-end. Schema
additions, endpoint shapes, and library choices are
recommendations for the implementation team to validate during
each PR's review.
