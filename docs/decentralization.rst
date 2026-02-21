=====================
Decentralization Model
=====================

PufferBlow is intentionally built as an instance-first platform:

- each instance is its own community server
- channels/voice channels remain local to that instance
- cross-instance communication is federated through ActivityPub for direct messaging

Instance Boundaries
===================

Local instance ownership is explicit in the user model:

- users are created with an ``origin_server`` value
- signin checks that ``origin_server`` matches the running instance
- JWT access tokens also embed ``origin_server`` and are validated against current instance identity

This prevents credential reuse across unrelated instances.

Decentralized Node Sessions
===========================

For node-level delegated auth (separate from user JWT sessions), the server
exposes:

- ``POST /api/v1/auth/decentralized/challenge``
- ``POST /api/v1/auth/decentralized/verify``
- ``POST /api/v1/auth/decentralized/introspect``
- ``POST /api/v1/auth/decentralized/revoke``

These map to ``decentralized_auth_challenges`` and
``decentralized_node_sessions`` tables.

ActivityPub Federation
======================

Current ActivityPub capabilities target identity and DMs:

- WebFinger: ``/.well-known/webfinger``
- actor document: ``/ap/users/{user_id}``
- outbox: ``/ap/users/{user_id}/outbox``
- inboxes: ``/ap/users/{user_id}/inbox`` and ``/ap/inbox``
- follow flow: ``POST /api/v1/federation/follow``
- direct messaging bridge:
  - ``POST /api/v1/dms/send``
  - ``GET /api/v1/dms/messages``

Local users are represented as ActivityPub actors. Remote actors are cached in
the database and can be mapped to local shadow users for consistent DM history.

Cross-Instance DM Behavior
==========================

When sending a DM:

1. Message is persisted locally.
2. If peer is local, delivery happens through internal websocket fanout.
3. If peer is remote, the server emits ActivityPub ``Create`` activity with a
   ``Note`` object and delivers it to remote inbox/shared inbox.
4. Incoming remote ``Create(Note)`` activities are persisted and pushed to local
   recipients in real time.

Current Scope and Direction
===========================

Implemented federation scope:

- remote identity resolution
- follows
- cross-instance direct messages

Channels, voice state, and server administration are still local-instance
responsibilities by design.

