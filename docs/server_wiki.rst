============================
Server Architecture Overview
============================

This page documents how the PufferBlow server is structured at runtime and how
requests move through the system.

For the full operator/developer guide, see :doc:`decentralization` and the
repository-level ``WIKI.md``.

Runtime Bootstrap
=================

The server is wired through ``APIInitializer`` in
``pufferblow/core/bootstrap.py``. During startup it initializes:

- configuration and database engine
- ``DatabaseHandler``
- core managers (auth, users, channels, messages, storage, background tasks)
- federation managers (decentralized auth + ActivityPub)
- websocket and webrtc managers

The ASGI export lives at ``pufferblow/server/app.py`` and points to
``pufferblow.api.api:api``.

Manager Map
===========

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Manager
     - Responsibility
   * - ``AuthTokenManager``
     - JWT access tokens, refresh token lifecycle, token origin-instance checks.
   * - ``UserManager``
     - Signup/signin, profile updates, account-locality checks.
   * - ``ChannelsManager``
     - Channel CRUD, membership checks, voice-channel integration.
   * - ``MessagesManager``
     - Channel and DM message persistence/reads.
   * - ``StorageManager``
     - Local/S3 storage abstraction, validation, server-side encryption.
   * - ``DecentralizedAuthManager``
     - Node challenge/verify/introspect/revoke flow.
   * - ``ActivityPubManager``
     - Actor/webfinger handling, inbox/outbox processing, cross-instance DMs.
   * - ``WebSocketsManager``
     - Real-time fanout by channel or user.
   * - ``WebRTCManager``
     - Voice participant sessions and cleanup.

HTTP Request Lifecycle
======================

Request processing is layered:

1. CORS middleware
2. ``SecurityMiddleware`` for privileged-route validation and parameter checks
3. ``RateLimitingMiddleware`` (bucketed sliding-window limits + cooldown/block)
4. request logging middleware (request id + duration)
5. route handler

Most feature routes are mounted from ``pufferblow/api/routes/``.

Security Layers
===============

- JWT-based user authentication with refresh token rotation
- instance-bound token claims (``origin_server`` + issuer checks)
- server-owner/admin guards in ``api/dependencies.py``
- persistent blocked IP table for abusive traffic
- centralized query and input checks via ``security_checks_handler``

Data Layer
==========

The server uses SQLAlchemy models under ``api/database/tables/``. Key table
families:

- core chat: ``users``, ``channels``, ``messages``
- moderation and metrics: ``blocked_ips``, ``activity_audit``, ``activity_metrics``
- federation: ``decentralized_*`` and ``activitypub_*``
- storage metadata: ``file_objects``, ``file_references``

Storage and Encryption
======================

Storage APIs use ``StorageManager`` and support local or S3 backends.
When server-side encryption is enabled, content is encrypted with AES-256-GCM
before backend write and decrypted on read.

Real-Time and Voice
===================

- Global WS endpoint: ``/ws`` for multi-channel message stream.
- Channel WS endpoint: ``/ws/channels/{channel_id}``.
- Voice endpoints are under ``/api/v1/channels/{channel_id}/...`` and use
  ``aiortc`` through ``WebRTCManager``.

Operational Tooling
===================

CLI commands are exposed via ``pufferblow.cli.cli``:

- ``pufferblow setup`` (includes Textual setup wizard when available)
- ``pufferblow serve``
- ``pufferblow storage setup|test|migrate``

