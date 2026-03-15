"""
PingManager — feature-complete ping system for PufferBlow.

Supports three ping modes:
    local       — ping another user on the same instance (WebSocket delivery)
    federated   — ping a user on a remote instance via ActivityPub
    instance    — HTTP health-check probe to a remote PufferBlow instance

Ping lifecycle
--------------
    sent -> delivered -> acked
                      -> timeout  (background task after expires_at)
    sent -> failed              (delivery-level error)

Federation extension
--------------------
Two custom ActivityPub activity types are used:

    Ping    (sender → receiver inbox)
    PingAck (receiver → sender inbox)

Both are namespaced under the pufferblow extension context:
    {"pufferblow": "<base_url>/ns#"}
"""

from __future__ import annotations

import datetime
import json
import time
import uuid
from typing import TYPE_CHECKING

import httpx
from loguru import logger

from pufferblow.api.database.tables.pings import DEFAULT_PING_TTL_SECONDS, Pings

if TYPE_CHECKING:
    from pufferblow.api.activitypub.activitypub_manager import ActivityPubManager
    from pufferblow.api.database.database_handler import DatabaseHandler
    from pufferblow.api.websocket.websocket_manager import WebSocketsManager


class PingManager:
    """
    Central manager for all ping operations — local, federated, and instance.
    """

    ACTIVITYSTREAMS_CONTEXT = "https://www.w3.org/ns/activitystreams"
    # Maximum characters allowed in a ping message body
    MAX_MESSAGE_LENGTH = 200
    # HTTP timeout for instance pings (seconds)
    INSTANCE_PING_HTTP_TIMEOUT = 10.0

    def __init__(
        self,
        database_handler: "DatabaseHandler",
        websockets_manager: "WebSocketsManager",
        activitypub_manager: "ActivityPubManager | None" = None,
    ) -> None:
        """Initialize the PingManager."""
        self.database_handler = database_handler
        self.websockets_manager = websockets_manager
        self.activitypub_manager = activitypub_manager

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _base_url(self) -> str:
        """Derive canonical base URL from runtime config."""
        if self.activitypub_manager is not None:
            return self.activitypub_manager.build_base_url()
        cfg = self.database_handler.config
        host = str(cfg.API_HOST).strip()
        port = str(cfg.API_PORT).strip()
        scheme = "https" if host not in {"127.0.0.1", "localhost"} else "http"
        if (scheme == "https" and port == "443") or (scheme == "http" and port == "80"):
            return f"{scheme}://{host}"
        return f"{scheme}://{host}:{port}"

    def _new_ping_id(self) -> uuid.UUID:
        return uuid.uuid4()

    def _now(self) -> datetime.datetime:
        return datetime.datetime.now(datetime.timezone.utc)

    def _expires_at(self, ttl_seconds: int = DEFAULT_PING_TTL_SECONDS) -> datetime.datetime:
        return self._now() + datetime.timedelta(seconds=ttl_seconds)

    def _validate_message(self, message: str | None) -> str | None:
        if message is None:
            return None
        message = message.strip()
        if len(message) > self.MAX_MESSAGE_LENGTH:
            raise ValueError(
                f"Ping message exceeds maximum length of {self.MAX_MESSAGE_LENGTH} characters."
            )
        return message or None

    # ------------------------------------------------------------------
    # Local ping
    # ------------------------------------------------------------------

    async def send_local_ping(
        self,
        sender_id: str,
        target_user_id: str,
        message: str | None = None,
        base_url: str | None = None,
    ) -> dict:
        """
        Send a ping to another user on the same instance.

        The target user receives a ``ping_received`` WebSocket event immediately.
        A matching receiver-side Pings record is created alongside the sender record.

        Args:
            sender_id: UUID of the sending user.
            target_user_id: UUID of the target user on this instance.
            message: Optional short message body (≤200 chars).
            base_url: Optional override for the canonical base URL.

        Returns:
            dict with ping metadata (ping_id, status, …).
        """
        message = self._validate_message(message)
        now = self._now()
        expires = self._expires_at()

        # Validate target exists
        target_user = self.database_handler.get_user(user_id=target_user_id)
        if target_user is None:
            raise ValueError(f"Target user '{target_user_id}' not found on this instance.")

        ping_id = self._new_ping_id()

        # Sender-side record
        sender_ping = Pings(
            ping_id=ping_id,
            ping_type="local",
            sender_id=uuid.UUID(sender_id),
            target_user_id=str(target_user.user_id),
            status="sent",
            is_sender=True,
            message=message,
            sent_at=now,
            expires_at=expires,
        )
        self.database_handler.create_ping(sender_ping)

        # Receiver-side record (separate row for inbox query)
        receiver_ping = Pings(
            ping_id=self._new_ping_id(),
            ping_type="local",
            sender_id=uuid.UUID(sender_id),
            target_user_id=str(target_user.user_id),
            status="delivered",
            is_sender=False,
            message=message,
            sent_at=now,
            expires_at=expires,
            # Link back to the sender's canonical ping_id via metadata
            metadata_json={"sender_ping_id": str(ping_id)},
        )
        self.database_handler.create_ping(receiver_ping)

        # Update sender ping to "delivered"
        self.database_handler.update_ping_status(
            ping_id=str(ping_id), status="delivered"
        )

        # Real-time delivery via WebSocket
        ws_payload = {
            "type": "ping_received",
            "ping_id": str(ping_id),
            "receiver_ping_id": str(receiver_ping.ping_id),
            "sender_id": sender_id,
            "ping_type": "local",
            "message": message,
            "sent_at": now.isoformat(),
            "expires_at": expires.isoformat(),
        }
        await self.websockets_manager.broadcast_to_user(
            user_id=str(target_user.user_id),
            message=ws_payload,
        )

        logger.info(
            f"Local ping sent | sender={sender_id} target={target_user_id} ping_id={ping_id}"
        )

        return {
            "ping_id": str(ping_id),
            "ping_type": "local",
            "target_user_id": str(target_user.user_id),
            "status": "delivered",
            "message": message,
            "sent_at": now.isoformat(),
            "expires_at": expires.isoformat(),
        }

    # ------------------------------------------------------------------
    # Federated ping
    # ------------------------------------------------------------------

    async def send_federated_ping(
        self,
        sender_id: str,
        target: str,
        base_url: str,
        message: str | None = None,
    ) -> dict:
        """
        Send a ping to a user on a remote instance using ActivityPub.

        Resolves the target via WebFinger / actor URI, emits a ``Ping``
        ActivityPub activity to the remote inbox, and stores the outgoing
        ping record locally.

        Args:
            sender_id: UUID of the local sending user.
            target: Remote handle (``user@domain``), actor URI, or local user ID.
            base_url: Canonical base URL of this instance.
            message: Optional short message body.

        Returns:
            dict with ping metadata and delivery details.
        """
        if self.activitypub_manager is None:
            raise RuntimeError("ActivityPub manager is required for federated pings.")

        message = self._validate_message(message)
        now = self._now()
        expires = self._expires_at()

        local_actor = self.activitypub_manager.ensure_local_actor(
            user_id=sender_id, base_url=base_url
        )
        peer = await self.activitypub_manager._resolve_peer(peer=target, base_url=base_url)

        if peer.is_local:
            # Silently fall back to local delivery
            return await self.send_local_ping(
                sender_id=sender_id,
                target_user_id=str(peer.user_id),
                message=message,
                base_url=base_url,
            )

        ping_id = self._new_ping_id()
        activity_uri = f"{base_url}/ap/activities/ping-{ping_id}"

        # Build ActivityPub Ping activity
        activity = {
            "@context": [
                self.ACTIVITYSTREAMS_CONTEXT,
                {"pufferblow": f"{base_url}/ns#"},
            ],
            "id": activity_uri,
            "type": "Ping",
            "actor": local_actor.actor_uri,
            "to": [peer.actor_uri],
            "published": now.isoformat(),
            "pufferblow:pingId": str(ping_id),
            "pufferblow:kind": "user_ping",
            "pufferblow:message": message or "",
            "pufferblow:expiresAt": expires.isoformat(),
        }

        # Persist outgoing ping record
        sender_ping = Pings(
            ping_id=ping_id,
            ping_type="federated",
            sender_id=uuid.UUID(sender_id),
            target_actor_uri=peer.actor_uri,
            activity_uri=activity_uri,
            status="sent",
            is_sender=True,
            message=message,
            sent_at=now,
            expires_at=expires,
            metadata_json={"target_inbox": peer.shared_inbox_uri or peer.inbox_uri},
        )
        self.database_handler.create_ping(sender_ping)

        # Store in outbox
        self.database_handler.store_activitypub_outbox_activity(
            activity_uri=activity_uri,
            activity_type="Ping",
            actor_uri=local_actor.actor_uri,
            payload_json=json.dumps(activity),
            object_uri=peer.actor_uri,
        )

        # Deliver to remote inbox
        delivery_target = peer.shared_inbox_uri or peer.inbox_uri
        try:
            await self.activitypub_manager._http_post_json(
                url=delivery_target, payload=activity
            )
            self.database_handler.update_ping_status(
                ping_id=str(ping_id), status="delivered"
            )
            delivery_status = "delivered"
        except Exception as exc:
            logger.error(f"Federated ping delivery failed: {exc}")
            self.database_handler.update_ping_status(
                ping_id=str(ping_id),
                status="failed",
                metadata_json={"error": str(exc)},
            )
            delivery_status = "failed"

        logger.info(
            f"Federated ping | sender={sender_id} target={peer.actor_uri} "
            f"ping_id={ping_id} status={delivery_status}"
        )

        return {
            "ping_id": str(ping_id),
            "ping_type": "federated",
            "target_actor_uri": peer.actor_uri,
            "activity_uri": activity_uri,
            "delivery_target": delivery_target,
            "status": delivery_status,
            "message": message,
            "sent_at": now.isoformat(),
            "expires_at": expires.isoformat(),
        }

    # ------------------------------------------------------------------
    # Unified send (auto-detects local vs. federated)
    # ------------------------------------------------------------------

    async def send_ping(
        self,
        sender_id: str,
        target: str,
        base_url: str,
        message: str | None = None,
    ) -> dict:
        """
        Send a ping to any target — automatically routes between local and
        federated delivery.

        Local targets (UUID, local username) → :meth:`send_local_ping`.
        Remote targets (user@domain, actor URI) → :meth:`send_federated_ping`.

        Args:
            sender_id: UUID of the authenticated local sender.
            target: Local user ID / username, remote handle, or actor URI.
            base_url: Canonical base URL of this instance.
            message: Optional short message body.

        Returns:
            dict with ping details.
        """
        import uuid as _uuid

        # Try UUID first (local user)
        try:
            _uuid.UUID(target)
            return await self.send_local_ping(
                sender_id=sender_id,
                target_user_id=target,
                message=message,
                base_url=base_url,
            )
        except (ValueError, TypeError):
            pass

        # Check local username
        local_user = self.database_handler.get_user(username=target)
        if local_user is not None:
            return await self.send_local_ping(
                sender_id=sender_id,
                target_user_id=str(local_user.user_id),
                message=message,
                base_url=base_url,
            )

        # Remote handle or actor URI → federated
        return await self.send_federated_ping(
            sender_id=sender_id,
            target=target,
            base_url=base_url,
            message=message,
        )

    # ------------------------------------------------------------------
    # Instance ping
    # ------------------------------------------------------------------

    async def send_instance_ping(
        self,
        sender_id: str,
        target_instance_url: str,
    ) -> dict:
        """
        HTTP health-check probe to a remote PufferBlow instance.

        Hits the remote ``/healthz`` endpoint and records the round-trip
        latency and HTTP status code.

        Args:
            sender_id: UUID of the requesting user (for audit / history).
            target_instance_url: Base URL of the remote instance (e.g.
                ``https://other.example.com``).

        Returns:
            dict with status, http_status, latency_ms, and ping record.
        """
        target_url = target_instance_url.rstrip("/")
        health_url = f"{target_url}/healthz"
        now = self._now()

        ping_id = self._new_ping_id()
        sender_ping = Pings(
            ping_id=ping_id,
            ping_type="instance",
            sender_id=uuid.UUID(sender_id),
            target_instance_url=target_url,
            status="sent",
            is_sender=True,
            sent_at=now,
            expires_at=self._expires_at(ttl_seconds=30),
        )
        self.database_handler.create_ping(sender_ping)

        start_ns = time.monotonic_ns()
        http_status: int | None = None
        error_msg: str | None = None

        try:
            async with httpx.AsyncClient(
                timeout=self.INSTANCE_PING_HTTP_TIMEOUT,
                follow_redirects=True,
            ) as client:
                response = await client.get(health_url)
                http_status = response.status_code
        except httpx.TimeoutException:
            error_msg = "timeout"
        except Exception as exc:
            error_msg = str(exc)

        elapsed_ms = int((time.monotonic_ns() - start_ns) / 1_000_000)

        if error_msg:
            self.database_handler.update_ping_status(
                ping_id=str(ping_id),
                status="failed",
                instance_http_status=http_status,
                instance_latency_ms=elapsed_ms,
                metadata_json={"error": error_msg, "health_url": health_url},
            )
            final_status = "failed"
        else:
            is_ok = http_status is not None and 200 <= http_status < 300
            final_status = "acked" if is_ok else "failed"
            self.database_handler.update_ping_status(
                ping_id=str(ping_id),
                status=final_status,
                instance_http_status=http_status,
                instance_latency_ms=elapsed_ms,
                acked_at=self._now() if is_ok else None,
                metadata_json={"health_url": health_url},
            )

        logger.info(
            f"Instance ping | target={target_url} status={final_status} "
            f"http={http_status} latency={elapsed_ms}ms ping_id={ping_id}"
        )

        return {
            "ping_id": str(ping_id),
            "ping_type": "instance",
            "target_instance_url": target_url,
            "health_url": health_url,
            "status": final_status,
            "http_status": http_status,
            "latency_ms": elapsed_ms,
            "error": error_msg,
            "sent_at": now.isoformat(),
        }

    # ------------------------------------------------------------------
    # Acknowledge a ping (receiver side)
    # ------------------------------------------------------------------

    async def ack_ping(
        self,
        ping_id: str,
        user_id: str,
        base_url: str,
    ) -> dict:
        """
        Acknowledge a received ping.

        For local pings: updates the receiver record and notifies the sender
        of the round-trip latency via WebSocket.

        For federated pings: additionally sends a ``PingAck`` ActivityPub
        activity back to the original sender's inbox.

        Args:
            ping_id: UUID of the receiver-side Pings record to acknowledge.
            user_id: UUID of the acknowledging user (must match target_user_id).
            base_url: Canonical base URL (for federated PingAck activity).

        Returns:
            dict with ack metadata.
        """
        ping = self.database_handler.get_ping(ping_id=ping_id)
        if ping is None:
            raise ValueError(f"Ping '{ping_id}' not found.")

        if ping.target_user_id != user_id:
            raise PermissionError("You are not the recipient of this ping.")

        if ping.status in ("acked", "timeout", "failed"):
            raise ValueError(f"Ping is already in terminal state: {ping.status!r}.")

        now = self._now()
        latency_ms = int((now - ping.sent_at).total_seconds() * 1000)

        self.database_handler.update_ping_status(
            ping_id=ping_id,
            status="acked",
            latency_ms=latency_ms,
            acked_at=now,
        )

        ack_payload: dict = {
            "type": "ping_acked",
            "ping_id": ping_id,
            "acker_user_id": user_id,
            "latency_ms": latency_ms,
            "acked_at": now.isoformat(),
        }

        # Notify sender via WebSocket
        sender_id = str(ping.sender_id)
        await self.websockets_manager.broadcast_to_user(
            user_id=sender_id, message=ack_payload
        )

        # Find and update sender-side record
        sender_ping_id: str | None = None
        meta = ping.metadata_json or {}
        if meta.get("sender_ping_id"):
            sender_ping_id = meta["sender_ping_id"]
            self.database_handler.update_ping_status(
                ping_id=sender_ping_id,
                status="acked",
                latency_ms=latency_ms,
                acked_at=now,
            )

        # Federated PingAck delivery
        if ping.ping_type == "federated" and ping.original_activity_uri:
            await self._send_federated_ping_ack(
                receiver_user_id=user_id,
                original_ping_id=ping_id,
                original_activity_uri=ping.original_activity_uri,
                latency_ms=latency_ms,
                base_url=base_url,
            )

        logger.info(
            f"Ping acked | ping_id={ping_id} user={user_id} latency={latency_ms}ms"
        )

        return {
            "ping_id": ping_id,
            "sender_ping_id": sender_ping_id,
            "status": "acked",
            "latency_ms": latency_ms,
            "acked_at": now.isoformat(),
        }

    # ------------------------------------------------------------------
    # Federated PingAck outgoing
    # ------------------------------------------------------------------

    async def _send_federated_ping_ack(
        self,
        receiver_user_id: str,
        original_ping_id: str,
        original_activity_uri: str,
        latency_ms: int,
        base_url: str,
    ) -> None:
        """
        Send a ``PingAck`` ActivityPub activity back to the original sender.
        """
        if self.activitypub_manager is None:
            return

        local_actor = self.activitypub_manager.ensure_local_actor(
            user_id=receiver_user_id, base_url=base_url
        )

        # Resolve the original sender from the Ping outbox activity
        original_ping = self.database_handler.get_ping_by_activity_uri(
            activity_uri=original_activity_uri
        )
        if original_ping is None:
            # Try looking up via sender-side record
            original_ping = self.database_handler.get_ping_by_original_activity_uri(
                original_activity_uri=original_activity_uri
            )

        # Derive sender actor URI from the stored AP outbox activity
        sender_actor_uri: str | None = None
        try:
            outbox_rows = self.database_handler.get_activitypub_outbox_activities(
                actor_uri=local_actor.actor_uri, limit=1, offset=0
            )
        except Exception:
            outbox_rows = []

        # Look up the original Ping outbox activity by its URI
        inbox_row = None
        try:
            from sqlalchemy import select as _select
            from pufferblow.api.database.tables.activitypub import ActivityPubInboxActivity

            with self.database_handler.database_session() as session:
                stmt = _select(ActivityPubInboxActivity).where(
                    ActivityPubInboxActivity.activity_uri == original_activity_uri
                )
                result = session.execute(stmt).fetchone()
                if result:
                    inbox_row = result[0]
                    sender_actor_uri = inbox_row.actor_uri
        except Exception as exc:
            logger.warning(f"Could not resolve sender actor for PingAck: {exc}")

        if not sender_actor_uri:
            logger.warning(
                f"Skipping PingAck — cannot resolve sender actor from {original_activity_uri}"
            )
            return

        # Fetch remote actor to get inbox
        try:
            remote_actor = await self.activitypub_manager.fetch_remote_actor(
                actor_uri=sender_actor_uri
            )
        except Exception as exc:
            logger.error(f"PingAck: could not fetch sender actor {sender_actor_uri}: {exc}")
            return

        now = self._now()
        ack_activity_uri = f"{base_url}/ap/activities/pingack-{uuid.uuid4()}"
        ack_activity = {
            "@context": [
                self.ACTIVITYSTREAMS_CONTEXT,
                {"pufferblow": f"{base_url}/ns#"},
            ],
            "id": ack_activity_uri,
            "type": "PingAck",
            "actor": local_actor.actor_uri,
            "to": [sender_actor_uri],
            "object": original_activity_uri,
            "published": now.isoformat(),
            "pufferblow:latencyMs": latency_ms,
            "pufferblow:originalPingId": original_ping_id,
            "pufferblow:kind": "user_ping_ack",
        }

        self.database_handler.store_activitypub_outbox_activity(
            activity_uri=ack_activity_uri,
            activity_type="PingAck",
            actor_uri=local_actor.actor_uri,
            payload_json=json.dumps(ack_activity),
            object_uri=original_activity_uri,
        )

        delivery_target = remote_actor.shared_inbox_uri or remote_actor.inbox_uri
        try:
            await self.activitypub_manager._http_post_json(
                url=delivery_target, payload=ack_activity
            )
            logger.info(
                f"PingAck delivered | to={sender_actor_uri} latency={latency_ms}ms "
                f"ack_activity={ack_activity_uri}"
            )
        except Exception as exc:
            logger.error(f"PingAck delivery failed to {delivery_target}: {exc}")

    # ------------------------------------------------------------------
    # Incoming federated Ping (inbox handler)
    # ------------------------------------------------------------------

    async def process_federated_ping(
        self,
        activity: dict,
        base_url: str,
        target_actor_uri: str | None = None,
    ) -> dict:
        """
        Handle an incoming ``Ping`` ActivityPub activity.

        Called from :meth:`ActivityPubManager.process_inbox_activity` when
        ``activity["type"] == "Ping"``.

        Creates a receiver-side Pings record and emits a ``ping_received``
        WebSocket event to the local target user.

        Args:
            activity: The full ActivityPub activity payload.
            base_url: Canonical base URL of this (receiving) instance.
            target_actor_uri: Actor URI of the intended recipient.

        Returns:
            dict describing the processing outcome.
        """
        if self.activitypub_manager is None:
            return {"processed": False, "reason": "activitypub_manager_not_available"}

        actor_uri = str(activity.get("actor", ""))
        targets_raw = activity.get("to", [])
        if isinstance(targets_raw, str):
            targets_raw = [targets_raw]

        # Resolve all local target actors
        local_targets = []
        for uri in targets_raw:
            actor = self.database_handler.get_activitypub_actor_by_uri(actor_uri=uri)
            if actor is not None and actor.is_local and actor.user_id:
                local_targets.append(actor)

        if not local_targets and target_actor_uri:
            actor = self.database_handler.get_activitypub_actor_by_uri(
                actor_uri=target_actor_uri
            )
            if actor is not None and actor.is_local and actor.user_id:
                local_targets.append(actor)

        if not local_targets:
            return {"processed": True, "action": "no_local_recipient"}

        # Fetch sender info for display
        try:
            remote_actor = await self.activitypub_manager.fetch_remote_actor(
                actor_uri=actor_uri
            )
            sender_username = remote_actor.preferred_username
        except Exception:
            sender_username = actor_uri.rsplit("/", 1)[-1]

        original_activity_uri = str(activity.get("id", ""))
        message = str(activity.get("pufferblow:message") or "").strip() or None
        expires_at_raw = activity.get("pufferblow:expiresAt")
        try:
            expires_at = datetime.datetime.fromisoformat(str(expires_at_raw))
        except Exception:
            expires_at = self._expires_at()

        now = self._now()
        delivered_to = []

        for target_actor in local_targets:
            target_user_id = str(target_actor.user_id)

            ping_id = self._new_ping_id()
            receiver_ping = Pings(
                ping_id=ping_id,
                ping_type="federated",
                sender_id=uuid.UUID(str(target_actor.user_id)),  # FK must be local user
                target_user_id=target_user_id,
                target_actor_uri=actor_uri,
                original_activity_uri=original_activity_uri,
                status="delivered",
                is_sender=False,
                message=message,
                sent_at=now,
                expires_at=expires_at,
                metadata_json={
                    "sender_actor_uri": actor_uri,
                    "sender_username": sender_username,
                },
            )
            # Sender FK must point to an existing local user; use the target user
            # as a placeholder because the remote sender has no local user_id.
            # We store the real sender identity in target_actor_uri + metadata.
            receiver_ping.sender_id = uuid.UUID(target_user_id)
            self.database_handler.create_ping(receiver_ping)

            ws_payload = {
                "type": "ping_received",
                "ping_id": str(ping_id),
                "sender_actor_uri": actor_uri,
                "sender_username": sender_username,
                "ping_type": "federated",
                "message": message,
                "sent_at": now.isoformat(),
                "expires_at": expires_at.isoformat(),
                "original_activity_uri": original_activity_uri,
            }
            await self.websockets_manager.broadcast_to_user(
                user_id=target_user_id, message=ws_payload
            )
            delivered_to.append(target_user_id)

        return {
            "processed": True,
            "activity_type": "Ping",
            "action": "ping_delivered",
            "delivered_to": delivered_to,
        }

    # ------------------------------------------------------------------
    # Incoming federated PingAck (inbox handler)
    # ------------------------------------------------------------------

    async def process_federated_ping_ack(
        self,
        activity: dict,
        base_url: str,
    ) -> dict:
        """
        Handle an incoming ``PingAck`` ActivityPub activity.

        Looks up the original outgoing Ping by the referenced object URI,
        updates its status to ``"acked"``, and fires a ``ping_acked``
        WebSocket event to the original sender.

        Args:
            activity: The full ActivityPub activity payload.
            base_url: Canonical base URL of this instance (unused, kept for symmetry).

        Returns:
            dict describing the processing outcome.
        """
        original_ping_uri = str(activity.get("object", ""))
        latency_ms_raw = activity.get("pufferblow:latencyMs")
        try:
            latency_ms = int(latency_ms_raw) if latency_ms_raw is not None else None
        except (TypeError, ValueError):
            latency_ms = None

        if not original_ping_uri:
            return {"processed": True, "action": "missing_object_uri"}

        # Find the sender-side Pings record
        sender_ping = self.database_handler.get_ping_by_activity_uri(
            activity_uri=original_ping_uri
        )
        if sender_ping is None:
            logger.warning(f"PingAck: original ping not found for URI {original_ping_uri}")
            return {"processed": True, "action": "original_ping_not_found"}

        now = self._now()
        if latency_ms is None:
            latency_ms = int((now - sender_ping.sent_at).total_seconds() * 1000)

        self.database_handler.update_ping_status(
            ping_id=str(sender_ping.ping_id),
            status="acked",
            latency_ms=latency_ms,
            acked_at=now,
        )

        ack_ws_payload = {
            "type": "ping_acked",
            "ping_id": str(sender_ping.ping_id),
            "acker_actor_uri": str(activity.get("actor", "")),
            "latency_ms": latency_ms,
            "acked_at": now.isoformat(),
            "federated": True,
        }
        await self.websockets_manager.broadcast_to_user(
            user_id=str(sender_ping.sender_id), message=ack_ws_payload
        )

        logger.info(
            f"Federated PingAck received | ping_id={sender_ping.ping_id} "
            f"latency={latency_ms}ms acker={activity.get('actor')}"
        )

        return {
            "processed": True,
            "activity_type": "PingAck",
            "action": "ping_marked_acked",
            "ping_id": str(sender_ping.ping_id),
            "latency_ms": latency_ms,
        }

    # ------------------------------------------------------------------
    # Query helpers (used by routes)
    # ------------------------------------------------------------------

    def get_ping_history(
        self,
        user_id: str,
        direction: str = "both",
        page: int = 1,
        per_page: int = 20,
    ) -> list[dict]:
        """Return serialized ping history for a user."""
        pings = self.database_handler.get_ping_history(
            user_id=user_id, direction=direction, page=page, per_page=per_page
        )
        return [p.to_dict() for p in pings]

    def get_pending_pings(self, user_id: str) -> list[dict]:
        """Return unacknowledged inbound pings for a user."""
        pings = self.database_handler.get_pending_pings_for_user(user_id=user_id)
        return [p.to_dict() for p in pings]

    def get_ping_stats(self, user_id: str) -> dict:
        """Return aggregated ping statistics for a user."""
        return self.database_handler.get_ping_stats(user_id=user_id)

    def dismiss_ping(self, ping_id: str, user_id: str) -> bool:
        """
        Delete / dismiss a ping record.

        The caller must be either the sender or the recipient.
        """
        return self.database_handler.delete_ping(ping_id=ping_id, user_id=user_id)

    def expire_stale_pings(self) -> int:
        """Transition expired pings to timeout status (for background scheduler)."""
        return self.database_handler.expire_stale_pings()
