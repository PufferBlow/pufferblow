from datetime import datetime, timezone
from typing import TYPE_CHECKING

from fastapi import WebSocket
from loguru import logger
from pufferblow.api.user.status import normalize_user_status

#: Event names for the per-user (DM) frames, as protocol-v1 sessions receive them.
DM_EVENT_NAMES = {
    "message": "dm.message.created",
    "message_edited": "dm.message.updated",
    "message_deleted": "dm.message.deleted",
    "reaction": "dm.reaction.updated",
    "pins_changed": "dm.pins.updated",
}


def as_protocol_event(message: dict) -> dict:
    """A per-user frame in the shape a protocol-v1 session understands.

    DM frames (those with a ``conversation_id``) become ``dm.*`` events; anything
    else (call signalling, pings) becomes ``user.<type>``. The legacy ``type`` key
    moves into the event name, the rest is the event's data unchanged. Frames that
    are already v1 events pass through.
    """
    if message.get("type") == "event" and "version" in message:
        return message
    from pufferblow.api.protocol.envelopes import build_event

    kind = str(message.get("type") or "notice")
    name = DM_EVENT_NAMES.get(kind) if message.get("conversation_id") else None
    data = {key: value for key, value in message.items() if key != "type"}
    return build_event(name or f"user.{kind}", data)

if TYPE_CHECKING:
    from pufferblow.api.user.user_manager import UserManager


class WebSocketsManager:
    """WebSocketManager class is responsible for managing websockets"""

    def __init__(self, user_manager: "UserManager | None" = None):
        # Format:
        # {websocket: {"user_id": str, "auth_token": str, "scope": "global", "protocol": 1,
        #              "channel_id": None, "accessible_channels": list[str], "context": ConnectionContext}}
        """Initialize the instance."""
        self.active_connections: dict[WebSocket, dict] = {}
        self.user_manager = user_manager
        #: Set during bootstrap; used to keep private-channel events away from unauthorised sockets.
        self.channels_manager = None

    @staticmethod
    def _connection_context(connection_info) -> tuple[str, str]:
        """
        Resolve (user_id, channel_or_scope) from normalized connection metadata.
        Returns (user_id, channel_id_or_scope).
        """
        if not isinstance(connection_info, dict):
            return ("unknown", "unknown")

        user_id = str(connection_info.get("user_id", "unknown"))
        return (user_id, "global")

    def count_connections_from_ip(self, ip: str) -> int:
        """Open connections from one client address."""
        return sum(
            1 for info in self.active_connections.values() if isinstance(info, dict) and info.get("ip") == ip
        )

    def _count_connections_for_user(self, user_id: str) -> int:
        """Return active websocket connections count for a specific user."""
        target = str(user_id)
        return sum(
            1
            for connection_info in self.active_connections.values()
            if isinstance(connection_info, dict)
            and str(connection_info.get("user_id")) == target
        )

    @staticmethod
    def _build_presence_message(user_id: str, status: str, source: str) -> dict:
        """Build canonical status update payload for websocket clients."""
        return {
            "type": "user_status_changed",
            "user_id": str(user_id),
            "status": status,
            "source": source,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    async def _broadcast_presence_message(self, message: dict) -> None:
        """Broadcast a presence update to every client, in the shape each one understands."""
        from pufferblow.api.protocol.envelopes import build_event
        from pufferblow.api.protocol.events import PRESENCE_CHANGED

        active_connections_copy = self.active_connections.copy()
        if not active_connections_copy:
            return

        v1_frame = build_event(
            PRESENCE_CHANGED,
            {
                "user_id": message.get("user_id"),
                "status": message.get("status"),
                "source": message.get("source"),
                "at": message.get("timestamp"),
            },
        )

        sent_count = 0
        failed_count = 0

        for websocket in active_connections_copy:
            try:
                await websocket.send_json(v1_frame)
                sent_count += 1
            except Exception as exc:
                failed_count += 1
                logger.warning(
                    f"Presence broadcast failed for one connection: {str(exc)}"
                )

        logger.info(
            f"Presence broadcast completed | Type: {message.get('type')} | User: {message.get('user_id')} | Status: {message.get('status')} | Sent: {sent_count} | Failed: {failed_count}"
        )

    async def update_user_presence_status(
        self, user_id: str, status: str, source: str = "client"
    ) -> str:
        """
        Persist and broadcast a user presence status.

        Args:
            user_id (str): Target user.
            status (str): Raw status value from caller/client.
            source (str): Source marker for telemetry.

        Returns:
            str: Normalized/canonical status.

        Raises:
            ValueError: If status is invalid or user manager is not configured.
        """
        if self.user_manager is None:
            raise ValueError("User manager is not configured for presence updates.")

        normalized_status = normalize_user_status(status)
        is_changed = self.user_manager.update_user_status(
            user_id=user_id, status=normalized_status
        )

        if is_changed:
            message = self._build_presence_message(
                user_id=user_id, status=normalized_status, source=source
            )
            await self._broadcast_presence_message(message)

        return normalized_status

    async def ensure_user_online(self, user_id: str, source: str = "ws_connect") -> None:
        """
        Mark user online when they establish their first websocket connection.
        Skips the update if the user has a manual status lock (DND or AFK).
        """
        if self._count_connections_for_user(user_id) != 1:
            return

        # Respect manual status locks — don't override DND/AFK on reconnect
        try:
            user_data = (
                self.user_manager.database_handler.get_user(user_id=user_id)
                if self.user_manager is not None
                else None
            )
            if user_data and user_data.status in {"dnd", "afk"}:
                logger.info(
                    f"Skipping ensure_user_online — manual status lock active | User: {user_id} | Status: {user_data.status}"
                )
                return
        except Exception as exc:
            logger.warning(
                f"Could not check user status before ensure_user_online | User: {user_id} | Error: {exc}"
            )

        try:
            await self.update_user_presence_status(
                user_id=user_id, status="online", source=source
            )
        except Exception as exc:
            logger.warning(
                f"Failed to set user online on websocket connect | User: {user_id} | Error: {str(exc)}"
            )

    async def ensure_user_offline_if_no_connections(
        self, user_id: str, source: str = "ws_disconnect"
    ) -> None:
        """
        Mark user offline when all websocket connections are gone.
        """
        if self._count_connections_for_user(user_id) != 0:
            return

        try:
            await self.update_user_presence_status(
                user_id=user_id, status="offline", source=source
            )
        except Exception as exc:
            logger.warning(
                f"Failed to set user offline on websocket disconnect | User: {user_id} | Error: {str(exc)}"
            )

    async def connect_global(
        self,
        websocket: WebSocket,
        auth_token: str,
        accessible_channels: list[str],
        *,
        context,
        ip: str | None = None,
    ) -> None:
        """
        Accept a protocol session. ``context`` (principal, subscriptions) is required.

        Args:
            websocket (WebSocket): A `WebSocket` object.
            auth_token (str): The client's `auth_token`.
            accessible_channels (list[str]): List of channel IDs this user can access.
            context (ConnectionContext): The session's principal and subscriptions.

        Returns:
            None.
        """
        try:
            # A browser client offers `pufferblow.v1` next to its `bearer.<token>`; echo only the former.
            await websocket.accept(subprotocol=websocket.scope.get("pufferblow.ws_subprotocol"))

            # The principal is the user or the bot; the token is not parsed to find out.
            user_id = context.principal.id

            self.active_connections[websocket] = {
                "user_id": user_id,
                "auth_token": auth_token,
                "scope": "global",
                "channel_id": None,
                "accessible_channels": accessible_channels,
                "protocol": 1,
                "context": context,
                "ip": ip,
            }

            logger.info(
                f"Global WebSocket connected | User: {user_id} | Accessible channels: {len(accessible_channels)} | Total connections: {len(self.active_connections)}"
            )
            await self.ensure_user_online(user_id=user_id, source="ws_global_connect")
        except Exception as e:
            logger.error(
                f"Global WebSocket connection failed | Auth: {auth_token[:8]}... | Error: {str(e)}"
            )
            raise

    async def disconnect(self, websocket: WebSocket) -> None:
        """
        Disconnects a client

        Args:
            websocket (WebSocket): A `WebSocket` object.

        Returns:
            None.
        """
        connection_info = self.active_connections.get(websocket)
        user_id = None

        if connection_info:
            user_id, channel_id = self._connection_context(connection_info)
            logger.info(
                f"WebSocket disconnected | User: {user_id} | Channel: {channel_id} | Remaining connections: {len(self.active_connections) - 1}"
            )

        try:
            # Check if websocket is already closed
            if websocket.client_state != 3:  # 3 = CLOSED
                await websocket.close()
        except Exception as e:
            logger.error(f"WebSocket disconnect error: {str(e)}")
        finally:
            if websocket in self.active_connections:
                del self.active_connections[websocket]

        if user_id is not None:
            await self.ensure_user_offline_if_no_connections(
                user_id=user_id, source="ws_disconnect"
            )
            await self._end_calls_if_offline(str(user_id))
            voice_manager = getattr(self, "voice_session_manager", None)
            if voice_manager is not None:
                try:
                    voice_manager.leave_all_active_sessions_for_user(user_id=str(user_id))
                except Exception as exc:
                    logger.warning(f"Voice session cleanup on disconnect failed for user {user_id}: {exc}")

    async def _end_calls_if_offline(self, user_id: str) -> None:
        """A person with no connection left cannot be on a call: end theirs and tell the other side."""
        calls = getattr(self, "dm_call_manager", None)
        if calls is None or any(
            isinstance(info, dict) and str(info.get("user_id")) == user_id for info in self.active_connections.values()
        ):
            return
        for call in calls.end_all_for_user(user_id):
            if call.get("delivered", True) or call["other_user_id"] != call["callee_id"]:
                await self.broadcast_to_user(call["other_user_id"], {"type": "dm_call_ended", "call_id": call["call_id"]})

    async def broadcast_to_channel(self, channel_id: str, message: dict) -> None:
        """Send a channel-wide notice (e.g. a voice session change) as a v1 event.

        The legacy ``type`` key becomes the event name (``channel.<type>``) and the rest the
        event data. Only sessions subscribed to the channel receive it, and private channels
        are re-checked like any other channel event.
        """
        from pufferblow.api.protocol.envelopes import build_event

        kind = str(message.get("type") or "notice")
        data = {key: value for key, value in message.items() if key != "type"}
        await self.deliver_channel_event(channel_id, build_event(f"channel.{kind}", data, channel_id=channel_id))

    async def broadcast_to_user(self, user_id: str, message: dict) -> None:
        """
        Broadcast a JSON message to all active websocket connections of one user.
        """
        active_connections_copy = self.active_connections.copy()
        recipients: list[WebSocket] = []

        for websocket, connection_info in active_connections_copy.items():
            if not isinstance(connection_info, dict):
                continue
            if str(connection_info.get("user_id")) == str(user_id):
                recipients.append(websocket)

        if not recipients:
            logger.debug(f"No websocket recipients for user {user_id}")
            return

        sent_count = 0
        failed_count = 0
        protocol_frame = as_protocol_event(message)
        for websocket in recipients:
            try:
                await websocket.send_json(protocol_frame)
                sent_count += 1
            except Exception as exc:
                failed_count += 1
                logger.error(
                    f"Failed to broadcast personal message to user {user_id}: {str(exc)}"
                )

        logger.info(
            f"Personal broadcast completed | User: {user_id} | Sent: {sent_count} | Failed: {failed_count}"
        )

    # ── command/event protocol delivery ───────────────────────

    def count_v1_connections(self) -> int:
        return sum(
            1
            for info in self.active_connections.values()
            if isinstance(info, dict) and info.get("protocol", 0) >= 1
        )

    def _private_channel_members(self, channel_id: str) -> set[str] | None:
        """``None`` for a public channel; for a private one, the user ids on its member list."""
        if self.channels_manager is None:
            return None
        try:
            channel = self.channels_manager.get_channel(channel_id=channel_id)
        except Exception:
            return set()  # when unsure, treat it as private with no members: do not leak
        if channel is None or not channel.is_private:
            return None
        return {str(user_id) for user_id in channel.allowed_users or []}

    def _may_view_private(self, user_id: str) -> bool:
        if self.user_manager is None:
            return False
        try:
            return bool(
                self.user_manager.has_privilege(user_id=user_id, privilege_id="view_private_channels")
            )
        except Exception:
            return False

    async def deliver_channel_event(self, channel_id: str, v1_frame: dict) -> None:
        """Send one committed channel event to every session subscribed to the channel.

        Private channels are re-checked at delivery time so a revoked privilege or a
        removal from the member list stops events immediately.
        """
        from pufferblow.api.commands.metrics import metrics

        members = self._private_channel_members(channel_id)
        sent = failed = 0

        for websocket, info in list(self.active_connections.items()):
            if not isinstance(info, dict) or "user_id" not in info:
                continue

            context = info.get("context")
            if context is None or channel_id not in context.subscriptions:
                continue

            if members is not None and not (
                str(context.principal.accountable_user_id) in members
                or self._may_view_private(str(info["user_id"]))
            ):
                continue

            try:
                await websocket.send_json(v1_frame)
                sent += 1
            except Exception as exc:
                failed += 1
                metrics.incr("delivery_failures")
                logger.warning(f"Event delivery failed for one client in channel {channel_id}: {exc}")

        metrics.incr("events_delivered", sent)
        logger.debug(f"Channel event delivered | channel={channel_id} sent={sent} failed={failed}")

    async def deliver_user_event(self, user_id: str, v1_frame: dict) -> None:
        """Send an event addressed to one user to every connection that user has open."""
        target = str(user_id)
        for websocket, info in list(self.active_connections.items()):
            if not isinstance(info, dict) or str(info.get("user_id")) != target:
                continue
            try:
                await websocket.send_json(v1_frame)
            except Exception as exc:
                logger.warning(f"User event delivery failed for {target}: {exc}")

    async def grant_subscriptions(self, authorizer, channel_id: str, *, name: str, data: dict) -> int:
        """Subscribe every open session that may now read ``channel_id`` and tell it so.

        The counterpart of :meth:`revalidate_subscriptions`. Call after anything that can
        give access (a channel created, made public, or shared with someone) so the change
        streams without a reconnect. Each newly subscribed session gets one event ``name``
        with ``data``, unsequenced like the revocation notice. Sessions already subscribed
        are left alone. Returns how many sessions were subscribed.
        """
        from pufferblow.api.protocol.envelopes import build_event

        may_read = authorizer.channel_reader(channel_id)
        granted = 0
        for websocket, info in list(self.active_connections.items()):
            context = info.get("context") if isinstance(info, dict) else None
            if context is None or channel_id in context.subscriptions or not may_read(context.principal):
                continue
            context.subscriptions.add(channel_id)
            granted += 1
            try:
                await websocket.send_json(build_event(name, data, channel_id=channel_id))
            except Exception as exc:
                logger.warning(f"Channel grant notice failed for one client in channel {channel_id}: {exc}")
        logger.debug(f"Channel access granted | channel={channel_id} sessions={granted}")
        return granted

    async def refresh_channel_access(self, authorizer) -> None:
        """Apply a privilege change (a role edited or reassigned) to every open session.

        Re-resolves each session's principal and drops channels it may no longer read, then
        subscribes it to private channels it may now read, with the usual `access` notices.
        Public channels are unaffected by privileges, so only private ones are granted.
        """
        from pufferblow.api.protocol.events import CHANNEL_UPDATED

        await self.revalidate_subscriptions(authorizer)
        if self.channels_manager is None:
            return
        for channel_id in self.channels_manager.private_channel_ids():
            await self.grant_subscriptions(
                authorizer,
                channel_id,
                name=CHANNEL_UPDATED,
                data={"channel_id": channel_id, "access": "granted"},
            )

    async def revalidate_subscriptions(self, authorizer, channel_id: str | None = None) -> int:
        """Drop subscriptions a connection is no longer allowed to hold.

        Call after anything that can change access (a channel made private, a role change).
        Returns how many subscriptions were removed. A connection whose credential no
        longer validates loses all of them.
        """
        from pufferblow.api.protocol.envelopes import build_event
        from pufferblow.api.protocol.events import CHANNEL_UPDATED

        removed = 0
        for websocket, info in list(self.active_connections.items()):
            context = info.get("context") if isinstance(info, dict) else None
            if context is None:
                continue

            # Tell any check running in a worker thread for this connection that its answer may be stale.
            context.access_version += 1
            credential_ok = True
            try:
                if context.revalidate is not None:
                    context.principal = context.revalidate()
            except Exception:
                credential_ok = False

            targets = [channel_id] if channel_id else list(context.subscriptions)
            for target in targets:
                if target not in context.subscriptions:
                    continue
                if credential_ok and authorizer.can_subscribe(context.principal, target):
                    continue
                context.subscriptions.discard(target)
                removed += 1
                try:
                    await websocket.send_json(
                        build_event(
                            CHANNEL_UPDATED,
                            {"channel_id": target, "access": "revoked"},
                            channel_id=target,
                        )
                    )
                except Exception:
                    pass
        return removed
