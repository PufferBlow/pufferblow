from __future__ import annotations

import datetime
import hashlib
import json
import secrets
import uuid
from dataclasses import dataclass
from urllib.parse import quote

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from loguru import logger

from pufferblow.api.database.database_handler import DatabaseHandler
from pufferblow.api.messages.messages_manager import MessagesManager
from pufferblow.api.user.user_manager import UserManager
from pufferblow.api.websocket.websocket_manager import WebSocketsManager


@dataclass
class ActivityPubPeer:
    """ActivityPubPeer class."""
    actor_uri: str
    preferred_username: str
    is_local: bool
    user_id: str | None
    inbox_uri: str
    outbox_uri: str
    shared_inbox_uri: str | None


class ActivityPubManager:
    """ActivityPub manager for cross-instance identity and direct messaging."""

    ACTIVITYSTREAMS_CONTEXT = "https://www.w3.org/ns/activitystreams"

    def __init__(
        self,
        database_handler: DatabaseHandler,
        user_manager: UserManager,
        messages_manager: MessagesManager,
        websockets_manager: WebSocketsManager,
    ) -> None:
        """Initialize the instance."""
        self.database_handler = database_handler
        self.user_manager = user_manager
        self.messages_manager = messages_manager
        self.websockets_manager = websockets_manager

    def build_base_url(self, request_base_url: str | None = None) -> str:
        """
        Build the canonical base URL for ActivityPub object IDs.
        """
        if request_base_url:
            return request_base_url.rstrip("/")

        config = self.database_handler.config
        host = str(config.API_HOST).strip()
        port = str(config.API_PORT).strip()
        scheme = "https" if host not in {"127.0.0.1", "localhost"} else "http"
        if (scheme == "https" and port == "443") or (scheme == "http" and port == "80"):
            return f"{scheme}://{host}"
        return f"{scheme}://{host}:{port}"

    @staticmethod
    def _generate_keypair() -> tuple[str, str]:
        """
        Generate RSA public/private keypair in PEM format.
        """
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        return public_pem, private_pem

    def _actor_uri_for_user(self, user_id: str, base_url: str) -> str:
        """Actor uri for user."""
        return f"{base_url}/ap/users/{user_id}"

    def _inbox_uri_for_user(self, user_id: str, base_url: str) -> str:
        """Inbox uri for user."""
        return f"{base_url}/ap/users/{user_id}/inbox"

    def _outbox_uri_for_user(self, user_id: str, base_url: str) -> str:
        """Outbox uri for user."""
        return f"{base_url}/ap/users/{user_id}/outbox"

    @staticmethod
    def _parse_handle(handle: str) -> tuple[str, str]:
        """
        Parse handle formats:
        - user@domain
        - @user@domain
        - acct:user@domain
        """
        normalized = handle.strip()
        if normalized.startswith("acct:"):
            normalized = normalized[5:]
        if normalized.startswith("@"):
            normalized = normalized[1:]

        if "@" not in normalized:
            raise ValueError("Remote handle must be in format user@domain")

        username, domain = normalized.split("@", 1)
        username = username.strip()
        domain = domain.strip().lower()
        if not username or not domain:
            raise ValueError("Invalid remote handle")
        return username, domain

    @staticmethod
    def _conversation_id(actor_a: str, actor_b: str) -> str:
        """
        Stable conversation id for a pair of actor URIs.
        """
        key = "::".join(sorted([actor_a, actor_b]))
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return f"dm-{digest[:32]}"

    @staticmethod
    def _clean_html_to_text(content: str) -> str:
        """
        Keep payload handling simple and safe for chat text.
        """
        return content.replace("<br>", "\n").replace("<br/>", "\n").replace("<br />", "\n")

    def ensure_local_actor(self, user_id: str, base_url: str) -> object:
        """
        Ensure an ActivityPub actor row exists for a local user.
        """
        existing = self.database_handler.get_activitypub_actor_by_user_id(user_id=user_id)
        user = self.database_handler.get_user(user_id=user_id)
        if user is None:
            raise ValueError("User not found")

        actor_uri = self._actor_uri_for_user(user_id=str(user.user_id), base_url=base_url)
        inbox_uri = self._inbox_uri_for_user(user_id=str(user.user_id), base_url=base_url)
        outbox_uri = self._outbox_uri_for_user(user_id=str(user.user_id), base_url=base_url)
        shared_inbox_uri = f"{base_url}/ap/inbox"

        if existing is None:
            public_key_pem, private_key_pem = self._generate_keypair()
            return self.database_handler.upsert_activitypub_actor(
                actor_uri=actor_uri,
                preferred_username=user.username,
                inbox_uri=inbox_uri,
                outbox_uri=outbox_uri,
                shared_inbox_uri=shared_inbox_uri,
                public_key_pem=public_key_pem,
                private_key_pem=private_key_pem,
                is_local=True,
                user_id=str(user.user_id),
            )

        return self.database_handler.upsert_activitypub_actor(
            actor_uri=existing.actor_uri,
            preferred_username=user.username,
            inbox_uri=inbox_uri,
            outbox_uri=outbox_uri,
            shared_inbox_uri=shared_inbox_uri,
            public_key_pem=existing.public_key_pem,
            private_key_pem=existing.private_key_pem,
            is_local=True,
            user_id=str(user.user_id),
        )

    def ensure_local_actor_by_username(self, username: str, base_url: str) -> object | None:
        """
        Ensure local actor exists and resolve by local username.
        """
        user = self.database_handler.get_user(username=username)
        if user is None:
            return None
        return self.ensure_local_actor(user_id=str(user.user_id), base_url=base_url)

    def build_actor_document(self, actor: object) -> dict:
        """
        Build an ActivityPub actor document.
        """
        key_id = f"{actor.actor_uri}#main-key"
        return {
            "@context": [self.ACTIVITYSTREAMS_CONTEXT, "https://w3id.org/security/v1"],
            "id": actor.actor_uri,
            "type": "Person",
            "preferredUsername": actor.preferred_username,
            "inbox": actor.inbox_uri,
            "outbox": actor.outbox_uri,
            "publicKey": {
                "id": key_id,
                "owner": actor.actor_uri,
                "publicKeyPem": actor.public_key_pem,
            },
            "endpoints": {
                "sharedInbox": actor.shared_inbox_uri,
            },
        }

    def build_webfinger_response(
        self, username: str, domain: str, actor_uri: str
    ) -> dict:
        """
        Build a WebFinger response.
        """
        subject = f"acct:{username}@{domain}"
        return {
            "subject": subject,
            "aliases": [actor_uri],
            "links": [
                {
                    "rel": "self",
                    "type": "application/activity+json",
                    "href": actor_uri,
                }
            ],
        }

    async def _http_get_json(self, url: str, timeout: float = 10.0) -> dict:
        """Http get json."""
        headers = {
            "Accept": "application/activity+json, application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\", application/json",
            "User-Agent": "PufferBlow-ActivityPub/0.0.1-beta",
        }
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            return response.json()

    async def _http_post_json(self, url: str, payload: dict, timeout: float = 10.0) -> None:
        """Http post json."""
        headers = {
            "Content-Type": "application/activity+json",
            "Accept": "application/activity+json, application/json",
            "User-Agent": "PufferBlow-ActivityPub/0.0.1-beta",
        }
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            response = await client.post(url, headers=headers, content=json.dumps(payload))
            response.raise_for_status()

    async def resolve_actor_uri_from_handle(self, handle: str) -> str:
        """
        Resolve actor URI from a WebFinger handle.
        """
        username, domain = self._parse_handle(handle)
        resource = quote(f"acct:{username}@{domain}", safe="")
        candidates = [
            f"https://{domain}/.well-known/webfinger?resource={resource}",
            f"http://{domain}/.well-known/webfinger?resource={resource}",
        ]

        last_error: Exception | None = None
        for candidate in candidates:
            try:
                wf = await self._http_get_json(candidate)
                for link in wf.get("links", []):
                    if link.get("rel") == "self" and "href" in link:
                        return str(link["href"])
            except Exception as exc:
                last_error = exc

        raise ValueError(f"Failed to resolve remote actor from handle '{handle}': {last_error}")

    async def fetch_remote_actor(self, actor_uri: str) -> object:
        """
        Fetch and cache a remote actor.
        """
        existing = self.database_handler.get_activitypub_actor_by_uri(actor_uri=actor_uri)
        now = datetime.datetime.now(datetime.timezone.utc)
        if existing is not None and existing.fetched_at is not None:
            age = now - existing.fetched_at
            if age.total_seconds() < 3600:
                return existing

        actor_doc = await self._http_get_json(actor_uri)
        inbox_uri = actor_doc.get("inbox")
        outbox_uri = actor_doc.get("outbox")
        preferred_username = actor_doc.get("preferredUsername") or actor_uri.rsplit("/", 1)[-1]
        public_key = actor_doc.get("publicKey", {}) or {}
        public_key_pem = public_key.get("publicKeyPem", "")
        endpoints = actor_doc.get("endpoints", {}) or {}
        shared_inbox_uri = endpoints.get("sharedInbox")

        if not inbox_uri or not outbox_uri or not public_key_pem:
            raise ValueError("Remote actor document missing required fields")

        return self.database_handler.upsert_activitypub_actor(
            actor_uri=actor_uri,
            preferred_username=preferred_username,
            inbox_uri=inbox_uri,
            outbox_uri=outbox_uri,
            shared_inbox_uri=shared_inbox_uri,
            public_key_pem=public_key_pem,
            is_local=False,
        )

    def _remote_shadow_username(self, preferred_username: str, actor_uri: str) -> str:
        """Remote shadow username."""
        base = preferred_username.lower().replace(" ", "_")
        digest = hashlib.sha1(actor_uri.encode("utf-8")).hexdigest()[:10]
        candidate = f"fedi_{base}_{digest}"[:64]
        if not self.user_manager.check_username(candidate):
            return candidate
        return f"fedi_{digest}_{secrets.token_hex(3)}"[:64]

    def _ensure_remote_shadow_user(self, remote_actor: object) -> str:
        """
        Ensure remote ActivityPub actor has a local read-only shadow user for message history.
        """
        if remote_actor.user_id:
            return str(remote_actor.user_id)

        generated_password = secrets.token_urlsafe(32)
        username = self._remote_shadow_username(
            preferred_username=remote_actor.preferred_username,
            actor_uri=remote_actor.actor_uri,
        )
        user = self.user_manager.sign_up(username=username, password=generated_password)
        remote_domain = remote_actor.actor_uri.split("/")[2] if "://" in remote_actor.actor_uri else ""
        self.database_handler.update_user_origin_server(
            user_id=str(user.user_id), origin_server=remote_domain or "remote"
        )
        updated_actor = self.database_handler.upsert_activitypub_actor(
            actor_uri=remote_actor.actor_uri,
            preferred_username=remote_actor.preferred_username,
            inbox_uri=remote_actor.inbox_uri,
            outbox_uri=remote_actor.outbox_uri,
            shared_inbox_uri=remote_actor.shared_inbox_uri,
            public_key_pem=remote_actor.public_key_pem,
            is_local=False,
            user_id=str(user.user_id),
        )
        return str(updated_actor.user_id)

    async def _resolve_peer(self, peer: str, base_url: str) -> ActivityPubPeer:
        """
        Resolve a peer as local user, remote handle, or actor URI.
        """
        normalized_peer = peer.strip()

        # Local user_id
        try:
            uuid.UUID(normalized_peer)
            user = self.database_handler.get_user(user_id=normalized_peer)
            if user is not None:
                actor = self.ensure_local_actor(user_id=str(user.user_id), base_url=base_url)
                return ActivityPubPeer(
                    actor_uri=actor.actor_uri,
                    preferred_username=actor.preferred_username,
                    is_local=True,
                    user_id=str(user.user_id),
                    inbox_uri=actor.inbox_uri,
                    outbox_uri=actor.outbox_uri,
                    shared_inbox_uri=actor.shared_inbox_uri,
                )
        except Exception:
            pass

        # Local username
        local_actor = self.ensure_local_actor_by_username(username=normalized_peer, base_url=base_url)
        if local_actor is not None:
            return ActivityPubPeer(
                actor_uri=local_actor.actor_uri,
                preferred_username=local_actor.preferred_username,
                is_local=True,
                user_id=str(local_actor.user_id),
                inbox_uri=local_actor.inbox_uri,
                outbox_uri=local_actor.outbox_uri,
                shared_inbox_uri=local_actor.shared_inbox_uri,
            )

        # Actor URI
        if normalized_peer.startswith("http://") or normalized_peer.startswith("https://"):
            remote_actor = await self.fetch_remote_actor(actor_uri=normalized_peer)
            return ActivityPubPeer(
                actor_uri=remote_actor.actor_uri,
                preferred_username=remote_actor.preferred_username,
                is_local=False,
                user_id=str(remote_actor.user_id) if remote_actor.user_id else None,
                inbox_uri=remote_actor.inbox_uri,
                outbox_uri=remote_actor.outbox_uri,
                shared_inbox_uri=remote_actor.shared_inbox_uri,
            )

        # Handle user@domain
        actor_uri = await self.resolve_actor_uri_from_handle(normalized_peer)
        remote_actor = await self.fetch_remote_actor(actor_uri=actor_uri)
        return ActivityPubPeer(
            actor_uri=remote_actor.actor_uri,
            preferred_username=remote_actor.preferred_username,
            is_local=False,
            user_id=str(remote_actor.user_id) if remote_actor.user_id else None,
            inbox_uri=remote_actor.inbox_uri,
            outbox_uri=remote_actor.outbox_uri,
            shared_inbox_uri=remote_actor.shared_inbox_uri,
        )

    async def send_follow(self, local_user_id: str, remote_handle: str, base_url: str) -> dict:
        """
        Send ActivityPub Follow from a local user to a remote actor.
        """
        local_actor = self.ensure_local_actor(user_id=local_user_id, base_url=base_url)
        remote_peer = await self._resolve_peer(peer=remote_handle, base_url=base_url)
        if remote_peer.is_local:
            raise ValueError("Follow target must be remote for federation follow flow")

        activity_uri = f"{base_url}/ap/activities/{uuid.uuid4()}"
        activity = {
            "@context": self.ACTIVITYSTREAMS_CONTEXT,
            "id": activity_uri,
            "type": "Follow",
            "actor": local_actor.actor_uri,
            "object": remote_peer.actor_uri,
        }

        self.database_handler.create_or_update_activitypub_follow(
            local_actor_uri=local_actor.actor_uri,
            remote_actor_uri=remote_peer.actor_uri,
            follow_activity_uri=activity_uri,
            accepted=False,
        )
        self.database_handler.store_activitypub_outbox_activity(
            activity_uri=activity_uri,
            activity_type="Follow",
            actor_uri=local_actor.actor_uri,
            payload_json=json.dumps(activity),
            object_uri=remote_peer.actor_uri,
        )

        delivery_target = remote_peer.shared_inbox_uri or remote_peer.inbox_uri
        await self._http_post_json(url=delivery_target, payload=activity)
        return {
            "activity_id": activity_uri,
            "target_actor": remote_peer.actor_uri,
            "delivery_target": delivery_target,
        }

    async def send_direct_message(
        self,
        local_user_id: str,
        peer: str,
        message: str,
        base_url: str,
        sent_at: str | None = None,
        attachments: list[str] | None = None,
    ) -> dict:
        """
        Send a direct message to local or remote peer. Remote delivery uses ActivityPub Create(Note).
        """
        if not message.strip():
            raise ValueError("Direct message body cannot be empty")

        local_actor = self.ensure_local_actor(user_id=local_user_id, base_url=base_url)
        peer_info = await self._resolve_peer(peer=peer, base_url=base_url)
        conversation_id = self._conversation_id(local_actor.actor_uri, peer_info.actor_uri)

        # Persist local copy
        local_message = self.messages_manager.send_direct_message(
            user_id=local_user_id,
            conversation_id=conversation_id,
            message=message,
            attachments=attachments or [],
            sent_at=sent_at,
        )

        if peer_info.is_local and peer_info.user_id:
            await self.websockets_manager.broadcast_to_user(
                user_id=peer_info.user_id,
                message={
                    "type": "message",
                    "conversation_id": conversation_id,
                    "message_id": str(local_message.message_id),
                    "sender_user_id": str(local_user_id),
                    "message": message,
                    "sent_at": (
                        local_message.sent_at.isoformat() if local_message.sent_at else None
                    ),
                    "attachments": attachments or [],
                    "federated": False,
                },
            )
            return {
                "conversation_id": conversation_id,
                "message_id": str(local_message.message_id),
                "delivered_local": True,
                "delivered_remote": False,
            }

        # Remote ActivityPub DM delivery
        published_at = (
            sent_at
            if sent_at
            else datetime.datetime.now(datetime.timezone.utc).isoformat()
        )
        object_uri = f"{base_url}/ap/objects/{uuid.uuid4()}"
        note_object = {
            "id": object_uri,
            "type": "Note",
            "attributedTo": local_actor.actor_uri,
            "to": [peer_info.actor_uri],
            "published": published_at,
            "content": message,
            "conversation": conversation_id,
            "attachment": [{"type": "Link", "href": item} for item in (attachments or [])],
            "sensitive": False,
            "pufferblow:visibility": "direct",
            "pufferblow:kind": "dm",
        }
        activity_uri = f"{base_url}/ap/activities/{uuid.uuid4()}"
        activity = {
            "@context": [self.ACTIVITYSTREAMS_CONTEXT, {"pufferblow": f"{base_url}/ns#"}],
            "id": activity_uri,
            "type": "Create",
            "actor": local_actor.actor_uri,
            "to": [peer_info.actor_uri],
            "object": note_object,
        }

        self.database_handler.store_activitypub_outbox_activity(
            activity_uri=activity_uri,
            activity_type="Create",
            actor_uri=local_actor.actor_uri,
            payload_json=json.dumps(activity),
            object_uri=object_uri,
        )
        delivery_target = peer_info.shared_inbox_uri or peer_info.inbox_uri
        await self._http_post_json(url=delivery_target, payload=activity)
        return {
            "conversation_id": conversation_id,
            "message_id": str(local_message.message_id),
            "activity_id": activity_uri,
            "delivered_local": False,
            "delivered_remote": True,
            "delivery_target": delivery_target,
        }

    async def process_inbox_activity(
        self, activity: dict, base_url: str, target_actor_uri: str | None = None
    ) -> dict:
        """
        Process incoming ActivityPub activity.
        """
        activity_type = str(activity.get("type", "")).strip()
        actor_uri = str(activity.get("actor", "")).strip()
        if not activity_type or not actor_uri:
            raise ValueError("Incoming activity must include 'type' and 'actor'")

        activity_uri = str(activity.get("id") or f"urn:uuid:{uuid.uuid4()}")
        self.database_handler.store_activitypub_inbox_activity(
            activity_uri=activity_uri,
            activity_type=activity_type,
            actor_uri=actor_uri,
            payload_json=json.dumps(activity),
            target_actor_uri=target_actor_uri,
        )

        if activity_type == "Follow":
            return await self._handle_follow(activity=activity, base_url=base_url, target_actor_uri=target_actor_uri)

        if activity_type == "Accept":
            return self._handle_accept(activity=activity)

        if activity_type == "Create":
            return await self._handle_create(activity=activity, base_url=base_url)

        return {"processed": True, "activity_type": activity_type, "action": "stored_only"}

    async def _handle_follow(self, activity: dict, base_url: str, target_actor_uri: str | None) -> dict:
        """Handle follow."""
        remote_actor_uri = str(activity.get("actor"))
        object_actor_uri = str(activity.get("object") or target_actor_uri or "").strip()
        if not object_actor_uri:
            raise ValueError("Follow activity missing local target actor")

        local_actor = self.database_handler.get_activitypub_actor_by_uri(object_actor_uri)
        if local_actor is None:
            raise ValueError("Target actor not found on this instance")

        remote_actor = await self.fetch_remote_actor(actor_uri=remote_actor_uri)
        self.database_handler.create_or_update_activitypub_follow(
            local_actor_uri=local_actor.actor_uri,
            remote_actor_uri=remote_actor.actor_uri,
            follow_activity_uri=str(activity.get("id") or ""),
            accepted=True,
        )

        accept_id = f"{base_url}/ap/activities/{uuid.uuid4()}"
        accept_activity = {
            "@context": self.ACTIVITYSTREAMS_CONTEXT,
            "id": accept_id,
            "type": "Accept",
            "actor": local_actor.actor_uri,
            "object": activity,
        }
        self.database_handler.store_activitypub_outbox_activity(
            activity_uri=accept_id,
            activity_type="Accept",
            actor_uri=local_actor.actor_uri,
            payload_json=json.dumps(accept_activity),
            object_uri=str(activity.get("id") or ""),
        )
        await self._http_post_json(
            url=remote_actor.shared_inbox_uri or remote_actor.inbox_uri,
            payload=accept_activity,
        )
        return {"processed": True, "activity_type": "Follow", "action": "accepted"}

    def _handle_accept(self, activity: dict) -> dict:
        """Handle accept."""
        actor_uri = str(activity.get("actor", ""))
        obj = activity.get("object", {})
        if not isinstance(obj, dict):
            return {"processed": True, "activity_type": "Accept", "action": "stored_only"}

        follow_object_uri = str(obj.get("object", ""))
        follower_uri = str(obj.get("actor", ""))
        if follow_object_uri and follower_uri:
            self.database_handler.accept_activitypub_follow(
                local_actor_uri=follower_uri,
                remote_actor_uri=actor_uri,
            )
        return {"processed": True, "activity_type": "Accept", "action": "follow_marked_accepted"}

    async def _handle_create(self, activity: dict, base_url: str) -> dict:
        """Handle create."""
        obj = activity.get("object", {})
        if not isinstance(obj, dict):
            return {"processed": True, "activity_type": "Create", "action": "stored_only"}

        if str(obj.get("type", "")) != "Note":
            return {"processed": True, "activity_type": "Create", "action": "non_note_ignored"}

        remote_actor_uri = str(activity.get("actor"))
        remote_actor = await self.fetch_remote_actor(actor_uri=remote_actor_uri)
        sender_user_id = self._ensure_remote_shadow_user(remote_actor=remote_actor)

        recipients = []
        for key in ("to", "cc"):
            value = obj.get(key) or activity.get(key) or []
            if isinstance(value, str):
                recipients.append(value)
            elif isinstance(value, list):
                recipients.extend([str(item) for item in value])

        local_targets = []
        for uri in recipients:
            actor = self.database_handler.get_activitypub_actor_by_uri(actor_uri=uri)
            if actor is not None and actor.is_local and actor.user_id:
                local_targets.append(actor)

        if not local_targets:
            return {"processed": True, "activity_type": "Create", "action": "no_local_recipient"}

        text_message = self._clean_html_to_text(str(obj.get("content", "")))
        raw_attachments = obj.get("attachment", []) or []
        attachments: list[str] = []
        for item in raw_attachments:
            if isinstance(item, str):
                attachments.append(item)
            elif isinstance(item, dict) and item.get("href"):
                attachments.append(str(item["href"]))
            elif isinstance(item, dict) and item.get("url"):
                attachments.append(str(item["url"]))

        delivered = 0
        for target in local_targets:
            conversation_id = obj.get("conversation") or self._conversation_id(
                remote_actor.actor_uri, target.actor_uri
            )
            message_obj = self.messages_manager.send_direct_message(
                user_id=sender_user_id,
                conversation_id=str(conversation_id),
                message=text_message,
                attachments=attachments,
                sent_at=str(obj.get("published") or ""),
            )
            await self.websockets_manager.broadcast_to_user(
                user_id=str(target.user_id),
                message={
                    "type": "message",
                    "conversation_id": str(conversation_id),
                    "message_id": str(message_obj.message_id),
                    "sender_user_id": str(sender_user_id),
                    "message": text_message,
                    "sent_at": message_obj.sent_at.isoformat() if message_obj.sent_at else None,
                    "attachments": attachments,
                    "federated": True,
                    "remote_actor_uri": remote_actor.actor_uri,
                },
            )
            delivered += 1

        return {
            "processed": True,
            "activity_type": "Create",
            "action": "dm_delivered",
            "delivered_count": delivered,
        }

    async def load_direct_messages(
        self,
        viewer_user_id: str,
        peer: str,
        base_url: str,
        page: int,
        messages_per_page: int,
    ) -> dict:
        """
        Resolve peer and load conversation messages.
        """
        viewer_actor = self.ensure_local_actor(user_id=viewer_user_id, base_url=base_url)
        peer_actor = await self._resolve_peer(peer=peer, base_url=base_url)
        conversation_id = self._conversation_id(viewer_actor.actor_uri, peer_actor.actor_uri)
        messages = self.messages_manager.load_direct_messages(
            conversation_id=conversation_id,
            messages_per_page=messages_per_page,
            page=page,
        )
        return {
            "conversation_id": conversation_id,
            "peer_actor_uri": peer_actor.actor_uri,
            "messages": messages,
        }
