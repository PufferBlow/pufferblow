from __future__ import annotations

import asyncio
import datetime
import hashlib
import json
import secrets
import time
import uuid
from dataclasses import dataclass
from urllib.parse import quote

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from loguru import logger

# Outbound POST retry policy. Network errors and 5xx responses are retried up
# to OUTBOUND_POST_MAX_ATTEMPTS times with exponential backoff
# (OUTBOUND_POST_BACKOFF_BASE_SECONDS * 2**i). 4xx responses are surfaced
# immediately because they signal protocol errors, not transient flakes.
OUTBOUND_POST_MAX_ATTEMPTS = 3
OUTBOUND_POST_BACKOFF_BASE_SECONDS = 1.0

from pufferblow.api.database.database_handler import DatabaseHandler
from pufferblow.api.federation.nodeinfo import fetch_peer_info
from pufferblow.api.federation.peers import FederationRefused, PeerPolicy, host_of
from pufferblow.api.messages.messages_manager import MessagesManager
from pufferblow.core.constants import VERSION

# Identifies this software to remote ActivityPub peers. The version
# tail tracks the canonical `VERSION` constant so a User-Agent grep on
# a federated peer's logs matches the release tag of this server.
_ACTIVITYPUB_USER_AGENT = f"PufferBlow-ActivityPub/{VERSION}"
from pufferblow.api.user.user_manager import UserManager
from pufferblow.api.websocket.websocket_manager import WebSocketsManager

# Avoid circular import — PingManager is resolved at runtime via TYPE_CHECKING
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from pufferblow.api.ping.ping_manager import PingManager


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


def call_preview(call: dict) -> str:
    """What the conversation list shows for a call's line: the same for both people, in a few words."""
    outcome = call.get("outcome")
    if outcome == "completed":
        seconds = int(call.get("duration_seconds") or 0)
        minutes, rest = divmod(seconds, 60)
        hours, minutes = divmod(minutes, 60)
        length = f"{hours} hr {minutes} min" if hours else f"{minutes} min" if minutes else f"{rest} sec"
        return f"Voice call · {length}"
    if outcome == "declined":
        return "Call declined"
    return "Missed call"


def _attachment_url(item) -> str | None:
    """Coerce an attachment item to its URL string.

    DM attachments live in the database as a JSON list that may hold
    either bare URL strings (the legacy / federation-inbound shape)
    or typed dicts with ``url`` + metadata (the new shape produced
    by the client's file picker). Federation outbound consumes URLs
    only, so the local format normaliser strips the metadata
    before serialisation.
    """
    if isinstance(item, str):
        s = item.strip()
        return s or None
    if isinstance(item, dict):
        url = item.get("url")
        if isinstance(url, str) and url.strip():
            return url.strip()
    return None


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
        # Injected after bootstrap to avoid circular construction
        self.ping_manager: "PingManager | None" = None
        # Who may federate with this instance (mode, blocked and pending hosts, per-peer switches).
        self._background_tasks: set[asyncio.Task] = set()
        self.peer_policy = PeerPolicy(database_handler, is_local=lambda host: self._is_local_host(host), on_new_peer=self._learn_peer)

    def _learn_peer(self, host: str) -> None:
        """Ask a host we have just met what it is (software, version, users), in the background.

        Without a running event loop (a test, a script) there is nothing to schedule and the admin can still
        use "Check now".
        """
        try:
            task = asyncio.get_running_loop().create_task(self._fetch_peer_info(host))
        except RuntimeError:
            return
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    async def _fetch_peer_info(self, host: str) -> None:
        try:
            info = await fetch_peer_info(host)
            if info is not None:
                self.database_handler.set_peer_info(host, software=info["software"], version=info["version"], users=info["users"])
        except Exception as exc:  # an unreachable or unsafe host just stays unlabelled
            logger.debug("No nodeinfo for {host}: {error}", host=host, error=exc)

    def _is_local_host(self, host: str) -> bool:
        """Whether ``host`` is this instance itself (which is never policed)."""
        try:
            return self._is_local_origin(host)
        except Exception:
            return False

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
            "followers": f"{actor.actor_uri}/followers",
            "following": f"{actor.actor_uri}/following",
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
            "User-Agent": _ACTIVITYPUB_USER_AGENT,
        }
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            return response.json()

    async def _http_post_json(
        self, url: str, payload: dict, timeout: float = 10.0, signing_actor: object | None = None
    ) -> None:
        """Deliver an activity to another instance, if this instance federates with it.

        Refuses (``FederationRefused``) a blocked, unapproved or closed-off host before anything is sent,
        and notes how the delivery went (and how long it took) against the peer.
        """
        host = host_of(url)
        decision = self.peer_policy.decide_outbound(host)
        if not decision.allowed:
            raise FederationRefused(host, decision.reason)
        started = time.perf_counter()
        try:
            await self._post_json_with_retries(url, payload, timeout=timeout, signing_actor=signing_actor)
        except Exception:
            self.peer_policy.record_delivery(host, False)
            raise
        self.peer_policy.record_delivery(host, True, round((time.perf_counter() - started) * 1000))

    async def _post_json_with_retries(
        self, url: str, payload: dict, timeout: float = 10.0, signing_actor: object | None = None
    ) -> None:
        """POST an ActivityPub payload with retry-on-transient-failure.

        Retries up to :data:`OUTBOUND_POST_MAX_ATTEMPTS` times on network
        errors and 5xx responses with exponential backoff. 4xx responses are
        re-raised immediately (the remote is rejecting us at the protocol
        layer; retrying won't help). The final exception is re-raised so
        callers can decide whether to surface to the user, persist for a
        background retry, or just log.

        ``signing_actor`` is the local actor row sending this activity (it
        has ``actor_uri`` + ``private_key_pem``). When given, the request is
        signed per HTTP Signatures — most real-world ActivityPub peers
        (Mastodon/Misskey/Pleroma) reject or heavily distrust unsigned
        deliveries, so every real send passes this.
        """
        headers = {
            "Content-Type": "application/activity+json",
            "Accept": "application/activity+json, application/json",
            "User-Agent": _ACTIVITYPUB_USER_AGENT,
        }
        body = json.dumps(payload)
        if signing_actor is not None and getattr(signing_actor, "private_key_pem", None):
            from pufferblow.api.activitypub.http_signatures import key_id_for_actor, sign_request

            headers.update(
                sign_request(
                    method="POST",
                    url=url,
                    body=body.encode("utf-8"),
                    private_key_pem=signing_actor.private_key_pem,
                    key_id=key_id_for_actor(signing_actor.actor_uri),
                )
            )
        last_error: Exception | None = None

        for attempt in range(1, OUTBOUND_POST_MAX_ATTEMPTS + 1):
            try:
                async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                    response = await client.post(url, headers=headers, content=body)
                # 4xx: client/protocol error — don't retry.
                if 400 <= response.status_code < 500:
                    response.raise_for_status()
                    return
                response.raise_for_status()
                return
            except httpx.HTTPStatusError as exc:
                status = exc.response.status_code if exc.response is not None else 0
                # Don't retry 4xx; bail out so the caller sees the real status.
                if 400 <= status < 500:
                    logger.warning(
                        "ActivityPub POST rejected with {status} (no retry): "
                        "url={url}",
                        status=status,
                        url=url,
                    )
                    raise
                last_error = exc
            except (httpx.RequestError, asyncio.TimeoutError) as exc:
                last_error = exc

            if attempt < OUTBOUND_POST_MAX_ATTEMPTS:
                delay = OUTBOUND_POST_BACKOFF_BASE_SECONDS * (2 ** (attempt - 1))
                logger.warning(
                    "ActivityPub POST attempt {attempt}/{max_attempts} failed "
                    "({error}); retrying in {delay:.1f}s. url={url}",
                    attempt=attempt,
                    max_attempts=OUTBOUND_POST_MAX_ATTEMPTS,
                    error=last_error,
                    delay=delay,
                    url=url,
                )
                await asyncio.sleep(delay)

        # Exhausted retries — surface the last failure so the caller's
        # exception handler can record it.
        logger.error(
            "ActivityPub POST failed after {max_attempts} attempts: url={url} "
            "error={error}",
            max_attempts=OUTBOUND_POST_MAX_ATTEMPTS,
            url=url,
            error=last_error,
        )
        assert last_error is not None
        raise last_error

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

    async def resolve_user_id_for_handle(
        self,
        *,
        username: str,
        origin_server: str | None,
        base_url: str,
    ) -> str | None:
        """Resolve `(username, origin_server)` to a local-DB `user_id`.

        Used by the friend-request flow when the user adds a friend
        by handle (e.g. typing `alice` + "This instance" in the
        Add Friend modal, or `alice` + `mastodon.example` for a
        federated friend).

        Behaviour:
          * Local (`origin_server` is empty / None / matches THIS
            instance's host) → straight `users.username` lookup. The
            global UNIQUE constraint on `username` guarantees at
            most one hit.
          * Remote → WebFinger → `fetch_remote_actor` →
            `_ensure_remote_shadow_user`, returning the shadow row's
            `user_id` so the friend-graph row can reference it the
            same way it would a local one. This is the only path
            that triggers shadow creation outside of an inbound
            Create(Note); we want it here because adding a friend
            shouldn't require the remote user to message you first.

        Returns `None` when the local lookup misses or when the
        WebFinger lookup fails — the route layer translates that
        into a 404 for the client.
        """
        normalized_username = (username or "").strip()
        if not normalized_username:
            return None

        if self._is_local_origin(origin_server):
            user = self.database_handler.get_user(username=normalized_username)
            return str(user.user_id) if user is not None else None

        # Remote — let WebFinger resolve actor URI, fetch it, and
        # create / reuse the shadow user row.
        handle = f"{normalized_username}@{(origin_server or '').strip()}"
        try:
            actor_uri = await self.resolve_actor_uri_from_handle(handle)
            remote_actor = await self.fetch_remote_actor(actor_uri=actor_uri)
        except Exception as exc:
            logger.warning(
                "Friend handle resolution failed: handle={h} err={e}",
                h=handle, e=str(exc),
            )
            return None
        return self._ensure_remote_shadow_user(remote_actor=remote_actor)

    def _is_local_origin(self, origin_server: str | None) -> bool:
        """True iff `origin_server` is empty / None / equals this host.

        The empty / None case is the natural shape when the client
        ticks "This instance" in the Add Friend modal. The
        host-comparison case is defensive — a federated client that
        explicitly passes our own host should still resolve locally
        instead of round-tripping through WebFinger.
        """
        if not origin_server:
            return True
        normalized = origin_server.strip().lower().rstrip("/")
        if not normalized:
            return True
        try:
            base = self._base_url().rstrip("/")
        except Exception:
            return False
        # `base` is `http(s)://host[:port]` — strip the scheme so the
        # comparison ignores the wire scheme the operator picked.
        for scheme in ("https://", "http://"):
            if base.startswith(scheme):
                base = base[len(scheme):]
                break
        return normalized == base.lower()

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
            direction="outgoing",
        )
        self.database_handler.store_activitypub_outbox_activity(
            activity_uri=activity_uri,
            activity_type="Follow",
            actor_uri=local_actor.actor_uri,
            payload_json=json.dumps(activity),
            object_uri=remote_peer.actor_uri,
        )

        delivery_target = remote_peer.shared_inbox_uri or remote_peer.inbox_uri
        await self._http_post_json(url=delivery_target, payload=activity, signing_actor=local_actor)
        return {
            "activity_id": activity_uri,
            "target_actor": remote_peer.actor_uri,
            "delivery_target": delivery_target,
        }

    def _local_message_from_object_uri(self, object_uri: str, base_url: str):
        """Reverse `_object_uri_for_message`'s local-object branch.

        Only matches our own deterministic `{base_url}/ap/objects/{id}`
        scheme — i.e. a remote peer referencing something WE sent them
        (they're replying to / reacting to our message). Returns None for
        anything else, including the remote's own object ids (those are
        looked up via `get_message_by_remote_object_uri` instead, which
        this does not duplicate).
        """
        prefix = f"{base_url}/ap/objects/"
        if not object_uri.startswith(prefix):
            return None
        candidate_id = object_uri[len(prefix):]
        if not candidate_id:
            return None
        return self.database_handler.get_message_by_id(message_id=candidate_id)

    def _object_uri_for_message(self, row, base_url: str) -> str:
        """The ActivityPub object id a message is addressable as.

        `remote_object_uri` wins when set (the message arrived from a
        remote peer under THEIR id); otherwise falls back to our own
        deterministic `{base_url}/ap/objects/{message_id}` scheme (used for
        anything we authored).
        """
        return row.remote_object_uri or f"{base_url}/ap/objects/{row.message_id}"

    async def send_direct_message(
        self,
        local_user_id: str,
        peer: str,
        message: str,
        base_url: str,
        sent_at: str | None = None,
        attachments: list[str] | None = None,
        reply_to_message_id: str | None = None,
        forwarded_from_message_id: str | None = None,
    ) -> dict:
        """
        Send a direct message to local or remote peer. Remote delivery uses ActivityPub Create(Note).

        `reply_to_message_id`/`forwarded_from_message_id` are stored locally
        either way. Federated as the Note's `inReplyTo` when the reply target
        resolves to an addressable object id (see `_object_uri_for_message`)
        — always true for a reply to anything previously sent or received
        through this same mechanism, so in practice this just works.
        """
        # Allow attachment-only / sticker-only DMs: the route layer
        # already enforces "at least one of body OR attachments OR
        # sticker_ids must be present" before reaching here. Blocking
        # empty bodies here too would reject legitimate
        # attachment-only sends (the file/sticker IS the message,
        # body is just an a11y hint). The check below also strips
        # noise from the attachments list — entries with no URL
        # don't count as a real attachment.
        has_real_attachment = any(
            _attachment_url(item) for item in (attachments or [])
        )
        if (
            (not isinstance(message, str) or not message.strip())
            and not has_real_attachment
        ):
            raise ValueError(
                "Direct message must include a body or at least one attachment"
            )

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
            reply_to_message_id=reply_to_message_id,
            forwarded_from_message_id=forwarded_from_message_id,
        )
        # Both people are on record from the first message, so the sender's own conversation list
        # shows it before the other person has replied.
        self.database_handler.record_dm_members(conversation_id, [str(local_user_id), peer_info.user_id])

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
                    "reply_to_message_id": reply_to_message_id,
                    "reply_to": self.messages_manager.reply_preview(reply_to_message_id) if reply_to_message_id else None,
                    "forwarded_from_message_id": forwarded_from_message_id,
                    "federated": False,
                    **self._sender_fields(local_user_id),
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
        # Deterministic from message_id (not a random uuid) so a later edit
        # or delete can federate an Update/Delete against the SAME object
        # without needing a message_id -> object_uri lookup table.
        object_uri = f"{base_url}/ap/objects/{local_message.message_id}"
        note_object = {
            "id": object_uri,
            "type": "Note",
            "attributedTo": local_actor.actor_uri,
            "to": [peer_info.actor_uri],
            "published": published_at,
            "content": message,
            "conversation": conversation_id,
            # Federation outbound: ActivityPub Notes carry attachments
            # as `{type: Link, href: <url>}`. The internal attachments
            # list may be either bare URL strings (legacy) or typed
            # dicts with metadata; extract just the URL for the
            # remote peer (they can re-derive MIME from the URL on
            # their end, and we'd be leaking sticker_id / lqip_url
            # extras that don't belong on the wire).
            "attachment": [
                {"type": "Link", "href": _attachment_url(item)}
                for item in (attachments or [])
                if _attachment_url(item)
            ],
            "sensitive": False,
            "pufferblow:visibility": "direct",
            "pufferblow:kind": "dm",
        }
        if reply_to_message_id:
            parent_row = self.database_handler.get_message_by_id(message_id=reply_to_message_id)
            if parent_row is not None:
                note_object["inReplyTo"] = self._object_uri_for_message(parent_row, base_url)
        if forwarded_from_message_id:
            source_row = self.database_handler.get_message_by_id(message_id=forwarded_from_message_id)
            if source_row is not None:
                note_object["pufferblow:forwardedFrom"] = self._object_uri_for_message(source_row, base_url)
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
        await self._http_post_json(url=delivery_target, payload=activity, signing_actor=local_actor)
        return {
            "conversation_id": conversation_id,
            "message_id": str(local_message.message_id),
            "activity_id": activity_uri,
            "delivered_local": False,
            "delivered_remote": True,
            "delivery_target": delivery_target,
        }

    async def _resolve_dm_peer_actor(
        self, *, conversation_id: str, viewer_user_id: str, base_url: str
    ) -> "ActivityPubPeer | None":
        """Resolve the other participant in a DM conversation.

        Same approach `list_dm_conversations` already uses. Returns `None`
        for an outgoing-only conversation (no reply yet) — same known
        limitation noted there: recovering the peer without a
        conversation_members table isn't possible when the viewer is the
        only sender so far.
        """
        peer_user_id = self.database_handler.get_conversation_other_sender(
            conversation_id=conversation_id, viewer_user_id=viewer_user_id
        )
        if peer_user_id is None:
            return None

        peer_actor_row = self.database_handler.get_activitypub_actor_by_user_id(user_id=peer_user_id)
        if peer_actor_row is not None:
            return ActivityPubPeer(
                actor_uri=peer_actor_row.actor_uri,
                preferred_username=peer_actor_row.preferred_username,
                is_local=peer_actor_row.is_local,
                user_id=peer_user_id,
                inbox_uri=peer_actor_row.inbox_uri,
                outbox_uri=peer_actor_row.outbox_uri,
                shared_inbox_uri=peer_actor_row.shared_inbox_uri,
            )
        local_peer_actor = self.ensure_local_actor(user_id=peer_user_id, base_url=base_url)
        return ActivityPubPeer(
            actor_uri=local_peer_actor.actor_uri,
            preferred_username=local_peer_actor.preferred_username,
            is_local=True,
            user_id=peer_user_id,
            inbox_uri=local_peer_actor.inbox_uri,
            outbox_uri=local_peer_actor.outbox_uri,
            shared_inbox_uri=local_peer_actor.shared_inbox_uri,
        )

    async def send_update(
        self, local_user_id: str, message_id: str, new_content: str, base_url: str
    ) -> dict | None:
        """Federate a DM edit as an ActivityPub Update(Note).

        Returns `None` (nothing to federate) when the message isn't a DM,
        the peer is local, or the peer can't be resolved (see
        `_resolve_dm_peer_actor`) — the edit itself already happened via the
        existing local edit path before this is called; this only handles
        telling a remote peer about it.
        """
        message_row = self.database_handler.get_message_by_id(message_id=message_id)
        if message_row is None or not message_row.conversation_id:
            return None

        local_actor = self.ensure_local_actor(user_id=local_user_id, base_url=base_url)
        peer = await self._resolve_dm_peer_actor(
            conversation_id=message_row.conversation_id, viewer_user_id=local_user_id, base_url=base_url
        )
        if peer is None or peer.is_local:
            return None

        object_uri = f"{base_url}/ap/objects/{message_id}"
        activity_uri = f"{base_url}/ap/activities/{uuid.uuid4()}"
        activity = {
            "@context": self.ACTIVITYSTREAMS_CONTEXT,
            "id": activity_uri,
            "type": "Update",
            "actor": local_actor.actor_uri,
            "to": [peer.actor_uri],
            "object": {
                "id": object_uri,
                "type": "Note",
                "attributedTo": local_actor.actor_uri,
                "to": [peer.actor_uri],
                "content": new_content,
                "conversation": message_row.conversation_id,
            },
        }
        self.database_handler.store_activitypub_outbox_activity(
            activity_uri=activity_uri,
            activity_type="Update",
            actor_uri=local_actor.actor_uri,
            payload_json=json.dumps(activity),
            object_uri=object_uri,
        )
        delivery_target = peer.shared_inbox_uri or peer.inbox_uri
        await self._http_post_json(url=delivery_target, payload=activity, signing_actor=local_actor)
        return {"activity_id": activity_uri, "delivery_target": delivery_target}

    async def send_delete(self, local_user_id: str, message_id: str, base_url: str) -> dict | None:
        """Federate a DM deletion as an ActivityPub Delete.

        Same "nothing to federate" cases as `send_update`. Must be called
        BEFORE the local row is actually deleted — it needs the message's
        `conversation_id` to resolve the peer.
        """
        message_row = self.database_handler.get_message_by_id(message_id=message_id)
        if message_row is None or not message_row.conversation_id:
            return None

        local_actor = self.ensure_local_actor(user_id=local_user_id, base_url=base_url)
        peer = await self._resolve_dm_peer_actor(
            conversation_id=message_row.conversation_id, viewer_user_id=local_user_id, base_url=base_url
        )
        if peer is None or peer.is_local:
            return None

        object_uri = f"{base_url}/ap/objects/{message_id}"
        activity_uri = f"{base_url}/ap/activities/{uuid.uuid4()}"
        activity = {
            "@context": self.ACTIVITYSTREAMS_CONTEXT,
            "id": activity_uri,
            "type": "Delete",
            "actor": local_actor.actor_uri,
            "to": [peer.actor_uri],
            "object": object_uri,
        }
        self.database_handler.store_activitypub_outbox_activity(
            activity_uri=activity_uri,
            activity_type="Delete",
            actor_uri=local_actor.actor_uri,
            payload_json=json.dumps(activity),
            object_uri=object_uri,
        )
        delivery_target = peer.shared_inbox_uri or peer.inbox_uri
        await self._http_post_json(url=delivery_target, payload=activity, signing_actor=local_actor)
        return {"activity_id": activity_uri, "delivery_target": delivery_target}

    def _local_conversation_id(self, user_a: str, user_b: str) -> str | None:
        """The conversation two local people share, from their existing actors. None until both have one.

        Nothing is created here: this runs for people other than whoever's request happened to notice the call,
        so no address a request carried may decide where it goes. Both actors are made when the call starts
        (``prepare_dm_call``), the same way sending a direct message makes them.
        """
        actors = [self.database_handler.get_activitypub_actor_by_user_id(user_id=str(u)) for u in (user_a, user_b)]
        if not all(actors):
            return None
        return self._conversation_id(actors[0].actor_uri, actors[1].actor_uri)

    def prepare_dm_call(self, caller_id: str, callee_id: str, base_url: str) -> None:
        """Make sure both people of a call have an actor, so the call's line has a conversation to go into."""
        for user_id in (caller_id, callee_id):
            self.ensure_local_actor(user_id=str(user_id), base_url=base_url)

    async def log_dm_call(self, call: dict) -> None:
        """Keep a line in the conversation about a call that finished.

        It is an ordinary direct message from the caller with no text and one attachment of type ``call``
        (``outcome``: completed, missed, cancelled or declined; ``duration_seconds`` for a completed one), so it
        is stored, listed in history, searched past and delivered live like any other, and each client words it
        for whoever is reading. Best effort: the call is over either way, so a failure only costs the line.
        """
        try:
            caller, callee = str(call["caller_id"]), str(call["callee_id"])
            conversation_id = self._local_conversation_id(caller, callee)
            if conversation_id is None:
                return
            entry = {
                "url": f"call:{call['call_id']}",
                "type": "call",
                "call": {
                    "call_id": call["call_id"],
                    "caller_id": caller,
                    "callee_id": callee,
                    "caller_name": self._sender_fields(caller)["username"],
                    "callee_name": self._sender_fields(callee)["username"],
                    "outcome": call["outcome"],
                    "duration_seconds": int(call.get("duration_seconds") or 0),
                },
            }
            row = self.messages_manager.send_direct_message(user_id=caller, conversation_id=conversation_id, message="", attachments=[entry])
            self.database_handler.record_dm_members(conversation_id, [caller, callee])
            frame = {
                "type": "message",
                "conversation_id": conversation_id,
                "message_id": str(row.message_id),
                "sender_user_id": caller,
                "message": "",
                "sent_at": row.sent_at.isoformat() if row.sent_at else None,
                "attachments": [entry],
                "reply_to_message_id": None,
                "reply_to": None,
                "forwarded_from_message_id": None,
                "federated": False,
                **self._sender_fields(caller),
            }
            for user_id in (caller, callee):
                await self.websockets_manager.broadcast_to_user(user_id=user_id, message=frame)
        except Exception as exc:
            logger.warning(f"Could not record a DM call in its conversation: {exc}")

    def _sender_fields(self, user_id: str) -> dict:
        """Author name and avatar for a live DM frame, so a client can draw the row."""
        try:
            user = self.database_handler.get_user(user_id=str(user_id))
        except Exception:
            user = None
        return {
            "username": getattr(user, "username", None) or "Unknown User",
            "sender_avatar_url": getattr(user, "avatar_url", None),
        }

    def local_dm_peer(self, conversation_id: str, viewer_user_id: str) -> str | None:
        """The other participant of a DM, if ``viewer_user_id`` is in it and the peer is local.

        A conversation id is derived from both participants' actor URIs, so recomputing it
        proves the viewer belongs to the conversation without trusting the caller. Returns
        ``None`` for a conversation the viewer is not in, a remote peer, or one the peer has
        not answered yet (the peer is only known from their messages).
        """
        peer_user_id = self.database_handler.get_conversation_other_sender(
            conversation_id=conversation_id, viewer_user_id=viewer_user_id
        )
        if peer_user_id is None:
            return None
        viewer = self.database_handler.get_activitypub_actor_by_user_id(user_id=viewer_user_id)
        peer = self.database_handler.get_activitypub_actor_by_user_id(user_id=peer_user_id)
        if viewer is None or peer is None or not peer.is_local:
            return None
        if self._conversation_id(viewer.actor_uri, peer.actor_uri) != conversation_id:
            return None
        return str(peer_user_id)

    async def notify_local_dm_peer(
        self, local_user_id: str, message_id: str, payload: dict, base_url: str
    ) -> None:
        """Tell the other side of a DM about an edit or delete when they are on this
        instance (a remote peer hears through federation instead). Best effort: the
        change itself has already happened."""
        try:
            row = self.database_handler.get_message_by_id(message_id=message_id)
            if row is None or not row.conversation_id:
                return
            peer = await self._resolve_dm_peer_actor(
                conversation_id=row.conversation_id, viewer_user_id=local_user_id, base_url=base_url
            )
            if peer is None or not peer.is_local or not peer.user_id:
                return
            await self.websockets_manager.broadcast_to_user(
                user_id=peer.user_id,
                message={**payload, "conversation_id": row.conversation_id, "message_id": str(message_id)},
            )
        except Exception as exc:
            logger.warning(f"Local DM peer notification failed: {exc}")

    async def send_undo_follow(self, local_user_id: str, remote_handle: str, base_url: str) -> dict:
        """Unfollow: send Undo(Follow) and drop the local follow row.

        Mirrors `send_follow`'s peer resolution. Raises if there's no
        existing follow row for this pair — mirroring `send_follow`'s own
        "target must be remote" guard, there's nothing sensible to undo.
        """
        local_actor = self.ensure_local_actor(user_id=local_user_id, base_url=base_url)
        remote_peer = await self._resolve_peer(peer=remote_handle, base_url=base_url)
        if remote_peer.is_local:
            raise ValueError("Unfollow target must be remote for federation follow flow")

        existing = self.database_handler.get_activitypub_follow(
            local_actor_uri=local_actor.actor_uri, remote_actor_uri=remote_peer.actor_uri
        )
        if existing is None or existing.direction != "outgoing":
            raise ValueError("No outgoing follow found for this peer to undo")

        activity_uri = f"{base_url}/ap/activities/{uuid.uuid4()}"
        activity = {
            "@context": self.ACTIVITYSTREAMS_CONTEXT,
            "id": activity_uri,
            "type": "Undo",
            "actor": local_actor.actor_uri,
            "object": {
                "id": existing.follow_activity_uri,
                "type": "Follow",
                "actor": local_actor.actor_uri,
                "object": remote_peer.actor_uri,
            },
        }
        self.database_handler.store_activitypub_outbox_activity(
            activity_uri=activity_uri,
            activity_type="Undo",
            actor_uri=local_actor.actor_uri,
            payload_json=json.dumps(activity),
            object_uri=existing.follow_activity_uri,
        )
        self.database_handler.delete_activitypub_follow(
            local_actor_uri=local_actor.actor_uri, remote_actor_uri=remote_peer.actor_uri
        )
        delivery_target = remote_peer.shared_inbox_uri or remote_peer.inbox_uri
        await self._http_post_json(url=delivery_target, payload=activity, signing_actor=local_actor)
        return {"activity_id": activity_uri, "target_actor": remote_peer.actor_uri, "delivery_target": delivery_target}

    def user_can_access_dm_message(self, user_id: str, row, base_url: str) -> bool:
        """Is `user_id` one of the two participants in `row`'s conversation?

        The sender always qualifies. Otherwise recomputes the conversation
        id for (this user's actor, the row's sender's actor) and checks it
        matches — the same verification `list_dm_conversations` already
        does, which guards against a conversation_id collision or a random
        uninvolved user passing in someone else's conversation.
        """
        if not row.conversation_id:
            return False
        if str(row.sender_id) == str(user_id):
            return True

        my_actor = self.ensure_local_actor(user_id=user_id, base_url=base_url)
        sender_actor_row = self.database_handler.get_activitypub_actor_by_user_id(user_id=str(row.sender_id))
        sender_actor_uri = (
            sender_actor_row.actor_uri
            if sender_actor_row is not None
            else self._actor_uri_for_user(str(row.sender_id), base_url)
        )
        expected = self._conversation_id(my_actor.actor_uri, sender_actor_uri)
        return expected == row.conversation_id

    async def _federate_dm_reaction(self, *, row, local_user_id: str, emoji: str, added: bool, base_url: str) -> None:
        """Best-effort: tell the DM peer about a reaction add/remove.

        No-ops when the peer is local (nothing to federate) or the message
        isn't addressable via our own deterministic object id scheme — a
        reaction on a message the PEER authored can't be federated back to
        them this way (same `_local_message_from_object_uri` restriction
        `_handle_like` documents: we can only tell a remote about a
        reaction to something WE sent them).
        """
        object_uri = self._object_uri_for_message(row, base_url)
        if not object_uri.startswith(f"{base_url}/ap/objects/"):
            return  # the message was THEIRS; nothing to federate here

        local_actor = self.ensure_local_actor(user_id=local_user_id, base_url=base_url)
        peer = await self._resolve_dm_peer_actor(
            conversation_id=row.conversation_id, viewer_user_id=local_user_id, base_url=base_url
        )
        if peer is None or peer.is_local:
            return

        like_object = {"id": object_uri, "type": "Note"}
        if added:
            activity_uri = f"{base_url}/ap/activities/{uuid.uuid4()}"
            activity: dict = {
                "@context": self.ACTIVITYSTREAMS_CONTEXT,
                "id": activity_uri,
                "type": "Like",
                "actor": local_actor.actor_uri,
                "content": emoji,
                "object": like_object,
            }
            activity_type = "Like"
        else:
            activity_uri = f"{base_url}/ap/activities/{uuid.uuid4()}"
            activity = {
                "@context": self.ACTIVITYSTREAMS_CONTEXT,
                "id": activity_uri,
                "type": "Undo",
                "actor": local_actor.actor_uri,
                "object": {"type": "Like", "content": emoji, "object": like_object},
            }
            activity_type = "Undo"

        self.database_handler.store_activitypub_outbox_activity(
            activity_uri=activity_uri,
            activity_type=activity_type,
            actor_uri=local_actor.actor_uri,
            payload_json=json.dumps(activity),
            object_uri=object_uri,
        )
        await self._http_post_json(
            url=peer.shared_inbox_uri or peer.inbox_uri, payload=activity, signing_actor=local_actor
        )

    async def _notify_dm_reaction(
        self, *, row, local_user_id: str, emoji: str, added: bool, base_url: str, reactions: list[dict]
    ) -> None:
        """Tell the OTHER participant about a reaction add/remove.

        Local peer gets a WS broadcast (same shape family as the message
        broadcast in `send_direct_message`); remote peer gets Like/Undo(Like)
        federation via `_federate_dm_reaction`. Both are best-effort — a
        failure here never unwinds the reaction itself, which already
        committed.
        """
        peer = await self._resolve_dm_peer_actor(
            conversation_id=row.conversation_id, viewer_user_id=local_user_id, base_url=base_url
        )
        if peer is not None and peer.is_local and peer.user_id:
            try:
                await self.websockets_manager.broadcast_to_user(
                    user_id=peer.user_id,
                    message={
                        "type": "reaction",
                        "conversation_id": row.conversation_id,
                        "message_id": row.message_id,
                        "emoji": emoji,
                        "added": added,
                        "reactor_user_id": str(local_user_id),
                        "reactions": reactions,
                    },
                )
            except Exception as exc:
                logger.warning(f"DM reaction WS broadcast failed: {exc}")
            return
        try:
            await self._federate_dm_reaction(row=row, local_user_id=local_user_id, emoji=emoji, added=added, base_url=base_url)
        except Exception as exc:
            logger.warning(f"DM reaction federation failed: {exc}")

    async def add_dm_reaction(self, local_user_id: str, message_id: str, emoji: str, base_url: str) -> dict:
        """Add a reaction to a DM message, authorized by conversation membership."""
        row = self.database_handler.get_message_by_id(message_id=message_id)
        if row is None or not row.conversation_id:
            raise ValueError("Message not found or is not a direct message")
        if not self.user_can_access_dm_message(local_user_id, row, base_url):
            raise PermissionError("Not a participant in this conversation")

        changed = self.messages_manager.add_reaction(message_id=message_id, user_id=local_user_id, emoji=emoji)
        summary = self.messages_manager.get_reaction_summary(message_id=message_id, viewer_user_id=local_user_id)
        if changed:
            await self._notify_dm_reaction(
                row=row, local_user_id=local_user_id, emoji=emoji, added=True, base_url=base_url, reactions=summary
            )
        return {"changed": changed, "emoji": emoji, "reactions": summary}

    async def remove_dm_reaction(self, local_user_id: str, message_id: str, emoji: str, base_url: str) -> dict:
        """Remove a reaction from a DM message, authorized by conversation membership."""
        row = self.database_handler.get_message_by_id(message_id=message_id)
        if row is None or not row.conversation_id:
            raise ValueError("Message not found or is not a direct message")
        if not self.user_can_access_dm_message(local_user_id, row, base_url):
            raise PermissionError("Not a participant in this conversation")

        changed = self.messages_manager.remove_reaction(message_id=message_id, user_id=local_user_id, emoji=emoji)
        summary = self.messages_manager.get_reaction_summary(message_id=message_id, viewer_user_id=local_user_id)
        if changed:
            await self._notify_dm_reaction(
                row=row, local_user_id=local_user_id, emoji=emoji, added=False, base_url=base_url, reactions=summary
            )
        return {"changed": changed, "emoji": emoji, "reactions": summary}

    async def forward_message(self, local_user_id: str, source_message, peer: str, base_url: str) -> dict:
        """Forward an existing message (channel or DM) to a DM peer.

        Re-sends the source's decrypted content and attachments through
        `send_direct_message`, so forwarding a channel message into a DM or
        forwarding between two DMs both get full attachment/reply/federation
        handling for free. Caller is responsible for authorizing that
        `local_user_id` may read `source_message` (channel access or DM
        participation) BEFORE calling this — see the route for the actual
        check, kept there since it already has an `Authorizer` / `Principal`
        to check channel access with.
        """
        import base64

        plaintext = self.messages_manager.decrypt_message(
            user_id=str(source_message.sender_id),
            message_id=source_message.message_id,
            encrypted_message=base64.b64decode(source_message.hashed_message),
        )
        return await self.send_direct_message(
            local_user_id=local_user_id,
            peer=peer,
            message=plaintext,
            base_url=base_url,
            attachments=source_message.attachments or [],
            forwarded_from_message_id=source_message.message_id,
        )

    async def verify_inbox_signature(
        self, *, method: str, path: str, headers, raw_body: bytes, claimed_actor_uri: str
    ) -> None:
        """Verify an inbound activity's HTTP Signature, or raise `ValueError`.

        No-ops when `[activitypub] require_http_signatures` is turned off
        (the operator escape hatch for a misbehaving peer). Resolves the
        signer's public key via the existing `fetch_remote_actor` cache —
        the same lookup `_handle_follow`/`_handle_create` already do, so
        this adds no new network call on top of what inbound handling
        already does for a previously-unseen actor.

        Deliberately does not disclose *which* check failed — never to the
        remote caller, and the exception message here is for logs only.
        """
        from pufferblow.api.activitypub.http_signatures import (
            SignatureVerificationError,
            verify_request,
        )

        config = getattr(self.database_handler, "config", None)
        if config is not None and not getattr(config, "ACTIVITYPUB_REQUIRE_HTTP_SIGNATURES", True):
            return

        try:
            remote_actor = await self.fetch_remote_actor(actor_uri=claimed_actor_uri)
        except Exception as exc:
            raise ValueError(f"could not resolve signer actor: {exc}") from exc

        try:
            verify_request(
                method=method,
                path=path,
                headers=headers,
                body=raw_body,
                public_key_pem=remote_actor.public_key_pem,
            )
        except SignatureVerificationError as exc:
            raise ValueError(str(exc)) from exc

    async def process_inbox_activity(
        self, activity: dict, base_url: str, target_actor_uri: str | None = None
    ) -> dict:
        """
        Process incoming ActivityPub activity.

        Replay protection: if the inbox already contains a row for
        ``activity.id`` we short-circuit and return ``action='duplicate'``
        instead of re-running side effects. Activities arriving without an
        ``id`` get a synthetic uuid (which is by definition unique) so they
        fall through to the normal handlers exactly once.
        """
        activity_type = str(activity.get("type", "")).strip()
        actor_uri = str(activity.get("actor", "")).strip()
        if not activity_type or not actor_uri:
            raise ValueError("Incoming activity must include 'type' and 'actor'")

        # The instance decides who it federates with before anything is stored or acted on.
        decision = self.peer_policy.decide_inbound(host_of(actor_uri))
        if not decision.allowed:
            logger.info("Refused {activity_type} from {host}: {reason}", activity_type=activity_type, host=host_of(actor_uri), reason=decision.reason)
            raise FederationRefused(host_of(actor_uri), decision.reason)

        provided_activity_id = str(activity.get("id") or "").strip()
        if provided_activity_id and self.database_handler.is_activitypub_inbox_known(
            activity_uri=provided_activity_id
        ):
            logger.info(
                "Replay short-circuit: activity_uri={activity_uri} already "
                "processed (type={activity_type})",
                activity_uri=provided_activity_id,
                activity_type=activity_type,
            )
            return {
                "processed": True,
                "activity_type": activity_type,
                "action": "duplicate",
            }

        activity_uri = provided_activity_id or f"urn:uuid:{uuid.uuid4()}"
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

        if activity_type == "Ping":
            return await self._handle_ping(activity=activity, base_url=base_url, target_actor_uri=target_actor_uri)

        if activity_type == "PingAck":
            return await self._handle_ping_ack(activity=activity, base_url=base_url)

        if activity_type == "Undo":
            return self._handle_undo(activity=activity, base_url=base_url)

        if activity_type == "Delete":
            return self._handle_delete(activity=activity)

        if activity_type == "Update":
            return self._handle_update(activity=activity)

        if activity_type == "Reject":
            return self._handle_reject(activity=activity)

        if activity_type == "Like":
            return await self._handle_like(activity=activity, base_url=base_url)

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
            direction="incoming",
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
            signing_actor=local_actor,
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

    def _handle_undo(self, activity: dict, base_url: str) -> dict:
        """Handle Undo — `Undo(Follow)` (an unfollow) or `Undo(Like)` (un-react)."""
        obj = activity.get("object", {})
        if not isinstance(obj, dict):
            return {"processed": True, "activity_type": "Undo", "action": "stored_only"}
        inner_type = str(obj.get("type", ""))

        if inner_type == "Like":
            target_uri = str(obj.get("object", "")).strip()
            row = self._local_message_from_object_uri(target_uri, base_url) if target_uri else None
            if row is None:
                return {"processed": True, "activity_type": "Undo", "action": "message_not_found"}
            emoji = str(obj.get("content") or "\U0001F44D")
            remote_actor_uri = str(activity.get("actor", "")).strip()
            remote_actor_row = self.database_handler.get_activitypub_actor_by_uri(remote_actor_uri)
            reactor_user_id = str(remote_actor_row.user_id) if remote_actor_row and remote_actor_row.user_id else None
            if not reactor_user_id:
                return {"processed": True, "activity_type": "Undo", "action": "stored_only"}
            removed = self.messages_manager.remove_reaction(message_id=row.message_id, user_id=reactor_user_id, emoji=emoji)
            return {
                "processed": True,
                "activity_type": "Undo",
                "action": "reaction_removed" if removed else "reaction_not_found",
            }

        if inner_type != "Follow":
            return {"processed": True, "activity_type": "Undo", "action": "stored_only"}

        remote_actor_uri = str(activity.get("actor", "")).strip()
        local_actor_uri = str(obj.get("object", "")).strip()
        if not local_actor_uri or not remote_actor_uri:
            return {"processed": True, "activity_type": "Undo", "action": "stored_only"}

        removed = self.database_handler.delete_activitypub_follow(
            local_actor_uri=local_actor_uri, remote_actor_uri=remote_actor_uri
        )
        return {
            "processed": True,
            "activity_type": "Undo",
            "action": "follow_removed" if removed else "follow_not_found",
        }

    def _handle_reject(self, activity: dict) -> dict:
        """Handle Reject. Currently only `Reject(Follow)` — a remote peer
        declined a Follow we sent. Removes our outgoing follow row.
        Pufferblow still auto-accepts every inbound follow (no
        pending-approval UX yet), so there's nothing to reciprocate here.
        """
        obj = activity.get("object", {})
        if not isinstance(obj, dict) or str(obj.get("type", "")) != "Follow":
            return {"processed": True, "activity_type": "Reject", "action": "stored_only"}

        remote_actor_uri = str(activity.get("actor", "")).strip()  # who rejected us
        local_actor_uri = str(obj.get("actor", "")).strip()  # us, the original follower
        if not local_actor_uri or not remote_actor_uri:
            return {"processed": True, "activity_type": "Reject", "action": "stored_only"}

        removed = self.database_handler.delete_activitypub_follow(
            local_actor_uri=local_actor_uri, remote_actor_uri=remote_actor_uri
        )
        return {
            "processed": True,
            "activity_type": "Reject",
            "action": "follow_removed" if removed else "follow_not_found",
        }

    def _handle_delete(self, activity: dict) -> dict:
        """Handle Delete — resolves the target via `remote_object_uri`
        (persisted by `_handle_create` since the object-tracking fix) and
        actually removes the local row.
        """
        obj = activity.get("object")
        object_uri = str(obj.get("id") if isinstance(obj, dict) else obj or "").strip()
        if not object_uri:
            return {"processed": True, "activity_type": "Delete", "action": "stored_only"}

        row = self.database_handler.get_message_by_remote_object_uri(object_uri)
        if row is None:
            return {"processed": True, "activity_type": "Delete", "action": "message_not_found"}

        self.messages_manager.delete_message(message_id=row.message_id, channel_id=row.channel_id)
        return {"processed": True, "activity_type": "Delete", "action": "message_deleted"}

    def _handle_update(self, activity: dict) -> dict:
        """Handle Update(Note) — resolves via `remote_object_uri` and applies
        the new body to the local row, same mechanism as `_handle_delete`.
        """
        obj = activity.get("object", {})
        if not isinstance(obj, dict) or str(obj.get("type", "")) != "Note":
            return {"processed": True, "activity_type": "Update", "action": "stored_only"}

        object_uri = str(obj.get("id") or "").strip()
        if not object_uri:
            return {"processed": True, "activity_type": "Update", "action": "stored_only"}

        row = self.database_handler.get_message_by_remote_object_uri(object_uri)
        if row is None:
            return {"processed": True, "activity_type": "Update", "action": "message_not_found"}

        new_content = self._clean_html_to_text(str(obj.get("content", "")))
        try:
            self.messages_manager.edit_message(
                message_id=row.message_id, editor_user_id=str(row.sender_id), new_body=new_content
            )
        except (PermissionError, ValueError) as exc:
            logger.warning(f"Inbound Update could not be applied to {row.message_id}: {exc}")
            return {"processed": True, "activity_type": "Update", "action": "edit_rejected"}
        return {"processed": True, "activity_type": "Update", "action": "message_updated"}

    async def _handle_like(self, activity: dict, base_url: str) -> dict:
        """Handle Like — a remote peer reacting to a message of ours.

        The emoji rides in a non-standard `content` field (Pufferblow
        reactions are free-form strings, not the fixed `Like` semantic);
        absent that, defaults to a thumbs-up. Only resolves against our own
        deterministic object ids (`_local_message_from_object_uri`) — a
        remote can only React to something WE sent them, never to their own
        message via this path.
        """
        obj = activity.get("object")
        object_uri = str(obj.get("id") if isinstance(obj, dict) else obj or "").strip()
        if not object_uri:
            return {"processed": True, "activity_type": "Like", "action": "stored_only"}

        row = self._local_message_from_object_uri(object_uri, base_url)
        if row is None:
            return {"processed": True, "activity_type": "Like", "action": "message_not_found"}

        emoji = str((activity.get("content") if isinstance(activity, dict) else None) or "\U0001F44D")
        remote_actor_uri = str(activity.get("actor", "")).strip()
        remote_actor = await self.fetch_remote_actor(actor_uri=remote_actor_uri)
        reactor_user_id = self._ensure_remote_shadow_user(remote_actor=remote_actor)

        self.messages_manager.add_reaction(message_id=row.message_id, user_id=reactor_user_id, emoji=emoji)
        return {"processed": True, "activity_type": "Like", "action": "reaction_added"}

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
        # A peer whose media switch is off can send words but not pictures or files.
        raw_attachments = (obj.get("attachment", []) or []) if self.peer_policy.policy_for(host_of(remote_actor_uri))["media"] else []
        attachments: list[str] = []
        for item in raw_attachments:
            if isinstance(item, str):
                attachments.append(item)
            elif isinstance(item, dict) and item.get("href"):
                attachments.append(str(item["href"]))
            elif isinstance(item, dict) and item.get("url"):
                attachments.append(str(item["url"]))

        # Resolve inReplyTo back to a local row when it points at something
        # addressable via `_object_uri_for_message` (anything we've sent or
        # received before) — None otherwise, same best-effort posture as
        # everywhere else that crosses the remote-object-id boundary.
        reply_to_uri = str(obj.get("inReplyTo") or "").strip()
        reply_to_message_id = None
        if reply_to_uri:
            parent = self.database_handler.get_message_by_remote_object_uri(reply_to_uri)
            if parent is None:
                parent = self._local_message_from_object_uri(reply_to_uri, base_url)
            if parent is not None:
                reply_to_message_id = parent.message_id

        remote_object_uri = str(obj.get("id") or "").strip() or None

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
                reply_to_message_id=reply_to_message_id,
                remote_object_uri=remote_object_uri,
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
                    "reply_to_message_id": reply_to_message_id,
                    "reply_to": self.messages_manager.reply_preview(reply_to_message_id) if reply_to_message_id else None,
                    **self._sender_fields(sender_user_id),
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

    async def _handle_ping(
        self,
        activity: dict,
        base_url: str,
        target_actor_uri: str | None,
    ) -> dict:
        """
        Dispatch incoming ``Ping`` activity to PingManager.

        If no PingManager is wired (e.g. in tests), falls back to stored-only.
        """
        if self.ping_manager is None:
            logger.warning("Received Ping activity but ping_manager is not wired; stored only.")
            return {"processed": True, "activity_type": "Ping", "action": "stored_only"}

        return await self.ping_manager.process_federated_ping(
            activity=activity,
            base_url=base_url,
            target_actor_uri=target_actor_uri,
        )

    async def _handle_ping_ack(self, activity: dict, base_url: str) -> dict:
        """
        Dispatch incoming ``PingAck`` activity to PingManager.
        """
        if self.ping_manager is None:
            logger.warning("Received PingAck activity but ping_manager is not wired; stored only.")
            return {"processed": True, "activity_type": "PingAck", "action": "stored_only"}

        return await self.ping_manager.process_federated_ping_ack(
            activity=activity,
            base_url=base_url,
        )

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

    def _recover_dm_peer(self, conversation_id: str, viewer_user_id: str, viewer_actor_uri: str, base_url: str) -> str | None:
        """Find who a conversation is with by trying each local user against its hash, and remember the answer.

        For conversations the viewer started before participants were recorded. Remote people cannot be
        recovered this way (their address is not known from here).
        """
        for user_id in self.database_handler.local_user_ids():
            if user_id == str(viewer_user_id):
                continue
            if self._conversation_id(viewer_actor_uri, self._actor_uri_for_user(user_id, base_url)) == conversation_id:
                self.database_handler.record_dm_members(conversation_id, [str(viewer_user_id), user_id])
                return user_id
        return None

    def list_dm_conversations(
        self,
        viewer_user_id: str,
        base_url: str,
    ) -> list[dict]:
        """List DM conversations the viewer participates in.

        Powers the conversation-list sidebar on the client. Returns
        an ordered (most-recent-first) list of conversation entries,
        each hydrated with the peer's identity, the last message
        preview, and the last-message timestamp so the UI can
        render the row without a second round-trip per conversation.

        Algorithm:

          1. Pull the universe of candidate conversation_ids from
             the DB — conversations where the viewer has either
             sent or received a message.
          2. For each candidate, find the OTHER participant
             (some sender_id in the conversation that isn't us).
          3. Verify the conversation truly involves the viewer by
             recomputing ``sha256(sorted([viewer_actor, peer_actor]))``
             — guards against junk rows or hash collisions on
             unrelated conversations.
          4. Hydrate peer info from the ``users`` table (covers
             both local users and federation shadow rows) and
             decrypt the last message body for preview.

        Returns list of dicts:

            {
              "conversation_id": str,
              "peer_user_id": str,
              "peer_username": str,
              "peer_origin_server": str,
              "peer_avatar_url": str | None,
              "peer_status": str,
              "last_message_at": str (ISO 8601),
              "last_message_preview": str (truncated to 120 chars),
              "last_message_sender_is_me": bool,
            }
        """
        import base64

        viewer_actor_uri = self._actor_uri_for_user(viewer_user_id, base_url)
        candidates = self.database_handler.list_user_dm_conversation_candidates(
            viewer_user_id
        )

        conversations: list[dict] = []
        for candidate in candidates:
            conv_id = candidate["conversation_id"]

            # Find the peer = first sender in this conversation that
            # isn't us. None means the only sender was the viewer
            # (an outgoing-only conversation that never got a
            # reply); in that case we still want to surface it but
            # need to find the peer differently — for the v1
            # implementation we skip these since we can't recover
            # the peer's identity without a conversation_members
            # table.
            peer_user_id = self.database_handler.get_conversation_other_sender(
                conversation_id=conv_id, viewer_user_id=viewer_user_id
            )
            if peer_user_id is None:
                # Outgoing-only so far: the messages name only the viewer. The members table has the
                # other person for anything sent since it was added; older ones are matched by hash.
                peer_user_id = self.database_handler.get_dm_other_member(conv_id, viewer_user_id)
            if peer_user_id is None:
                peer_user_id = self._recover_dm_peer(conv_id, viewer_user_id, viewer_actor_uri, base_url)
            if peer_user_id is None:
                continue

            # Resolve the peer's actor_uri. Local users have a
            # deterministic uri pattern; shadow users (federated)
            # have a row in activitypub_actors with the remote uri.
            peer_actor_row = self.database_handler.get_activitypub_actor_by_user_id(
                user_id=peer_user_id
            )
            if peer_actor_row is not None:
                peer_actor_uri = peer_actor_row.actor_uri
            else:
                peer_actor_uri = self._actor_uri_for_user(peer_user_id, base_url)

            # Verify the conversation_id matches the hash of
            # viewer + peer. Mismatches are conversations that
            # involve OTHER users; the candidates list is broad
            # (any conv where the viewer received a message
            # there could also be a junk row where another user
            # happens to be a sender). Verification protects us.
            expected = self._conversation_id(viewer_actor_uri, peer_actor_uri)
            if expected != conv_id:
                continue

            # Hydrate peer info from the users table.
            peer_user = self.database_handler.get_user(user_id=peer_user_id)
            if peer_user is None:
                # Shouldn't happen if the actor was found above,
                # but defensive — log and skip.
                logger.warning(
                    "DM conversation peer user_id={peer_id} missing from users table",
                    peer_id=peer_user_id,
                )
                continue

            # Decrypt the last message for the preview. Best-effort —
            # a decryption failure shouldn't drop the whole row,
            # we just show "[unavailable]" instead.
            last_msg = self.database_handler.get_message_by_id(
                message_id=candidate["last_message_id"]
            )
            preview = ""
            if last_msg is not None and last_msg.hashed_message:
                try:
                    decoded = self.messages_manager.decrypt_message(
                        user_id=str(last_msg.sender_id),
                        message_id=last_msg.message_id,
                        encrypted_message=base64.b64decode(last_msg.hashed_message),
                    )
                    preview = decoded.strip()
                except Exception as exc:
                    logger.warning(
                        "DM preview decrypt failed for message_id={mid}: {err}",
                        mid=candidate["last_message_id"],
                        err=str(exc),
                    )
                    preview = "[message unavailable]"

            if not preview and last_msg is not None:
                for attachment in last_msg.attachments or []:
                    if isinstance(attachment, dict) and attachment.get("type") == "call":
                        preview = call_preview(attachment.get("call") or {})
                        break

            # Truncate the preview so the sidebar row stays one-line.
            # The dashboard CSS truncates with ellipsis too, but
            # capping server-side saves bytes on huge messages.
            if len(preview) > 120:
                preview = preview[:117] + "…"

            sender_is_me = (
                last_msg is not None
                and str(last_msg.sender_id) == str(viewer_user_id)
            )

            conversations.append({
                "conversation_id": conv_id,
                "peer_user_id": str(peer_user.user_id),
                "peer_username": peer_user.username,
                "peer_origin_server": peer_user.origin_server or "",
                "peer_avatar_url": peer_user.avatar_url,
                "peer_status": peer_user.status or "offline",
                "last_message_at": (
                    candidate["last_message_at"].isoformat()
                    if candidate["last_message_at"]
                    else None
                ),
                "last_message_preview": preview,
                "last_message_sender_is_me": sender_is_me,
            })

        # Already sorted by last_message_at desc from the DB layer;
        # keep that order so the most-recent-first conversation is
        # at the top of the sidebar.
        return conversations
