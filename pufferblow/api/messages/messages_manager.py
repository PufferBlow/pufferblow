import base64
import hashlib
import random
import string
import uuid

from loguru import logger

from pufferblow.api.auth.auth_token_manager import AuthTokenManager
from pufferblow.api.database.database_handler import DatabaseHandler

# Tables
from pufferblow.api.database.tables.messages import Messages
from pufferblow.api.encrypt.encrypt import Encrypt
from pufferblow.api.user.user_manager import UserManager


def build_search_index_text(
    message: str | None,
    attachments: list[dict] | None,
) -> str:
    """Compose the searchable text for a message row.

    Pure function — same input always yields the same output, no
    state. Used by both the live write path
    (`MessagesManager._build_message_record`) and the
    `migrate --backfill-search` command so the two never drift.

    Rules:
      * Plaintext message body comes first when present.
      * Attachment filenames are appended (space-separated). This is
        why "find that PDF I sent" works for attachment-only messages
        — the filename itself is indexed even when the text is empty.
      * Whitespace is collapsed and trimmed; the function returns
        an empty string for a message with neither text nor named
        attachments. The save path treats an empty result as
        "indexed but empty" (sentinel empty `tsvector`) — see the
        comment in `DatabaseHandler.save_message`.

    Filenames are taken verbatim — `to_tsvector('simple', ...)` does
    the lexeme split on Postgres side and handles things like
    ``"design-spec_v3.pdf"`` as four tokens (design, spec, v3, pdf).
    """
    parts: list[str] = []
    if message:
        text = message.strip()
        if text:
            parts.append(text)
    for attachment in attachments or []:
        if not isinstance(attachment, dict):
            continue
        filename = attachment.get("filename")
        if isinstance(filename, str) and filename.strip():
            parts.append(filename.strip())
    # Single space collapse — multiple filenames join cleanly and a
    # trailing-only space message doesn't leak into the index.
    return " ".join(parts).strip()


def _summarize_reactions(
    reactions: list, viewer_user_id: str | None
) -> list[dict]:
    """Group raw reaction rows by emoji and emit summary dicts.

    Each summary has ``{emoji, count, viewer_reacted, user_ids}`` where
    ``user_ids`` is the full list of users that reacted with that emoji. The
    list is ordered by descending count, then emoji string for stability.
    """
    groups: dict[str, list[str]] = {}
    for reaction in reactions:
        groups.setdefault(reaction.emoji, []).append(str(reaction.user_id))

    summary: list[dict] = []
    for emoji, user_ids in groups.items():
        summary.append({
            "emoji": emoji,
            "count": len(user_ids),
            "viewer_reacted": bool(viewer_user_id) and viewer_user_id in user_ids,
            "user_ids": user_ids,
        })
    summary.sort(key=lambda entry: (-entry["count"], entry["emoji"]))
    return summary


class MessagesManager:
    """Messages manager class"""

    def __init__(
        self,
        database_handler: DatabaseHandler,
        auth_token_manager: AuthTokenManager,
        user_manager: UserManager,
        encrypt_manager: Encrypt,
    ) -> None:
        """Initialize the instance."""
        self.database_handler = database_handler
        self.auth_token_manager = auth_token_manager
        self.user_manager = user_manager
        self.encrypt_manager = encrypt_manager

    def load_messages(
        self,
        channel_id: str,
        messages_per_page: int | None = 20,
        page: int | None = 1,
        websocket: bool | None = False,
        viewed_messages_ids: list | None = None,
        viewer_user_id: str | None = None,
        before_cursor: str | None = None,
        accessible_channels: list[str] | None = None,
    ) -> list[dict] | tuple[list[dict], str | None]:
        """Load history for an HTTP page fetch or a WS reconnect burst.

        Three call shapes the route layer uses:

        * `before_cursor=<token>` → keyset-paginated history walk.
          Returns `(messages, next_cursor)`. The cursor is opaque to
          the client — it's a `"<sent_at>|<message_id>"` string we
          minted on the previous response. `next_cursor=None` when
          this is the last page. Use this for any new client; it is
          O(log N + limit) regardless of channel size.

        * `page=N, messages_per_page=M`, no cursor → legacy offset-style
          page fetch. We translate it into a keyset walk internally,
          but the depth is capped at
          `DatabaseHandler.MAX_OFFSET_PAGINATION_ROWS` so a client
          asking for "page 10000" gets a clear error instead of
          stalling Postgres. Returns just `list[dict]` for
          backwards compatibility.

        * `websocket=True` → the bounded reconnect-burst path. Returns
          at most `DatabaseHandler.MAX_UNVIEWED_BURST` rows, never
          older than `DatabaseHandler.UNVIEWED_BURST_MAX_AGE`. The
          client must paginate via the cursor path for anything
          older.
        """
        if before_cursor is not None:
            rows, next_cursor = self.database_handler.fetch_channel_messages_keyset(
                channel_id=channel_id,
                limit=messages_per_page or 20,
                before_cursor=before_cursor,
            )
            return (
                self._hydrate_messages(rows, viewer_user_id=viewer_user_id),
                next_cursor,
            )

        if not websocket:
            messages = self.database_handler.fetch_channel_messages(
                channel_id=channel_id, messages_per_page=messages_per_page, page=page
            )
        else:
            # The WS path used to call this method once per accessible
            # channel — N round-trips to Postgres per tick. When the
            # caller supplies `accessible_channels`, route through the
            # bulk handler that does it in ONE query. The per-channel
            # path is retained for the deprecated `/ws/channels/{id}`
            # endpoint and for back-compat with callers that don't
            # supply the list.
            if accessible_channels:
                messages = (
                    self.database_handler.fetch_unviewed_messages_across_channels(
                        channel_ids=accessible_channels,
                        viewed_messages_ids=viewed_messages_ids or [],
                    )
                )
            else:
                messages = self.database_handler.fetch_unviewed_channel_messages(
                    channel_id=channel_id, viewed_messages_ids=viewed_messages_ids
                )
        return self._hydrate_messages(messages, viewer_user_id=viewer_user_id)

    def search_messages(
        self,
        channel_id: str,
        query: str,
        scan_limit: int,
        max_results: int,
        viewer_user_id: str | None = None,
    ) -> tuple[list[dict], int, bool]:
        """Ranked in-channel search.

        Two code paths share this signature:

        * **Postgres (production)** — uses
          `DatabaseHandler.search_channel_messages_ranked`, which runs a
          `WHERE channel_id = ? AND search_tokens @@ plainto_tsquery(?)`
          against the GIN-indexed `search_tokens` column and ranks hits
          via `ts_rank_cd`. Cost is O(matches) regardless of how many
          messages the channel holds — a search across a 10M-message
          channel and a 1K-message channel take roughly the same time.
          Only the top `max_results` rows get decrypted (one decrypt
          per hit, instead of one per candidate).

        * **SQLite (test harness)** — `search_channel_messages_ranked`
          returns empty, so we fall back to the original decrypt-and-
          scan path. Bounded by `scan_limit` (default 1000, hard cap
          5000) the same way the old implementation was — production
          never takes this branch.

        Args:
            channel_id: The channel's id.
            query: The free-text query (passed through
                `plainto_tsquery('simple', …)` on Postgres).
            scan_limit: Only consulted on the SQLite fallback path. On
                Postgres the search is index-bounded, not scan-bounded.
            max_results: Max ranked matches to return.

        Returns:
            (matches, scanned_count, truncated_scan):
              * ``matches`` — hydrated message dicts, ranked best→recent.
              * ``scanned_count`` — Postgres: number of hits inspected.
                SQLite: number of messages decrypted.
              * ``truncated_scan`` — SQLite only; True if the channel
                had more rows than `scan_limit`. Always False on
                Postgres (the GIN search isn't a scan).
        """
        ranked = self.database_handler.search_channel_messages_ranked(
            channel_id=channel_id, query_text=query, limit=max_results
        )
        if ranked:
            # Postgres path: strip the score (clients don't see it
            # today; rank is implicit in the order), then hydrate.
            matches = [(message, user) for message, user, _ in ranked]
            hydrated = self._hydrate_messages(matches, viewer_user_id=viewer_user_id)
            return hydrated, len(ranked), False

        # SQLite fallback (or "Postgres found nothing"). On Postgres
        # the empty-result short-circuit means we never spin up the
        # decrypt path for misses — only the SQLite tests reach it.
        if not str(
            self.database_handler.database_engine.url
        ).startswith("sqlite://"):
            return [], 0, False

        candidates = self.database_handler.fetch_channel_messages_for_search(
            channel_id=channel_id, scan_limit=scan_limit
        )

        needle = query.lower()
        matches: list[tuple[Messages, object | None]] = []
        for message_tuple in candidates:
            message_data = message_tuple[0]
            try:
                raw_message = self.decrypt_message(
                    user_id=str(message_data.sender_id),
                    message_id=message_data.message_id,
                    encrypted_message=base64.b64decode(message_data.hashed_message),
                )
            except Exception as exc:
                logger.warning(
                    "Failed to decrypt during search: message_id={message_id} error={error}",
                    message_id=message_data.message_id,
                    error=str(exc),
                )
                continue

            if needle in raw_message.lower():
                matches.append(message_tuple)
                if len(matches) >= max_results:
                    break

        hydrated = self._hydrate_messages(matches, viewer_user_id=viewer_user_id)
        truncated = len(candidates) >= scan_limit
        return hydrated, len(candidates), truncated

    def load_direct_messages(
        self,
        conversation_id: str,
        messages_per_page: int | None = 20,
        page: int | None = 1,
        viewer_user_id: str | None = None,
    ) -> list[dict]:
        """
        Load direct messages for a conversation_id.
        """
        messages = self.database_handler.fetch_conversation_messages(
            conversation_id=conversation_id,
            messages_per_page=messages_per_page,
            page=page,
        )
        return self._hydrate_messages(messages, viewer_user_id=viewer_user_id)

    # --- Reactions -------------------------------------------------------

    def add_reaction(self, message_id: str, user_id: str, emoji: str) -> bool:
        """Apply a reaction. Returns True if newly added, False if no-op."""
        return self.database_handler.add_message_reaction(
            message_id=message_id, user_id=user_id, emoji=emoji
        )

    def remove_reaction(self, message_id: str, user_id: str, emoji: str) -> bool:
        """Remove a reaction. Returns True if removed, False if not present."""
        return self.database_handler.remove_message_reaction(
            message_id=message_id, user_id=user_id, emoji=emoji
        )

    def get_reaction_summary(
        self, message_id: str, viewer_user_id: str | None = None
    ) -> list[dict]:
        """Return the reaction summary for a single message."""
        grouped = self.database_handler.get_reactions_for_messages(
            message_ids=[message_id]
        )
        return _summarize_reactions(
            grouped.get(message_id, []), viewer_user_id=viewer_user_id
        )

    def send_message(
        self,
        channel_id: str,
        user_id: str,
        message: str,
        attachments: list[dict] | None = None,
        sent_at: str | None = None,
    ) -> Messages:
        """
        Send a message to a channel

        Args:
            channel_id (str): The channel's `channel_id`.
            user_id (str): The sender user's `user_id`.
            message (str): The message to send.
            attachments (list[dict], optional): List of attachment objects with url/filename/type/size.
            sent_at (str, optional): ISO format timestamp when message was sent. If None, uses current time.

        Returns:
            Messages: The message metadata object.
        """
        # Block text messages in voice-only channels.
        from pufferblow.core.bootstrap import api_initializer

        channel_type = api_initializer.channels_manager.get_channel_type(channel_id)
        if channel_type == "voice":
            from fastapi import exceptions

            logger.warning(
                f"Attempted to send text message to voice-only channel | User: {user_id} | Channel: {channel_id}"
            )
            raise exceptions.HTTPException(
                status_code=400,
                detail="Messages cannot be sent to voice-only channels. Use a text or mixed channel.",
            )

        message_metadata, encryption_key = self._build_message_record(
            user_id=user_id,
            message=message,
            attachments=attachments,
            sent_at=sent_at,
            channel_id=channel_id,
            conversation_id=None,
        )
        self.database_handler.save_message(message=message_metadata)
        self.database_handler.save_keys(key=encryption_key)
        # Bump usage_count for any sticker attachments so the picker can
        # rank most-used first. Best-effort — handled inside the manager
        # via try/except, so a bump failure can't break the send.
        try:
            if api_initializer.stickers_manager is not None:
                api_initializer.stickers_manager.bump_usage_from_attachments(attachments)
        except Exception:  # pragma: no cover - defensive only
            pass
        return message_metadata

    def send_direct_message(
        self,
        user_id: str,
        conversation_id: str,
        message: str,
        attachments: list[dict] | None = None,
        sent_at: str | None = None,
    ) -> Messages:
        """
        Save a direct message in a conversation.
        """
        message_metadata, encryption_key = self._build_message_record(
            user_id=user_id,
            message=message,
            attachments=attachments,
            sent_at=sent_at,
            channel_id=None,
            conversation_id=conversation_id,
        )
        self.database_handler.save_direct_message(message=message_metadata)
        self.database_handler.save_keys(key=encryption_key)
        # Same sticker-usage bump as send_message. Best-effort.
        try:
            from pufferblow.core.bootstrap import api_initializer as _ai
            if _ai.stickers_manager is not None:
                _ai.stickers_manager.bump_usage_from_attachments(attachments)
        except Exception:  # pragma: no cover - defensive only
            pass
        return message_metadata

    def delete_message(self, message_id: str, channel_id: str) -> None:
        """
        Delete a message from a channel in the server

        Args:
            message_id (str): The message's `message_id`.
            channel_id (str): The channel's `channel_id`.

        Returns:
            None
        """
        self.database_handler.delete_message(
            message_id=message_id, channel_id=channel_id
        )

    def mark_message_as_read(
        self, user_id: str, message_id: str, channel_id: str
    ) -> None:
        """
        Mark a message as read in the `message_read_history` table in the database

        Args:
            auth_token (str): The user's `auth_token`.
            channel_id (str): The channel's `channel_id`.
            message_id (str): "The message's `message_id` that should be marked as read.

        Returns:
            None.
        """
        viewed_messages_ids = self.database_handler.get_user_read_messages_ids(
            user_id=user_id
        )

        if message_id in viewed_messages_ids:
            return

        self.database_handler.add_message_to_read_history(
            user_id=user_id, message_id=message_id
        )

    def check_message(self, message_id: str) -> bool:
        """
        Check weiher a message exists by its `message_id`
        or not

        Args:
            message_id (str): The message's `message_id`.

        Returns:
            None.
        """
        message_metadata = self.database_handler.get_message_metadata(
            message_id=message_id
        )

        return message_metadata is not None

    def encrypt_message(
        self, message: str, user_id: str, message_id: str
    ) -> tuple[str, object]:
        """
        Encrypt a message and return the encrypted message and encryption key

        Args:
            message (str): The raw message.
            user_id (str): The sender user's `user_id`.
            message_id (str): The message's `message_id`.

        Returns:
            tuple[str, object]: (base64 encoded encrypted message, encryption key object)
        """
        encrypted_message, key = self.encrypt_manager.encrypt(data=message)

        key.user_id = user_id
        key.message_id = message_id
        key.associated_to = "message"

        encrypted_message = base64.b64encode(encrypted_message).decode("ascii")

        return encrypted_message, key

    def decrypt_message(
        self, user_id: str, message_id: str, encrypted_message: bytes
    ) -> str:
        """
        Decrypt a message

        Args:
            user_id (str): The sender user's `user_id`.
            message_id (str): The message's `message_id`.

        Returns:
            str: The decrypted message.
        """
        key = self.database_handler.get_keys(
            user_id=user_id, associated_to="message", message_id=message_id
        )
        if key is None:
            raise ValueError(
                f"Missing encryption key for message_id={message_id}, user_id={user_id}"
            )

        decrypted_message = self.encrypt_manager.decrypt(
            ciphertext=encrypted_message, key=key.key_value, iv=key.iv
        )

        return decrypted_message

    def check_message_sender(self, message_id: str) -> str:
        """
        Check the message sender

        Args:
            message_id (str): The message's `message_id`.

        Returns:
            str: The message sender's `user_id`.
        """
        message_metadata = self.database_handler.get_message_metadata(
            message_id=message_id
        )

        return str(message_metadata.sender_id)

    def _generate_message_id(self, user_id: str, message: str) -> str:
        """
        Generate a unique `message_id` based of the sender user's `user_id`
        and a slice from the original message

        Args:
            user_id (str): The sender user's `user_id`.
            message (str): A slice of the original message.

        Returns:
            str: The generated `user_id`.
        """
        data = f"{user_id}{message}{''.join([char for char in random.choices(string.ascii_letters)])}"  # Adding random charachters to the username

        hashed_data_salt = hashlib.md5(data.encode()).hexdigest()
        generated_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, hashed_data_salt)

        return str(generated_uuid)

    def _build_message_record(
        self,
        user_id: str,
        message: str,
        attachments: list[str] | None,
        sent_at: str | None,
        channel_id: str | None,
        conversation_id: str | None,
    ) -> tuple[Messages, object]:
        """
        Build encrypted message record and encryption key tuple.

        Also populates the `search_tokens` tsvector from the plaintext
        BEFORE we encrypt it — this is the only place plaintext exists
        in the request scope, and we need it to build the index that
        powers `DatabaseHandler.search_channel_messages_ranked`. The
        encryption keys live in the same database the index does
        (`keys` table), so adding a tsvector does NOT weaken the
        encryption-at-rest posture: anyone who can read `search_tokens`
        already has the keys to decrypt `hashed_message`.
        """
        message_metadata = Messages()
        message_metadata.message_id = self._generate_message_id(
            user_id=user_id,
            message=(
                message[: random.choice([i for i in range(len(message))])]
                if message
                else "attachment"
            ),
        )
        message_metadata.channel_id = channel_id
        message_metadata.conversation_id = conversation_id
        message_metadata.sender_id = user_id
        message_metadata.attachments = attachments or []

        if sent_at:
            try:
                from datetime import datetime

                dt_str = (
                    sent_at.replace("Z", "").replace("+00:00", "").replace("+00", "")
                )
                message_metadata.sent_at = datetime.fromisoformat(dt_str)
            except ValueError:
                pass

        message_metadata.hashed_message, encryption_key = self.encrypt_message(
            message=message,
            user_id=user_id,
            message_id=message_metadata.message_id,
        )
        # Stash the searchable text as a transient (non-persisted)
        # attribute so `DatabaseHandler.save_message` can apply Postgres'
        # `to_tsvector` in the INSERT path. We cannot assign a raw
        # string to the `search_tokens` TSVECTOR column via the ORM —
        # the wire format for a tsvector literal isn't just plain text
        # (it's `'token':position`) — so the cast has to happen
        # server-side via `to_tsvector('simple', ?)`. SQLAlchemy keeps
        # `__allow_unmapped__ = True` (see tables/messages.py) which
        # permits stashing this.
        #
        # `build_search_index_text` includes attachment filenames in
        # the indexed text so attachment-only messages are still
        # findable ("find that PDF I sent"). It returns "" when the
        # message has neither text nor named attachments, and the
        # save path writes an empty tsvector sentinel for that case
        # so the backfill never re-picks the row.
        message_metadata.raw_message = build_search_index_text(
            message=message, attachments=attachments
        )

        return message_metadata, encryption_key

    def _hydrate_messages(
        self,
        messages: list[tuple[Messages, object | None]],
        viewer_user_id: str | None = None,
    ) -> list[dict]:
        """
        Convert DB message tuples to client-facing dictionaries.

        When ``viewer_user_id`` is supplied each reaction summary includes a
        ``viewer_reacted`` flag indicating whether the viewer is in the set of
        users that applied that emoji to the message.
        """
        messages_metadata: list[dict] = []

        message_ids = [m[0].message_id for m in messages]
        reactions_by_message = self.database_handler.get_reactions_for_messages(
            message_ids=message_ids
        )

        for message_tuple in messages:
            message_data = message_tuple[0]
            user_data = message_tuple[1]

            try:
                raw_message = self.decrypt_message(
                    user_id=str(message_data.sender_id),
                    message_id=message_data.message_id,
                    encrypted_message=base64.b64decode(message_data.hashed_message),
                )
            except Exception as exc:
                logger.warning(
                    "Failed to decrypt message_id={message_id} sender_id={sender_id}: {error}",
                    message_id=message_data.message_id,
                    sender_id=message_data.sender_id,
                    error=str(exc),
                )
                raw_message = "[message unavailable]"

            json_metadata_format = message_data.to_dict()
            json_metadata_format["message"] = raw_message
            json_metadata_format.pop("hashed_message", None)

            for key in ["channel_id", "conversation_id"]:
                if json_metadata_format.get(key) is None:
                    json_metadata_format.pop(key, None)

            if user_data:
                json_metadata_format["sender_username"] = user_data.username
                json_metadata_format["sender_avatar_url"] = user_data.avatar_url
                json_metadata_format["sender_banner_url"] = user_data.banner_url
                # LQIP variants of the avatar / banner so each
                # message row can crossfade its avatar from a
                # placeholder. We resolve here on the read path
                # rather than mirroring the column on the messages
                # table so we don't have to keep the LQIP pointer
                # in sync per-message — a single source of truth
                # (file_objects.lqip_path) is consulted at read
                # time.
                from pufferblow.api.user.user_manager import (
                    _resolve_storage_lqip_url,
                )
                json_metadata_format["sender_avatar_lqip_url"] = _resolve_storage_lqip_url(
                    user_data.avatar_url, self.database_handler
                )
                json_metadata_format["sender_banner_lqip_url"] = _resolve_storage_lqip_url(
                    user_data.banner_url, self.database_handler
                )
                json_metadata_format["sender_status"] = user_data.status or "offline"
                json_metadata_format["sender_roles"] = user_data.roles_ids or []
                json_metadata_format["sender_about"] = user_data.about
                json_metadata_format["sender_last_seen"] = (
                    user_data.last_seen.isoformat() if user_data.last_seen else None
                )
                json_metadata_format["sender_created_at"] = (
                    user_data.created_at.isoformat() if user_data.created_at else None
                )
            else:
                json_metadata_format["sender_username"] = "Unknown User"
                json_metadata_format["sender_avatar_url"] = None
                json_metadata_format["sender_banner_url"] = None
                json_metadata_format["sender_avatar_lqip_url"] = None
                json_metadata_format["sender_banner_lqip_url"] = None
                json_metadata_format["sender_status"] = "offline"
                json_metadata_format["sender_roles"] = []
                json_metadata_format["sender_about"] = None
                json_metadata_format["sender_last_seen"] = None
                json_metadata_format["sender_created_at"] = None

            if message_data.attachments and len(message_data.attachments) > 0:
                # Attachments are stored as structured dicts
                # {url, filename, type, size, [lqip_url]}.
                # `lqip_url` was added to the schema later, so old
                # rows don't have it. Backfill on read for image
                # attachments by resolving against file_objects.
                # Non-image and non-/storage URLs stay None. This
                # is best-effort — a failed lookup just leaves the
                # client to render skeleton until the full image
                # finishes.
                from pufferblow.api.user.user_manager import (
                    _resolve_storage_lqip_url,
                )
                hydrated: list[dict] = []
                for attachment in message_data.attachments:
                    if not isinstance(attachment, dict):
                        hydrated.append(attachment)
                        continue
                    if "lqip_url" not in attachment:
                        mime = attachment.get("type") or ""
                        if mime.startswith("image/") and mime != "image/gif":
                            attachment["lqip_url"] = _resolve_storage_lqip_url(
                                attachment.get("url"), self.database_handler
                            )
                        else:
                            attachment["lqip_url"] = None
                    hydrated.append(attachment)
                json_metadata_format["attachments"] = hydrated
            else:
                json_metadata_format["attachments"] = []

            json_metadata_format["sender_user_id"] = str(message_data.sender_id)

            message_reactions = reactions_by_message.get(message_data.message_id, [])
            json_metadata_format["reactions"] = _summarize_reactions(
                message_reactions, viewer_user_id=viewer_user_id
            )

            messages_metadata.append(json_metadata_format)

        logger.debug(f"{messages = }")
        return messages_metadata

