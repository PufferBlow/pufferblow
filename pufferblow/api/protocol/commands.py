"""Input schemas for every v1 command.

Each command's ``data`` is validated against one of these models before any
handler runs. ``extra="forbid"`` makes unknown fields an error so typos and
attempts to smuggle fields (for example a principal id) are rejected rather
than silently ignored.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

MAX_NONCE_LENGTH = 128
MAX_EMOJI_LENGTH = 64
MAX_STICKERS_PER_MESSAGE = 10
MAX_RESYNC_LIMIT = 100


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class MessageCreate(_Strict):
    channel_id: str = Field(min_length=1, max_length=128)
    content: str = Field(default="", max_length=20_000)
    sticker_ids: list[str] = Field(default_factory=list, max_length=MAX_STICKERS_PER_MESSAGE)
    #: The message (in the same channel) this one replies to.
    reply_to_message_id: str | None = Field(default=None, min_length=1, max_length=128)
    #: Client-generated idempotency key. Retrying with the same nonce never creates a second message.
    nonce: str | None = Field(default=None, min_length=1, max_length=MAX_NONCE_LENGTH)


class MessageEdit(_Strict):
    channel_id: str = Field(min_length=1, max_length=128)
    message_id: str = Field(min_length=1, max_length=128)
    content: str = Field(min_length=1, max_length=20_000)


class MessageDelete(_Strict):
    channel_id: str = Field(min_length=1, max_length=128)
    message_id: str = Field(min_length=1, max_length=128)


class ReactionChange(_Strict):
    channel_id: str = Field(min_length=1, max_length=128)
    message_id: str = Field(min_length=1, max_length=128)
    emoji: str = Field(min_length=1, max_length=MAX_EMOJI_LENGTH)


class ChannelRef(_Strict):
    channel_id: str = Field(min_length=1, max_length=128)


class EventsResync(_Strict):
    channel_id: str = Field(min_length=1, max_length=128)
    limit: int = Field(default=50, ge=1, le=MAX_RESYNC_LIMIT)


#: Command name -> input model. The dispatcher refuses any name not listed here.
COMMAND_SCHEMAS: dict[str, type[BaseModel]] = {
    "message.create": MessageCreate,
    "message.edit": MessageEdit,
    "message.delete": MessageDelete,
    "reaction.add": ReactionChange,
    "reaction.remove": ReactionChange,
    "channel.subscribe": ChannelRef,
    "channel.unsubscribe": ChannelRef,
    "events.resync": EventsResync,
}
