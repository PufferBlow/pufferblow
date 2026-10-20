"""Input schemas for every v1 command.

Each command's ``data`` is validated against one of these models before any
handler runs. ``extra="forbid"`` makes unknown fields an error so typos and
attempts to smuggle fields (for example a principal id) are rejected rather
than silently ignored.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

MAX_NONCE_LENGTH = 128
MAX_EMOJI_LENGTH = 64
MAX_STICKERS_PER_MESSAGE = 10
MAX_RESYNC_LIMIT = 100
MAX_UPLOADS_PER_MESSAGE = 10
#: Base64 characters in one chunk. 32 KiB of file is about 43,700 of them, inside a 64 KiB frame.
MAX_CHUNK_BASE64_CHARS = 48_000


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
    #: Files sent earlier with ``upload.begin`` / ``upload.chunk``, attached to this message.
    upload_ids: list[str] = Field(default_factory=list, max_length=MAX_UPLOADS_PER_MESSAGE)


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


class TypingStart(_Strict):
    """Exactly one of ``channel_id`` or ``conversation_id`` (a direct message)."""

    channel_id: str | None = Field(default=None, min_length=1, max_length=128)
    conversation_id: str | None = Field(default=None, min_length=1, max_length=128)

    @model_validator(mode="after")
    def _one_target(self) -> "TypingStart":
        if (self.channel_id is None) == (self.conversation_id is None):
            raise ValueError("give exactly one of channel_id or conversation_id")
        return self


class UploadBegin(_Strict):
    """Start sending a file. The answer carries the ``upload_id`` and the largest chunk to send."""

    name: str = Field(min_length=1, max_length=255)
    content_type: str | None = Field(default=None, min_length=1, max_length=255)
    size: int = Field(ge=1)


class UploadChunk(_Strict):
    """The next piece of a file, base64 encoded. Chunks go in order starting at ``index`` 0."""

    upload_id: str = Field(min_length=1, max_length=128)
    index: int = Field(ge=0)
    data: str = Field(min_length=1, max_length=MAX_CHUNK_BASE64_CHARS)


class UploadAbort(_Strict):
    upload_id: str = Field(min_length=1, max_length=128)


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
    "typing.start": TypingStart,
    "upload.begin": UploadBegin,
    "upload.chunk": UploadChunk,
    "upload.abort": UploadAbort,
}
