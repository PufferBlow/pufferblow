"""Command handlers for protocol v1.

Each handler is a thin translation layer: it unpacks an already-validated
payload, calls the shared service, and returns a result plus domain events.
Business rules live in :mod:`pufferblow.api.services`, not here.

The services and the authorizer are synchronous and talk to the database, so a handler hands
them to a worker thread (``asyncio.to_thread``) instead of calling them on the event loop, where
one slow query would stall every connection. Each database call opens its own session, so this is
safe. Anything that touches loop-owned state (``ctx.subscriptions``, the publisher's sequence
counters) stays on the loop, after the call returns.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
from collections.abc import Callable

from pufferblow.api.commands.dispatcher import CommandSpec, ConnectionContext, HandlerOutput
from pufferblow.api.errors import ApiError, ErrorCode
from pufferblow.api.principals.authorizer import Authorizer
from pufferblow.api.protocol import commands as schema
from pufferblow.api.protocol.events import TYPING_EXPIRES_MS, TYPING_STARTED, DomainEvent
from pufferblow.api.services.messages import MessageService
from pufferblow.api.uploads.staging import CHUNK_BYTES, UploadStaging


def build_registry(
    *,
    messages: MessageService,
    authorizer: Authorizer,
    publisher,
    dm_peer: Callable[[str, str], str | None] | None = None,
    staging: UploadStaging | None = None,
    store_attachments: Callable | None = None,
) -> dict[str, CommandSpec]:
    """``dm_peer(conversation_id, user_id)`` returns the other, local participant of a DM the
    user is part of, or ``None``; without it, typing in DMs is accepted but not delivered.

    ``staging`` and ``store_attachments`` (``async (principal, channel_id, files) -> [attachment dicts]``)
    switch on sending files over the socket: ``upload.begin`` / ``upload.chunk`` / ``upload.abort`` and
    ``upload_ids`` on ``message.create``. Without them those commands are not registered."""

    async def message_create(ctx: ConnectionContext, data: schema.MessageCreate) -> HandlerOutput:
        attachments: list[dict] = []
        if data.upload_ids:
            if staging is None or store_attachments is None:
                raise ApiError(ErrorCode.VALIDATION_FIELD_TYPE, user_message="Sending files over the socket is not available here.")
            # Refuse before any storage work if the sender could not post here anyway.
            await ctx.in_thread_unless_access_changed(authorizer.require_send, ctx.principal, data.channel_id)
            files = staging.collect(ctx.principal.id, data.upload_ids)
            attachments = await store_attachments(ctx.principal, data.channel_id, files)
        outcome = await asyncio.to_thread(
            messages.create,
            ctx.principal,
            data.channel_id,
            data.content,
            sticker_ids=data.sticker_ids,
            attachments=attachments,
            reply_to_message_id=data.reply_to_message_id,
        )
        if data.upload_ids and staging is not None:
            staging.discard(ctx.principal.id, data.upload_ids)  # kept until here so a failed send can be retried
        return HandlerOutput(result={"message": outcome.value["message"]}, events=outcome.events)

    async def upload_begin(ctx: ConnectionContext, data: schema.UploadBegin) -> HandlerOutput:
        upload = staging.begin(ctx.principal.id, data.name, data.content_type, data.size)
        return HandlerOutput(result={"upload_id": upload.upload_id, "chunk_size": CHUNK_BYTES, "size": upload.size})

    async def upload_chunk(ctx: ConnectionContext, data: schema.UploadChunk) -> HandlerOutput:
        try:
            raw = base64.b64decode(data.data, validate=True)
        except (binascii.Error, ValueError):
            raise ApiError(ErrorCode.VALIDATION_FIELD_TYPE, user_message="`data` is not valid base64.", details={"field": "data"}) from None
        upload, duplicate = staging.append(ctx.principal.id, data.upload_id, data.index, raw)
        return HandlerOutput(
            result={"upload_id": upload.upload_id, "received": upload.received, "size": upload.size, "complete": upload.complete, "duplicate": duplicate}
        )

    async def upload_abort(ctx: ConnectionContext, data: schema.UploadAbort) -> HandlerOutput:
        staging.abort(ctx.principal.id, data.upload_id)
        return HandlerOutput(result={"upload_id": data.upload_id, "aborted": True})

    async def message_edit(ctx: ConnectionContext, data: schema.MessageEdit) -> HandlerOutput:
        outcome = await asyncio.to_thread(messages.edit, ctx.principal, data.channel_id, data.message_id, data.content)
        return HandlerOutput(result=outcome.value, events=outcome.events)

    async def message_delete(ctx: ConnectionContext, data: schema.MessageDelete) -> HandlerOutput:
        outcome = await asyncio.to_thread(messages.delete, ctx.principal, data.channel_id, data.message_id)
        return HandlerOutput(result=outcome.value, events=outcome.events)

    async def reaction_add(ctx: ConnectionContext, data: schema.ReactionChange) -> HandlerOutput:
        outcome = await asyncio.to_thread(messages.add_reaction, ctx.principal, data.channel_id, data.message_id, data.emoji)
        return HandlerOutput(result=outcome.value, events=outcome.events)

    async def reaction_remove(ctx: ConnectionContext, data: schema.ReactionChange) -> HandlerOutput:
        outcome = await asyncio.to_thread(messages.remove_reaction, ctx.principal, data.channel_id, data.message_id, data.emoji)
        return HandlerOutput(result=outcome.value, events=outcome.events)

    async def channel_subscribe(ctx: ConnectionContext, data: schema.ChannelRef) -> HandlerOutput:
        if not await ctx.in_thread_unless_access_changed(authorizer.can_subscribe, ctx.principal, data.channel_id):
            # Same answer for "does not exist" and "not yours": existence is not disclosed.
            raise ApiError(ErrorCode.CHANNELS_NOT_FOUND, details={"channel_id": data.channel_id})
        ctx.subscriptions.add(data.channel_id)
        await publisher.ensure_loaded(data.channel_id)  # so `seq` is the channel's real position after a restart
        return HandlerOutput(
            result={
                "channel_id": data.channel_id,
                "subscribed": True,
                "seq": publisher.current_seq(data.channel_id),
                "epoch": publisher.epoch,
            }
        )

    async def channel_unsubscribe(ctx: ConnectionContext, data: schema.ChannelRef) -> HandlerOutput:
        ctx.subscriptions.discard(data.channel_id)
        return HandlerOutput(result={"channel_id": data.channel_id, "subscribed": False})

    async def events_resync(ctx: ConnectionContext, data: schema.EventsResync) -> HandlerOutput:
        recent = await asyncio.to_thread(messages.recent, ctx.principal, data.channel_id, data.limit)
        await publisher.ensure_loaded(data.channel_id)
        return HandlerOutput(
            result={
                "channel_id": data.channel_id,
                "messages": recent,
                "seq": publisher.current_seq(data.channel_id),
                "epoch": publisher.epoch,
            }
        )

    async def typing_start(ctx: ConnectionContext, data: schema.TypingStart) -> HandlerOutput:
        user_id = ctx.principal.accountable_user_id
        typing = {"user_id": ctx.principal.id, "expires_in_ms": TYPING_EXPIRES_MS}

        if data.channel_id is not None:
            # Only someone who could send here may announce they are about to.
            await asyncio.to_thread(authorizer.require_send, ctx.principal, data.channel_id)
            await asyncio.to_thread(authorizer.require_not_timed_out, ctx.principal, "send messages")
            event = DomainEvent(
                name=TYPING_STARTED,
                data={"channel_id": data.channel_id, **typing},
                channel_id=data.channel_id,
                sequenced=False,
            )
            return HandlerOutput(result={"delivered": True}, events=[event])

        # A DM: the same answer whether the conversation is unknown, not yours, or with a
        # remote peer (typing is not federated), so nothing about it is disclosed.
        peer = None if ctx.principal.is_bot or dm_peer is None else await asyncio.to_thread(dm_peer, data.conversation_id, user_id)
        if peer is None:
            return HandlerOutput(result={"delivered": False})
        event = DomainEvent(
            name=TYPING_STARTED,
            data={"conversation_id": data.conversation_id, **typing},
            target_user_id=peer,
        )
        return HandlerOutput(result={"delivered": True}, events=[event])

    def nonce_key(data: schema.MessageCreate) -> str | None:
        return data.nonce

    specs = [
        CommandSpec("message.create", schema.MessageCreate, message_create, idempotency_key=nonce_key),
        CommandSpec("message.edit", schema.MessageEdit, message_edit),
        CommandSpec("message.delete", schema.MessageDelete, message_delete),
        CommandSpec("reaction.add", schema.ReactionChange, reaction_add),
        CommandSpec("reaction.remove", schema.ReactionChange, reaction_remove),
        CommandSpec("channel.subscribe", schema.ChannelRef, channel_subscribe),
        CommandSpec("channel.unsubscribe", schema.ChannelRef, channel_unsubscribe),
        CommandSpec("events.resync", schema.EventsResync, events_resync),
        CommandSpec("typing.start", schema.TypingStart, typing_start),
    ]
    if staging is not None:
        specs += [
            CommandSpec("upload.begin", schema.UploadBegin, upload_begin),
            CommandSpec("upload.chunk", schema.UploadChunk, upload_chunk),
            CommandSpec("upload.abort", schema.UploadAbort, upload_abort),
        ]
    return {spec.name: spec for spec in specs}
