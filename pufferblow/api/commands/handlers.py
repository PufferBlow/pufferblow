"""Command handlers for protocol v1.

Each handler is a thin translation layer: it unpacks an already-validated
payload, calls the shared service, and returns a result plus domain events.
Business rules live in :mod:`pufferblow.api.services`, not here.
"""

from __future__ import annotations

from pufferblow.api.commands.dispatcher import CommandSpec, ConnectionContext, HandlerOutput
from pufferblow.api.errors import ApiError, ErrorCode
from pufferblow.api.principals.authorizer import Authorizer
from pufferblow.api.protocol import commands as schema
from pufferblow.api.services.messages import MessageService


def build_registry(*, messages: MessageService, authorizer: Authorizer, publisher) -> dict[str, CommandSpec]:
    async def message_create(ctx: ConnectionContext, data: schema.MessageCreate) -> HandlerOutput:
        outcome = messages.create(ctx.principal, data.channel_id, data.content, sticker_ids=data.sticker_ids)
        return HandlerOutput(result={"message": outcome.value["message"]}, events=outcome.events)

    async def message_edit(ctx: ConnectionContext, data: schema.MessageEdit) -> HandlerOutput:
        outcome = messages.edit(ctx.principal, data.channel_id, data.message_id, data.content)
        return HandlerOutput(result=outcome.value, events=outcome.events)

    async def message_delete(ctx: ConnectionContext, data: schema.MessageDelete) -> HandlerOutput:
        outcome = messages.delete(ctx.principal, data.channel_id, data.message_id)
        return HandlerOutput(result=outcome.value, events=outcome.events)

    async def reaction_add(ctx: ConnectionContext, data: schema.ReactionChange) -> HandlerOutput:
        outcome = messages.add_reaction(ctx.principal, data.channel_id, data.message_id, data.emoji)
        return HandlerOutput(result=outcome.value, events=outcome.events)

    async def reaction_remove(ctx: ConnectionContext, data: schema.ReactionChange) -> HandlerOutput:
        outcome = messages.remove_reaction(ctx.principal, data.channel_id, data.message_id, data.emoji)
        return HandlerOutput(result=outcome.value, events=outcome.events)

    async def channel_subscribe(ctx: ConnectionContext, data: schema.ChannelRef) -> HandlerOutput:
        if not authorizer.can_subscribe(ctx.principal, data.channel_id):
            # Same answer for "does not exist" and "not yours": existence is not disclosed.
            raise ApiError(ErrorCode.CHANNELS_NOT_FOUND, details={"channel_id": data.channel_id})
        ctx.subscriptions.add(data.channel_id)
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
        recent = messages.recent(ctx.principal, data.channel_id, data.limit)
        return HandlerOutput(
            result={
                "channel_id": data.channel_id,
                "messages": recent,
                "seq": publisher.current_seq(data.channel_id),
                "epoch": publisher.epoch,
            }
        )

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
    ]
    return {spec.name: spec for spec in specs}
