"""Telling the people who decide that someone asked to join, and the person who asked what was decided."""

from __future__ import annotations

from loguru import logger

from pufferblow.api.protocol.events import JOIN_REQUEST_CREATED, JOIN_REQUEST_DECIDED, DomainEvent
from pufferblow.core.bootstrap import api_initializer


async def announce_join_request(request: dict) -> None:
    """A realtime event to everyone who may approve (the owner and moderators), carrying the request and how many wait."""
    try:
        database = api_initializer.database_handler
        pending = database.count_join_requests("pending")
        events = [
            DomainEvent(name=JOIN_REQUEST_CREATED, data={"request": request, "pending": pending}, target_user_id=user_id, sequenced=False)
            for user_id in database.user_ids_with_privilege("manage_join_requests")
        ]
        await api_initializer.event_publisher.publish_all(events)
    except Exception:
        # Telling people is a courtesy; the request is saved and shows up in the list either way.
        logger.exception("Could not announce a join request")


async def announce_decision(request: dict) -> None:
    """A realtime event to a local person whose request was decided (a federated one asks again from their own server)."""
    user_id = request.get("user_id")
    if not user_id:
        return
    try:
        await api_initializer.event_publisher.publish_all(
            [DomainEvent(name=JOIN_REQUEST_DECIDED, data={"request": request}, target_user_id=str(user_id), sequenced=False)]
        )
    except Exception:
        logger.exception("Could not announce a join decision")
