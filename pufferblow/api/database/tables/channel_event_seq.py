"""The highest event sequence number a channel may already have used.

Channel events carry a per-channel ``seq`` so a client can tell when it missed one. The counter lives in
memory; this table keeps a *high-water mark* of it (reserved in blocks, see ``InProcessPublisher``), so after
a restart a channel's numbers continue above anything sent before instead of starting again at 1.
"""

from __future__ import annotations

from sqlalchemy import BigInteger, String
from sqlalchemy.orm import Mapped, mapped_column

from pufferblow.api.database.tables.declarative_base import Base


class ChannelEventSeq(Base):
    __tablename__ = "channel_event_seq"

    channel_id: Mapped[str] = mapped_column(String, primary_key=True, nullable=False)
    #: No event of this channel has been sent with a number above this.
    high_water: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
