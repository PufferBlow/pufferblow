from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from sqlalchemy import String, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from pufferblow.api.database.tables.declarative_base import Base
from pufferblow.api.utils.current_date import date_in_gmt


class BlockedIPS(Base):
    """BlockedIPS table"""
    __tablename__ = "blocked_ips"

    ip_id: Mapped[str] = mapped_column(String, primary_key=True, nullable=False)
    ip: Mapped[str] = mapped_column(String, nullable=False)
    block_reason: Mapped[str] = mapped_column(String, nullable=False)
    blocked_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: date_in_gmt("%Y-%m-%d %H:%M:%S"),
        nullable=False
    )

    def __repr__(self):
        return (
            f"BlockedIPS(ip_id={self.ip_id!r}, ip={self.ip!r}, "
            f"block_reason={self.block_reason!r}, blocked_at={self.blocked_at!r})"
        )

    def to_dict(self) -> dict:
        return {
            "ip_id"         :   self.ip_id,
            "ip"            :   self.ip,
            "block_reason"  :   self.block_reason,
            "blocked_at"    :   self.blocked_at
        }
    

# from sqlalchemy import (
#     Column,
#     String,
#     DateTime,
# )

# # Decrlarative base class
# from pufferblow.api.database.tables.declarative_base import Base

# # Utils
# from pufferblow.api.utils.current_date import date_in_gmt

# class BlockedIPS(Base):
#     """ `blocked_ips` table """
#     __tablename__ = "blocked_ips"

#     ip_id           =   Column(String, primary_key=True, nullable=False)
#     ip              =   Column(String, nullable=False)
#     block_reason    =   Column(String, nullable=False)
#     blocked_at      =   Column(DateTime, default=date_in_gmt("%Y-%m-%d %H:%M:%S"), nullable=False)

#     def __repr__(self):
#         return f"BlockedIPS(ip_id={self.ip_id!r}, ip={self.ip!r}, block_reason={self.block_reason!r}, blocked_at={self.blocked_at!r})"
