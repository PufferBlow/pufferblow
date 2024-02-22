from sqlalchemy import (
    Column,
    String,
    DateTime,
)

# Decrlarative base class
from pufferblow.src.database.tables.declarative_base import Base

# Utils
from pufferblow.src.utils.current_date import date_in_gmt

class BlockedIPS(Base):
    """ `blocked_ips` table """
    __tablename__ = "blocked_ips"

    ip_id           =   Column(String, primary_key=True, nullable=False)
    ip              =   Column(String, nullable=False)
    block_reason    =   Column(String, nullable=False)
    blocked_at      =   Column(DateTime, default=date_in_gmt("%Y-%m-%d %H:%M:%S"), nullable=False)

    def __repr__(self):
        return f"BlockedIPS(ip_id={self.ip_id!r}, ip={self.ip!r}, block_reason={self.block_reason!r}, blocked_at={self.blocked_at!r})"
