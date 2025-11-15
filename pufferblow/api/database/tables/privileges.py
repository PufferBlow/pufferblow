from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from pufferblow.api.database.tables.declarative_base import Base
from pufferblow.api.utils.current_date import date_in_gmt


class Privileges(Base):
    """Privileges table"""

    __tablename__ = "privileges"

    privilege_id: Mapped[str] = mapped_column(String, primary_key=True, nullable=False)
    privilege_name: Mapped[str] = mapped_column(String, nullable=False)
    category: Mapped[str] = mapped_column(String, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=date_in_gmt, nullable=False
    )
    updated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    def __repr__(self) -> str:
        return (
            f"Privileges(privilege_id={self.privilege_id!r}, "
            f"privilege_name={self.privilege_name!r}, "
            f"category={self.category!r}, "
            f"created_at={self.created_at!r}, "
            f"updated_at={self.updated_at!r})"
        )


# from sqlalchemy import (
#     Column,
#     String,
#     DateTime,
#     ARRAY
# )

# # Declarative base class
# from pufferblow.api.database.tables.declarative_base import Base

# # Utils
# from pufferblow.api.utils.current_date import date_in_gmt

# class Privileges(Base):
#     """ privileges table """
#     __tablename__ = "privileges"

#     privilege_id        =  Column(String, primary_key=True, nullable=False)
#     privilege_name      =  Column(String, nullable=False)
#     category            =  Column(String, nullable=False)
#     created_at          =  Column(DateTime, default=date_in_gmt(), nullable=False)
#     updated_at          =  Column(DateTime, nullable=True)
