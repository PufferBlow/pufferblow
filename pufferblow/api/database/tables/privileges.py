from sqlalchemy import (
    Column,
    String,
    DateTime,
    ARRAY
)

# Declarative base class
from pufferblow.api.database.tables.declarative_base import Base

# Utils
from pufferblow.api.utils.current_date import date_in_gmt

class Privileges(Base):
    """ privileges table """
    __tablename__ = "privileges"

    privilege_id    = Column(String, primary_key=True, nullable=False)
    privilege_name  = Column(String, nullable=False)

    created_at = Column(DateTime, default=date_in_gmt(), nullable=False)
    updated_at = Column(DateTime, nullable=True)

