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

class Roles(Base): 
    """ roles table """
    __tablename__ = "roles"

    role_id = Column(String, primary_key=True, nullable=False)
    role_name = Column(String, nullable=False)
    privileges_ids  = Column(ARRAY(String), nullable=False)

    created_at = Column(DateTime, default=date_in_gmt(), nullable=False)
    updated_at = Column(DateTime, nullable=True)

    def __repr__(self) -> str:
        return f"Roles(role_id={self.role_id!r}, role_name={self.role_name!r}, privileges_ids={self.privileges_ids!r}, created_at={self.created_at!r}, updated_at={self.updated_at!r})"
