from sqlalchemy import (
    Column,
    String,
    DateTime
)

# Decrlarative base class
from pufferblow.src.database.tables.declarative_base import Base

# Utils
from pufferblow.src.utils.current_date import date_in_gmt

class Salts(Base):
    """ `Salts` table """
    __tablename__ = "salts"

    salt_value      =   Column(String, primary_key=True, nullable=False)
    hashed_data     =   Column(String)
    user_id         =   Column(String)
    associated_to   =   Column(String)
    created_at      =   Column(DateTime, default=date_in_gmt("%Y-%m-%d %H:%M:%S"))
    updated_at      =   Column(DateTime)
    
    def __repr__(self):
        return f"Salts(salt_value={self.salt_value!r}, hashed_data={self.hashed_data!r}, user_id={self.hashed_data!r}, associated_to={self.associated_to!r}, created_at={self.created_at!r}, updated_at={self.updated_at!r})"
