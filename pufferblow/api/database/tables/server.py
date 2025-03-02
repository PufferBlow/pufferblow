from sqlalchemy import (
    Column,
    String,
    DateTime,
    Integer
)

# Decrlarative base class
from pufferblow.api.database.tables.declarative_base import Base

# Utils
from pufferblow.api.utils.current_date import date_in_gmt

class Server(Base):
    """ server table """
    __tablename__ = "server"

    server_id = Column(String, primary_key=True, nullable=False)
    server_name = Column(String, nullable=False)
    description = Column(String, nullable=True)
    server_welcome_message = Column(String, nullable=False)
    members_count = Column(Integer, default=0, nullable=False)
    online_members = Column(Integer, default=0, nullable=False)
    updated_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=date_in_gmt(), nullable=False)
    
    def __repr__(self) -> str:
        return f"Server(server_id={self.server_id!r}, server_name={self.server_name!r}, description={self.description!r}, server_welcome_message={self.server_welcome_message!r}. updated_at={self.updated_at!r}. created_at={self.created_at!r})"

