from sqlalchemy import (
    Column,
    String,
    DateTime
)

# Decrlarative base class
from pufferblow_api.src.database.tables.declarative_base import Base

class AuthTokens(Base):
    """ `AuthToken` table """
    __tablename__ = "auth_tokens"

    auth_token              =   Column(String, primary_key=True, nullable=False)
    auth_token_expire_time  =   Column(DateTime)
    user_id                 =   Column(String)
    updated_at              =   Column(DateTime, nullable=True)

    def __repr__(self):
        return f"AuthTokens(auth_token={self.auth_token!r}, auth_token_expire_time={self.auth_token_expire_time!r}, user_id={self.user_id!r}, updated_at={self.updated_at!r}"
