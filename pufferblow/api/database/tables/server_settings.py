from sqlalchemy import (
    Column,
    String,
    DateTime,
    Integer,
    Boolean,
    ARRAY
)

# Decrlarative base class
from pufferblow.api.database.tables.declarative_base import Base

# Utils
from pufferblow.api.utils.current_date import date_in_gmt

class ServerSettings(Base):
    """ ServerSettings table """
    __tablename__ = "server_settings"

    server_settings_id          =   Column(String, primary_key=True, nullable=False, default="global_settings")
    is_private                  =   Column(Boolean, default=False, nullable=False)
    max_message_length          =   Column(Integer, default=50_000, nullable=False)
    max_image_size              =   Column(Integer, default=5, nullable=False) # In MB
    max_video_size              =   Column(Integer, default=50, nullable=False) # In MB
    max_sticker_size            =   Column(Integer, default=5, nullable=False) # In MB
    max_gif_size                =   Column(Integer, default=10, nullable=False)  # 10MB for animated content
    allowed_images_extensions   =   Column(ARRAY(String), default=["png", "jpg", "jpeg", "gif", "webp"], nullable=False)
    allowed_stickers_extensions =   Column(ARRAY(String), default=["png", "gif"], nullable=False)
    allowed_gif_extensions      =   Column(ARRAY(String), default=["gif"], nullable=False)
    allowed_videos_extensions   =   Column(ARRAY(String), default=["mp4", "webm"], nullable=False)
    allowed_doc_extensions      =   Column(ARRAY(String), default=["pdf", "doc", "docx", "txt", "zip"], nullable=False)
    rate_limit_duration         =   Column(Integer, default=5, nullable=False)  # In minutes
    max_rate_limit_requests     =   Column(Integer, default=6000, nullable=False)
    max_rate_limit_warnings     =   Column(Integer, default=15, nullable=False)
    updated_at                  =   Column(DateTime, nullable=True)
    created_at                  =   Column(DateTime, default=date_in_gmt(), nullable=False)
    
    def __repr__(self) -> str:
        return f"Server(server_settings_id={self.server_settings_id!r}, is_private={self.is_private!r}, max_message_length={self.max_message_length!r}, max_image_size={self.max_image_size!r}, max_video_size={self.max_video_size!r}, allowed_images_extensions={self.allowed_images_extensions!r}, allowed_videos_extensions={self.allowed_videos_extensions!r}, allowed_doc_extensions={self.allowed_doc_extensions!r}, updated_at={self.updated_at!r}, created_at={self.created_at!r})"
