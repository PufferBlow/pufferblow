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

class Server(Base):
    """ server table """
    __tablename__ = "server"

    server_id               =   Column(String, primary_key=True, nullable=False)
    server_name             =   Column(String, nullable=False)
    host_port               =   Column(String, nullable=False)
    description             =   Column(String, nullable=True)
    avatar_url              =   Column(String, nullable=True)
    banner_url              =   Column(String, nullable=True)
    welcome_message         =   Column(String, nullable=False)
    members_count           =   Column(Integer, default=0, nullable=False)
    online_members          =   Column(Integer, default=0, nullable=False)

    # Server settings
    is_private                  =   Column(Boolean, default=False, nullable=False)
    max_message_length          =   Column(Integer, default=50_000, nullable=False)
    max_image_size              =   Column(Integer, default=5, nullable=False) # In MB
    max_video_size              =   Column(Integer, default=50, nullable=False) # In MB
    allowed_images_extensions   =   Column(ARRAY(String), default=["png", "jpg", "jpeg", "gif", "webp"], nullable=False)
    allowed_videos_extensions   =   Column(ARRAY(String), default=["mp4", "webm"], nullable=False)
    allowed_doc_extensions      =   Column(ARRAY(String), default=["pdf", "doc", "docx", "txt", "zip"], nullable=False)
    
    # Server stats
    stats_id                    =   Column(String, nullable=False)

    updated_at              =   Column(DateTime, nullable=True)
    created_at              =   Column(DateTime, default=date_in_gmt(), nullable=False)
    
    def __repr__(self) -> str:
        return f"Server(server_id={self.server_id!r}, server_name={self.server_name!r}, description={self.description!r}, avatar_url={self.avatar_url!r}, banner_url={self.banner_url!r}, welcome_message={self.welcome_message!r}, updated_at={self.updated_at!r}, created_at={self.created_at!r})"

