from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

# Base
from pufferblow.api.database.tables.declarative_base import Base


class FileObjects(Base):
    """SQLAlchemy model representing the file_objects table.

    This table tracks physical files with reference counting and integrity metadata.

    Attributes:
        file_hash (Mapped[str]): SHA-256 hash of file content (primary key).
        ref_count (Mapped[int]): Number of references to this file.
        file_path (Mapped[str]): Relative path to file within CDN storage.
        filename (Mapped[str]): Original filename of the uploaded file.
        file_size (Mapped[int]): File size in bytes.
        mime_type (Mapped[str]): Detected MIME type of file.
        created_at (Mapped[datetime]): When file was first stored.
        last_referenced (Mapped[datetime]): When file was last referenced.
        verification_status (Mapped[str]): Integrity verification status.
        integrity_signature (Mapped[Optional[str]]): Cryptographic signature for integrity.

    Example:
        >>> file_obj = FileObjects(
        ...     file_hash="abc123...",
        ...     ref_count=1,
        ...     file_path="avatars/uuid.png",
        ...     filename="avatar.png"
        ... )
    """

    __tablename__ = "file_objects"

    file_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    ref_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    file_path: Mapped[str] = mapped_column(String, nullable=False, unique=True, index=True)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    file_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    mime_type: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    last_referenced: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
    verification_status: Mapped[str] = mapped_column(String(50), default="unverified")
    integrity_signature: Mapped[str | None] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return (
            f"FileObjects(file_hash={self.file_hash!r}, "
            f"ref_count={self.ref_count!r}, "
            f"file_path={self.file_path!r}, "
            f"file_size={self.file_size!r}, "
            f"mime_type={self.mime_type!r}, "
            f"verification_status={self.verification_status!r}, "
            f"created_at={self.created_at!r})"
        )


class FileReferences(Base):
    """SQLAlchemy model representing the file_references table.

    This table links logical references (like user avatars) to physical files.

    Attributes:
        reference_id (Mapped[str]): Unique identifier for this reference.
        file_hash (Mapped[str]): SHA-256 hash linking to file_objects.
        reference_type (Mapped[str]): Type of reference ('user_avatar', 'user_banner', etc.).
        reference_entity_id (Mapped[str]): ID of entity being referenced (user_id, message_id, etc.).
        created_at (Mapped[datetime]): When reference was created.

    Example:
        >>> ref = FileReferences(
        ...     reference_id="uuid-123",
        ...     file_hash="abc123...",
        ...     reference_type="user_avatar",
        ...     reference_entity_id="user-uuid"
        ... )
    """

    __tablename__ = "file_references"

    reference_id: Mapped[str] = mapped_column(String, primary_key=True)
    file_hash: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("file_objects.file_hash", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    reference_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    reference_entity_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    def __repr__(self) -> str:
        return (
            f"FileReferences(reference_id={self.reference_id!r}, "
            f"file_hash={self.file_hash!r}, "
            f"reference_type={self.reference_type!r}, "
            f"reference_entity_id={self.reference_entity_id!r})"
        )
