"""Storing a message's attachments, for every way a message can arrive.

The HTTP ``send_message`` route and the socket's ``message.create`` (with ``upload_ids``) both end up here, so
the size limit, the storage rules, the image placeholders and the audit trail are the same for both.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import UploadFile, exceptions
from loguru import logger


def measure_upload_size(file: UploadFile) -> int:
    """Measure an uploaded file without consuming its stream permanently."""
    if hasattr(file.file, "getbuffer"):
        return len(file.file.getbuffer())

    current_position = file.file.tell()
    file.file.seek(0, 2)
    size = file.file.tell()
    file.file.seek(current_position)
    return size


async def store_attachments(principal, channel_id: str, files: list[UploadFile], *, max_total_mb: int) -> list[dict]:
    """Store each file and return the attachment objects a message carries.

    Raises ``HTTPException`` (400 for a refused file or an oversized set, 503 when the instance has no storage,
    500 for an unexpected failure); the socket maps those to its own error codes.
    """
    from pufferblow.core.bootstrap import api_initializer

    files = [file for file in files if file.filename]
    if not files:
        return []
    if api_initializer.storage_manager is None:
        raise exceptions.HTTPException(status_code=503, detail="File uploads are disabled on this server.")

    total_bytes = sum(measure_upload_size(file) for file in files)
    if total_bytes > max_total_mb * 1024 * 1024:
        raise exceptions.HTTPException(
            status_code=400,
            detail=f"Combined attachment size exceeds the instance limit of {max_total_mb}MB.",
        )

    attachment_objects: list[dict] = []
    for file in files:
        try:
            storage_url, is_duplicate, filename, mime_type, file_size = await api_initializer.storage_manager.upload_file(
                file=file,
                user_id=principal.id,
                reference_type="message_attachment",
                check_duplicates=True,
            )
            # A placeholder for images lets a client paint something while the full file loads; other
            # types get None and a type-specific placeholder on the client.
            lqip_url = None
            if mime_type.startswith("image/") and mime_type != "image/gif":
                from pufferblow.api.user.user_manager import _resolve_storage_lqip_url

                lqip_url = _resolve_storage_lqip_url(storage_url, api_initializer.database_handler)
            attachment_objects.append(
                {"url": storage_url, "lqip_url": lqip_url, "filename": filename, "type": mime_type, "size": file_size}
            )

            try:
                api_initializer.database_handler.create_activity(
                    {
                        "event_type": "message_attachment",
                        "description": f"Attachment '{filename}' uploaded for message in channel {channel_id}",
                        "metadata": {
                            "file_url": storage_url,
                            "file_size": file_size,
                            "file_type": mime_type,
                            "channel_id": channel_id,
                            "is_duplicate": is_duplicate,
                        },
                        "user_id": principal.id,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )
            except Exception as exc:
                logger.warning(f"Failed to log attachment upload activity: {exc}")

        except exceptions.HTTPException:
            raise
        except Exception as exc:
            logger.error(f"Failed to upload attachment '{file.filename}': {exc}")
            raise exceptions.HTTPException(
                status_code=500,
                detail=f"Failed to upload attachment '{file.filename}'. Please try again.",
            ) from exc

    return attachment_objects
