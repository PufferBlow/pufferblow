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


MAX_DESCRIPTION_LENGTH = 1000
#: Only pictures and video are described; other files are told apart by their name and type.
DESCRIBABLE_TYPES = ("image/", "video/")


def clean_descriptions(raw: str | list | None, count: int) -> list[str]:
    """The per-file descriptions a client sent, as one string per file (empty when none).

    ``raw`` is a JSON list of strings in the same order as the files. Anything else (not JSON, not a list, a
    non-string entry) is ignored rather than failing the send, and each text is trimmed and cut to
    ``MAX_DESCRIPTION_LENGTH``.
    """
    import json

    if isinstance(raw, str):
        try:
            raw = json.loads(raw) if raw.strip() else []
        except ValueError:
            raw = []
    items = raw if isinstance(raw, list) else []
    cleaned = [item.strip()[:MAX_DESCRIPTION_LENGTH] if isinstance(item, str) else "" for item in items]
    return (cleaned + [""] * count)[:count]


async def store_attachments(
    principal, channel_id: str, files: list[UploadFile], *, max_total_mb: int, descriptions: list[str] | None = None
) -> list[dict]:
    """Store each file and return the attachment objects a message carries.

    Raises ``HTTPException`` (400 for a refused file or an oversized set, 503 when the instance has no storage,
    500 for an unexpected failure); the socket maps those to its own error codes.
    """
    from pufferblow.core.bootstrap import api_initializer

    described = list(descriptions or []) + [""] * len(files)
    paired = [(file, described[i]) for i, file in enumerate(files) if file.filename]
    files = [file for file, _ in paired]
    texts = [text for _, text in paired]
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
    for file, description in zip(files, texts):
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
            # A file the instance already holds comes back under the name of whoever sent it first. The name belongs
            # to this message (it carries the SPOILER_ marker), so a repeat keeps the name it was sent with.
            if is_duplicate:
                filename = file.filename
            attachment = {"url": storage_url, "lqip_url": lqip_url, "filename": filename, "type": mime_type, "size": file_size}
            if description and mime_type.startswith(DESCRIBABLE_TYPES):
                attachment["description"] = description  # what the file shows, for people who cannot see it
            attachment_objects.append(attachment)

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
