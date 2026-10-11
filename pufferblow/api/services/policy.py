"""Instance-wide message limits, shared by every transport."""

from __future__ import annotations


def message_policy(database_handler, storage_manager, config):
    """Build the ``(max_message_length, max_total_attachment_mb)`` provider.

    Storage is optional on an instance: without it text messages keep working and
    only uploads are unavailable, so the attachment limit falls back to a default.
    """

    def policy() -> tuple[int, int]:
        settings = database_handler.get_server_settings()
        if storage_manager is not None:
            storage_manager.update_server_limits()

        max_message_length = getattr(settings, "max_message_length", None) or config.MAX_MESSAGE_SIZE
        max_attachment_mb = getattr(storage_manager, "MAX_TOTAL_ATTACHMENT_SIZE_MB", 50)
        return int(max_message_length), int(max_attachment_mb)

    return policy
