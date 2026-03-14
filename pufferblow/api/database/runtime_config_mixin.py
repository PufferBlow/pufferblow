"""Runtime configuration mixin for database handler."""

from __future__ import annotations

import datetime
import json

from loguru import logger

from pufferblow.api.database.tables.instance_runtime_config import InstanceRuntimeConfig
from pufferblow.api.database.tables.server_settings import ServerSettings


class DatabaseRuntimeConfigMixin:
    def _ensure_default_server_settings(self) -> None:
        """
        Ensure that default server settings exist in the database.
        This is called during table setup to guarantee server settings are available.
        """
        # Skip for SQLite tests where server_settings table is not created
        database_uri = str(self.database_engine.url)
        if database_uri.startswith("sqlite://"):
            return

        try:
            with self.database_session() as session:
                # Check if server settings already exist
                existing_settings = session.query(ServerSettings).first()

                if existing_settings:
                    logger.debug(
                        "Server settings already exist, skipping initialization"
                    )
                    return

                logger.info("Inserting default server settings")

                # Create default server settings
                server_settings = ServerSettings(
                    server_settings_id="global_settings",
                    is_private=False,
                    max_message_length=50000,
                    max_image_size=5,  # 5MB
                    max_video_size=50,  # 50MB
                    max_sticker_size=5,  # 5MB
                    max_gif_size=10,  # 10MB for animated GIFs
                    allowed_images_extensions=["png", "jpg", "jpeg", "gif", "webp"],
                    allowed_stickers_extensions=[
                        "png",
                        "gif",
                    ],  # Stickers support PNG and GIF
                    allowed_gif_extensions=["gif"],  # Standalone GIFs
                    allowed_videos_extensions=["mp4", "webm"],
                    allowed_doc_extensions=["pdf", "doc", "docx", "txt", "zip"],
                    rate_limit_duration=5,  # 5 minutes
                    max_rate_limit_requests=6000,  # 6000 requests per window
                    max_rate_limit_warnings=15,  # 15 warnings before blocking
                )

                session.add(server_settings)
                session.commit()

                logger.info("Default server settings inserted successfully")

        except Exception as e:
            logger.error(f"Failed to ensure default server settings: {str(e)}")
            raise

    def _runtime_defaults(self) -> dict[str, tuple[object, bool]]:
        """
        Build default runtime config map from the current config model.

        Returns:
            dict[str, tuple[object, bool]]: Runtime setting key -> (value, is_secret)
        """
        cfg = self.config
        return {
            "API_HOST": (cfg.API_HOST, False),
            "API_PORT": (cfg.API_PORT, False),
            "LOGS_PATH": (cfg.LOGS_PATH, False),
            "WORKERS": (cfg.WORKERS, False),
            "RATE_LIMIT_DURATION": (cfg.RATE_LIMIT_DURATION, False),
            "MAX_RATE_LIMIT_REQUESTS": (cfg.MAX_RATE_LIMIT_REQUESTS, False),
            "MAX_RATE_LIMIT_WARNINGS": (cfg.MAX_RATE_LIMIT_WARNINGS, False),
            "JWT_SECRET": (cfg.JWT_SECRET, True),
            "JWT_ACCESS_TTL_MINUTES": (cfg.JWT_ACCESS_TTL_MINUTES, False),
            "JWT_REFRESH_TTL_DAYS": (cfg.JWT_REFRESH_TTL_DAYS, False),
            "VOICE_BACKEND": (cfg.VOICE_BACKEND, False),
            "RTC_SIGNALING_URL": (cfg.RTC_SIGNALING_URL, False),
            "RTC_JOIN_TOKEN_TTL_SECONDS": (cfg.RTC_JOIN_TOKEN_TTL_SECONDS, False),
            "RTC_JOIN_SECRET": (cfg.RTC_JOIN_SECRET, True),
            "RTC_INTERNAL_SECRET": (cfg.RTC_INTERNAL_SECRET, True),
            "RTC_BOOTSTRAP_SECRET": (cfg.RTC_BOOTSTRAP_SECRET, True),
            "RTC_INTERNAL_API_BASE": (cfg.RTC_INTERNAL_API_BASE, False),
            "RTC_STUN_SERVERS": (cfg.RTC_STUN_SERVERS, False),
            "TURN_URL": (cfg.TURN_URL, False),
            "TURN_USERNAME": (cfg.TURN_USERNAME, False),
            "TURN_PASSWORD": (cfg.TURN_PASSWORD, True),
            "RTC_MAX_TOTAL_PEERS": (cfg.RTC_MAX_TOTAL_PEERS, False),
            "RTC_MAX_ROOM_PEERS": (cfg.RTC_MAX_ROOM_PEERS, False),
            "RTC_ROOM_END_GRACE_SECONDS": (cfg.RTC_ROOM_END_GRACE_SECONDS, False),
            "RTC_INTERNAL_EVENT_WORKERS": (cfg.RTC_INTERNAL_EVENT_WORKERS, False),
            "RTC_INTERNAL_EVENT_QUEUE_SIZE": (cfg.RTC_INTERNAL_EVENT_QUEUE_SIZE, False),
            "RTC_INTERNAL_HTTP_TIMEOUT_SECONDS": (cfg.RTC_INTERNAL_HTTP_TIMEOUT_SECONDS, False),
            "RTC_WS_WRITE_TIMEOUT_SECONDS": (cfg.RTC_WS_WRITE_TIMEOUT_SECONDS, False),
            "RTC_WS_PING_INTERVAL_SECONDS": (cfg.RTC_WS_PING_INTERVAL_SECONDS, False),
            "RTC_WS_PONG_WAIT_SECONDS": (cfg.RTC_WS_PONG_WAIT_SECONDS, False),
            "RTC_WS_READ_LIMIT_BYTES": (cfg.RTC_WS_READ_LIMIT_BYTES, False),
            "RTC_UDP_PORT_MIN": (cfg.RTC_UDP_PORT_MIN, False),
            "RTC_UDP_PORT_MAX": (cfg.RTC_UDP_PORT_MAX, False),
            "RTC_DEFAULT_QUALITY_PROFILE": (cfg.RTC_DEFAULT_QUALITY_PROFILE, False),
            "RTC_AUDIO_SAMPLE_RATE_HZ": (cfg.RTC_AUDIO_SAMPLE_RATE_HZ, False),
            "RTC_AUDIO_CHANNELS": (cfg.RTC_AUDIO_CHANNELS, False),
            "RTC_AUDIO_STEREO_ENABLED": (cfg.RTC_AUDIO_STEREO_ENABLED, False),
            "RTC_AUDIO_DTX_ENABLED": (cfg.RTC_AUDIO_DTX_ENABLED, False),
            "RTC_AUDIO_FEC_ENABLED": (cfg.RTC_AUDIO_FEC_ENABLED, False),
            "RTC_AUDIO_BITRATE_LOW_KBPS": (cfg.RTC_AUDIO_BITRATE_LOW_KBPS, False),
            "RTC_AUDIO_BITRATE_BALANCED_KBPS": (
                cfg.RTC_AUDIO_BITRATE_BALANCED_KBPS,
                False,
            ),
            "RTC_AUDIO_BITRATE_HIGH_KBPS": (cfg.RTC_AUDIO_BITRATE_HIGH_KBPS, False),
            "RTC_VIDEO_BITRATE_LOW_KBPS": (cfg.RTC_VIDEO_BITRATE_LOW_KBPS, False),
            "RTC_VIDEO_BITRATE_BALANCED_KBPS": (
                cfg.RTC_VIDEO_BITRATE_BALANCED_KBPS,
                False,
            ),
            "RTC_VIDEO_BITRATE_HIGH_KBPS": (cfg.RTC_VIDEO_BITRATE_HIGH_KBPS, False),
            "RTC_VIDEO_WIDTH_LOW": (cfg.RTC_VIDEO_WIDTH_LOW, False),
            "RTC_VIDEO_WIDTH_BALANCED": (cfg.RTC_VIDEO_WIDTH_BALANCED, False),
            "RTC_VIDEO_WIDTH_HIGH": (cfg.RTC_VIDEO_WIDTH_HIGH, False),
            "RTC_VIDEO_HEIGHT_LOW": (cfg.RTC_VIDEO_HEIGHT_LOW, False),
            "RTC_VIDEO_HEIGHT_BALANCED": (cfg.RTC_VIDEO_HEIGHT_BALANCED, False),
            "RTC_VIDEO_HEIGHT_HIGH": (cfg.RTC_VIDEO_HEIGHT_HIGH, False),
            "RTC_VIDEO_FPS_LOW": (cfg.RTC_VIDEO_FPS_LOW, False),
            "RTC_VIDEO_FPS_BALANCED": (cfg.RTC_VIDEO_FPS_BALANCED, False),
            "RTC_VIDEO_FPS_HIGH": (cfg.RTC_VIDEO_FPS_HIGH, False),
            "DERIVED_KEY_BYTES": (cfg.DERIVED_KEY_BYTES, False),
            "DERIVED_KEY_ROUNDS": (cfg.DERIVED_KEY_ROUNDS, False),
            "MAX_MESSAGE_SIZE": (cfg.MAX_MESSAGE_SIZE, False),
            "MAX_MESSAGES_PER_PAGE": (cfg.MAX_MESSAGES_PER_PAGE, False),
            "MIN_MESSAGES_PER_PAGE": (cfg.MIN_MESSAGES_PER_PAGE, False),
            "STORAGE_PROVIDER": (cfg.STORAGE_PROVIDER, False),
            "STORAGE_PATH": (cfg.STORAGE_PATH, False),
            "STORAGE_BASE_URL": (cfg.STORAGE_BASE_URL, False),
            "STORAGE_ALLOCATED_GB": (cfg.STORAGE_ALLOCATED_GB, False),
            "STORAGE_SSE_ENABLED": (cfg.STORAGE_SSE_ENABLED, False),
            "STORAGE_SSE_KEY": (cfg.STORAGE_SSE_KEY, True),
            "S3_BUCKET_NAME": (cfg.S3_BUCKET_NAME, False),
            "S3_REGION": (cfg.S3_REGION, False),
            "S3_ACCESS_KEY": (cfg.S3_ACCESS_KEY, True),
            "S3_SECRET_KEY": (cfg.S3_SECRET_KEY, True),
            "S3_ENDPOINT_URL": (cfg.S3_ENDPOINT_URL, False),
        }

    def get_runtime_default_map(self) -> dict[str, tuple[object, bool]]:
        """
        Return default runtime key metadata map.
        """
        return self._runtime_defaults()

    def _ensure_default_runtime_config(self) -> None:
        """
        Ensure runtime config keys are present in database.
        """
        database_uri = str(self.database_engine.url)
        if database_uri.startswith("sqlite://"):
            return

        defaults = self._runtime_defaults()
        inserted = 0

        with self.database_session() as session:
            existing_rows = session.query(InstanceRuntimeConfig.config_key).all()
            existing_keys = {row[0] for row in existing_rows}

            for key, (value, is_secret) in defaults.items():
                if key in existing_keys:
                    continue

                session.add(
                    InstanceRuntimeConfig(
                        config_key=key,
                        config_value=json.dumps(value),
                        is_secret=is_secret,
                    )
                )
                inserted += 1

            if inserted > 0:
                session.commit()
                logger.info(
                    "Inserted default runtime config rows: {count}",
                    count=inserted,
                )

    def get_runtime_config(self, include_secrets: bool = True) -> dict[str, object]:
        """
        Fetch runtime configuration key/value pairs from database.

        Args:
            include_secrets: Whether secret rows should be returned.

        Returns:
            dict[str, object]: Runtime settings map.
        """
        database_uri = str(self.database_engine.url)
        if database_uri.startswith("sqlite://"):
            return {
                key: value
                for key, (value, is_secret) in self._runtime_defaults().items()
                if include_secrets or not is_secret
            }

        with self.database_session() as session:
            query = session.query(InstanceRuntimeConfig)
            if not include_secrets:
                query = query.filter(InstanceRuntimeConfig.is_secret.is_(False))

            rows = query.all()

            parsed: dict[str, object] = {}
            for row in rows:
                try:
                    parsed[row.config_key] = json.loads(row.config_value)
                except json.JSONDecodeError:
                    parsed[row.config_key] = row.config_value

            return parsed

    def update_runtime_config(
        self, settings_updates: dict[str, object], secret_keys: set[str] | None = None
    ) -> None:
        """
        Upsert runtime settings into instance runtime config table.

        Args:
            settings_updates: Key/value updates.
            secret_keys: Optional explicit secret key set for inserted rows.
        """
        if not settings_updates:
            return

        secret_keys = secret_keys or set()
        known_defaults = self._runtime_defaults()
        now = datetime.datetime.now(datetime.timezone.utc)

        with self.database_session() as session:
            existing_rows = (
                session.query(InstanceRuntimeConfig)
                .filter(InstanceRuntimeConfig.config_key.in_(list(settings_updates.keys())))
                .all()
            )
            existing_by_key = {row.config_key: row for row in existing_rows}

            for key, value in settings_updates.items():
                encoded = json.dumps(value)
                existing = existing_by_key.get(key)

                if existing is not None:
                    existing.config_value = encoded
                    existing.updated_at = now
                    continue

                is_secret = (
                    key in secret_keys
                    or key in {
                        default_key
                        for default_key, (_, default_secret) in known_defaults.items()
                        if default_secret
                    }
                )

                session.add(
                    InstanceRuntimeConfig(
                        config_key=key,
                        config_value=encoded,
                        is_secret=is_secret,
                    )
                )

            session.commit()

        logger.info(
            "Runtime config updated keys={keys}",
            keys=sorted(settings_updates.keys()),
        )

