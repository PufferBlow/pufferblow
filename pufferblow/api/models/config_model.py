import pufferblow.core.constants as constants


class Config:
    """Configuration model class."""

    # API related parameters
    API_HOST: str = "127.0.0.1"
    API_PORT: int = 7575
    LOGS_PATH: str = f"{constants.HOME}/.pufferblow/logs/pufferblow.log"
    WORKERS: int = 7
    RATE_LIMIT_DURATION: int = 5
    MAX_RATE_LIMIT_REQUESTS: int = 6000
    MAX_RATE_LIMIT_WARNINGS: int = 15
    JWT_SECRET: str = "change-this-jwt-secret-in-production"
    JWT_ACCESS_TTL_MINUTES: int = 15
    JWT_REFRESH_TTL_DAYS: int = 30
    CORS_ALLOWED_ORIGINS: tuple[str, ...] = ()
    CORS_ALLOWED_ORIGIN_REGEX: str | None = None
    CORS_ALLOWED_METHODS: tuple[str, ...] = (
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "OPTIONS",
    )
    CORS_ALLOWED_HEADERS: tuple[str, ...] = ("*",)
    CORS_ALLOW_CREDENTIALS: bool = True

    # RTC/voice related parameters
    VOICE_BACKEND: str = "sfu_v2"
    RTC_SIGNALING_URL: str = "ws://127.0.0.1:8787/rtc/v1/ws"
    RTC_JOIN_TOKEN_TTL_SECONDS: int = 60
    RTC_JOIN_SECRET: str = "change-this-rtc-join-secret"
    RTC_INTERNAL_SECRET: str = "change-this-rtc-internal-secret"
    RTC_BOOTSTRAP_SECRET: str = "change-this-rtc-bootstrap-secret"
    RTC_INTERNAL_API_BASE: str = "http://127.0.0.1:7575/api/internal/v1/voice"
    RTC_STUN_SERVERS: str = "stun:stun.l.google.com:19302"
    TURN_URL: str | None = None
    TURN_USERNAME: str | None = None
    TURN_PASSWORD: str | None = None
    RTC_MAX_TOTAL_PEERS: int = 1000
    RTC_MAX_ROOM_PEERS: int = 100
    RTC_ROOM_END_GRACE_SECONDS: int = 15
    RTC_INTERNAL_EVENT_WORKERS: int = 4
    RTC_INTERNAL_EVENT_QUEUE_SIZE: int = 8192
    RTC_INTERNAL_HTTP_TIMEOUT_SECONDS: int = 5
    RTC_WS_WRITE_TIMEOUT_SECONDS: int = 4
    RTC_WS_PING_INTERVAL_SECONDS: int = 20
    RTC_WS_PONG_WAIT_SECONDS: int = 45
    RTC_WS_READ_LIMIT_BYTES: int = 1_048_576
    RTC_UDP_PORT_MIN: int = 50000
    RTC_UDP_PORT_MAX: int = 51999
    RTC_DEFAULT_QUALITY_PROFILE: str = "balanced"
    RTC_AUDIO_SAMPLE_RATE_HZ: int = 48000
    RTC_AUDIO_CHANNELS: int = 1
    RTC_AUDIO_STEREO_ENABLED: bool = False
    RTC_AUDIO_DTX_ENABLED: bool = True
    RTC_AUDIO_FEC_ENABLED: bool = True
    RTC_AUDIO_BITRATE_LOW_KBPS: int = 24
    RTC_AUDIO_BITRATE_BALANCED_KBPS: int = 48
    RTC_AUDIO_BITRATE_HIGH_KBPS: int = 64
    RTC_VIDEO_BITRATE_LOW_KBPS: int = 800
    RTC_VIDEO_BITRATE_BALANCED_KBPS: int = 1500
    RTC_VIDEO_BITRATE_HIGH_KBPS: int = 2500
    RTC_VIDEO_WIDTH_LOW: int = 640
    RTC_VIDEO_WIDTH_BALANCED: int = 1280
    RTC_VIDEO_WIDTH_HIGH: int = 1920
    RTC_VIDEO_HEIGHT_LOW: int = 360
    RTC_VIDEO_HEIGHT_BALANCED: int = 720
    RTC_VIDEO_HEIGHT_HIGH: int = 1080
    RTC_VIDEO_FPS_LOW: int = 15
    RTC_VIDEO_FPS_BALANCED: int = 30
    RTC_VIDEO_FPS_HIGH: int = 60

    # PostgreSQL Database
    DATABASE_NAME: str
    USERNAME: str
    DATABASE_PASSWORD: str
    DATABASE_HOST: str
    DATABASE_PORT: int
    DATABASE_SSL_MODE: str = "prefer"
    DATABASE_SSL_CERT: str | None = None
    DATABASE_SSL_KEY: str | None = None
    DATABASE_SSL_ROOT_CERT: str | None = None

    # Encryption
    DERIVED_KEY_BYTES: int = 56
    DERIVED_KEY_ROUNDS: int = 100

    # Messages related parameters
    MAX_MESSAGE_SIZE: int = 1024
    MAX_MESSAGES_PER_PAGE: int = 50
    MIN_MESSAGES_PER_PAGE: int = 20

    # Storage related parameters
    STORAGE_PROVIDER: str = "local"
    STORAGE_PATH: str = f"{constants.HOME}/.pufferblow/storage"
    STORAGE_BASE_URL: str = "/storage"
    STORAGE_ALLOCATED_GB: int = 10
    STORAGE_SSE_ENABLED: bool = False
    STORAGE_SSE_KEY: str | None = None

    # AWS S3 configuration (when provider = "s3")
    S3_BUCKET_NAME: str | None = None
    S3_REGION: str = "us-east-1"
    S3_ACCESS_KEY: str | None = None
    S3_SECRET_KEY: str | None = None
    S3_ENDPOINT_URL: str | None = None

    # Database backup settings
    BACKUP_ENABLED: bool = False
    BACKUP_MODE: str = "file"  # "file" or "mirror"
    BACKUP_PATH: str = f"{constants.HOME}/.pufferblow/backups"
    BACKUP_MIRROR_DSN: str | None = None
    BACKUP_SCHEDULE_HOURS: int = 24
    BACKUP_MAX_FILES: int = 7

    def __init__(self, config: dict | None = None) -> None:
        """Initialize the instance."""
        if config is not None:
            self.set_attr_from_config(config)

    def set_attr_from_config(self, config: dict) -> None:
        """Set model attributes from config file data."""
        self.API_HOST = config["api"]["host"]
        self.API_PORT = config["api"]["port"]
        self.LOGS_PATH = config["api"]["logs_path"]
        self.WORKERS = config["api"]["workers"]
        self.RATE_LIMIT_DURATION = config["api"]["rate_limit_duration"]
        self.MAX_RATE_LIMIT_REQUESTS = config["api"]["max_rate_limit_requests"]
        self.MAX_RATE_LIMIT_WARNINGS = config["api"]["max_rate_limit_warnings"]
        self.JWT_SECRET = config["api"].get(
            "jwt_secret", "change-this-jwt-secret-in-production"
        )
        self.JWT_ACCESS_TTL_MINUTES = config["api"].get("jwt_access_ttl_minutes", 15)
        self.JWT_REFRESH_TTL_DAYS = config["api"].get("jwt_refresh_ttl_days", 30)
        security_section = config.get("security", {})
        self.CORS_ALLOWED_ORIGINS = tuple(security_section.get("cors_origins", ()))
        self.CORS_ALLOWED_ORIGIN_REGEX = security_section.get("cors_origin_regex")
        self.CORS_ALLOWED_METHODS = tuple(
            security_section.get(
                "cors_allow_methods",
                ("GET", "POST", "PUT", "DELETE", "OPTIONS"),
            )
        )
        self.CORS_ALLOWED_HEADERS = tuple(
            security_section.get("cors_allow_headers", ("*",))
        )
        self.CORS_ALLOW_CREDENTIALS = bool(
            security_section.get("cors_allow_credentials", True)
        )

        rtc_section = config.get("rtc", {})
        self.VOICE_BACKEND = rtc_section.get("voice_backend", "sfu_v2")
        self.RTC_SIGNALING_URL = rtc_section.get(
            "signaling_url", "ws://127.0.0.1:8787/rtc/v1/ws"
        )
        self.RTC_JOIN_TOKEN_TTL_SECONDS = int(
            rtc_section.get("join_token_ttl_seconds", 60)
        )
        self.RTC_JOIN_SECRET = rtc_section.get(
            "join_secret", "change-this-rtc-join-secret"
        )
        self.RTC_INTERNAL_SECRET = rtc_section.get(
            "internal_secret", "change-this-rtc-internal-secret"
        )
        self.RTC_BOOTSTRAP_SECRET = rtc_section.get(
            "bootstrap_secret", "change-this-rtc-bootstrap-secret"
        )
        self.RTC_INTERNAL_API_BASE = rtc_section.get(
            "internal_api_base", "http://127.0.0.1:7575/api/internal/v1/voice"
        )
        self.RTC_STUN_SERVERS = rtc_section.get(
            "stun_servers", "stun:stun.l.google.com:19302"
        )
        self.TURN_URL = rtc_section.get("turn_url")
        self.TURN_USERNAME = rtc_section.get("turn_username")
        self.TURN_PASSWORD = rtc_section.get("turn_password")
        self.RTC_MAX_TOTAL_PEERS = int(rtc_section.get("max_total_peers", 1000))
        self.RTC_MAX_ROOM_PEERS = int(rtc_section.get("max_room_peers", 100))
        self.RTC_ROOM_END_GRACE_SECONDS = int(
            rtc_section.get("room_end_grace_seconds", 15)
        )
        self.RTC_INTERNAL_EVENT_WORKERS = int(
            rtc_section.get("internal_event_workers", 4)
        )
        self.RTC_INTERNAL_EVENT_QUEUE_SIZE = int(
            rtc_section.get("internal_event_queue_size", 8192)
        )
        self.RTC_INTERNAL_HTTP_TIMEOUT_SECONDS = int(
            rtc_section.get("internal_http_timeout_seconds", 5)
        )
        self.RTC_WS_WRITE_TIMEOUT_SECONDS = int(
            rtc_section.get("ws_write_timeout_seconds", 4)
        )
        self.RTC_WS_PING_INTERVAL_SECONDS = int(
            rtc_section.get("ws_ping_interval_seconds", 20)
        )
        self.RTC_WS_PONG_WAIT_SECONDS = int(
            rtc_section.get("ws_pong_wait_seconds", 45)
        )
        self.RTC_WS_READ_LIMIT_BYTES = int(
            rtc_section.get("ws_read_limit_bytes", 1_048_576)
        )
        self.RTC_UDP_PORT_MIN = int(rtc_section.get("udp_port_min", 50000))
        self.RTC_UDP_PORT_MAX = int(rtc_section.get("udp_port_max", 51999))
        self.RTC_DEFAULT_QUALITY_PROFILE = str(
            rtc_section.get("default_quality_profile", "balanced")
        ).strip() or "balanced"
        self.RTC_AUDIO_SAMPLE_RATE_HZ = int(
            rtc_section.get("audio_sample_rate_hz", 48000)
        )
        self.RTC_AUDIO_CHANNELS = int(rtc_section.get("audio_channels", 1))
        self.RTC_AUDIO_STEREO_ENABLED = bool(
            rtc_section.get("audio_stereo_enabled", False)
        )
        self.RTC_AUDIO_DTX_ENABLED = bool(
            rtc_section.get("audio_dtx_enabled", True)
        )
        self.RTC_AUDIO_FEC_ENABLED = bool(
            rtc_section.get("audio_fec_enabled", True)
        )
        self.RTC_AUDIO_BITRATE_LOW_KBPS = int(
            rtc_section.get("audio_bitrate_low_kbps", 24)
        )
        self.RTC_AUDIO_BITRATE_BALANCED_KBPS = int(
            rtc_section.get("audio_bitrate_balanced_kbps", 48)
        )
        self.RTC_AUDIO_BITRATE_HIGH_KBPS = int(
            rtc_section.get("audio_bitrate_high_kbps", 64)
        )
        self.RTC_VIDEO_BITRATE_LOW_KBPS = int(
            rtc_section.get("video_bitrate_low_kbps", 800)
        )
        self.RTC_VIDEO_BITRATE_BALANCED_KBPS = int(
            rtc_section.get("video_bitrate_balanced_kbps", 1500)
        )
        self.RTC_VIDEO_BITRATE_HIGH_KBPS = int(
            rtc_section.get("video_bitrate_high_kbps", 2500)
        )
        self.RTC_VIDEO_WIDTH_LOW = int(rtc_section.get("video_width_low", 640))
        self.RTC_VIDEO_WIDTH_BALANCED = int(
            rtc_section.get("video_width_balanced", 1280)
        )
        self.RTC_VIDEO_WIDTH_HIGH = int(rtc_section.get("video_width_high", 1920))
        self.RTC_VIDEO_HEIGHT_LOW = int(rtc_section.get("video_height_low", 360))
        self.RTC_VIDEO_HEIGHT_BALANCED = int(
            rtc_section.get("video_height_balanced", 720)
        )
        self.RTC_VIDEO_HEIGHT_HIGH = int(rtc_section.get("video_height_high", 1080))
        self.RTC_VIDEO_FPS_LOW = int(rtc_section.get("video_fps_low", 15))
        self.RTC_VIDEO_FPS_BALANCED = int(rtc_section.get("video_fps_balanced", 30))
        self.RTC_VIDEO_FPS_HIGH = int(rtc_section.get("video_fps_high", 60))

        db_section = config.get("postgresql")
        if not db_section:
            raise KeyError("'postgresql' section not found in config")

        self.DATABASE_NAME = db_section["database_name"]
        self.USERNAME = db_section["username"]
        self.DATABASE_PASSWORD = db_section["password"]
        self.DATABASE_HOST = db_section["host"]
        self.DATABASE_PORT = db_section["port"]
        self.DATABASE_SSL_MODE = db_section.get("ssl_mode", "prefer")
        self.DATABASE_SSL_CERT = db_section.get("ssl_cert")
        self.DATABASE_SSL_KEY = db_section.get("ssl_key")
        self.DATABASE_SSL_ROOT_CERT = db_section.get("ssl_root_cert")

        self.DERIVED_KEY_BYTES = config["encryption"]["derived_key_bytes"]
        self.DERIVED_KEY_ROUNDS = config["encryption"]["derived_key_rounds"]

        self.MAX_MESSAGE_SIZE = config["messages"]["max_message_size"]
        self.MAX_MESSAGES_PER_PAGE = config["messages"]["max_messages_per_page"]
        self.MIN_MESSAGES_PER_PAGE = config["messages"]["min_messages_per_page"]

        if "storage" in config:
            self.STORAGE_PROVIDER = config["storage"]["provider"]
            self.STORAGE_PATH = config["storage"]["storage_path"]
            self.STORAGE_BASE_URL = config["storage"]["base_url"]
            self.STORAGE_ALLOCATED_GB = config["storage"]["allocated_gb"]
            self.STORAGE_SSE_ENABLED = config["storage"].get("sse_enabled", False)
            self.STORAGE_SSE_KEY = config["storage"].get("sse_key")

            if "s3" in config["storage"]:
                self.S3_BUCKET_NAME = config["storage"]["s3"].get("bucket_name")
                self.S3_REGION = config["storage"]["s3"].get("region", "us-east-1")
                self.S3_ACCESS_KEY = config["storage"]["s3"].get("access_key")
                self.S3_SECRET_KEY = config["storage"]["s3"].get("secret_key")
                self.S3_ENDPOINT_URL = config["storage"]["s3"].get("endpoint_url")

    def __repr__(self) -> str:
        """Repr special method."""
        return (
            "Config("
            f"API_HOST={self.API_HOST!r}, "
            f"API_PORT={self.API_PORT!r}, "
            f"WORKERS={self.WORKERS!r}, "
            f"LOGS_PATH={self.LOGS_PATH!r}, "
            f"RATE_LIMIT_DURATION={self.RATE_LIMIT_DURATION!r}, "
            f"MAX_RATE_LIMIT_REQUESTS={self.MAX_RATE_LIMIT_REQUESTS!r}, "
            f"MAX_RATE_LIMIT_WARNINGS={self.MAX_RATE_LIMIT_WARNINGS!r}, "
            f"VOICE_BACKEND={self.VOICE_BACKEND!r})"
        )
