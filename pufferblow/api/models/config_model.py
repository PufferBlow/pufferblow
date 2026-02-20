from pufferblow import constants


class Config:
    """config model class"""

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

    # Storage related parameters (replaces CDN)
    STORAGE_PROVIDER: str = "local"
    STORAGE_PATH: str = f"{constants.HOME}/.pufferblow/storage"
    STORAGE_BASE_URL: str = "/storage"
    STORAGE_ALLOCATED_GB: int = 10  # Default 10GB for local storage
    STORAGE_SSE_ENABLED: bool = False
    STORAGE_SSE_KEY: str | None = None

    # AWS S3 configuration (when provider = "s3")
    S3_BUCKET_NAME: str | None = None
    S3_REGION: str = "us-east-1"
    S3_ACCESS_KEY: str | None = None
    S3_SECRET_KEY: str | None = None
    S3_ENDPOINT_URL: str | None = None  # For custom S3-compatible services

    # Legacy CDN parameters (for backward compatibility)
    CDN_STORAGE_PATH: str = f"{constants.HOME}/.pufferblow/cdn"
    CDN_BASE_URL: str = "/cdn"
    CDN_CACHE_MAX_AGE: int = 86400  # 24 hours in seconds

    def __init__(self, config: dict | None = None) -> None:
        if config is not None:
            self.set_attr_from_config(config)

    def set_attr_from_config(self, config: dict) -> None:
        """
        Sets the attributes values from the config file

        Args:
            config (dict): The config file data.

        Returns:
            None.
        """
        # API related parameters
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

        # PostgreSQL Database - support for both postregsql (legacy) and postgresql
        db_section = config.get("postgresql") or config.get("postregsql")
        if not db_section:
            # If neither section exists, raise error
            raise KeyError(
                "Neither 'postgresql' nor 'postregsql' section found in config"
            )

        self.DATABASE_NAME = db_section["database_name"]
        self.USERNAME = db_section["username"]
        self.DATABASE_PASSWORD = db_section["password"]
        self.DATABASE_HOST = db_section["host"]
        self.DATABASE_PORT = db_section["port"]
        self.DATABASE_SSL_MODE = db_section.get("ssl_mode", "prefer")
        self.DATABASE_SSL_CERT = db_section.get("ssl_cert")
        self.DATABASE_SSL_KEY = db_section.get("ssl_key")
        self.DATABASE_SSL_ROOT_CERT = db_section.get("ssl_root_cert")

        # Encryption
        self.DERIVED_KEY_BYTES = config["encryption"]["derived_key_bytes"]
        self.DERIVED_KEY_ROUNDS = config["encryption"]["derived_key_rounds"]

        # Messages related parameters
        self.MAX_MESSAGE_SIZE = config["messages"]["max_message_size"]
        self.MAX_MESSAGES_PER_PAGE = config["messages"]["max_messages_per_page"]
        self.MIN_MESSAGES_PER_PAGE = config["messages"]["min_messages_per_page"]

        # Storage related parameters
        if "storage" in config:
            self.STORAGE_PROVIDER = config["storage"]["provider"]
            self.STORAGE_PATH = config["storage"]["storage_path"]
            self.STORAGE_BASE_URL = config["storage"]["base_url"]
            self.STORAGE_ALLOCATED_GB = config["storage"]["allocated_gb"]
            self.STORAGE_SSE_ENABLED = config["storage"].get("sse_enabled", False)
            self.STORAGE_SSE_KEY = config["storage"].get("sse_key")

            # S3 configuration
            if "s3" in config["storage"]:
                self.S3_BUCKET_NAME = config["storage"]["s3"]["bucket_name"]
                self.S3_REGION = config["storage"]["s3"]["region"]
                self.S3_ACCESS_KEY = config["storage"]["s3"]["access_key"]
                self.S3_SECRET_KEY = config["storage"]["s3"]["secret_key"]
                self.S3_ENDPOINT_URL = config["storage"]["s3"].get("endpoint_url")

        # Legacy CDN related parameters (for backward compatibility)
        if "cdn" in config:
            self.CDN_STORAGE_PATH = config["cdn"]["storage_path"]
            self.CDN_BASE_URL = config["cdn"]["base_url"]
            self.CDN_CACHE_MAX_AGE = config["cdn"]["cache_max_age"]

    def export_toml(self) -> str:
        """
        Exports the attributes into a toml format.

        Args:
            None.

        Returns:
            str: The attributes in the toml format.
        """
        config = f"""# This is the config file for pufferblow-api
# please if you do edit this file you will need
# to restart, in order to apply the changes

[api]
host = "{self.API_HOST}"
port = {self.API_PORT}
logs_path = "{self.LOGS_PATH}"
workers = {self.WORKERS} # number of workers for the ASGI, the higher the better
rate_limit_duration = {self.RATE_LIMIT_DURATION} # the duration of a rate limit of an IP address (in minutes)
max_rate_limit_requests = {self.MAX_RATE_LIMIT_REQUESTS} # number of request before a rate limit warning
max_rate_limit_warnings = {self.MAX_RATE_LIMIT_WARNINGS} # number of rate limit warnings before blocking the IP address
jwt_secret = "{self.JWT_SECRET}" # JWT signing secret (change this in production)
jwt_access_ttl_minutes = {self.JWT_ACCESS_TTL_MINUTES} # Access token lifetime in minutes
jwt_refresh_ttl_days = {self.JWT_REFRESH_TTL_DAYS} # Refresh token lifetime in days

[postgresql]
database_name = "{self.DATABASE_NAME}"
username = "{self.USERNAME}"
password = "{self.DATABASE_PASSWORD}"
host = "{self.DATABASE_HOST}"
port = "{self.DATABASE_PORT}"
ssl_mode = "{self.DATABASE_SSL_MODE}"
ssl_cert = "{self.DATABASE_SSL_CERT}" if self.DATABASE_SSL_CERT else ""
ssl_key = "{self.DATABASE_SSL_KEY}" if self.DATABASE_SSL_KEY else ""
ssl_root_cert = "{self.DATABASE_SSL_ROOT_CERT}" if self.DATABASE_SSL_ROOT_CERT else ""

[encryption]
derived_key_bytes = {self.DERIVED_KEY_BYTES} # This specifies the bytes length of the derived key. A 56-bit key provides a good balance between security and performance. The bytes should be 5 to 56 bytes.
derived_key_rounds = {self.DERIVED_KEY_ROUNDS} # This represents the number of iterations for the derived key generation process. A higher value increases the computational effort required, enhancing security but also using more CPU resources.

[messages]
max_message_size = {self.MAX_MESSAGE_SIZE} # This defines the maximum size (in KB) for a message that can be sent. Setting this to a larger value may provide more flexibility, but it could also impact your storage capacity. Please adjust according to your storage resources.
max_messages_per_page = {self.MAX_MESSAGES_PER_PAGE} # This defines the maximum number of messages that can be displayed on each page. A value of 50 is recommended to balance between data load and user experience.
min_messages_per_page = {self.MIN_MESSAGES_PER_PAGE} # This defines the minimum number of messages that can be displayed on each page. A value of 20 is recommended to ensure that there is enough message for the user to engage with on each page.

[storage]
provider = "{self.STORAGE_PROVIDER}" # Storage backend provider: "local" or "s3"
storage_path = "{self.STORAGE_PATH}" # Local storage directory (for local provider)
base_url = "{self.STORAGE_BASE_URL}" # Base URL for serving files
allocated_gb = {self.STORAGE_ALLOCATED_GB} # Allocated storage space in GB (for local provider)
sse_enabled = {str(self.STORAGE_SSE_ENABLED).lower()} # Enable AES-256 server-side encryption for stored files
sse_key = "{self.STORAGE_SSE_KEY}" if self.STORAGE_SSE_KEY else "" # Encryption key or passphrase (recommended: set via env PUFFERBLOW_STORAGE_SSE_KEY)

[storage.s3]
bucket_name = "{self.S3_BUCKET_NAME}" if self.S3_BUCKET_NAME else "" # S3 bucket name (for s3 provider)
region = "{self.S3_REGION}" # AWS region
access_key = "{self.S3_ACCESS_KEY}" if self.S3_ACCESS_KEY else "" # AWS access key
secret_key = "{self.S3_SECRET_KEY}" if self.S3_SECRET_KEY else "" # AWS secret key
endpoint_url = "{self.S3_ENDPOINT_URL}" if self.S3_ENDPOINT_URL else "" # Custom S3 endpoint (optional)

[cdn]
storage_path = "{self.CDN_STORAGE_PATH}" # This defines the directory where uploaded files will be stored on the server.
base_url = "{self.CDN_BASE_URL}" # This defines the base URL path for serving files (e.g., /cdn).
cache_max_age = {self.CDN_CACHE_MAX_AGE} # This defines the maximum age (in seconds) for caching file responses. A value of 86400 (24 hours) is recommended for good performance.
"""
        return config

    def __repr__(self) -> str:
        return f"Config(API_HOST={self.API_HOST!r}, API_PORT={self.API_PORT!r}, WORKERS={self.WORKERS!r}, LOGS_PATH={self.LOGS_PATH!r}, RATE_LIMIT_DURATION={self.RATE_LIMIT_DURATION!r}, MAX_RATE_LIMIT_REQUESTS={self.MAX_RATE_LIMIT_REQUESTS!r}, MAX_RATE_LIMIT_WARNINGS={self.MAX_RATE_LIMIT_WARNINGS!r})"
