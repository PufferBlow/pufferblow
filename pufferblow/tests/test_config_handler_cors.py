from pathlib import Path

from pufferblow.api.config.config_handler import ConfigHandler


def test_build_bootstrap_config_reads_cors_settings_from_shared_config(tmp_path: Path):
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """
[server]
api_host = "127.0.0.1"
api_port = 7575
workers = 2
logs_path = "/tmp/pufferblow.log"

[security]
cors_origins = ["http://localhost:3000", "https://app.example.com"]
cors_allow_credentials = false
cors_allow_methods = ["GET", "POST", "OPTIONS"]
cors_allow_headers = ["Authorization", "Content-Type"]
""".strip(),
        encoding="utf-8",
    )

    handler = ConfigHandler()
    handler.config_toml_path = config_path

    config = handler.build_bootstrap_config()

    assert config.CORS_ALLOWED_ORIGINS == (
        "http://localhost:3000",
        "https://app.example.com",
    )
    assert config.CORS_ALLOW_CREDENTIALS is False
    assert config.CORS_ALLOWED_METHODS == ("GET", "POST", "OPTIONS")
    assert config.CORS_ALLOWED_HEADERS == ("Authorization", "Content-Type")


def test_build_bootstrap_config_accepts_comma_separated_cors_origins(tmp_path: Path):
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """
[security]
cors_origins = "http://localhost:3000, https://app.example.com"
""".strip(),
        encoding="utf-8",
    )

    handler = ConfigHandler()
    handler.config_toml_path = config_path

    config = handler.build_bootstrap_config()

    assert config.CORS_ALLOWED_ORIGINS == (
        "http://localhost:3000",
        "https://app.example.com",
    )


def test_build_bootstrap_config_reads_cors_origin_regex_from_shared_config(
    tmp_path: Path,
):
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """
[security]
cors_origin_regex = ".*"
cors_allow_credentials = true
""".strip(),
        encoding="utf-8",
    )

    handler = ConfigHandler()
    handler.config_toml_path = config_path

    config = handler.build_bootstrap_config()

    assert config.CORS_ALLOWED_ORIGIN_REGEX == ".*"
    assert config.CORS_ALLOWED_ORIGINS == ()


def test_write_config_toml_merges_security_section(tmp_path: Path):
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """
[security]
rate_limit_requests = 100
cors_origins = ["http://localhost:3000"]
""".strip(),
        encoding="utf-8",
    )

    handler = ConfigHandler()
    handler.config_toml_path = config_path

    handler.write_config_toml(
        security_config={
            "cors_origin_regex": ".*",
            "cors_origins": [],
            "cors_allow_credentials": True,
        }
    )

    config = handler._load_config_toml()

    assert config["security"]["rate_limit_requests"] == 100
    assert config["security"]["cors_origin_regex"] == ".*"
    assert config["security"]["cors_origins"] == []
    assert config["security"]["cors_allow_credentials"] is True
