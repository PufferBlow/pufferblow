from __future__ import annotations

import hashlib
import hmac
import json
import time
from contextlib import contextmanager

from fastapi.testclient import TestClient

from pufferblow.core.bootstrap import api_initializer


@contextmanager
def _patched_rtc_quality(**updates):
    cfg = api_initializer.config
    previous: dict[str, object] = {}

    for key, value in updates.items():
        previous[key] = getattr(cfg, key)
        setattr(cfg, key, value)

    try:
        yield
    finally:
        for key, value in previous.items():
            setattr(cfg, key, value)


def _bootstrap_headers(body: bytes, nonce: str = "quality-nonce", timestamp: int | None = None):
    effective_timestamp = timestamp or int(time.time())
    secret = api_initializer.voice_session_manager.bootstrap_secret.encode("utf-8")
    signed_payload = f"{effective_timestamp}.{nonce}.".encode("utf-8") + body
    signature = hmac.new(secret, signed_payload, hashlib.sha256).hexdigest()
    return {
        "Content-Type": "application/json",
        "X-Pufferblow-Timestamp": str(effective_timestamp),
        "X-Pufferblow-Nonce": nonce,
        "X-Pufferblow-Signature": f"sha256={signature}",
    }


def test_server_info_exposes_voice_media_quality(client: TestClient):
    with _patched_rtc_quality(
        RTC_DEFAULT_QUALITY_PROFILE="high",
        RTC_AUDIO_BITRATE_HIGH_KBPS=96,
        RTC_VIDEO_WIDTH_HIGH=2560,
        RTC_VIDEO_HEIGHT_HIGH=1440,
        RTC_VIDEO_FPS_HIGH=60,
    ):
        response = client.get("/api/v1/system/server-info")

    assert response.status_code == 200
    media_quality = response.json()["server_info"]["rtc_media_quality"]
    assert media_quality["default_profile"] == "high"
    assert media_quality["audio"]["profiles"]["high"]["bitrate_kbps"] == 96
    assert media_quality["video"]["profiles"]["high"]["width"] == 2560
    assert media_quality["video"]["profiles"]["high"]["height"] == 1440
    assert media_quality["video"]["profiles"]["high"]["fps"] == 60


def test_internal_bootstrap_config_exposes_voice_media_quality(client: TestClient):
    body = json.dumps({"service": "media-sfu", "nonce": "quality-bootstrap"}).encode("utf-8")

    with _patched_rtc_quality(
        RTC_DEFAULT_QUALITY_PROFILE="low",
        RTC_AUDIO_SAMPLE_RATE_HZ=44100,
        RTC_AUDIO_BITRATE_LOW_KBPS=20,
        RTC_VIDEO_BITRATE_LOW_KBPS=600,
        RTC_VIDEO_WIDTH_LOW=480,
        RTC_VIDEO_HEIGHT_LOW=270,
        RTC_VIDEO_FPS_LOW=12,
    ):
        response = client.post(
            "/api/internal/v1/voice/bootstrap-config",
            data=body,
            headers=_bootstrap_headers(body, nonce="quality-bootstrap"),
        )

    assert response.status_code == 200
    media_quality = response.json()["config"]["media_quality"]
    assert media_quality["default_profile"] == "low"
    assert media_quality["audio"]["sample_rate_hz"] == 44100
    assert media_quality["audio"]["profiles"]["low"]["bitrate_kbps"] == 20
    assert media_quality["video"]["profiles"]["low"]["bitrate_kbps"] == 600
    assert media_quality["video"]["profiles"]["low"]["width"] == 480
    assert media_quality["video"]["profiles"]["low"]["height"] == 270
    assert media_quality["video"]["profiles"]["low"]["fps"] == 12
