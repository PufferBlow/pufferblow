from __future__ import annotations

from pufferblow.api.routes.system_routes import server_runtime


def test_instance_health_route_includes_media_sfu_health(client):
    original_fetch = server_runtime._fetch_media_sfu_health
    server_runtime._fetch_media_sfu_health = lambda: {
        "enabled": True,
        "status": "ok",
        "url": "http://127.0.0.1:8787/healthz",
        "healthz": {
            "status": "ok",
            "version": "0.2.0",
            "total_peers": 2,
            "active_rooms": 1,
        },
        "error": None,
    }

    try:
        response = client.get("/api/v1/system/instance-health")
    finally:
        server_runtime._fetch_media_sfu_health = original_fetch

    assert response.status_code == 200
    payload = response.json()["instance_health"]
    assert payload["status"] == "ok"
    assert payload["api_loaded"] is True
    assert payload["components"]["database_handler"] is True
    assert payload["media_sfu"]["status"] == "ok"
    assert payload["media_sfu"]["healthz"]["active_rooms"] == 1


def test_root_healthz_mirrors_degraded_media_sfu_state(client):
    original_fetch = server_runtime._fetch_media_sfu_health
    server_runtime._fetch_media_sfu_health = lambda: {
        "enabled": True,
        "status": "unreachable",
        "url": "http://127.0.0.1:8787/healthz",
        "healthz": None,
        "error": "media-sfu health probe failed: connection refused",
    }

    try:
        response = client.get("/healthz")
    finally:
        server_runtime._fetch_media_sfu_health = original_fetch

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "degraded"
    assert payload["media_sfu"]["status"] == "unreachable"
    assert "connection refused" in payload["media_sfu"]["error"]
