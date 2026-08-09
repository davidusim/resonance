import sqlite3
from pathlib import Path

import pytest
import resonance.main as main_module
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from resonance.config import Settings
from resonance.main import create_app

ADMIN_TOKEN = "test-admin-token-that-is-long-enough"


@pytest.fixture
def client(tmp_path: Path):
    app = create_app(
        Settings(
            data_dir=tmp_path,
            admin_token=ADMIN_TOKEN,
            default_lead_ms=3_000,
        )
    )
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def limited_client(tmp_path: Path):
    app = create_app(
        Settings(
            data_dir=tmp_path,
            admin_token=ADMIN_TOKEN,
            default_lead_ms=3_000,
            rate_limit_window_seconds=60,
            rate_limit_max_clients=3,
            enrollment_attempt_limit=2,
            device_auth_attempt_limit=2,
            device_peer_attempt_limit=10,
            admin_auth_failure_limit=2,
        )
    )
    with TestClient(app) as test_client:
        yield test_client


def admin_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {ADMIN_TOKEN}"}


def enroll(client: TestClient, name: str = "Lobby receiver") -> dict[str, str]:
    created = client.post("/api/enrollments", headers=admin_headers(), json={})
    assert created.status_code == 200
    response = client.post(
        "/api/devices/enroll",
        json={"code": created.json()["code"], "name": name},
    )
    assert response.status_code == 201
    return response.json()


def upload_track(client: TestClient) -> dict[str, object]:
    response = client.post(
        "/api/tracks",
        headers=admin_headers(),
        files={"file": ("siren.wav", b"RIFFtest-audio-payload", "audio/wav")},
    )
    assert response.status_code == 200
    return response.json()


def test_health_and_security_headers(client: TestClient) -> None:
    response = client.get("/healthz")

    assert response.json() == {"status": "ok", "database": "ok"}
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cross-origin-resource-policy"] == "same-origin"
    assert response.headers["x-request-id"]
    assert response.headers["server-timing"].startswith("app;dur=")
    assert "microphone=()" in response.headers["permissions-policy"]


def test_admin_routes_require_bearer_token(client: TestClient) -> None:
    unauthenticated = client.get("/api/devices")
    assert unauthenticated.status_code == 401
    assert unauthenticated.headers["www-authenticate"] == "Bearer"
    assert client.get("/api/devices", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/api/devices", headers=admin_headers()).status_code == 200


def test_invalid_admin_attempts_are_limited_without_blocking_valid_token(
    limited_client: TestClient,
) -> None:
    wrong_headers = {"Authorization": "Bearer wrong"}

    assert limited_client.get("/api/devices", headers=wrong_headers).status_code == 401
    assert limited_client.get("/api/devices", headers=wrong_headers).status_code == 401
    blocked = limited_client.get("/api/devices", headers=wrong_headers)

    assert blocked.status_code == 429
    assert int(blocked.headers["retry-after"]) >= 1
    assert blocked.json() == {"detail": "Too many attempts. Try again later."}
    assert limited_client.get("/api/devices", headers=admin_headers()).status_code == 200


def test_health_reports_database_failure(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unavailable() -> None:
        raise sqlite3.OperationalError("database unavailable")

    monkeypatch.setattr(client.app.state.db, "check_health", unavailable)

    response = client.get("/healthz")

    assert response.status_code == 503
    assert response.json() == {"status": "unavailable", "database": "error"}


def test_enrollment_code_is_single_use_and_secret_is_not_listed(client: TestClient) -> None:
    created = client.post("/api/enrollments", headers=admin_headers(), json={}).json()
    first = client.post(
        "/api/devices/enroll",
        json={"code": created["code"].lower(), "name": "  West   hallway  "},
    )
    replay = client.post(
        "/api/devices/enroll",
        json={"code": created["code"], "name": "Intruder"},
    )
    devices = client.get("/api/devices", headers=admin_headers()).json()["devices"]

    assert first.status_code == 201
    assert first.json()["name"] == "West hallway"
    assert replay.status_code == 400
    assert devices[0]["name"] == "West hallway"
    assert "secret" not in devices[0]
    assert "secret_hash" not in devices[0]


def test_enrollment_attempts_return_retry_after_when_limited(
    limited_client: TestClient,
) -> None:
    payload = {"code": "AAAAA-AAAAA", "name": "Untrusted receiver"}

    assert limited_client.post("/api/devices/enroll", json=payload).status_code == 400
    assert limited_client.post("/api/devices/enroll", json=payload).status_code == 400
    blocked = limited_client.post("/api/devices/enroll", json=payload)

    assert blocked.status_code == 429
    assert int(blocked.headers["retry-after"]) >= 1


def test_device_http_authentication_attempts_are_limited(limited_client: TestClient) -> None:
    headers = {"X-Device-Id": "missing", "Authorization": "Bearer invalid"}

    assert limited_client.get("/media/missing", headers=headers).status_code == 401
    assert limited_client.get("/media/missing", headers=headers).status_code == 401
    blocked = limited_client.get("/media/missing", headers=headers)

    assert blocked.status_code == 429
    assert int(blocked.headers["retry-after"]) >= 1


def test_receivers_behind_one_peer_have_independent_device_buckets(tmp_path: Path) -> None:
    app = create_app(
        Settings(
            data_dir=tmp_path,
            admin_token=ADMIN_TOKEN,
            enrollment_attempt_limit=3,
            device_auth_attempt_limit=1,
            device_peer_attempt_limit=5,
        )
    )
    with TestClient(app) as shared_peer_client:
        first_headers = {"X-Device-Id": "first-device", "Authorization": "Bearer invalid"}
        second_headers = {"X-Device-Id": "second-device", "Authorization": "Bearer invalid"}

        assert shared_peer_client.get("/media/missing", headers=first_headers).status_code == 401
        assert shared_peer_client.get("/media/missing", headers=first_headers).status_code == 429
        assert shared_peer_client.get("/media/missing", headers=second_headers).status_code == 401


def test_receiver_websocket_authentication_attempts_are_limited(
    limited_client: TestClient,
) -> None:
    invalid_auth = {
        "type": "auth",
        "device_id": "missing",
        "device_secret": "invalid",
    }
    for _ in range(2):
        with pytest.raises(WebSocketDisconnect) as rejected:
            with limited_client.websocket_connect("/ws/receiver") as websocket:
                websocket.send_json(invalid_auth)
                websocket.receive_json()
        assert rejected.value.code == 4401

    with pytest.raises(WebSocketDisconnect) as limited:
        with limited_client.websocket_connect("/ws/receiver") as websocket:
            websocket.send_json(invalid_auth)
            websocket.receive_json()

    assert limited.value.code == 4429


def test_receiver_websocket_authentication_timeout_sends_close_frame(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(main_module, "WEBSOCKET_AUTH_TIMEOUT_SECONDS", 0.01)

    with pytest.raises(WebSocketDisconnect) as timed_out:
        with client.websocket_connect("/ws/receiver") as websocket:
            websocket.receive_json()

    assert timed_out.value.code == 4408


def test_media_requires_enrolled_device_credentials(client: TestClient) -> None:
    device = enroll(client)
    track = upload_track(client)
    path = f"/media/{track['id']}"

    assert client.get(path).status_code == 401
    response = client.get(
        path,
        headers={
            "X-Device-Id": device["device_id"],
            "Authorization": f"Bearer {device['device_secret']}",
        },
    )

    assert response.status_code == 200
    assert response.content == b"RIFFtest-audio-payload"
    assert response.headers["x-content-sha256"] == track["sha256"]


def test_authenticated_receiver_gets_scheduled_alert(client: TestClient) -> None:
    device = enroll(client)
    track = upload_track(client)

    with client.websocket_connect("/ws/receiver") as websocket:
        websocket.send_json(
            {
                "type": "auth",
                "device_id": device["device_id"],
                "device_secret": device["device_secret"],
            }
        )
        assert websocket.receive_json()["type"] == "auth.ok"

        response = client.post(
            "/api/alerts",
            headers=admin_headers(),
            json={"track_id": track["id"], "lead_ms": 3_000},
        )
        event = websocket.receive_json()
        websocket.send_json(
            {
                "type": "alert.status",
                "alert_id": event["alert_id"],
                "status": "ready",
                "detail": "Verified and scheduled",
                "client_time_ms": event["start_at_ms"] - 1_000,
            }
        )
        websocket.send_json({"type": "ping", "client_time_ms": 1})
        assert websocket.receive_json()["type"] == "pong"

        coordinator_status = client.get("/api/status", headers=admin_headers()).json()

    assert response.status_code == 200
    assert response.json()["delivered"] == 1
    assert event["type"] == "alert.prepare"
    assert event["track"]["sha256"] == track["sha256"]
    # The persistence margin preserves almost all of the requested lead time even
    # on unusually slow filesystems.
    assert event["start_at_ms"] >= event["sent_at_ms"] + 2_500
    alert_status = coordinator_status["alerts"][0]
    assert alert_status["delivered_count"] == 1
    assert alert_status["ready_count"] == 1
    assert alert_status["error_count"] == 0
    assert alert_status["receipts"][0]["device_name"] == "Lobby receiver"
    assert alert_status["receipts"][0]["detail"] == "Verified and scheduled"


def test_receiver_reconnecting_before_start_gets_pending_alert(client: TestClient) -> None:
    device = enroll(client)
    track = upload_track(client)
    created = client.post(
        "/api/alerts",
        headers=admin_headers(),
        json={"track_id": track["id"], "lead_ms": 3_000},
    )

    assert created.status_code == 200
    assert created.json()["delivered"] == 0

    with client.websocket_connect("/ws/receiver") as websocket:
        websocket.send_json(
            {
                "type": "auth",
                "device_id": device["device_id"],
                "device_secret": device["device_secret"],
            }
        )
        assert websocket.receive_json()["type"] == "auth.ok"
        replay = websocket.receive_json()

    assert replay["type"] == "alert.prepare"
    assert replay["alert_id"] == created.json()["alert_id"]
    assert replay["replayed"] is True
    assert replay["track"]["id"] == track["id"]
    status_payload = client.get("/api/status", headers=admin_headers()).json()
    assert status_payload["alerts"][0]["delivered_count"] == 1


def test_receiver_reconnecting_gets_a_durable_stop(client: TestClient) -> None:
    device = enroll(client)
    track = upload_track(client)

    with client.websocket_connect("/ws/receiver") as websocket:
        websocket.send_json(
            {
                "type": "auth",
                "device_id": device["device_id"],
                "device_secret": device["device_secret"],
            }
        )
        assert websocket.receive_json()["type"] == "auth.ok"
        created = client.post(
            "/api/alerts",
            headers=admin_headers(),
            json={"track_id": track["id"], "lead_ms": 3_000},
        ).json()
        assert websocket.receive_json()["type"] == "alert.prepare"

    stopped = client.post(f"/api/alerts/{created['alert_id']}/stop", headers=admin_headers())
    assert stopped.status_code == 200

    with client.websocket_connect("/ws/receiver") as websocket:
        websocket.send_json(
            {
                "type": "auth",
                "device_id": device["device_id"],
                "device_secret": device["device_secret"],
            }
        )
        assert websocket.receive_json()["type"] == "auth.ok"
        replay = websocket.receive_json()
        websocket.send_json(
            {
                "type": "alert.status",
                "alert_id": replay["alert_id"],
                "status": "stopped",
            }
        )
        websocket.send_json({"type": "ping", "client_time_ms": 1})
        assert websocket.receive_json()["type"] == "pong"

    assert replay == {
        "type": "alert.stop",
        "alert_id": created["alert_id"],
        "sent_at_ms": replay["sent_at_ms"],
        "replayed": True,
    }
    alert_status = client.get("/api/status", headers=admin_headers()).json()["alerts"][0]
    assert alert_status["stopped_count"] == 1


def test_receiver_cannot_acknowledge_an_undelivered_alert(client: TestClient) -> None:
    device = enroll(client)
    track = upload_track(client)
    created = client.post(
        "/api/alerts",
        headers=admin_headers(),
        json={"track_id": track["id"], "lead_ms": 3_000},
    ).json()
    client.post(f"/api/alerts/{created['alert_id']}/stop", headers=admin_headers())

    with client.websocket_connect("/ws/receiver") as websocket:
        websocket.send_json(
            {
                "type": "auth",
                "device_id": device["device_id"],
                "device_secret": device["device_secret"],
            }
        )
        assert websocket.receive_json()["type"] == "auth.ok"
        websocket.send_json(
            {
                "type": "alert.status",
                "alert_id": created["alert_id"],
                "status": "ready",
            }
        )
        websocket.send_json({"type": "ping", "client_time_ms": 1})
        assert websocket.receive_json()["type"] == "pong"

    alert_status = client.get("/api/status", headers=admin_headers()).json()["alerts"][0]
    assert alert_status["delivered_count"] == 0
    assert alert_status["receipt_count"] == 0
    assert alert_status["receipts"] == []


def test_revocation_invalidates_media_access(client: TestClient) -> None:
    device = enroll(client)
    track = upload_track(client)
    client.delete(f"/api/devices/{device['device_id']}", headers=admin_headers())

    response = client.get(
        f"/media/{track['id']}",
        headers={
            "X-Device-Id": device["device_id"],
            "Authorization": f"Bearer {device['device_secret']}",
        },
    )

    assert response.status_code == 401
