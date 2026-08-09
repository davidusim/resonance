from pathlib import Path

import pytest
from fastapi.testclient import TestClient

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

    assert response.json() == {"status": "ok"}
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "microphone=()" in response.headers["permissions-policy"]


def test_admin_routes_require_bearer_token(client: TestClient) -> None:
    assert client.get("/api/devices").status_code == 401
    assert client.get("/api/devices", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/api/devices", headers=admin_headers()).status_code == 200


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

    assert response.status_code == 200
    assert response.json()["delivered"] == 1
    assert event["type"] == "alert.prepare"
    assert event["track"]["sha256"] == track["sha256"]
    # SQLite/audit work happens before the socket send, so allow a small part of the
    # requested lead time to be consumed on unusually slow filesystems.
    assert event["start_at_ms"] >= event["sent_at_ms"] + 2_500


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
