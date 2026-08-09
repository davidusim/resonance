from __future__ import annotations

import asyncio
import hashlib
import sys
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any

from fastapi import (
    Depends,
    FastAPI,
    File,
    Header,
    HTTPException,
    Request,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .config import Settings
from .db import Database
from .security import (
    constant_time_equal,
    generate_enrollment_code,
    generate_secret,
)

SOURCE_STATIC_DIR = Path(__file__).parent.parent / "static"
INSTALLED_STATIC_DIR = Path(sys.prefix) / "static"
STATIC_DIR = SOURCE_STATIC_DIR if SOURCE_STATIC_DIR.is_dir() else INSTALLED_STATIC_DIR
ALERT_RECEIPT_STATUSES = frozenset({"ready", "playing", "completed", "stopped", "error"})
SCHEDULE_PERSISTENCE_MARGIN_MS = 1_000


class EnrollmentRequest(BaseModel):
    ttl_seconds: int | None = Field(default=None, ge=60, le=3600)


class DeviceEnrollment(BaseModel):
    code: str = Field(min_length=8, max_length=32)
    name: str = Field(min_length=1, max_length=80)


class AlertRequest(BaseModel):
    track_id: str
    lead_ms: int | None = Field(default=None, ge=3_000, le=30_000)


class ConnectionManager:
    def __init__(self) -> None:
        self._connections: dict[str, WebSocket] = {}
        self._lock = asyncio.Lock()

    async def connect(self, device_id: str, websocket: WebSocket) -> None:
        async with self._lock:
            previous = self._connections.get(device_id)
            self._connections[device_id] = websocket
        if previous and previous is not websocket:
            await previous.close(code=4001, reason="A newer connection replaced this session")

    async def disconnect(self, device_id: str, websocket: WebSocket) -> None:
        async with self._lock:
            if self._connections.get(device_id) is websocket:
                self._connections.pop(device_id, None)

    async def disconnect_device(self, device_id: str) -> None:
        async with self._lock:
            websocket = self._connections.pop(device_id, None)
        if websocket:
            try:
                await websocket.close(code=4003, reason="Device access revoked")
            except RuntimeError:
                pass

    async def broadcast(self, payload: dict[str, Any]) -> list[str]:
        async with self._lock:
            connections = list(self._connections.items())
        delivered: list[str] = []
        stale: list[tuple[str, WebSocket]] = []
        for device_id, websocket in connections:
            try:
                await websocket.send_json(payload)
                delivered.append(device_id)
            except (RuntimeError, OSError, WebSocketDisconnect):
                stale.append((device_id, websocket))
        for device_id, websocket in stale:
            await self.disconnect(device_id, websocket)
        return delivered

    @property
    def count(self) -> int:
        return len(self._connections)

    @property
    def connected_ids(self) -> frozenset[str]:
        return frozenset(self._connections)


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved = settings or Settings.from_environment()
    resolved.data_dir.mkdir(parents=True, exist_ok=True)
    tracks_dir = resolved.data_dir / "tracks"
    tracks_dir.mkdir(parents=True, exist_ok=True)
    database = Database(resolved.data_dir / "resonance.sqlite3")
    manager = ConnectionManager()

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield

    app = FastAPI(
        title="Resonance Alert",
        version="0.2.0",
        docs_url=None,
        redoc_url=None,
        lifespan=lifespan,
    )
    app.state.settings = resolved
    app.state.db = database
    app.state.connections = manager

    def build_alert_event(
        *,
        alert_id: str,
        track_id: str,
        track_name: str,
        sha256: str,
        content_type: str,
        start_at_ms: int,
        replayed: bool = False,
    ) -> dict[str, Any]:
        return {
            "type": "alert.prepare",
            "alert_id": alert_id,
            "track": {
                "id": track_id,
                "name": track_name,
                "sha256": sha256,
                "content_type": content_type,
                "url": f"/media/{track_id}",
            },
            "start_at_ms": start_at_ms,
            "sent_at_ms": int(time.time() * 1000),
            "replayed": replayed,
        }

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), geolocation=(), microphone=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; connect-src 'self' ws: wss:; media-src 'self' blob:; "
            "style-src 'self'; script-src 'self'; img-src 'self' data:"
        )
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    def require_admin(authorization: Annotated[str | None, Header()] = None) -> None:
        scheme, _, supplied = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not constant_time_equal(supplied, resolved.admin_token):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid admin token"
            )

    def authenticate_device_headers(
        x_device_id: Annotated[str | None, Header()] = None,
        authorization: Annotated[str | None, Header()] = None,
    ) -> str:
        scheme, _, secret = (authorization or "").partition(" ")
        if (
            not x_device_id
            or scheme.lower() != "bearer"
            or not database.authenticate_device(x_device_id, secret)
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid device credentials"
            )
        database.touch_device(x_device_id)
        return x_device_id

    @app.get("/healthz")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/time")
    async def server_time() -> dict[str, int]:
        return {"server_time_ms": int(time.time() * 1000)}

    @app.post("/api/enrollments", dependencies=[Depends(require_admin)])
    async def create_enrollment(payload: EnrollmentRequest) -> dict[str, Any]:
        enrollment_id = str(uuid.uuid4())
        code = generate_enrollment_code()
        ttl_seconds = payload.ttl_seconds or resolved.enrollment_ttl_seconds
        expires_at = int(time.time() * 1000) + ttl_seconds * 1000
        database.create_enrollment(enrollment_id, code, expires_at)
        return {"code": code, "expires_at": expires_at}

    @app.post("/api/devices/enroll", status_code=status.HTTP_201_CREATED)
    async def enroll_device(payload: DeviceEnrollment) -> dict[str, str]:
        device_id = str(uuid.uuid4())
        secret = generate_secret(32)
        clean_name = " ".join(payload.name.split())
        if not clean_name:
            raise HTTPException(status_code=422, detail="Device name cannot be blank")
        if not database.consume_enrollment(payload.code, device_id, clean_name, secret):
            raise HTTPException(
                status_code=400, detail="Enrollment code is invalid, expired, or already used"
            )
        return {"device_id": device_id, "device_secret": secret, "name": clean_name}

    @app.get("/api/devices", dependencies=[Depends(require_admin)])
    async def list_devices() -> dict[str, Any]:
        devices = database.fetch_all(
            """
            SELECT id, name, created_at, last_seen_at, revoked
            FROM devices ORDER BY created_at DESC
            """
        )
        connected_ids = manager.connected_ids
        for device in devices:
            device["connected"] = device["id"] in connected_ids
            device["revoked"] = bool(device["revoked"])
        return {"devices": devices}

    @app.delete("/api/devices/{device_id}", dependencies=[Depends(require_admin)])
    async def revoke_device(device_id: str) -> dict[str, str]:
        existing = database.fetch_one("SELECT id FROM devices WHERE id = ?", (device_id,))
        if not existing:
            raise HTTPException(status_code=404, detail="Device not found")
        database.execute("UPDATE devices SET revoked = 1 WHERE id = ?", (device_id,))
        database.audit("device.revoked", device_id, {})
        await manager.disconnect_device(device_id)
        return {"status": "revoked"}

    @app.post("/api/tracks", dependencies=[Depends(require_admin)])
    async def upload_track(file: Annotated[UploadFile, File()]) -> dict[str, Any]:
        content_type = (file.content_type or "").lower()
        if not content_type.startswith("audio/"):
            raise HTTPException(status_code=415, detail="Only audio uploads are accepted")
        track_id = str(uuid.uuid4())
        destination = tracks_dir / f"{track_id}.audio"
        hasher = hashlib.sha256()
        size = 0
        try:
            with destination.open("wb") as output:
                while chunk := await file.read(1024 * 1024):
                    size += len(chunk)
                    if size > resolved.max_audio_bytes:
                        raise HTTPException(status_code=413, detail="Audio file is too large")
                    hasher.update(chunk)
                    output.write(chunk)
        except Exception:
            destination.unlink(missing_ok=True)
            raise
        finally:
            await file.close()
        if size == 0:
            destination.unlink(missing_ok=True)
            raise HTTPException(status_code=400, detail="Audio file is empty")

        clean_name = Path(file.filename or "Emergency audio").name[:120]
        created_at = int(time.time() * 1000)
        digest = hasher.hexdigest()
        database.execute(
            """
            INSERT INTO tracks(id, name, content_type, size_bytes, sha256, filename, created_at)
            VALUES(?, ?, ?, ?, ?, ?, ?)
            """,
            (track_id, clean_name, content_type, size, digest, destination.name, created_at),
        )
        database.audit("track.uploaded", track_id, {"name": clean_name, "sha256": digest})
        return {
            "id": track_id,
            "name": clean_name,
            "content_type": content_type,
            "size_bytes": size,
            "sha256": digest,
            "created_at": created_at,
        }

    @app.get("/api/tracks", dependencies=[Depends(require_admin)])
    async def list_tracks() -> dict[str, Any]:
        tracks = database.fetch_all(
            """
            SELECT id, name, content_type, size_bytes, sha256, created_at
            FROM tracks ORDER BY created_at DESC
            """
        )
        return {"tracks": tracks}

    @app.get("/media/{track_id}")
    async def media(track_id: str, _: str = Depends(authenticate_device_headers)) -> FileResponse:
        track = database.fetch_one("SELECT * FROM tracks WHERE id = ?", (track_id,))
        if not track:
            raise HTTPException(status_code=404, detail="Track not found")
        path = tracks_dir / track["filename"]
        if not path.is_file():
            raise HTTPException(status_code=404, detail="Track data is missing")
        return FileResponse(
            path,
            media_type=track["content_type"],
            filename=track["name"],
            headers={"Cache-Control": "private, max-age=300", "X-Content-SHA256": track["sha256"]},
        )

    @app.post("/api/alerts", dependencies=[Depends(require_admin)])
    async def start_alert(payload: AlertRequest) -> dict[str, Any]:
        track = database.fetch_one(
            "SELECT id, name, sha256, content_type FROM tracks WHERE id = ?", (payload.track_id,)
        )
        if not track:
            raise HTTPException(status_code=404, detail="Track not found")
        lead_ms = payload.lead_ms or resolved.default_lead_ms
        now = int(time.time() * 1000)
        # Leave room for the durable SQLite write before the prepare event is sent.
        # Receivers still receive at least the configured preparation window on
        # ordinary storage, rather than losing it to coordinator persistence.
        start_at = now + lead_ms + SCHEDULE_PERSISTENCE_MARGIN_MS
        alert_id = str(uuid.uuid4())
        database.execute(
            "INSERT INTO alerts(id, track_id, start_at, created_at) VALUES(?, ?, ?, ?)",
            (alert_id, payload.track_id, start_at, now),
        )
        event = build_alert_event(
            alert_id=alert_id,
            track_id=track["id"],
            track_name=track["name"],
            sha256=track["sha256"],
            content_type=track["content_type"],
            start_at_ms=start_at,
        )
        delivered_ids = await manager.broadcast(event)
        delivered = database.record_alert_deliveries(alert_id, delivered_ids, replayed=False)
        database.audit(
            "alert.started", alert_id, {"track_id": payload.track_id, "delivered": delivered}
        )
        return {"alert_id": alert_id, "start_at_ms": start_at, "delivered": delivered}

    @app.post("/api/alerts/{alert_id}/stop", dependencies=[Depends(require_admin)])
    async def stop_alert(alert_id: str) -> dict[str, Any]:
        alert = database.fetch_one("SELECT id FROM alerts WHERE id = ?", (alert_id,))
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        stopped_at = int(time.time() * 1000)
        database.execute("UPDATE alerts SET stopped_at = ? WHERE id = ?", (stopped_at, alert_id))
        delivered_ids = await manager.broadcast(
            {"type": "alert.stop", "alert_id": alert_id, "sent_at_ms": stopped_at}
        )
        delivered = len(delivered_ids)
        database.audit("alert.stopped", alert_id, {"delivered": delivered})
        return {"status": "stopped", "delivered": delivered}

    @app.get("/api/status", dependencies=[Depends(require_admin)])
    async def coordinator_status() -> dict[str, Any]:
        recent_alerts = database.fetch_all(
            """
            SELECT
                a.id, a.track_id, t.name AS track_name, a.start_at, a.created_at,
                a.stopped_at, a.delivered_count,
                COUNT(r.device_id) AS receipt_count,
                COALESCE(SUM(CASE WHEN r.status = 'ready' THEN 1 ELSE 0 END), 0) AS ready_count,
                COALESCE(SUM(CASE WHEN r.status = 'playing' THEN 1 ELSE 0 END), 0) AS playing_count,
                COALESCE(SUM(CASE WHEN r.status = 'completed' THEN 1 ELSE 0 END), 0) AS completed_count,
                COALESCE(SUM(CASE WHEN r.status = 'stopped' THEN 1 ELSE 0 END), 0) AS stopped_count,
                COALESCE(SUM(CASE WHEN r.status = 'error' THEN 1 ELSE 0 END), 0) AS error_count
            FROM alerts a
            JOIN tracks t ON t.id = a.track_id
            LEFT JOIN alert_receipts r ON r.alert_id = a.id
            GROUP BY a.id
            ORDER BY a.created_at DESC LIMIT 20
            """
        )
        if recent_alerts:
            placeholders = ",".join("?" for _ in recent_alerts)
            receipts = database.fetch_all(
                f"""
                SELECT
                    r.alert_id, r.device_id, d.name AS device_name, r.status,
                    r.detail, r.client_time_ms, r.updated_at
                FROM alert_receipts r
                JOIN devices d ON d.id = r.device_id
                WHERE r.alert_id IN ({placeholders})
                ORDER BY r.updated_at DESC
                """,
                tuple(alert["id"] for alert in recent_alerts),
            )
            for alert in recent_alerts:
                alert["receipts"] = [
                    receipt for receipt in receipts if receipt["alert_id"] == alert["id"]
                ]
        audit = database.fetch_all(
            """
            SELECT event_type, subject_id, details_json, created_at
            FROM audit_events ORDER BY created_at DESC LIMIT 30
            """
        )
        return {"connected_receivers": manager.count, "alerts": recent_alerts, "audit": audit}

    @app.websocket("/ws/receiver")
    async def receiver_socket(websocket: WebSocket) -> None:
        await websocket.accept()
        device_id = ""
        try:
            auth_message = await asyncio.wait_for(websocket.receive_json(), timeout=8)
            if not isinstance(auth_message, dict) or auth_message.get("type") != "auth":
                await websocket.close(code=4401, reason="Authentication required")
                return
            device_id = str(auth_message.get("device_id", ""))
            device_secret = str(auth_message.get("device_secret", ""))
            if not database.authenticate_device(device_id, device_secret):
                await websocket.close(code=4401, reason="Invalid device credentials")
                return
            database.touch_device(device_id)
            await manager.connect(device_id, websocket)
            await websocket.send_json(
                {
                    "type": "auth.ok",
                    "device_id": device_id,
                    "server_time_ms": int(time.time() * 1000),
                }
            )
            for pending in database.pending_alerts():
                await websocket.send_json(
                    build_alert_event(
                        alert_id=pending["id"],
                        track_id=pending["track_id"],
                        track_name=pending["track_name"],
                        sha256=pending["sha256"],
                        content_type=pending["content_type"],
                        start_at_ms=pending["start_at"],
                        replayed=True,
                    )
                )
                database.record_alert_deliveries(pending["id"], [device_id], replayed=True)
            while True:
                message = await websocket.receive_json()
                if not isinstance(message, dict):
                    continue
                if message.get("type") == "ping":
                    await websocket.send_json(
                        {
                            "type": "pong",
                            "client_time_ms": message.get("client_time_ms"),
                            "server_time_ms": int(time.time() * 1000),
                        }
                    )
                    database.touch_device(device_id)
                elif message.get("type") == "alert.status":
                    receipt_status = str(message.get("status", ""))
                    alert_id = str(message.get("alert_id", ""))
                    if receipt_status not in ALERT_RECEIPT_STATUSES or not alert_id:
                        continue
                    raw_client_time = message.get("client_time_ms")
                    client_time_ms = (
                        int(raw_client_time)
                        if isinstance(raw_client_time, (int, float))
                        and not isinstance(raw_client_time, bool)
                        and -(2**53) < raw_client_time < 2**53
                        else None
                    )
                    detail = " ".join(str(message.get("detail", "")).split())[:240]
                    database.record_alert_receipt(
                        alert_id, device_id, receipt_status, detail, client_time_ms
                    )
        except (WebSocketDisconnect, asyncio.TimeoutError, ValueError):
            pass
        finally:
            if device_id:
                await manager.disconnect(device_id, websocket)

    @app.exception_handler(HTTPException)
    async def http_exception_handler(_: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/", include_in_schema=False)
    async def receiver_page() -> FileResponse:
        return FileResponse(STATIC_DIR / "receiver.html")

    @app.get("/admin", include_in_schema=False)
    async def admin_page() -> FileResponse:
        return FileResponse(STATIC_DIR / "admin.html")

    return app


def run() -> None:
    import uvicorn

    uvicorn.run("resonance.main:create_app", factory=True, host="0.0.0.0", port=8080)


if __name__ == "__main__":
    run()
