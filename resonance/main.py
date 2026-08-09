from __future__ import annotations

import asyncio
import hashlib
import logging
import sqlite3
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
from .rate_limit import RateLimitDecision, TokenBucketRateLimiter
from .realtime import ConnectionManager
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
WEBSOCKET_AUTH_TIMEOUT_SECONDS = 8
logger = logging.getLogger("uvicorn.error.resonance")


class EnrollmentRequest(BaseModel):
    ttl_seconds: int | None = Field(default=None, ge=60, le=3600)


class DeviceEnrollment(BaseModel):
    code: str = Field(min_length=8, max_length=32)
    name: str = Field(min_length=1, max_length=80)


class AlertRequest(BaseModel):
    track_id: str
    lead_ms: int | None = Field(default=None, ge=3_000, le=30_000)


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
        version="0.4.0",
        docs_url=None,
        redoc_url=None,
        lifespan=lifespan,
    )
    app.state.settings = resolved
    app.state.db = database
    app.state.connections = manager
    rate_limiters = {
        "admin": TokenBucketRateLimiter(
            resolved.admin_auth_failure_limit,
            window_seconds=resolved.rate_limit_window_seconds,
            max_clients=resolved.rate_limit_max_clients,
        ),
        "enrollment": TokenBucketRateLimiter(
            resolved.enrollment_attempt_limit,
            window_seconds=resolved.rate_limit_window_seconds,
            max_clients=resolved.rate_limit_max_clients,
        ),
        "device_peer": TokenBucketRateLimiter(
            resolved.device_peer_attempt_limit,
            window_seconds=resolved.rate_limit_window_seconds,
            max_clients=resolved.rate_limit_max_clients,
        ),
        "device_http": TokenBucketRateLimiter(
            resolved.device_auth_attempt_limit,
            window_seconds=resolved.rate_limit_window_seconds,
            max_clients=resolved.rate_limit_max_clients,
        ),
        "device_websocket": TokenBucketRateLimiter(
            resolved.device_auth_attempt_limit,
            window_seconds=resolved.rate_limit_window_seconds,
            max_clients=resolved.rate_limit_max_clients,
        ),
    }
    app.state.rate_limiters = rate_limiters

    async def run_db(operation, *args, **kwargs):
        return await asyncio.to_thread(operation, *args, **kwargs)

    def client_key(connection: Request | WebSocket, discriminator: str | None = None) -> str:
        peer = connection.client.host if connection.client else "unknown"
        return f"{peer}\x1f{discriminator}" if discriminator else peer

    def reject_rate_limited(scope: str, decision: RateLimitDecision) -> None:
        logger.warning(
            "rate_limit_exceeded scope=%s retry_after_seconds=%s",
            scope,
            decision.retry_after_seconds,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many attempts. Try again later.",
            headers={"Retry-After": str(decision.retry_after_seconds)},
        )

    def enforce_rate_limit(
        scope: str,
        connection: Request | WebSocket,
        discriminator: str | None = None,
    ) -> None:
        decision = rate_limiters[scope].check(client_key(connection, discriminator))
        if not decision.allowed:
            reject_rate_limited(scope, decision)

    def parse_client_time(value: Any) -> int | None:
        return (
            int(value)
            if isinstance(value, (int, float))
            and not isinstance(value, bool)
            and -(2**53) < value < 2**53
            else None
        )

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
        supplied_request_id = request.headers.get("X-Request-ID", "")
        request_id = (
            supplied_request_id
            if 0 < len(supplied_request_id) <= 64
            and all(character.isalnum() or character in "-_." for character in supplied_request_id)
            else uuid.uuid4().hex
        )
        started_at = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            logger.exception(
                "http_request_failed method=%s path=%s request_id=%s",
                request.method,
                request.url.path,
                request_id,
            )
            raise
        duration_ms = (time.perf_counter() - started_at) * 1000
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = "camera=(), geolocation=(), microphone=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; connect-src 'self' ws: wss:; media-src 'self' blob:; "
            "style-src 'self'; script-src 'self'; img-src 'self' data:"
        )
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        response.headers["X-Request-ID"] = request_id
        response.headers["Server-Timing"] = f"app;dur={duration_ms:.1f}"
        log_request = logger.debug if request.url.path == "/healthz" else logger.info
        log_request(
            "http_request method=%s path=%s status=%s duration_ms=%.1f request_id=%s",
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
            request_id,
        )
        return response

    def require_admin(
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
    ) -> None:
        scheme, _, supplied = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not constant_time_equal(supplied, resolved.admin_token):
            enforce_rate_limit("admin", request)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid admin token",
                headers={"WWW-Authenticate": "Bearer"},
            )

    async def authenticate_device_headers(
        request: Request,
        x_device_id: Annotated[str | None, Header()] = None,
        authorization: Annotated[str | None, Header()] = None,
    ) -> str:
        scheme, _, secret = (authorization or "").partition(" ")
        if (
            not x_device_id
            or scheme.lower() != "bearer"
            or not 1 <= len(x_device_id) <= 64
            or not 1 <= len(secret) <= 128
        ):
            enforce_rate_limit("device_peer", request)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid device credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        enforce_rate_limit("device_peer", request)
        enforce_rate_limit("device_http", request, x_device_id)
        if not await run_db(database.authenticate_device, x_device_id, secret):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid device credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        await run_db(database.touch_device, x_device_id)
        return x_device_id

    @app.get("/healthz")
    async def health() -> JSONResponse:
        try:
            await run_db(database.check_health)
        except sqlite3.Error:
            logger.exception("health_check_failed component=database")
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"status": "unavailable", "database": "error"},
            )
        return JSONResponse(content={"status": "ok", "database": "ok"})

    @app.get("/api/time")
    async def server_time() -> dict[str, int]:
        return {"server_time_ms": int(time.time() * 1000)}

    @app.post("/api/enrollments", dependencies=[Depends(require_admin)])
    async def create_enrollment(payload: EnrollmentRequest) -> dict[str, Any]:
        enrollment_id = str(uuid.uuid4())
        code = generate_enrollment_code()
        ttl_seconds = payload.ttl_seconds or resolved.enrollment_ttl_seconds
        expires_at = int(time.time() * 1000) + ttl_seconds * 1000
        await run_db(database.create_enrollment, enrollment_id, code, expires_at)
        return {"code": code, "expires_at": expires_at}

    @app.post("/api/devices/enroll", status_code=status.HTTP_201_CREATED)
    async def enroll_device(request: Request, payload: DeviceEnrollment) -> dict[str, str]:
        enforce_rate_limit("enrollment", request)
        device_id = str(uuid.uuid4())
        secret = generate_secret(32)
        clean_name = " ".join(payload.name.split())
        if not clean_name:
            raise HTTPException(status_code=422, detail="Device name cannot be blank")
        if not await run_db(
            database.consume_enrollment, payload.code, device_id, clean_name, secret
        ):
            raise HTTPException(
                status_code=400, detail="Enrollment code is invalid, expired, or already used"
            )
        return {"device_id": device_id, "device_secret": secret, "name": clean_name}

    @app.get("/api/devices", dependencies=[Depends(require_admin)])
    async def list_devices() -> dict[str, Any]:
        devices = await run_db(
            database.fetch_all,
            """
            SELECT id, name, created_at, last_seen_at, revoked
            FROM devices ORDER BY created_at DESC
            """,
        )
        connected_ids = manager.connected_ids
        for device in devices:
            device["connected"] = device["id"] in connected_ids
            device["revoked"] = bool(device["revoked"])
        return {"devices": devices}

    @app.delete("/api/devices/{device_id}", dependencies=[Depends(require_admin)])
    async def revoke_device(device_id: str) -> dict[str, str]:
        existing = await run_db(
            database.fetch_one, "SELECT id FROM devices WHERE id = ?", (device_id,)
        )
        if not existing:
            raise HTTPException(status_code=404, detail="Device not found")
        await run_db(database.execute, "UPDATE devices SET revoked = 1 WHERE id = ?", (device_id,))
        await run_db(database.audit, "device.revoked", device_id, {})
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
        await run_db(
            database.execute,
            """
            INSERT INTO tracks(id, name, content_type, size_bytes, sha256, filename, created_at)
            VALUES(?, ?, ?, ?, ?, ?, ?)
            """,
            (track_id, clean_name, content_type, size, digest, destination.name, created_at),
        )
        await run_db(
            database.audit, "track.uploaded", track_id, {"name": clean_name, "sha256": digest}
        )
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
        tracks = await run_db(
            database.fetch_all,
            """
            SELECT id, name, content_type, size_bytes, sha256, created_at
            FROM tracks ORDER BY created_at DESC
            """,
        )
        return {"tracks": tracks}

    @app.get("/media/{track_id}")
    async def media(track_id: str, _: str = Depends(authenticate_device_headers)) -> FileResponse:
        track = await run_db(database.fetch_one, "SELECT * FROM tracks WHERE id = ?", (track_id,))
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
        track = await run_db(
            database.fetch_one,
            "SELECT id, name, sha256, content_type FROM tracks WHERE id = ?",
            (payload.track_id,),
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
        event = build_alert_event(
            alert_id=alert_id,
            track_id=track["id"],
            track_name=track["name"],
            sha256=track["sha256"],
            content_type=track["content_type"],
            start_at_ms=start_at,
        )
        targets = await manager.snapshot()
        target_ids = [device_id for device_id, _ in targets]
        delivered = await run_db(
            database.create_alert,
            alert_id,
            payload.track_id,
            start_at,
            now,
            target_ids,
        )
        delivered_ids = await manager.broadcast(event, targets=targets)
        failed_ids = list(set(target_ids) - set(delivered_ids))
        if failed_ids:
            delivered = await run_db(database.remove_alert_deliveries, alert_id, failed_ids)
        await run_db(
            database.audit,
            "alert.started",
            alert_id,
            {"track_id": payload.track_id, "delivered": delivered},
        )
        logger.info("alert_started alert_id=%s delivered=%s", alert_id, delivered)
        return {"alert_id": alert_id, "start_at_ms": start_at, "delivered": delivered}

    @app.post("/api/alerts/{alert_id}/stop", dependencies=[Depends(require_admin)])
    async def stop_alert(alert_id: str) -> dict[str, Any]:
        alert = await run_db(database.fetch_one, "SELECT id FROM alerts WHERE id = ?", (alert_id,))
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        stopped_at = int(time.time() * 1000)
        await run_db(
            database.execute,
            "UPDATE alerts SET stopped_at = ? WHERE id = ?",
            (stopped_at, alert_id),
        )
        authorized_ids = set(await run_db(database.alert_delivery_ids, alert_id))
        stop_targets = [
            target for target in await manager.snapshot() if target[0] in authorized_ids
        ]
        delivered_ids = await manager.broadcast(
            {
                "type": "alert.stop",
                "alert_id": alert_id,
                "sent_at_ms": stopped_at,
                "replayed": False,
            },
            targets=stop_targets,
        )
        delivered = len(delivered_ids)
        await run_db(database.audit, "alert.stopped", alert_id, {"delivered": delivered})
        logger.info("alert_stopped alert_id=%s delivered=%s", alert_id, delivered)
        return {"status": "stopped", "delivered": delivered}

    @app.get("/api/status", dependencies=[Depends(require_admin)])
    async def coordinator_status() -> dict[str, Any]:
        recent_alerts = await run_db(
            database.fetch_all,
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
            """,
        )
        if recent_alerts:
            placeholders = ",".join("?" for _ in recent_alerts)
            receipts = await run_db(
                database.fetch_all,
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
        audit = await run_db(
            database.fetch_all,
            """
            SELECT event_type, subject_id, details_json, created_at
            FROM audit_events ORDER BY created_at DESC LIMIT 30
            """,
        )
        return {"connected_receivers": manager.count, "alerts": recent_alerts, "audit": audit}

    @app.websocket("/ws/receiver")
    async def receiver_socket(websocket: WebSocket) -> None:
        await websocket.accept()
        device_id = ""
        try:
            decision = rate_limiters["device_peer"].check(client_key(websocket))
            if not decision.allowed:
                logger.warning(
                    "rate_limit_exceeded scope=device_peer retry_after_seconds=%s",
                    decision.retry_after_seconds,
                )
                await websocket.close(code=4429, reason="Too many connection attempts")
                return
            auth_message = await asyncio.wait_for(
                websocket.receive_json(), timeout=WEBSOCKET_AUTH_TIMEOUT_SECONDS
            )
            if not isinstance(auth_message, dict) or auth_message.get("type") != "auth":
                await websocket.close(code=4401, reason="Authentication required")
                return
            raw_device_id = auth_message.get("device_id")
            raw_device_secret = auth_message.get("device_secret")
            if (
                not isinstance(raw_device_id, str)
                or not isinstance(raw_device_secret, str)
                or not 1 <= len(raw_device_id) <= 64
                or not 1 <= len(raw_device_secret) <= 128
            ):
                await websocket.close(code=4401, reason="Invalid device credentials")
                return
            device_id = raw_device_id
            device_secret = raw_device_secret
            decision = rate_limiters["device_websocket"].check(client_key(websocket, device_id))
            if not decision.allowed:
                logger.warning(
                    "rate_limit_exceeded scope=device_websocket retry_after_seconds=%s",
                    decision.retry_after_seconds,
                )
                await websocket.close(code=4429, reason="Too many connection attempts")
                return
            if not await run_db(database.authenticate_device, device_id, device_secret):
                await websocket.close(code=4401, reason="Invalid device credentials")
                return
            await run_db(database.touch_device, device_id)
            await manager.connect(device_id, websocket)
            authenticated = await manager.send(
                device_id,
                websocket,
                {
                    "type": "auth.ok",
                    "device_id": device_id,
                    "server_time_ms": int(time.time() * 1000),
                },
            )
            if not authenticated:
                return
            for stopped in await run_db(database.stopped_alerts_for_device, device_id):
                sent = await manager.send(
                    device_id,
                    websocket,
                    {
                        "type": "alert.stop",
                        "alert_id": stopped["id"],
                        "sent_at_ms": stopped["stopped_at"],
                        "replayed": True,
                    },
                )
                if not sent:
                    return
            for pending in await run_db(database.pending_alerts):
                await run_db(
                    database.record_alert_deliveries,
                    pending["id"],
                    [device_id],
                    replayed=True,
                )
                sent = await manager.send(
                    device_id,
                    websocket,
                    build_alert_event(
                        alert_id=pending["id"],
                        track_id=pending["track_id"],
                        track_name=pending["track_name"],
                        sha256=pending["sha256"],
                        content_type=pending["content_type"],
                        start_at_ms=pending["start_at"],
                        replayed=True,
                    ),
                )
                if not sent:
                    return
                logger.info("alert_replayed alert_id=%s device_id=%s", pending["id"], device_id)
            while True:
                message = await websocket.receive_json()
                if not isinstance(message, dict):
                    continue
                if message.get("type") == "ping":
                    client_time_ms = parse_client_time(message.get("client_time_ms"))
                    sent = await manager.send(
                        device_id,
                        websocket,
                        {
                            "type": "pong",
                            "client_time_ms": client_time_ms,
                            "server_time_ms": int(time.time() * 1000),
                        },
                    )
                    if not sent:
                        return
                    await run_db(database.touch_device, device_id)
                elif message.get("type") == "alert.status":
                    receipt_status = message.get("status")
                    alert_id = message.get("alert_id")
                    if (
                        not isinstance(receipt_status, str)
                        or receipt_status not in ALERT_RECEIPT_STATUSES
                        or not isinstance(alert_id, str)
                        or not 1 <= len(alert_id) <= 64
                    ):
                        continue
                    client_time_ms = parse_client_time(message.get("client_time_ms"))
                    raw_detail = message.get("detail", "")
                    detail = (
                        " ".join(raw_detail.split())[:240] if isinstance(raw_detail, str) else ""
                    )
                    recorded = await run_db(
                        database.record_alert_receipt,
                        alert_id,
                        device_id,
                        receipt_status,
                        detail,
                        client_time_ms,
                    )
                    if not recorded:
                        logger.warning(
                            "alert_receipt_rejected alert_id=%s device_id=%s status=%s",
                            alert_id,
                            device_id,
                            receipt_status,
                        )
        except asyncio.TimeoutError:
            try:
                await asyncio.wait_for(
                    websocket.close(code=4408, reason="Authentication timed out"),
                    timeout=2,
                )
            except (TimeoutError, asyncio.TimeoutError, RuntimeError, OSError, WebSocketDisconnect):
                pass
        except (WebSocketDisconnect, ValueError):
            pass
        finally:
            if device_id:
                await manager.disconnect(device_id, websocket)

    @app.exception_handler(HTTPException)
    async def http_exception_handler(_: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
            headers=exc.headers,
        )

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
