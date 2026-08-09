from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from .security import hash_secret, normalize_enrollment_code, verify_secret


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection

    def _initialize(self) -> None:
        with self._lock, self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS devices (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    secret_hash TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    last_seen_at INTEGER,
                    revoked INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS enrollment_codes (
                    id TEXT PRIMARY KEY,
                    code_hash TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    used_at INTEGER
                );
                CREATE TABLE IF NOT EXISTS tracks (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    content_type TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    track_id TEXT NOT NULL REFERENCES tracks(id),
                    start_at INTEGER NOT NULL,
                    created_at INTEGER NOT NULL,
                    stopped_at INTEGER,
                    delivered_count INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS alert_receipts (
                    alert_id TEXT NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
                    device_id TEXT NOT NULL REFERENCES devices(id),
                    status TEXT NOT NULL,
                    detail TEXT,
                    client_time_ms INTEGER,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY(alert_id, device_id)
                );
                CREATE TABLE IF NOT EXISTS alert_deliveries (
                    alert_id TEXT NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
                    device_id TEXT NOT NULL REFERENCES devices(id),
                    delivered_at INTEGER NOT NULL,
                    replayed INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY(alert_id, device_id)
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    subject_id TEXT,
                    details_json TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_receipts_alert ON alert_receipts(alert_id);
                CREATE INDEX IF NOT EXISTS idx_deliveries_alert ON alert_deliveries(alert_id);
                """
            )
            alert_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(alerts)").fetchall()
            }
            if "delivered_count" not in alert_columns:
                connection.execute(
                    "ALTER TABLE alerts ADD COLUMN delivered_count INTEGER NOT NULL DEFAULT 0"
                )

    def execute(self, sql: str, parameters: tuple[Any, ...] = ()) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(sql, parameters)
            connection.commit()

    def fetch_one(self, sql: str, parameters: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        with self._lock, self._connect() as connection:
            row = connection.execute(sql, parameters).fetchone()
            return dict(row) if row else None

    def fetch_all(self, sql: str, parameters: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        with self._lock, self._connect() as connection:
            return [dict(row) for row in connection.execute(sql, parameters).fetchall()]

    def create_enrollment(self, enrollment_id: str, code: str, expires_at: int) -> None:
        now = int(time.time() * 1000)
        normalized = normalize_enrollment_code(code)
        self.execute(
            "INSERT INTO enrollment_codes(id, code_hash, created_at, expires_at) VALUES(?, ?, ?, ?)",
            (enrollment_id, hash_secret(normalized), now, expires_at),
        )
        self.audit("enrollment.created", enrollment_id, {"expires_at": expires_at})

    def consume_enrollment(self, code: str, device_id: str, name: str, secret: str) -> bool:
        normalized = normalize_enrollment_code(code)
        now = int(time.time() * 1000)
        with self._lock, self._connect() as connection:
            candidates = connection.execute(
                """
                SELECT id, code_hash FROM enrollment_codes
                WHERE used_at IS NULL AND expires_at >= ?
                """,
                (now,),
            ).fetchall()
            match = next(
                (row for row in candidates if verify_secret(normalized, row["code_hash"])), None
            )
            if not match:
                return False
            updated = connection.execute(
                "UPDATE enrollment_codes SET used_at = ? WHERE id = ? AND used_at IS NULL",
                (now, match["id"]),
            )
            if updated.rowcount != 1:
                return False
            connection.execute(
                """
                INSERT INTO devices(id, name, secret_hash, created_at)
                VALUES(?, ?, ?, ?)
                """,
                (device_id, name, hash_secret(secret), now),
            )
            connection.execute(
                """
                INSERT INTO audit_events(event_type, subject_id, details_json, created_at)
                VALUES(?, ?, ?, ?)
                """,
                ("device.enrolled", device_id, json.dumps({"name": name}), now),
            )
            connection.commit()
            return True

    def authenticate_device(self, device_id: str, secret: str) -> bool:
        row = self.fetch_one("SELECT secret_hash, revoked FROM devices WHERE id = ?", (device_id,))
        return bool(row and not row["revoked"] and verify_secret(secret, row["secret_hash"]))

    def touch_device(self, device_id: str) -> None:
        self.execute(
            "UPDATE devices SET last_seen_at = ? WHERE id = ?",
            (int(time.time() * 1000), device_id),
        )

    def record_alert_receipt(
        self,
        alert_id: str,
        device_id: str,
        receipt_status: str,
        detail: str,
        client_time_ms: int | None,
    ) -> bool:
        now = int(time.time() * 1000)
        with self._lock, self._connect() as connection:
            delivery = connection.execute(
                """
                SELECT a.id
                FROM alerts a
                JOIN alert_deliveries d ON d.alert_id = a.id
                WHERE a.id = ? AND d.device_id = ? AND a.created_at >= ?
                """,
                (alert_id, device_id, now - 24 * 60 * 60 * 1000),
            ).fetchone()
            if not delivery:
                return False
            connection.execute(
                """
                INSERT INTO alert_receipts(
                    alert_id, device_id, status, detail, client_time_ms, updated_at
                ) VALUES(?, ?, ?, ?, ?, ?)
                ON CONFLICT(alert_id, device_id) DO UPDATE SET
                    status = excluded.status,
                    detail = excluded.detail,
                    client_time_ms = excluded.client_time_ms,
                    updated_at = excluded.updated_at
                """,
                (alert_id, device_id, receipt_status, detail, client_time_ms, now),
            )
            connection.execute("UPDATE devices SET last_seen_at = ? WHERE id = ?", (now, device_id))
            connection.commit()
            return True

    def record_alert_deliveries(
        self, alert_id: str, device_ids: list[str], *, replayed: bool
    ) -> int:
        now = int(time.time() * 1000)
        unique_ids = set(device_ids)
        with self._lock, self._connect() as connection:
            connection.executemany(
                """
                INSERT INTO alert_deliveries(alert_id, device_id, delivered_at, replayed)
                VALUES(?, ?, ?, ?)
                ON CONFLICT(alert_id, device_id) DO UPDATE SET
                    delivered_at = excluded.delivered_at,
                    replayed = MAX(alert_deliveries.replayed, excluded.replayed)
                """,
                [(alert_id, device_id, now, int(replayed)) for device_id in unique_ids],
            )
            delivered_count = connection.execute(
                "SELECT COUNT(*) AS count FROM alert_deliveries WHERE alert_id = ?",
                (alert_id,),
            ).fetchone()["count"]
            connection.execute(
                "UPDATE alerts SET delivered_count = ? WHERE id = ?",
                (delivered_count, alert_id),
            )
            connection.commit()
            return int(delivered_count)

    def pending_alerts(self) -> list[dict[str, Any]]:
        now = int(time.time() * 1000)
        return self.fetch_all(
            """
            SELECT
                a.id, a.start_at, t.id AS track_id, t.name AS track_name,
                t.sha256, t.content_type
            FROM alerts a
            JOIN tracks t ON t.id = a.track_id
            WHERE a.stopped_at IS NULL AND a.start_at > ?
            ORDER BY a.start_at ASC
            """,
            (now,),
        )

    def audit(self, event_type: str, subject_id: str | None, details: dict[str, Any]) -> None:
        self.execute(
            """
            INSERT INTO audit_events(event_type, subject_id, details_json, created_at)
            VALUES(?, ?, ?, ?)
            """,
            (
                event_type,
                subject_id,
                json.dumps(details, separators=(",", ":")),
                int(time.time() * 1000),
            ),
        )
