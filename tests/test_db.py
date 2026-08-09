import sqlite3
from pathlib import Path

from resonance.db import Database


def test_existing_alert_schema_is_migrated_without_data_loss(tmp_path: Path) -> None:
    path = tmp_path / "resonance.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE alerts (
                id TEXT PRIMARY KEY,
                track_id TEXT NOT NULL,
                start_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                stopped_at INTEGER
            )
            """
        )
        connection.execute(
            "INSERT INTO alerts(id, track_id, start_at, created_at) VALUES(?, ?, ?, ?)",
            ("existing-alert", "existing-track", 2_000, 1_000),
        )

    database = Database(path)

    migrated = database.fetch_one("SELECT * FROM alerts WHERE id = ?", ("existing-alert",))
    assert migrated is not None
    assert migrated["track_id"] == "existing-track"
    assert migrated["delivered_count"] == 0
    assert database.fetch_one(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'alert_receipts'"
    ) == {"name": "alert_receipts"}
    assert database.fetch_one(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'alert_deliveries'"
    ) == {"name": "alert_deliveries"}
