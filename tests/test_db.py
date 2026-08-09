import sqlite3
from pathlib import Path

from resonance.db import Database
from resonance.security import hash_secret


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


def test_legacy_device_hash_is_upgraded_after_authentication(tmp_path: Path) -> None:
    database = Database(tmp_path / "resonance.sqlite3")
    legacy_hash = hash_secret("legacy-device-secret", iterations=1_000)
    database.execute(
        """
        INSERT INTO devices(id, name, secret_hash, created_at)
        VALUES(?, ?, ?, ?)
        """,
        ("legacy-device", "Legacy device", legacy_hash, 1_000),
    )

    assert database.authenticate_device("legacy-device", "legacy-device-secret")
    upgraded = database.fetch_one(
        "SELECT secret_hash, token_hash FROM devices WHERE id = ?", ("legacy-device",)
    )
    assert upgraded is not None
    assert upgraded["secret_hash"] == legacy_hash
    assert upgraded["token_hash"].startswith("sha256$")


def test_new_enrollment_has_an_indexed_lookup_key(tmp_path: Path) -> None:
    database = Database(tmp_path / "resonance.sqlite3")

    database.create_enrollment("enrollment", "ABCDE-FGHIJ", 10_000)

    stored = database.fetch_one(
        "SELECT code_hash, code_lookup FROM enrollment_codes WHERE id = ?", ("enrollment",)
    )
    assert stored is not None
    assert stored["code_lookup"]
    assert stored["code_lookup"] not in stored["code_hash"]
