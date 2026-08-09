from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .security import generate_secret


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    admin_token: str
    max_audio_bytes: int = 25 * 1024 * 1024
    default_lead_ms: int = 5_000
    enrollment_ttl_seconds: int = 600
    rate_limit_window_seconds: int = 60
    rate_limit_max_clients: int = 10_000
    enrollment_attempt_limit: int = 6
    device_auth_attempt_limit: int = 60
    device_peer_attempt_limit: int = 600
    admin_auth_failure_limit: int = 10

    @classmethod
    def from_environment(cls) -> Settings:
        def positive_integer(name: str, default: int, maximum: int) -> int:
            raw_value = os.getenv(name, "").strip()
            if not raw_value:
                return default
            try:
                value = int(raw_value)
            except ValueError as exc:
                raise RuntimeError(f"{name} must be an integer") from exc
            if not 1 <= value <= maximum:
                raise RuntimeError(f"{name} must be between 1 and {maximum}")
            return value

        data_dir = Path(os.getenv("RESONANCE_DATA_DIR", "data")).resolve()
        data_dir.mkdir(parents=True, exist_ok=True)

        configured = os.getenv("RESONANCE_ADMIN_TOKEN", "").strip()
        token_file = data_dir / "admin.token"
        if configured:
            admin_token = configured
        elif token_file.exists():
            admin_token = token_file.read_text(encoding="utf-8").strip()
        else:
            admin_token = generate_secret(32)
            token_file.write_text(admin_token, encoding="utf-8")
            try:
                token_file.chmod(0o600)
            except OSError:
                pass
            print(f"Resonance admin token (also saved to {token_file}): {admin_token}")

        if len(admin_token) < 24:
            raise RuntimeError("RESONANCE_ADMIN_TOKEN must be at least 24 characters")
        return cls(
            data_dir=data_dir,
            admin_token=admin_token,
            rate_limit_window_seconds=positive_integer(
                "RESONANCE_RATE_LIMIT_WINDOW_SECONDS", 60, 3_600
            ),
            rate_limit_max_clients=positive_integer(
                "RESONANCE_RATE_LIMIT_MAX_CLIENTS", 10_000, 1_000_000
            ),
            enrollment_attempt_limit=positive_integer(
                "RESONANCE_ENROLLMENT_ATTEMPT_LIMIT", 6, 10_000
            ),
            device_auth_attempt_limit=positive_integer(
                "RESONANCE_DEVICE_AUTH_ATTEMPT_LIMIT", 60, 100_000
            ),
            device_peer_attempt_limit=positive_integer(
                "RESONANCE_DEVICE_PEER_ATTEMPT_LIMIT", 600, 1_000_000
            ),
            admin_auth_failure_limit=positive_integer(
                "RESONANCE_ADMIN_AUTH_FAILURE_LIMIT", 10, 100_000
            ),
        )
