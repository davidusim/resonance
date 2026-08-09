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

    @classmethod
    def from_environment(cls) -> "Settings":
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
        return cls(data_dir=data_dir, admin_token=admin_token)
