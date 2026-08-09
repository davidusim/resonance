from pathlib import Path

import pytest

from resonance.config import Settings


def test_rate_limits_are_configurable_from_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RESONANCE_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("RESONANCE_ADMIN_TOKEN", "configured-admin-token-long-enough")
    monkeypatch.setenv("RESONANCE_RATE_LIMIT_WINDOW_SECONDS", "120")
    monkeypatch.setenv("RESONANCE_RATE_LIMIT_MAX_CLIENTS", "250")
    monkeypatch.setenv("RESONANCE_ENROLLMENT_ATTEMPT_LIMIT", "8")
    monkeypatch.setenv("RESONANCE_DEVICE_AUTH_ATTEMPT_LIMIT", "80")
    monkeypatch.setenv("RESONANCE_DEVICE_PEER_ATTEMPT_LIMIT", "800")
    monkeypatch.setenv("RESONANCE_ADMIN_AUTH_FAILURE_LIMIT", "12")

    settings = Settings.from_environment()

    assert settings.rate_limit_window_seconds == 120
    assert settings.rate_limit_max_clients == 250
    assert settings.enrollment_attempt_limit == 8
    assert settings.device_auth_attempt_limit == 80
    assert settings.device_peer_attempt_limit == 800
    assert settings.admin_auth_failure_limit == 12


@pytest.mark.parametrize("value", ["0", "not-a-number", "3601"])
def test_invalid_rate_limit_configuration_fails_closed(
    value: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RESONANCE_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("RESONANCE_ADMIN_TOKEN", "configured-admin-token-long-enough")
    monkeypatch.setenv("RESONANCE_RATE_LIMIT_WINDOW_SECONDS", value)

    with pytest.raises(RuntimeError, match="RESONANCE_RATE_LIMIT_WINDOW_SECONDS"):
        Settings.from_environment()
