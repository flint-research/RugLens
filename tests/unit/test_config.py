"""Configuration tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from ruglens.core.config import RugLensSettings
from ruglens.core.exceptions import ConfigurationError


def test_env_loading_and_overrides(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("RUGLENS_DATA_DIR", str(tmp_path / "home"))
    monkeypatch.setenv("RUGLENS_RPC_TIMEOUT", "3.5")
    monkeypatch.setenv("RUGLENS_SIMULATION_ENABLED", "false")
    monkeypatch.setenv("RUGLENS_API_PORT", "9001")
    monkeypatch.setenv(
        "RUGLENS_EXTRA_LP_LOCKERS",
        "0x1111111111111111111111111111111111111111,0x2222222222222222222222222222222222222222",
    )
    settings = RugLensSettings.from_env({"cache_max_bytes": 1000})
    assert settings.data_dir == tmp_path / "home"
    assert settings.rpc_timeout == 3.5
    assert settings.simulation_enabled is False
    assert settings.api_port == 9001
    assert settings.cache_max_bytes == 1000
    assert len(settings.extra_lp_lockers) == 2
    assert settings.resolved_cache_path() == tmp_path / "home" / "cache.sqlite3"
    assert settings.resolved_database_url().startswith("sqlite+aiosqlite:///")
    assert settings.resolved_plugin_dir() == tmp_path / "home" / "plugins"


def test_invalid_env_values_raise(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RUGLENS_RPC_MAX_RETRIES", "not-an-int")
    with pytest.raises(ConfigurationError):
        RugLensSettings.from_env()
    monkeypatch.setenv("RUGLENS_RPC_MAX_RETRIES", "2")
    monkeypatch.setenv("RUGLENS_RPC_TIMEOUT", "-1")
    with pytest.raises(ValidationError):
        RugLensSettings.from_env()


def test_api_limits_are_validated() -> None:
    with pytest.raises(ValidationError):
        RugLensSettings(api_max_body_bytes=0)
    with pytest.raises(ValidationError):
        RugLensSettings(api_queue_timeout=0)


def test_ensure_directories(tmp_path: Path) -> None:
    settings = RugLensSettings(data_dir=tmp_path / "data", plugins_enabled=True)
    settings.ensure_directories()
    assert (tmp_path / "data").is_dir()
    assert (tmp_path / "data" / "plugins").is_dir()
