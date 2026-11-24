"""Boot the production app with no injected engine (no network)."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from ruglens.core.config import RugLensSettings
from ruglens.interfaces.api.app import create_app


def test_production_app_builds_and_serves_health(tmp_path: Path) -> None:
    settings = RugLensSettings(
        data_dir=tmp_path,
        cache_path=tmp_path / "cache.sqlite3",
        database_url=f"sqlite+aiosqlite:///{(tmp_path / 'db.sqlite3').as_posix()}",
        simulation_enabled=False,
        plugins_enabled=False,
        slither_enabled=False,
        persist_reports=False,
        load_cached_reports=False,
    )
    with TestClient(create_app(settings)) as client:
        health = client.get("/v1/health")
        assert health.status_code == 200
        payload = health.json()
        assert payload["engine_ready"] is True
        assert payload["detector_count"] == 10
        assert payload["simulation_enabled"] is False
        detectors = client.get("/v1/detectors")
        assert detectors.status_code == 200
        ids = {item["detector_id"] for item in detectors.json()["detectors"]}
        assert {"bytecode_selectors", "dynamic_honeypot", "ownership", "liquidity"} <= ids
