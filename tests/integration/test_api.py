"""FastAPI contract tests with an injected engine."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from tests.helpers import TOKEN, make_finding

from ruglens.core.config import RugLensSettings
from ruglens.core.enums import DetectorStatus, RiskLevel
from ruglens.core.exceptions import RpcError
from ruglens.core.models import AssessmentReport
from ruglens.detectors.registry import DetectorRegistry
from ruglens.interfaces.api.app import create_app


class FakeApiEngine:
    def __init__(self) -> None:
        self.registry = DetectorRegistry([])
        self.calls: list[tuple[Any, ...]] = []
        self.closed = False

    def detector_descriptors(self):
        return []

    async def assess_token(self, chain_id: int, address: str, block_number=None, **kwargs):
        self.calls.append((chain_id, address, block_number, kwargs))
        if address.lower() == "0x" + "22" * 20:
            raise RpcError("upstream failed")
        return AssessmentReport(
            chain_id=chain_id,
            token_address=TOKEN,
            block_number=block_number or 100,
            risk_level=RiskLevel.MODERATE,
            confidence_score=0.7,
            data_coverage=0.9,
            findings=(make_finding(),),
            detector_statuses={"bytecode_selectors": DetectorStatus.SUCCESS},
            limitations=(),
        )

    async def close(self) -> None:
        self.closed = True


@pytest.fixture
def api_settings(tmp_path: Path) -> RugLensSettings:
    return RugLensSettings(
        data_dir=tmp_path,
        database_url=f"sqlite+aiosqlite:///{(tmp_path / 'db.sqlite3').as_posix()}",
        persist_reports=False,
        simulation_enabled=False,
        plugins_enabled=False,
        api_max_body_bytes=512,
    )


def test_assess_health_and_detectors(api_settings: RugLensSettings) -> None:
    engine = FakeApiEngine()
    app = create_app(api_settings, engine=engine)
    with TestClient(app) as client:
        response = client.post(
            "/v1/assess",
            json={"chain": "eth", "address": TOKEN, "block_number": 123},
        )
        assert response.status_code == 200
        payload = response.json()
        assert payload["risk_level"] == "MODERATE"
        assert payload["token_address"] == TOKEN
        assert engine.calls[0][0] == 1
        assert engine.calls[0][2] == 123

        health = client.get("/v1/health")
        assert health.status_code == 200
        assert health.json()["engine_ready"] is True
        assert health.json()["simulation_enabled"] is False

        detectors = client.get("/v1/detectors")
        assert detectors.status_code == 200
        assert detectors.json() == {"detectors": []}
    assert engine.closed is False  # caller-owned engines are not closed


def test_unsupported_chain_is_400(api_settings: RugLensSettings) -> None:
    with TestClient(create_app(api_settings, engine=FakeApiEngine())) as client:
        response = client.post("/v1/assess", json={"chain": "arbitrum", "address": TOKEN})
        assert response.status_code == 400


def test_solana_chain_is_dispatched_as_101(api_settings: RugLensSettings) -> None:
    engine = FakeApiEngine()
    with TestClient(create_app(api_settings, engine=engine)) as client:
        response = client.post(
            "/v1/assess",
            json={
                "chain": "solana",
                "address": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            },
        )
        assert response.status_code == 200
        assert engine.calls[0][0] == 101


def test_rpc_failure_is_502(api_settings: RugLensSettings) -> None:
    with TestClient(create_app(api_settings, engine=FakeApiEngine())) as client:
        response = client.post("/v1/assess", json={"chain": 1, "address": "0x" + "22" * 20})
        assert response.status_code == 502


def test_custom_rpc_disabled_by_default(api_settings: RugLensSettings) -> None:
    with TestClient(create_app(api_settings, engine=FakeApiEngine())) as client:
        response = client.post(
            "/v1/assess",
            json={"chain": 1, "address": TOKEN, "rpc_url": "https://example.com"},
        )
        assert response.status_code == 400
        assert "disabled" in response.json()["detail"]


def test_custom_rpc_ssrf_blocked(api_settings: RugLensSettings) -> None:
    settings = api_settings.model_copy(update={"api_allow_custom_rpc": True})
    with TestClient(create_app(settings, engine=FakeApiEngine())) as client:
        response = client.post(
            "/v1/assess",
            json={"chain": 1, "address": TOKEN, "rpc_url": "http://127.0.0.1:8545"},
        )
        assert response.status_code == 400
        assert "blocked" in response.json()["detail"].lower()


def test_request_body_limit(api_settings: RugLensSettings) -> None:
    with TestClient(create_app(api_settings, engine=FakeApiEngine())) as client:
        response = client.post(
            "/v1/assess",
            json={"chain": 1, "address": "0x" + "a" * 2_000},
        )
        assert response.status_code == 413
