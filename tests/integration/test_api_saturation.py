"""Async API saturation test using a manually initialized ASGI app."""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest
from tests.helpers import TOKEN
from tests.integration.test_api import FakeApiEngine

from ruglens.core.config import RugLensSettings
from ruglens.interfaces.api.app import create_app


@pytest.mark.asyncio
async def test_saturated_assessment_pool_returns_429(tmp_path: Path) -> None:
    settings = RugLensSettings(
        data_dir=tmp_path,
        persist_reports=False,
        simulation_enabled=False,
        plugins_enabled=False,
        api_max_concurrent_assessments=1,
        api_queue_timeout=0.01,
    )
    app = create_app(settings, engine=FakeApiEngine())
    app.state.engine = FakeApiEngine()
    app.state.settings = settings
    app.state.assessment_semaphore = asyncio.Semaphore(1)
    await app.state.assessment_semaphore.acquire()
    try:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/v1/assess",
                json={"chain": "eth", "address": TOKEN},
            )
        assert response.status_code == 429
        assert "capacity" in response.json()["detail"].lower()
    finally:
        app.state.assessment_semaphore.release()
