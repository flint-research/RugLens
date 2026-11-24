"""Anvil process lifecycle tests (no external network)."""

from __future__ import annotations

import shutil
from pathlib import Path

import httpx
import pytest

from ruglens.core.config import RugLensSettings
from ruglens.core.exceptions import AnvilUnavailableError
from ruglens.simulation.anvil import AnvilManager


def simulation_settings(tmp_path: Path) -> RugLensSettings:
    return RugLensSettings(
        data_dir=tmp_path,
        simulation_enabled=True,
        simulation_concurrency=1,
        anvil_startup_timeout=30.0,
        anvil_shutdown_timeout=5.0,
        plugins_enabled=False,
        persist_reports=False,
    )


@pytest.mark.asyncio
@pytest.mark.simulation
@pytest.mark.skipif(shutil.which("anvil") is None, reason="Anvil is not installed")
async def test_anvil_starts_is_reachable_and_is_cleaned_up(tmp_path: Path) -> None:
    manager = AnvilManager(simulation_settings(tmp_path))
    work_dir: Path | None = None
    async with manager.fork(None, None, 1) as instance:
        work_dir = instance.work_dir
        assert instance.chain_id == 1
        assert manager.active_instances == 1
        assert work_dir.exists()
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.post(
                instance.url,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "eth_chainId",
                    "params": [],
                },
            )
            assert response.status_code == 200
            assert response.json()["result"] == "0x1"
    assert manager.active_instances == 0
    assert work_dir is not None and not work_dir.exists()
    async with httpx.AsyncClient(timeout=1) as client:
        with pytest.raises(httpx.HTTPError):
            await client.post(
                instance.url,
                json={"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []},
            )


@pytest.mark.asyncio
async def test_missing_anvil_binary_fails_cleanly(tmp_path: Path) -> None:
    settings = simulation_settings(tmp_path).model_copy(
        update={"anvil_binary": "ruglens-definitely-not-anvil"}
    )
    manager = AnvilManager(settings)
    with pytest.raises(AnvilUnavailableError):
        async with manager.fork(None, None, 1):
            pass
    assert manager.active_instances == 0
