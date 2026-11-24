"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from ruglens.core.config import RugLensSettings


@pytest.fixture
def settings(tmp_path: Path) -> RugLensSettings:
    """Isolated settings with no network simulation or plugins."""
    return RugLensSettings(
        data_dir=tmp_path,
        cache_path=tmp_path / "cache.sqlite3",
        database_url=f"sqlite+aiosqlite:///{(tmp_path / 'assessments.sqlite3').as_posix()}",
        plugins_enabled=False,
        simulation_enabled=False,
        slither_enabled=False,
        persist_reports=False,
        load_cached_reports=False,
        rpc_max_retries=1,
        rpc_backoff_base=0.01,
        rpc_timeout=5.0,
    )
