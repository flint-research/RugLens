"""Assessment cache and persistence integration tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.fixtures_loader import all_cases
from tests.helpers import FakeChainFactory

from ruglens.core.config import RugLensSettings
from ruglens.detectors.registry import DetectorRegistry, build_default_detectors
from ruglens.orchestrator.engine import AssessmentEngine
from ruglens.storage.database import Database
from ruglens.storage.repositories import SQLAlchemyReportRepository


@pytest.mark.asyncio
async def test_block_pinned_report_is_cached_and_retrievable(tmp_path: Path) -> None:
    case = next(case for case in all_cases() if case.name == "clean_token")
    settings = RugLensSettings(
        data_dir=tmp_path,
        cache_path=tmp_path / "cache.sqlite3",
        database_url=f"sqlite+aiosqlite:///{(tmp_path / 'db.sqlite3').as_posix()}",
        plugins_enabled=False,
        simulation_enabled=True,
        slither_enabled=False,
        persist_reports=True,
        load_cached_reports=True,
        holder_log_lookback_blocks=500_000,
        rpc_max_retries=0,
    )
    repository = SQLAlchemyReportRepository(Database(settings.resolved_database_url()))
    await repository.initialize()
    engine = AssessmentEngine(
        settings,
        FakeChainFactory(case.adapter),
        DetectorRegistry(build_default_detectors(settings)),
        repository=repository,
        simulator_factory=case.simulator_factory,
    )
    try:
        first = await engine.assess_token(1, case.token, case.block_number)
        calls_after_first = case.adapter.rpc_calls
        second = await engine.assess_token(1, case.token, case.block_number)
        assert second.assessment_id == first.assessment_id
        assert second == first
        assert case.adapter.rpc_calls == calls_after_first
        stored = await engine.get_report(str(first.assessment_id))
        assert stored == first
        refreshed = await engine.assess_token(
            1,
            case.token,
            case.block_number,
            use_cached_report=False,
        )
        assert refreshed.assessment_id != first.assessment_id
        assert case.adapter.rpc_calls > calls_after_first
    finally:
        await engine.close()
