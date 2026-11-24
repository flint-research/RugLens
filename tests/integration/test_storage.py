"""Storage repository tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.helpers import TOKEN, make_finding

from ruglens.core.enums import DetectorStatus, RiskLevel
from ruglens.core.models import AssessmentReport
from ruglens.storage.database import Database
from ruglens.storage.repositories import SQLAlchemyReportRepository


def make_report(block: int = 100) -> AssessmentReport:
    return AssessmentReport(
        chain_id=1,
        token_address=TOKEN,
        block_number=block,
        risk_level=RiskLevel.MODERATE,
        confidence_score=0.7,
        data_coverage=0.9,
        findings=(make_finding(block_number=block),),
        detector_statuses={"d": DetectorStatus.SUCCESS},
        limitations=("note",),
    )


@pytest.mark.asyncio
async def test_report_persistence_roundtrip(tmp_path: Path) -> None:
    url = f"sqlite+aiosqlite:///{(tmp_path / 'reports.sqlite3').as_posix()}"
    repository = SQLAlchemyReportRepository(Database(url))
    await repository.initialize()
    first = make_report(100)
    second = make_report(101)
    await repository.save(first)
    await repository.save(first)  # idempotent
    await repository.save(second)

    loaded = await repository.get(str(first.assessment_id))
    assert loaded == first
    latest = await repository.find_latest(1, TOKEN)
    assert latest is not None
    assert latest.block_number == 101
    exact = await repository.find_latest(1, TOKEN, 100)
    assert exact == first
    recent = await repository.list_recent(limit=5)
    assert len(recent) == 2
    await repository.close()


@pytest.mark.asyncio
async def test_solana_report_persistence_roundtrip(tmp_path: Path) -> None:
    url = f"sqlite+aiosqlite:///{(tmp_path / 'solana.sqlite3').as_posix()}"
    repository = SQLAlchemyReportRepository(Database(url))
    await repository.initialize()
    mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
    report = AssessmentReport(
        chain_id=101,
        token_address=mint,
        block_number=123456,
        risk_level=RiskLevel.MODERATE,
        confidence_score=0.8,
        data_coverage=0.9,
        metrics={"creator_holdings_pct": 12.5, "cluster_probability": 0.4},
    )
    await repository.save(report)
    assert await repository.get(str(report.assessment_id)) == report
    latest = await repository.find_latest(101, mint)
    assert latest == report
    assert await repository.find_latest(101, mint, 123456) == report
    await repository.close()


@pytest.mark.asyncio
async def test_missing_report_returns_none(tmp_path: Path) -> None:
    repository = SQLAlchemyReportRepository(
        Database(f"sqlite+aiosqlite:///{(tmp_path / 'r.sqlite3').as_posix()}")
    )
    await repository.initialize()
    assert await repository.get("00000000-0000-0000-0000-000000000000") is None
    assert await repository.find_latest(1, TOKEN) is None
    await repository.close()
