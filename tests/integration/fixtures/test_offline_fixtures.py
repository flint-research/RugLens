"""End-to-end offline fixture integration tests (15 distinct token patterns)."""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.fixtures_loader import FIXTURE_DIR, all_cases, load_case
from tests.helpers import FakeChainFactory

from ruglens.core.config import RugLensSettings
from ruglens.core.enums import DetectorStatus, RiskLevel, Severity
from ruglens.detectors.registry import DetectorRegistry, build_default_detectors
from ruglens.orchestrator.engine import AssessmentEngine

CASES = all_cases()
IDS = [case.name for case in CASES]


def engine_settings(tmp_path: Path) -> RugLensSettings:
    return RugLensSettings(
        data_dir=tmp_path,
        cache_path=tmp_path / "cache.sqlite3",
        database_url=f"sqlite+aiosqlite:///{(tmp_path / 'db.sqlite3').as_posix()}",
        plugins_enabled=False,
        simulation_enabled=True,
        slither_enabled=False,
        persist_reports=False,
        load_cached_reports=False,
        holder_log_lookback_blocks=500_000,
        holder_log_chunk_blocks=100_000,
        rpc_max_retries=0,
    )


async def run_case(case, tmp_path: Path):
    settings = engine_settings(tmp_path)
    registry = DetectorRegistry(build_default_detectors(settings))
    engine = AssessmentEngine(
        settings,
        FakeChainFactory(case.adapter),
        registry,
        simulator_factory=case.simulator_factory,
        repository=None,
    )
    return await engine.assess_token(case.raw["chain_id"], case.token, case.block_number)


def test_fixture_inventory_is_large_enough() -> None:
    assert len(CASES) >= 10
    names = {case.name for case in CASES}
    assert {"clean_token", "honeypot_token", "proxy_admin_eoa", "partial_data"} <= names


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.parametrize("case", CASES, ids=IDS)
async def test_offline_fixture_end_to_end(case, tmp_path: Path) -> None:
    report = await run_case(case, tmp_path)
    expected = case.expected
    assert report.risk_level.value == expected["risk"], (
        f"{case.name}: expected {expected['risk']}, got {report.risk_level.value}; "
        f"findings={[finding.rule_id for finding in report.findings]}; "
        f"coverage={report.data_coverage}; limitations={report.limitations}"
    )
    rules = {finding.rule_id for finding in report.findings}
    for rule in expected["rules"]:
        assert rule in rules, f"{case.name} missing {rule}; present={sorted(rules)}"
    for rule in expected["forbidden_rules"]:
        assert rule not in rules
    for detector_id, status in expected["statuses"].items():
        assert report.detector_statuses[detector_id].value == status, (
            f"{case.name}: {detector_id} expected {status}, "
            f"got {report.detector_statuses[detector_id]}"
        )
    assert expected["coverage_min"] <= report.data_coverage <= expected["coverage_max"]
    assert report.token_address == case.token
    assert report.block_number == case.block_number
    assert report.engine_version
    assert report.to_json()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_clean_fixture_has_no_dangerous_findings(tmp_path: Path) -> None:
    case = next(case for case in CASES if case.name == "clean_token")
    report = await run_case(case, tmp_path)
    assert report.risk_level is RiskLevel.LOW
    assert not [
        f
        for f in report.findings
        if f.severity in {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}
    ]
    assert report.data_coverage == 1.0


@pytest.mark.asyncio
@pytest.mark.integration
async def test_honeypot_fixture_carries_executable_evidence(tmp_path: Path) -> None:
    case = next(case for case in CASES if case.name == "honeypot_token")
    report = await run_case(case, tmp_path)
    finding = next(f for f in report.findings if f.rule_id == "DYN-HONEYPOT-001")
    assert report.risk_level is RiskLevel.CRITICAL
    assert finding.severity is Severity.CRITICAL
    assert finding.evidence["sell_success"] is False
    assert finding.evidence["sell_revert_reason"] == "blocked sell"
    assert report.detector_statuses["dynamic_honeypot"] is DetectorStatus.SUCCESS


@pytest.mark.asyncio
@pytest.mark.integration
async def test_data_gaps_produce_unknown_not_low(tmp_path: Path) -> None:
    case = load_case(FIXTURE_DIR / "partial_data.json")
    report = await run_case(case, tmp_path)
    assert report.risk_level is RiskLevel.UNKNOWN
    assert report.data_coverage < 0.65
    assert report.detector_statuses["dynamic_honeypot"] is DetectorStatus.SKIPPED
    assert report.detector_statuses["holder_distribution"] is DetectorStatus.FAILED
    assert any("coverage" in limitation.lower() for limitation in report.limitations)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_assessment_is_reproducible_for_same_fixture(tmp_path: Path) -> None:
    case = next(case for case in CASES if case.name == "mintable_eoa")
    first = await run_case(case, tmp_path)
    second = await run_case(case, tmp_path)
    assert first.risk_level is second.risk_level
    assert first.data_coverage == second.data_coverage
    assert [finding.finding_id for finding in first.findings] == [
        finding.finding_id for finding in second.findings
    ]
