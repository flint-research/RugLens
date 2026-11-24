"""End-to-end Solana assessments with offline JSON-RPC fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.helpers import FakeChainAdapter, FakeChainFactory
from tests.solana_helpers import (
    FakeSolanaRpcFactory,
    build_scenario,
    clean_scenario,
    moderate_scenario,
    rug_scenario,
    unknown_cluster_scenario,
)

from ruglens.chains.solana.hydrator import hydrate_solana_context
from ruglens.core.config import RugLensSettings
from ruglens.core.enums import DetectorStatus, RiskLevel
from ruglens.core.exceptions import ValidationError
from ruglens.detectors.registry import DetectorRegistry
from ruglens.detectors.solana import build_solana_detectors
from ruglens.orchestrator.engine import AssessmentEngine
from ruglens.orchestrator.solana_engine import SolanaAssessmentService


def solana_settings(tmp_path: Path) -> RugLensSettings:
    return RugLensSettings(
        data_dir=tmp_path,
        database_url=f"sqlite+aiosqlite:///{(tmp_path / 'db.sqlite3').as_posix()}",
        persist_reports=False,
        plugins_enabled=False,
        simulation_enabled=False,
        solana_enabled=True,
    )


async def assess(scenario, settings):
    service = SolanaAssessmentService(
        settings,
        FakeSolanaRpcFactory(scenario.chain),
        build_solana_detectors(settings),
    )
    return await service.assess(scenario.mint)


@pytest.mark.asyncio
async def test_clean_solana_token_is_low_with_metrics(tmp_path: Path) -> None:
    scenario = clean_scenario()
    report = await assess(scenario, solana_settings(tmp_path))
    assert report.chain_id == 101
    assert report.token_address == scenario.mint
    assert report.block_number == scenario.chain.slot
    assert report.risk_level is RiskLevel.LOW, (
        report.findings,
        report.limitations,
    )
    assert report.data_coverage == pytest.approx(0.97)
    assert report.token is not None
    assert report.token.decimals == 9
    metrics = report.metrics
    assert metrics["creator"] == scenario.creator
    assert metrics["creator_holdings_pct"] == pytest.approx(0.3333, abs=0.01)
    assert metrics["top10_holder_pct"] == pytest.approx(16.6667, abs=0.01)
    assert metrics["cluster_probability"] == pytest.approx(0.05)
    assert metrics["program_controlled_pct"] == pytest.approx(30.0)
    assert metrics["liquidity_depth_verified"] is False
    assert report.detector_statuses["solana_clusters"] is DetectorStatus.SUCCESS
    assert any("historical account pinning" in item.lower() for item in report.limitations)


@pytest.mark.asyncio
async def test_rug_shaped_solana_token_is_critical(tmp_path: Path) -> None:
    scenario = rug_scenario()
    report = await assess(scenario, solana_settings(tmp_path))
    assert report.risk_level is RiskLevel.CRITICAL
    rules = {finding.rule_id for finding in report.findings}
    assert "SOL-MINT-AUTHORITY-001" in rules
    assert "SOL-FREEZE-AUTHORITY-001" in rules
    assert "SOL-TRANSFER-FEE-001" in rules
    assert "SOL-CREATOR-HOLDINGS-001" in rules
    assert "SOL-TOP10-HOLDINGS-001" in rules
    assert "SOL-CLUSTER-001" in rules
    assert report.metrics["creator_holdings_pct"] == pytest.approx(25.0)
    assert report.metrics["top10_holder_pct"] == pytest.approx(59.0)
    assert report.metrics["largest_cluster_share_pct"] == pytest.approx(45.0)
    assert report.metrics["cluster_probability"] >= 0.7


@pytest.mark.asyncio
async def test_moderate_solana_token_has_creator_and_cluster_metrics(tmp_path: Path) -> None:
    scenario = moderate_scenario()
    report = await assess(scenario, solana_settings(tmp_path))
    assert report.risk_level is RiskLevel.MODERATE
    rules = {finding.rule_id for finding in report.findings}
    assert "SOL-CREATOR-HOLDINGS-001" in rules
    assert "SOL-TOP10-HOLDINGS-001" in rules
    assert "SOL-CLUSTER-001" in rules
    assert report.metrics["creator_holdings_pct"] == pytest.approx(15.3846, abs=0.01)
    assert report.metrics["cluster_probability"] > 0.5
    assert report.detector_statuses["solana_holders"] is DetectorStatus.SUCCESS


@pytest.mark.asyncio
async def test_missing_cluster_funding_data_is_unknown(tmp_path: Path) -> None:
    scenario = unknown_cluster_scenario()
    report = await assess(scenario, solana_settings(tmp_path))
    assert report.risk_level is RiskLevel.UNKNOWN
    assert report.detector_statuses["solana_clusters"] is DetectorStatus.FAILED
    assert report.data_coverage < 0.80


@pytest.mark.asyncio
async def test_engine_dispatches_chain_101_and_closes_solana(tmp_path: Path) -> None:
    settings = solana_settings(tmp_path)
    scenario = clean_scenario()
    factory = FakeSolanaRpcFactory(scenario.chain)
    service = SolanaAssessmentService(
        settings,
        factory,
        build_solana_detectors(settings),
    )
    engine = AssessmentEngine(
        settings,
        FakeChainFactory(FakeChainAdapter()),
        DetectorRegistry([]),
        solana_service=service,
    )
    assert engine.detector_count == 4
    report = await engine.assess_token(101, scenario.mint)
    assert report.chain_id == 101
    descriptors = engine.detector_descriptors()
    assert {descriptor.chain_family for descriptor in descriptors} == {"solana"}
    await engine.close()
    assert factory.closed is True


@pytest.mark.asyncio
async def test_token_2022_metadata_extension_fallback() -> None:
    scenario = build_scenario(
        "embedded-metadata",
        token_2022=True,
        extensions=[
            {
                "extension": "tokenMetadata",
                "state": {
                    "name": "Embedded Token",
                    "symbol": "EMB",
                    "uri": "https://example.invalid/emb.json",
                    "updateAuthority": None,
                },
            }
        ],
    )
    scenario.chain.metadata_accounts.clear()
    context = await hydrate_solana_context(scenario.chain, scenario.mint)
    assert context.metadata is not None
    assert context.metadata.name == "Embedded Token"
    assert context.metadata.symbol == "EMB"
    assert context.creator is None


@pytest.mark.asyncio
async def test_saturated_mint_history_does_not_guess_creator() -> None:
    scenario = build_scenario("saturated-creator")
    scenario.chain.metadata_accounts.clear()
    scenario.chain.signatures[scenario.mint] = [
        {"signature": f"mint-sig-{index}"} for index in range(100)
    ]
    context = await hydrate_solana_context(scenario.chain, scenario.mint)
    assert context.creator is None
    assert any("skipped" in note.lower() for note in context.notes)


@pytest.mark.asyncio
async def test_solana_rejects_historical_block_pin(tmp_path: Path) -> None:
    scenario = clean_scenario()
    service = SolanaAssessmentService(
        solana_settings(tmp_path),
        FakeSolanaRpcFactory(scenario.chain),
        build_solana_detectors(solana_settings(tmp_path)),
    )
    with pytest.raises(ValidationError, match="historical slot pinning"):
        await service.assess(scenario.mint, block_number=123)
