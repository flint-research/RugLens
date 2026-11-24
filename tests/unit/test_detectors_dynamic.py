"""Dynamic honeypot/tax detector tests."""

from __future__ import annotations

import pytest
from tests.helpers import (
    FakeChainAdapter,
    FakeSimulator,
    clean_simulation,
    make_context,
)

from ruglens.core.enums import DetectorStatus, Severity
from ruglens.core.exceptions import (
    AnvilUnavailableError,
    SimulationError,
    SimulationSetupError,
    SimulationTimeoutError,
)
from ruglens.core.interfaces import DetectorDependencies
from ruglens.detectors.dynamic.honeypot_sim import DynamicHoneypotDetector


def deps(simulator: FakeSimulator | None) -> DetectorDependencies:
    return DetectorDependencies(chain=FakeChainAdapter(), simulator=simulator)


@pytest.mark.asyncio
async def test_confirmed_honeypot_is_critical(settings) -> None:
    result = clean_simulation(
        sell_success=False,
        approve_success=True,
        sell_revert_reason="blocked sell",
        sell_amount_received=0,
        sell_gas_used=0,
    )
    detector = DynamicHoneypotDetector(settings)
    outcome = await detector.detect(
        make_context(),
        deps(FakeSimulator(result)),
    )
    assert outcome.status is DetectorStatus.SUCCESS
    honeypot = next(f for f in outcome.findings if f.rule_id == "DYN-HONEYPOT-001")
    assert honeypot.severity is Severity.CRITICAL
    assert honeypot.confidence >= 0.95
    assert honeypot.evidence["sell_success"] is False


@pytest.mark.asyncio
async def test_successful_round_trip_with_clean_tax_has_no_findings(settings) -> None:
    detector = DynamicHoneypotDetector(settings)
    outcome = await detector.detect(make_context(), deps(FakeSimulator(clean_simulation())))
    assert outcome.status is DetectorStatus.SUCCESS
    assert outcome.findings == ()
    assert outcome.details["honeypot"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("sell_tax", "expected"),
    [
        (0.12, Severity.MEDIUM),
        (0.30, Severity.HIGH),
        (0.60, Severity.CRITICAL),
    ],
)
async def test_measured_tax_thresholds(settings, sell_tax: float, expected: Severity) -> None:
    detector = DynamicHoneypotDetector(settings)
    outcome = await detector.detect(
        make_context(),
        deps(FakeSimulator(clean_simulation(sell_tax=sell_tax))),
    )
    tax_findings = [f for f in outcome.findings if f.rule_id.startswith("DYN-TAX")]
    assert len(tax_findings) == 1
    assert tax_findings[0].severity is expected
    assert tax_findings[0].evidence["sell_tax"] == sell_tax


@pytest.mark.asyncio
async def test_buy_tax_uses_buy_thresholds(settings) -> None:
    detector = DynamicHoneypotDetector(settings)
    outcome = await detector.detect(
        make_context(),
        deps(FakeSimulator(clean_simulation(buy_tax=0.55, sell_tax=0.0))),
    )
    tax_findings = [f for f in outcome.findings if f.rule_id.startswith("DYN-TAX")]
    assert tax_findings and tax_findings[0].severity is Severity.CRITICAL


@pytest.mark.asyncio
async def test_gas_griefing_is_medium(settings) -> None:
    detector = DynamicHoneypotDetector(settings)
    outcome = await detector.detect(
        make_context(),
        deps(FakeSimulator(clean_simulation(sell_gas_used=1_500_000))),
    )
    gas = next(f for f in outcome.findings if f.rule_id == "DYN-GAS-001")
    assert gas.severity is Severity.MEDIUM


@pytest.mark.asyncio
async def test_failed_buy_is_medium_not_honeypot(settings) -> None:
    result = clean_simulation(
        buy_success=False,
        sell_success=False,
        approve_success=None,
        buy_revert_reason="trading disabled",
    )
    detector = DynamicHoneypotDetector(settings)
    outcome = await detector.detect(make_context(), deps(FakeSimulator(result)))
    assert {finding.rule_id for finding in outcome.findings} == {"DYN-BUY-REVERT-001"}
    assert outcome.findings[0].severity is Severity.MEDIUM


@pytest.mark.asyncio
async def test_approval_failure_is_not_claimed_as_confirmed_honeypot(settings) -> None:
    result = clean_simulation(
        sell_success=False,
        approve_success=False,
        sell_revert_reason="Router approval failed: blocked",
        sell_amount_received=0,
    )
    detector = DynamicHoneypotDetector(settings)
    outcome = await detector.detect(make_context(), deps(FakeSimulator(result)))
    rules = {finding.rule_id for finding in outcome.findings}
    assert "DYN-HONEYPOT-001" not in rules
    assert "DYN-APPROVE-FAIL-001" in rules


@pytest.mark.asyncio
async def test_missing_simulator_or_pair_is_skipped(settings) -> None:
    detector = DynamicHoneypotDetector(settings)
    skipped = await detector.detect(make_context(), deps(None))
    assert skipped.status is DetectorStatus.SKIPPED
    no_pair = await detector.detect(
        make_context(pair=None), deps(FakeSimulator(clean_simulation()))
    )
    assert no_pair.status is DetectorStatus.SKIPPED
    assert no_pair.coverage_fraction == 0.0


@pytest.mark.asyncio
async def test_simulation_exception_statuses(settings) -> None:
    detector = DynamicHoneypotDetector(settings)
    unavailable = await detector.detect(
        make_context(), deps(FakeSimulator(error=AnvilUnavailableError("missing anvil")))
    )
    assert unavailable.status is DetectorStatus.SKIPPED
    setup = await detector.detect(
        make_context(), deps(FakeSimulator(error=SimulationSetupError("no reserves")))
    )
    assert setup.status is DetectorStatus.SKIPPED
    timeout = await detector.detect(
        make_context(), deps(FakeSimulator(error=SimulationTimeoutError("timeout")))
    )
    assert timeout.status is DetectorStatus.TIMEOUT
    failed = await detector.detect(
        make_context(), deps(FakeSimulator(error=SimulationError("broken")))
    )
    assert failed.status is DetectorStatus.FAILED
