"""Risk engine unit tests."""

from __future__ import annotations

from tests.helpers import make_finding, make_outcome

from ruglens.core.enums import CoverageArea, DetectorStatus, RiskLevel, Severity
from ruglens.risk.consensus import ConsensusEngine
from ruglens.risk.coverage import AREA_WEIGHTS, SOLANA_AREA_WEIGHTS, CoverageCalculator
from ruglens.risk.evaluator import RiskEvaluator


def full_coverage() -> list:
    return [make_outcome(area=area, findings=()) for area in CoverageArea]


def test_weights_sum_to_one() -> None:
    assert abs(sum(AREA_WEIGHTS.values()) - 1.0) < 1e-9


def test_all_success_with_no_findings_is_low() -> None:
    result = RiskEvaluator().evaluate(full_coverage())
    assert result.risk_level is RiskLevel.LOW
    assert result.data_coverage == 1.0
    assert result.confidence_score == 1.0


def test_missing_dynamic_simulation_prevents_low() -> None:
    outcomes = [
        outcome
        for outcome in full_coverage()
        if outcome.coverage_area is not CoverageArea.DYNAMIC_TRADE
    ]
    result = RiskEvaluator().evaluate(outcomes)
    assert result.data_coverage == 0.65
    assert result.risk_level is RiskLevel.UNKNOWN
    assert any("LOW" in limitation for limitation in result.limitations)


def test_critical_finding_overrides_low_coverage() -> None:
    critical = make_finding(severity=Severity.CRITICAL, confidence=0.98, rule_id="DYN-HONEYPOT-001")
    result = RiskEvaluator().evaluate(
        [make_outcome(area=CoverageArea.DYNAMIC_TRADE, findings=[critical])]
    )
    assert result.risk_level is RiskLevel.CRITICAL
    assert result.confidence_score == 0.98
    assert result.data_coverage == 0.35


def test_critical_below_confidence_gate_does_not_escalate() -> None:
    finding = make_finding(severity=Severity.CRITICAL, confidence=0.5, rule_id="X")
    result = RiskEvaluator().evaluate(
        [*full_coverage(), make_outcome(area=None, findings=[finding])]
    )
    assert result.risk_level is RiskLevel.UNKNOWN


def test_high_finding_overrides_low_coverage() -> None:
    high = make_finding(severity=Severity.HIGH, confidence=0.8, rule_id="HIGH-1")
    result = RiskEvaluator().evaluate(
        [make_outcome(area=CoverageArea.DYNAMIC_TRADE, findings=[high])]
    )
    assert result.risk_level is RiskLevel.HIGH


def test_three_medium_findings_escalate_to_high() -> None:
    findings = [
        make_finding(rule_id=f"M-{index}", severity=Severity.MEDIUM, confidence=0.75)
        for index in range(3)
    ]
    result = RiskEvaluator().evaluate(
        [*full_coverage(), make_outcome(area=None, findings=findings)]
    )
    assert result.risk_level is RiskLevel.HIGH


def test_two_medium_findings_are_moderate() -> None:
    findings = [
        make_finding(rule_id=f"M-{index}", severity=Severity.MEDIUM, confidence=0.75)
        for index in range(2)
    ]
    result = RiskEvaluator().evaluate(
        [*full_coverage(), make_outcome(area=None, findings=findings)]
    )
    assert result.risk_level is RiskLevel.MODERATE


def test_medium_with_low_coverage_is_unknown() -> None:
    finding = make_finding(severity=Severity.MEDIUM, confidence=0.8, rule_id="M")
    outcomes = [
        make_outcome(area=CoverageArea.BYTECODE, findings=[finding]),
        make_outcome(area=CoverageArea.LIQUIDITY),
    ]
    result = RiskEvaluator().evaluate(outcomes)
    assert result.data_coverage == 0.45
    assert result.risk_level is RiskLevel.UNKNOWN


def test_medium_is_hidden_above_unknown_ceiling_but_below_low_floor() -> None:
    outcomes = [
        outcome for outcome in full_coverage() if outcome.coverage_area is not CoverageArea.HOLDERS
    ]
    result = RiskEvaluator().evaluate(outcomes)
    assert result.data_coverage == 0.95
    assert result.risk_level is RiskLevel.LOW


def test_coverage_between_floor_and_ceiling_without_findings_is_unknown() -> None:
    outcomes = [
        outcome
        for outcome in full_coverage()
        if outcome.coverage_area not in {CoverageArea.HOLDERS, CoverageArea.DYNAMIC_TRADE}
    ]
    outcomes.append(
        make_outcome(
            area=CoverageArea.DYNAMIC_TRADE,
            status=DetectorStatus.SUCCESS,
            coverage_fraction=0.4,
        )
    )
    result = RiskEvaluator().evaluate(outcomes)
    assert 0.65 <= result.data_coverage < 0.80
    assert result.risk_level is RiskLevel.UNKNOWN


def test_low_severity_findings_do_not_prevent_low() -> None:
    low = make_finding(severity=Severity.LOW, confidence=0.5, rule_id="LOW-1")
    result = RiskEvaluator().evaluate([*full_coverage(), make_outcome(area=None, findings=[low])])
    assert result.risk_level is RiskLevel.LOW


def test_coverage_uses_best_fraction_per_area() -> None:
    outcomes = [
        make_outcome(area=CoverageArea.BYTECODE, coverage_fraction=0.2),
        make_outcome(area=CoverageArea.BYTECODE, detector_id="second", coverage_fraction=1.0),
    ]
    breakdown = CoverageCalculator().calculate(outcomes)
    assert breakdown.data_coverage == 0.25


def test_solana_coverage_profile_weights_and_cluster_failure() -> None:
    assert abs(sum(SOLANA_AREA_WEIGHTS.values()) - 1.0) < 1e-9
    calculator = CoverageCalculator(SOLANA_AREA_WEIGHTS)
    outcomes = [
        make_outcome(area=area, detector_id=f"solana-{area.value}") for area in SOLANA_AREA_WEIGHTS
    ]
    assert calculator.calculate(outcomes).data_coverage == 1.0
    failed = [
        make_outcome(
            area=area,
            detector_id=f"solana-{area.value}",
            status=DetectorStatus.FAILED,
            coverage_fraction=0.0,
        )
        if area is CoverageArea.SOLANA_CLUSTERS
        else make_outcome(area=area, detector_id=f"solana-{area.value}")
        for area in SOLANA_AREA_WEIGHTS
    ]
    assert calculator.calculate(failed).data_coverage == 0.75


def test_detector_statuses_are_recorded_for_failures() -> None:
    outcomes = [
        make_outcome(
            area=CoverageArea.BYTECODE, status=DetectorStatus.FAILED, limitations=("boom",)
        ),
        make_outcome(area=CoverageArea.DYNAMIC_TRADE, status=DetectorStatus.TIMEOUT),
    ]
    result = RiskEvaluator().evaluate(outcomes)
    assert result.risk_level is RiskLevel.UNKNOWN
    assert result.detector_statuses["det_bytecode"] is DetectorStatus.FAILED
    assert any("boom" in limitation for limitation in result.limitations)


def test_duplicate_findings_merge_sources_and_confidence() -> None:
    target = "0x1111111111111111111111111111111111111111"
    first = make_finding(
        rule_id="STATIC-MINT-001",
        severity=Severity.MEDIUM,
        confidence=0.72,
        detector_id="bytecode_selectors",
        target=target,
    )
    second = make_finding(
        rule_id="STATIC-MINT-001",
        severity=Severity.MEDIUM,
        confidence=0.8,
        detector_id="slither_source",
        target=target,
    )
    merged = ConsensusEngine().deduplicate([first, second])
    assert len(merged) == 1
    assert merged[0].confidence == 0.8
    assert len(merged[0].evidence["sources"]) == 2
    assert merged[0].finding_id == first.finding_id


def test_dedup_is_idempotent_and_order_independent() -> None:
    findings = [
        make_finding(rule_id="R-1", detector_id="a", confidence=0.7),
        make_finding(rule_id="R-1", detector_id="b", confidence=0.9),
        make_finding(rule_id="R-2", detector_id="c", confidence=0.6),
    ]
    engine = ConsensusEngine()
    first = engine.deduplicate(findings)
    second = engine.deduplicate(list(reversed(findings)))
    assert first == second
    assert engine.deduplicate(first) == first
