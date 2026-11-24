"""Property-based invariants for the risk and consensus engines."""

from __future__ import annotations

from hypothesis import HealthCheck, given
from hypothesis import settings as hypothesis_settings
from hypothesis import strategies as st
from tests.helpers import TOKEN, make_finding, make_outcome

from ruglens.core.enums import CoverageArea, DetectorStatus, RiskLevel, Severity
from ruglens.core.models import DetectorOutcome, Finding
from ruglens.risk.consensus import ConsensusEngine
from ruglens.risk.evaluator import RiskEvaluator

SEVERITIES = list(Severity)
STATUSES = list(DetectorStatus)
RULES = ["R-1", "R-2", "R-3", "R-4"]


@st.composite
def finding_lists(draw: st.DrawFn, *, max_size: int = 6) -> list[Finding]:
    findings: list[Finding] = []
    for index in range(draw(st.integers(min_value=0, max_value=max_size))):
        findings.append(
            make_finding(
                rule_id=draw(st.sampled_from(RULES)),
                severity=draw(st.sampled_from(SEVERITIES)),
                confidence=draw(st.floats(min_value=0.0, max_value=1.0)),
                detector_id=draw(st.sampled_from(["det-a", "det-b", "det-c"])),
                target=TOKEN,
                block_number=10,
                title=f"finding-{index}",
            )
        )
    return findings


@st.composite
def outcome_lists(draw: st.DrawFn) -> list[DetectorOutcome]:
    outcomes: list[DetectorOutcome] = []
    for area in CoverageArea:
        include = draw(st.booleans())
        if not include:
            continue
        status = draw(st.sampled_from(STATUSES))
        fraction = draw(st.floats(min_value=0.0, max_value=1.0))
        outcomes.append(
            make_outcome(
                area=area,
                detector_id=f"det-{area.value}",
                status=status,
                coverage_fraction=fraction,
                findings=draw(finding_lists(max_size=3)),
            )
        )
    # Optional plugin-style findings never contribute coverage.
    for _ in range(draw(st.integers(min_value=0, max_value=2))):
        outcomes.append(
            make_outcome(
                area=None,
                detector_id=f"optional-{draw(st.integers(min_value=0, max_value=9999))}",
                findings=draw(finding_lists(max_size=2)),
            )
        )
    return outcomes


@hypothesis_settings(
    max_examples=80,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
@given(outcomes=outcome_lists())
def test_low_requires_full_enough_coverage_and_no_dangerous_findings(
    outcomes: list[DetectorOutcome],
) -> None:
    result = RiskEvaluator().evaluate(outcomes)
    if result.risk_level is RiskLevel.LOW:
        assert result.data_coverage >= 0.80
        assert all(finding.severity in {Severity.LOW, Severity.INFO} for finding in result.findings)
    assert 0.0 <= result.data_coverage <= 1.0
    assert 0.0 <= result.confidence_score <= 1.0


@hypothesis_settings(max_examples=80, deadline=None)
@given(outcomes=outcome_lists())
def test_low_never_with_coverage_below_unknown_ceiling(
    outcomes: list[DetectorOutcome],
) -> None:
    result = RiskEvaluator().evaluate(outcomes)
    if result.data_coverage < 0.65:
        assert result.risk_level is not RiskLevel.LOW


@hypothesis_settings(max_examples=80, deadline=None)
@given(outcomes=outcome_lists())
def test_confirmed_critical_always_wins(outcomes: list[DetectorOutcome]) -> None:
    critical = make_finding(
        rule_id="CONFIRMED",
        severity=Severity.CRITICAL,
        confidence=0.9,
    )
    outcomes = [*outcomes, make_outcome(area=None, detector_id="critical", findings=[critical])]
    result = RiskEvaluator().evaluate(outcomes)
    assert result.risk_level is RiskLevel.CRITICAL


@hypothesis_settings(max_examples=60, deadline=None)
@given(findings=finding_lists(max_size=12), data=st.data())
def test_dedup_idempotent_and_permutation_invariant(
    findings: list[Finding],
    data: st.DataObject,
) -> None:
    shuffled = list(data.draw(st.permutations(findings)))
    engine = ConsensusEngine()
    canonical = engine.deduplicate(findings)
    assert engine.deduplicate(shuffled) == canonical
    assert engine.deduplicate(canonical) == canonical
    assert len({finding.finding_id for finding in canonical}) == len(canonical)


@hypothesis_settings(max_examples=80, deadline=None)
@given(outcomes=outcome_lists())
def test_evaluation_is_deterministic_under_outcome_order(
    outcomes: list[DetectorOutcome],
) -> None:
    reversed_outcomes = list(reversed(outcomes))
    first = RiskEvaluator().evaluate(outcomes)
    second = RiskEvaluator().evaluate(reversed_outcomes)
    assert first.risk_level is second.risk_level
    assert first.data_coverage == second.data_coverage
    assert first.findings == second.findings
    assert first.detector_statuses == second.detector_statuses
