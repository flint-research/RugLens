"""Deterministic veto/escalation risk evaluator.

The evaluator consumes only ``DetectorOutcome`` objects. It knows nothing about
detector internals, cannot be influenced by external APIs, and never emits
``LOW`` when coverage is below 0.80.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from ruglens.core.enums import DetectorStatus, RiskLevel, Severity
from ruglens.core.models import DetectorOutcome, Finding
from ruglens.risk.consensus import ConsensusEngine
from ruglens.risk.coverage import (
    COVERAGE_LOW_FLOOR,
    COVERAGE_UNKNOWN_CEILING,
    CoverageBreakdown,
    CoverageCalculator,
)

CRITICAL_CONFIDENCE_GATE = 0.85
HIGH_CONFIDENCE_GATE = 0.70
MEDIUM_CONFIDENCE_GATE = 0.50
MEDIUM_ESCALATION_COUNT = 3


@dataclass(frozen=True, slots=True)
class RiskEvaluation:
    """Output of the risk synthesis step."""

    risk_level: RiskLevel
    confidence_score: float
    data_coverage: float
    findings: tuple[Finding, ...]
    limitations: tuple[str, ...]
    detector_statuses: Mapping[str, DetectorStatus]
    coverage: CoverageBreakdown = field(repr=False)


class RiskEvaluator:
    """Apply the evidence consensus model and deterministic risk gates."""

    def __init__(
        self,
        consensus: ConsensusEngine | None = None,
        coverage: CoverageCalculator | None = None,
    ) -> None:
        self._consensus = consensus or ConsensusEngine()
        self._coverage = coverage or CoverageCalculator()

    def evaluate(
        self,
        outcomes: Sequence[DetectorOutcome],
        *,
        extra_limitations: Sequence[str] = (),
    ) -> RiskEvaluation:
        """Evaluate all detector outcomes into one risk result."""
        ordered = sorted(outcomes, key=lambda outcome: outcome.detector_id)
        findings = self._consensus.deduplicate(
            finding for outcome in ordered for finding in outcome.findings
        )
        coverage = self._coverage.calculate(ordered)

        critical = [
            finding
            for finding in findings
            if finding.severity is Severity.CRITICAL
            and finding.confidence >= CRITICAL_CONFIDENCE_GATE
        ]
        high = [
            finding
            for finding in findings
            if finding.severity is Severity.HIGH and finding.confidence >= HIGH_CONFIDENCE_GATE
        ]
        medium = [
            finding
            for finding in findings
            if finding.severity is Severity.MEDIUM and finding.confidence >= MEDIUM_CONFIDENCE_GATE
        ]
        medium_for_escalation = [
            finding for finding in medium if finding.confidence >= HIGH_CONFIDENCE_GATE
        ]

        limitations = self._limitations(ordered)
        limitations.extend(sanitize_limitation(item) for item in extra_limitations)

        if critical:
            risk = RiskLevel.CRITICAL
            confidence = max(finding.confidence for finding in critical)
        elif high or len(medium_for_escalation) >= MEDIUM_ESCALATION_COUNT:
            risk = RiskLevel.HIGH
            decisive = high + medium_for_escalation
            confidence = max(finding.confidence for finding in decisive) if decisive else 0.0
        elif coverage.data_coverage < COVERAGE_UNKNOWN_CEILING:
            risk = RiskLevel.UNKNOWN
            confidence = coverage.data_coverage
            limitations.append(
                f"Data coverage {coverage.data_coverage:.2f} is below the "
                f"{COVERAGE_UNKNOWN_CEILING:.2f} minimum; no LOW verdict is permitted."
            )
        elif medium:
            risk = RiskLevel.MODERATE
            confidence = max(finding.confidence for finding in medium)
        elif any(
            finding.severity in {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}
            for finding in findings
        ):
            below_gate = [
                finding
                for finding in findings
                if finding.severity in {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}
            ]
            risk = RiskLevel.UNKNOWN
            confidence = max(finding.confidence for finding in below_gate)
            limitations.append(
                "Dangerous findings are present below the confidence gates; "
                "a LOW verdict would be unsafe."
            )
        elif coverage.data_coverage < COVERAGE_LOW_FLOOR:
            risk = RiskLevel.UNKNOWN
            confidence = coverage.data_coverage
            limitations.append(
                f"Data coverage {coverage.data_coverage:.2f} is insufficient for a "
                f"LOW verdict (requires {COVERAGE_LOW_FLOOR:.2f})."
            )
        else:
            risk = RiskLevel.LOW
            confidence = coverage.data_coverage

        detector_statuses = {
            outcome.detector_id: outcome.status for outcome in ordered if outcome.detector_id
        }
        return RiskEvaluation(
            risk_level=risk,
            confidence_score=min(1.0, max(0.0, round(confidence, 6))),
            data_coverage=coverage.data_coverage,
            findings=tuple(findings),
            limitations=tuple(_dedupe(limitations)),
            detector_statuses=detector_statuses,
            coverage=coverage,
        )

    @staticmethod
    def _limitations(outcomes: Sequence[DetectorOutcome]) -> list[str]:
        limitations: list[str] = []
        for outcome in outcomes:
            if outcome.status is not DetectorStatus.SUCCESS:
                reason = outcome.error or (outcome.limitations[0] if outcome.limitations else "")
                label = (
                    outcome.detector_id
                    if outcome.coverage_area is not None
                    else (f"optional:{outcome.detector_id}")
                )
                text = f"{label} status {outcome.status.value}"
                if reason:
                    text += f": {sanitize_limitation(reason)}"
                limitations.append(text)
            for note in outcome.limitations:
                limitations.append(sanitize_limitation(note))
            if outcome.coverage_fraction < 1.0 and outcome.status is DetectorStatus.SUCCESS:
                limitations.append(
                    f"{outcome.detector_id} completed with "
                    f"{outcome.coverage_fraction:.0%} of its coverage area."
                )
        return limitations


def sanitize_limitation(text: str, *, max_length: int = 300) -> str:
    """Bound and normalize a limitation string."""
    cleaned = " ".join(str(text).split())
    return cleaned[:max_length]


def _dedupe(items: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    return result
