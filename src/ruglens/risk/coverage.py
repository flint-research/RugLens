"""Weighted data-coverage calculation.

Each required assessment area carries a fixed weight. The denominator is
always the sum of every required weight, even if a detector is absent or
unregistered, which prevents a partial engine from producing a false ``LOW``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from ruglens.core.enums import CoverageArea, DetectorStatus
from ruglens.core.models import DetectorOutcome

AREA_WEIGHTS: dict[CoverageArea, float] = {
    CoverageArea.DYNAMIC_TRADE: 0.35,
    CoverageArea.BYTECODE: 0.25,
    CoverageArea.LIQUIDITY: 0.20,
    CoverageArea.OWNERSHIP: 0.15,
    CoverageArea.HOLDERS: 0.05,
}

# Solana V1 has no reliable local sell simulation (swap routing is not a single
# canonical V2-style call). Its profile weighs the evidence that can be verified
# natively on Solana: token authorities/extensions, holders, funding clusters,
# and identifiable liquidity custody.
SOLANA_AREA_WEIGHTS: dict[CoverageArea, float] = {
    CoverageArea.SOLANA_AUTHORITIES: 0.30,
    CoverageArea.SOLANA_HOLDERS: 0.30,
    CoverageArea.SOLANA_CLUSTERS: 0.25,
    CoverageArea.SOLANA_LIQUIDITY: 0.15,
}

COVERAGE_UNKNOWN_CEILING = 0.65
COVERAGE_LOW_FLOOR = 0.80


@dataclass(frozen=True, slots=True)
class CoverageBreakdown:
    """Data coverage plus the fraction attained in each area."""

    data_coverage: float
    area_fractions: Mapping[CoverageArea, float] = field(default_factory=dict)
    missing_areas: tuple[CoverageArea, ...] = ()


class CoverageCalculator:
    """Compute weighted coverage from detector outcomes."""

    def __init__(self, weights: Mapping[CoverageArea, float] | None = None) -> None:
        self._weights = dict(weights or AREA_WEIGHTS)
        total = sum(self._weights.values())
        if total <= 0:
            raise ValueError("Coverage weights must sum to a positive value")
        self._total = total

    @property
    def weights(self) -> Mapping[CoverageArea, float]:
        """Read-only view of the configured area weights."""
        return dict(self._weights)

    def calculate(self, outcomes: Sequence[DetectorOutcome]) -> CoverageBreakdown:
        """Calculate coverage, taking the best fraction per coverage area."""
        per_area: dict[CoverageArea, float] = dict.fromkeys(self._weights, 0.0)
        for outcome in outcomes:
            area = outcome.coverage_area
            if area is None or area not in per_area:
                continue
            fraction = (
                outcome.coverage_fraction if outcome.status is DetectorStatus.SUCCESS else 0.0
            )
            per_area[area] = max(per_area[area], min(1.0, max(0.0, fraction)))

        weighted = sum(self._weights[area] * fraction for area, fraction in per_area.items())
        coverage = min(1.0, max(0.0, weighted / self._total))
        missing = tuple(area for area in CoverageArea if area in per_area and per_area[area] < 1.0)
        return CoverageBreakdown(
            data_coverage=round(coverage, 6),
            area_fractions=per_area,
            missing_areas=missing,
        )
