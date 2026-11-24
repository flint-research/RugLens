"""Solana creator and retail holder concentration analysis."""

from __future__ import annotations

import time
from typing import Any

from ruglens.core.enums import CoverageArea, DetectorCategory, DetectorStatus, Severity
from ruglens.core.interfaces import BaseSolanaDetector, SolanaDetectorDependencies
from ruglens.core.models import DetectorOutcome, Finding
from ruglens.core.solana_models import SolanaHolder, SolanaTokenContext

_REFERENCES = (
    "https://docs.solanatracker.io/data-api/risk",
    "https://docs.solanatracker.io/guides/token-holders",
    "https://data.birdeye.so/docs/use-cases/risk-and-integrity/rug-checker",
)


class SolanaHolderDetector(BaseSolanaDetector):
    """Measure creator holdings and top-1/top-10 retail concentration on Solana."""

    detector_id = "solana_holders"
    category = DetectorCategory.HOLDERS
    coverage_area = CoverageArea.SOLANA_HOLDERS
    description = (
        "Creator token balance, aggregated top-10 wallet concentration, burn and "
        "program-controlled custody exclusion, and largest single retail holder."
    )
    required = True

    async def detect(
        self,
        context: SolanaTokenContext,
        dependencies: SolanaDetectorDependencies,
    ) -> DetectorOutcome:
        started = time.perf_counter()
        limitations: list[str] = []
        findings: list[Finding] = []
        if not context.top_holders:
            return self.make_outcome(
                status=DetectorStatus.FAILED,
                error="No largest token accounts were available for holder analysis",
                duration_ms=(time.perf_counter() - started) * 1000,
            )

        retail: dict[str, int] = {}
        for holder in context.top_holders:
            if holder.is_burn or holder.program_controlled:
                continue
            retail[holder.owner] = retail.get(holder.owner, 0) + holder.amount
        ordered = sorted(retail.items(), key=lambda item: (-item[1], item[0]))
        circulating = context.circulating_supply
        denominator = circulating if circulating > 0 else context.mint.supply
        if denominator <= 0:
            return self.make_outcome(
                status=DetectorStatus.FAILED,
                error="Solana supply is zero; concentration is undefined",
                duration_ms=(time.perf_counter() - started) * 1000,
            )
        top10_amount = sum(amount for _, amount in ordered[:10])
        top1_amount = ordered[0][1] if ordered else 0
        top10_share = min(1.0, top10_amount / denominator)
        top1_share = min(1.0, top1_amount / denominator)
        creator_share = context.creator_pct_circulating

        creator_known = context.creator is not None
        if not creator_known:
            limitations.append(
                "Creator wallet could not be determined; creator-holding risk is incomplete."
            )

        if creator_known and creator_share >= self.settings.solana_creator_high_pct:
            findings.append(
                self._finding(
                    context,
                    "SOL-CREATOR-HOLDINGS-001",
                    Severity.HIGH,
                    0.9,
                    f"Creator holds {creator_share:.1%} of circulating supply",
                    (
                        "The identified creator wallet controls a large share of the retail "
                        "float. A single actor can exit a material portion of supply."
                    ),
                    creator_share,
                    ordered,
                    denominator,
                )
            )
        elif creator_known and creator_share >= self.settings.solana_creator_medium_pct:
            findings.append(
                self._finding(
                    context,
                    "SOL-CREATOR-HOLDINGS-001",
                    Severity.MEDIUM,
                    0.82,
                    f"Creator holds {creator_share:.1%} of circulating supply",
                    (
                        "The creator holds more than the common 10% watch threshold. This is "
                        "not proof of intent but concentrates exit risk."
                    ),
                    creator_share,
                    ordered,
                    denominator,
                )
            )

        if top1_share >= self.settings.solana_top1_high_pct:
            findings.append(
                self._finding(
                    context,
                    "SOL-TOP1-HOLDINGS-001",
                    Severity.HIGH,
                    0.88,
                    f"Largest retail holder controls {top1_share:.1%} of circulating supply",
                    (
                        "A single non-pool wallet holds more than the high-concentration "
                        "threshold. Coordinated with other wallets, this can drain liquidity."
                    ),
                    top1_share,
                    ordered,
                    denominator,
                )
            )
        elif top1_share >= self.settings.solana_top1_medium_pct:
            findings.append(
                self._finding(
                    context,
                    "SOL-TOP1-HOLDINGS-001",
                    Severity.MEDIUM,
                    0.78,
                    f"Largest retail holder controls {top1_share:.1%} of circulating supply",
                    (
                        "The largest non-pool holder exceeds the 10% single-wallet watch "
                        "threshold used by Solana risk tools."
                    ),
                    top1_share,
                    ordered,
                    denominator,
                )
            )

        if top10_share >= self.settings.solana_top10_high_pct:
            findings.append(
                self._finding(
                    context,
                    "SOL-TOP10-HOLDINGS-001",
                    Severity.HIGH,
                    0.86,
                    f"Top 10 retail holders control {top10_share:.1%} of circulating supply",
                    (
                        "Top-10 concentration exceeds the 50% alert threshold commonly used "
                        "for Solana token screening."
                    ),
                    top10_share,
                    ordered,
                    denominator,
                )
            )
        elif top10_share >= self.settings.solana_top10_medium_pct:
            findings.append(
                self._finding(
                    context,
                    "SOL-TOP10-HOLDINGS-001",
                    Severity.MEDIUM,
                    0.8,
                    f"Top 10 retail holders control {top10_share:.1%} of circulating supply",
                    (
                        "Top-10 concentration exceeds the 30% watch threshold commonly used "
                        "for Solana token screening."
                    ),
                    top10_share,
                    ordered,
                    denominator,
                )
            )

        fraction = context.holder_coverage
        if not context.holder_data_complete:
            fraction = min(fraction, 0.65)
            limitations.append(
                "Some largest-token-account or owner data was incomplete; holder "
                "percentages are approximate."
            )
        if not creator_known:
            fraction = min(fraction, 0.85)
        if context.circulating_supply <= 0:
            limitations.append(
                "No retail circulating supply remained after burn and program-controlled "
                "custody; concentration is measured against total supply."
            )
        if fraction < 0.5:
            return self.make_outcome(
                status=DetectorStatus.FAILED,
                error="Less than half of the largest holder accounts could be classified",
                duration_ms=(time.perf_counter() - started) * 1000,
            )

        metrics: dict[str, Any] = {
            "creator": context.creator,
            "creator_source": context.creator_source,
            "creator_holdings_amount": context.creator_holdings,
            "creator_holdings_pct": round(creator_share * 100, 4),
            "top1_holder_pct": round(top1_share * 100, 4),
            "top10_holder_pct": round(top10_share * 100, 4),
            "top10_holder_amount": str(top10_amount),
            "circulating_supply": str(circulating),
            "total_supply": str(context.mint.supply),
            "burned_pct": round(context.burn_pct * 100, 4),
            "program_controlled_pct": round(context.program_controlled_pct * 100, 4),
            "unique_retail_owners": context.unique_retail_owners,
            "holder_data_complete": context.holder_data_complete,
            "top_holders": [
                {
                    "owner": owner,
                    "amount": str(amount),
                    "pct_circulating": round(amount / denominator * 100, 4),
                }
                for owner, amount in ordered[:10]
            ],
        }
        return self.make_outcome(
            findings=findings[: self.settings.max_findings_per_detector],
            coverage_fraction=fraction,
            limitations=limitations,
            details={"metrics": metrics},
            duration_ms=(time.perf_counter() - started) * 1000,
        )

    def _finding(
        self,
        context: SolanaTokenContext,
        rule_id: str,
        severity: Severity,
        confidence: float,
        title: str,
        description: str,
        share: float,
        ordered: list[tuple[str, int]],
        denominator: int,
    ) -> Finding:
        top: list[SolanaHolder] = (
            [holder for holder in context.top_holders if holder.owner == ordered[0][0]]
            if ordered
            else []
        )
        return Finding.create(
            rule_id=rule_id,
            detector_id=self.detector_id,
            category=DetectorCategory.HOLDERS,
            severity=severity,
            confidence=confidence,
            title=title,
            description=description,
            evidence={
                "share": share,
                "share_pct": round(share * 100, 4),
                "denominator": str(denominator),
                "creator": context.creator,
                "creator_pct_circulating": context.creator_pct_circulating,
                "top_holders": [
                    {
                        "owner": owner,
                        "amount": str(amount),
                        "pct_circulating": round(amount / denominator * 100, 4),
                    }
                    for owner, amount in ordered[:10]
                ],
                "largest_holder_token_accounts": [holder.model_dump() for holder in top],
            },
            target=context.token_address,
            block_number=context.slot,
            references=list(_REFERENCES),
        )
