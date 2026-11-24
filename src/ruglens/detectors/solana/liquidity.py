"""Solana liquidity/custody identification without third-party APIs."""

from __future__ import annotations

import time
from typing import Any

from ruglens.chains.solana.registry import known_program_name
from ruglens.core.enums import CoverageArea, DetectorCategory, DetectorStatus, Severity
from ruglens.core.interfaces import BaseSolanaDetector, SolanaDetectorDependencies
from ruglens.core.models import DetectorOutcome, Finding
from ruglens.core.solana_models import SolanaTokenContext


class SolanaLiquidityDetector(BaseSolanaDetector):
    """Identify program-controlled liquidity/custody and avoid false depth claims."""

    detector_id = "solana_liquidity"
    category = DetectorCategory.LIQUIDITY
    coverage_area = CoverageArea.SOLANA_LIQUIDITY
    description = (
        "Program-controlled token custody detection from PDA/executable account owners. "
        "Does not claim DEX depth or LP lock status without a verified venue adapter."
    )
    required = True

    async def detect(
        self,
        context: SolanaTokenContext,
        dependencies: SolanaDetectorDependencies,
    ) -> DetectorOutcome:
        started = time.perf_counter()
        findings: list[Finding] = []
        limitations: list[str] = [
            "Solana V1 does not independently verify DEX pool depth or LP burn/lock status.",
        ]
        program_holders = [holder for holder in context.top_holders if holder.program_controlled]
        custody_pct = context.program_controlled_pct
        metrics: dict[str, Any] = {
            "liquidity_custody_pct": round(custody_pct * 100, 4),
            "liquidity_depth_verified": False,
            "lp_lock_verified": False,
            "program_controlled_accounts": len(program_holders),
            "program_controlled_pct": round(context.program_controlled_pct * 100, 4),
            "custody_programs": sorted(
                {
                    known_program_name(holder.owner_program) or holder.owner_program or holder.tag
                    for holder in program_holders
                }
            ),
        }
        if not context.top_holders:
            return self.make_outcome(
                status=DetectorStatus.FAILED,
                error="Holder account data is unavailable; liquidity custody is unknown",
                limitations=limitations,
                details={"metrics": metrics},
                duration_ms=(time.perf_counter() - started) * 1000,
            )

        if custody_pct >= self.settings.solana_liquidity_min_custody_pct:
            limitations.append(
                "Program-controlled custody may include DEX pools, launchpad bonding curves, "
                "or vesting/treasury programs; RugLens cannot distinguish these from top "
                "accounts alone."
            )
            coverage = 0.8 if context.holder_data_complete else 0.5
            finding = Finding.create(
                rule_id="SOL-LIQUIDITY-CUSTODY-001",
                detector_id=self.detector_id,
                category=DetectorCategory.LIQUIDITY,
                severity=Severity.INFO,
                confidence=0.65,
                title="Program-controlled token custody detected",
                description=(
                    f"{custody_pct:.1%} of supply sits in token accounts controlled by "
                    "off-curve/program owners. This is consistent with DEX/launchpad custody "
                    "but venue depth and LP lock status are not independently verified."
                ),
                evidence={
                    "custody_pct": custody_pct,
                    "program_controlled_accounts": [
                        holder.model_dump() for holder in program_holders[:10]
                    ],
                },
                target=context.token_address,
                block_number=context.slot,
            )
            findings.append(finding)
        else:
            findings.append(
                Finding.create(
                    rule_id="SOL-LIQUIDITY-UNVERIFIED-001",
                    detector_id=self.detector_id,
                    category=DetectorCategory.LIQUIDITY,
                    severity=Severity.MEDIUM,
                    confidence=0.62,
                    title="No identifiable program-controlled liquidity custody",
                    description=(
                        "None of the largest token accounts is controlled by a recognizable "
                        "off-curve/program owner. The token may have no DEX liquidity, may be "
                        "pre-launch, or may use a venue not visible in the top-20 accounts. "
                        "Liquidity cannot be verified from this RPC state."
                    ),
                    evidence={
                        "custody_pct": custody_pct,
                        "program_controlled_accounts": 0,
                        "top_holder_count": len(context.top_holders),
                    },
                    target=context.token_address,
                    block_number=context.slot,
                )
            )
            limitations.append(
                "Without identifiable liquidity custody, a sell path cannot be verified."
            )
            coverage = 0.25

        return self.make_outcome(
            findings=findings,
            coverage_fraction=coverage,
            limitations=limitations,
            details={"metrics": metrics},
            duration_ms=(time.perf_counter() - started) * 1000,
        )
