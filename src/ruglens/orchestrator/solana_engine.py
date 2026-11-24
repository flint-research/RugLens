"""End-to-end Solana assessment service."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import Sequence
from typing import Any

from ruglens.chains.solana.hydrator import hydrate_solana_context
from ruglens.chains.solana.registry import normalize_solana_address
from ruglens.core.config import RugLensSettings
from ruglens.core.enums import DetectorStatus
from ruglens.core.exceptions import (
    InvalidAddressError,
    UnsupportedChainError,
    ValidationError,
)
from ruglens.core.interfaces import (
    BaseSolanaDetector,
    SolanaDetectorDependencies,
    SolanaRpcFactory,
)
from ruglens.core.models import (
    AssessmentReport,
    DetectorOutcome,
    TokenMetadata,
)
from ruglens.core.sanitization import sanitize_reason
from ruglens.core.solana_models import SolanaTokenContext
from ruglens.detectors.registry import DetectorDescriptor
from ruglens.risk.coverage import SOLANA_AREA_WEIGHTS, CoverageCalculator
from ruglens.risk.evaluator import RiskEvaluator

logger = logging.getLogger(__name__)

_SOLANA_CHAIN_ID = 101


class SolanaAssessmentService:
    """Stateless Solana mint assessment coordinator."""

    def __init__(
        self,
        settings: RugLensSettings,
        rpc_factory: SolanaRpcFactory,
        detectors: Sequence[BaseSolanaDetector],
        *,
        evaluator: RiskEvaluator | None = None,
    ) -> None:
        self.settings = settings
        self._rpc_factory = rpc_factory
        self._detectors = tuple(detectors)
        self._evaluator = evaluator or RiskEvaluator(
            coverage=CoverageCalculator(SOLANA_AREA_WEIGHTS)
        )

    @property
    def detectors(self) -> tuple[BaseSolanaDetector, ...]:
        """Configured Solana detectors."""
        return self._detectors

    def detector_descriptors(self) -> list[DetectorDescriptor]:
        """Metadata for /v1/detectors and the CLI."""
        return [
            DetectorDescriptor(
                detector_id=detector.detector_id,
                category=detector.category,
                required=detector.required,
                coverage_area=detector.coverage_area,
                description=detector.description,
                origin="builtin",
                chain_family="solana",
            )
            for detector in self._detectors
        ]

    async def assess(
        self,
        address: str,
        *,
        rpc_urls: Sequence[str] | None = None,
        block_number: int | None = None,
    ) -> AssessmentReport:
        """Assess one Solana mint."""
        if not self.settings.solana_enabled:
            raise UnsupportedChainError("Solana support is disabled")
        if block_number is not None:
            raise ValidationError(
                "Solana V1 records the observed slot and does not support historical slot pinning"
            )
        if not isinstance(address, str):
            raise InvalidAddressError("Solana token address must be a string")
        try:
            mint = normalize_solana_address(address)
        except ValueError as exc:
            raise InvalidAddressError(str(exc)) from exc

        started = time.perf_counter()
        chain = self._rpc_factory.get_client(rpc_urls)
        context = await hydrate_solana_context(chain, mint)
        dependencies = SolanaDetectorDependencies(chain=chain)
        outcomes = await asyncio.gather(
            *(self._run_detector(detector, context, dependencies) for detector in self._detectors)
        )
        extra_limitations = [
            *context.notes,
            (
                "Solana V1 has no local buy/sell sell-path simulation; the Solana coverage "
                "profile excludes the EVM dynamic-trade area."
            ),
            "Solana liquidity depth and LP lock status are not independently verified in V1.",
        ]
        evaluation = self._evaluator.evaluate(outcomes, extra_limitations=extra_limitations)
        metrics = self._merge_metrics(context, outcomes, evaluation.coverage.area_fractions)
        report = self._build_report(
            context,
            evaluation,
            outcomes,
            metrics,
            duration_ms=(time.perf_counter() - started) * 1000,
            rpc_calls=chain.rpc_calls,
        )
        return report

    async def _run_detector(
        self,
        detector: BaseSolanaDetector,
        context: SolanaTokenContext,
        dependencies: SolanaDetectorDependencies,
    ) -> DetectorOutcome:
        started = time.perf_counter()
        try:
            outcome = await asyncio.wait_for(
                detector.detect(context, dependencies),
                timeout=self.settings.anomaly_detector_timeout,
            )
        except TimeoutError:
            return detector.make_outcome(
                status=DetectorStatus.TIMEOUT,
                error=f"Detector exceeded {self.settings.anomaly_detector_timeout:.0f}s deadline",
                duration_ms=(time.perf_counter() - started) * 1000,
            )
        except Exception as exc:
            logger.exception("Solana detector %s failed", detector.detector_id)
            return detector.make_outcome(
                status=DetectorStatus.FAILED,
                error=sanitize_reason(str(exc)) or exc.__class__.__name__,
                duration_ms=(time.perf_counter() - started) * 1000,
            )
        updates: dict[str, Any] = {}
        if outcome.detector_id != detector.detector_id:
            updates["detector_id"] = detector.detector_id
        if updates:
            outcome = outcome.model_copy(update=updates)
        return outcome

    def _merge_metrics(
        self,
        context: SolanaTokenContext,
        outcomes: Sequence[DetectorOutcome],
        area_fractions: Any,
    ) -> dict[str, Any]:
        metrics: dict[str, Any] = {
            "chain_family": "solana",
            "slot": context.slot,
            "token_program": context.mint.program_name,
            "decimals": context.mint.decimals,
            "total_supply": str(context.mint.supply),
            "mint_authority": context.mint.mint_authority,
            "freeze_authority": context.mint.freeze_authority,
            "creator": context.creator,
            "creator_source": context.creator_source,
            "holder_basis": "largest_20_token_accounts",
            "simulation_supported": False,
            "liquidity_depth_verified": False,
            "lp_lock_verified": False,
        }
        for outcome in outcomes:
            values = outcome.details.get("metrics")
            if isinstance(values, dict):
                metrics.update(values)
        with contextlib.suppress(AttributeError, TypeError, ValueError):
            metrics["coverage_by_area"] = {
                str(area.value): round(float(value), 4) for area, value in area_fractions.items()
            }
        return metrics

    def _build_report(
        self,
        context: SolanaTokenContext,
        evaluation: Any,
        outcomes: Sequence[DetectorOutcome],
        metrics: dict[str, Any],
        *,
        duration_ms: float,
        rpc_calls: int,
    ) -> AssessmentReport:
        metadata = context.metadata
        token = TokenMetadata(
            name=metadata.name if metadata else "Unknown Token",
            symbol=metadata.symbol if metadata else "UNKNOWN",
            decimals=context.mint.decimals,
            total_supply=context.mint.supply,
        )

        def _percent(label: str, key: str) -> str:
            value = metrics.get(key)
            if isinstance(value, int | float):
                return f"{label} {float(value):.1f}%"
            return f"{label} n/a"

        def _probability(key: str) -> str:
            value = metrics.get(key)
            if isinstance(value, int | float):
                return f"cluster probability {float(value):.0%}"
            return "cluster probability n/a"

        summary = (
            f"{evaluation.risk_level.value} risk; "
            f"{_percent('creator', 'creator_holdings_pct')}; "
            f"{_percent('top-10', 'top10_holder_pct')}; "
            f"{_probability('cluster_probability')}; "
            f"data coverage {evaluation.data_coverage:.0%}."
        )
        return AssessmentReport(
            chain_id=_SOLANA_CHAIN_ID,
            token_address=context.token_address,
            block_number=context.slot,
            risk_level=evaluation.risk_level,
            confidence_score=evaluation.confidence_score,
            data_coverage=evaluation.data_coverage,
            findings=tuple(evaluation.findings),
            detector_statuses=dict(evaluation.detector_statuses),
            limitations=tuple(evaluation.limitations),
            token=token,
            summary=summary,
            metrics=metrics,
            duration_ms=duration_ms,
            rpc_calls=rpc_calls,
        )

    async def close(self) -> None:
        """Close RPC clients owned by the factory."""
        await self._rpc_factory.close()


__all__ = ["SolanaAssessmentService"]
