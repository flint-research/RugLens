"""Dynamic honeypot and measured-tax detector."""

from __future__ import annotations

import logging
import time
from typing import Any

from ruglens.core.enums import CoverageArea, DetectorCategory, DetectorStatus, Severity
from ruglens.core.exceptions import (
    AnvilUnavailableError,
    SimulationError,
    SimulationSetupError,
    SimulationTimeoutError,
)
from ruglens.core.interfaces import BaseDetector, DetectorDependencies
from ruglens.core.models import DetectorOutcome, Finding, TokenContext
from ruglens.core.sanitization import sanitize_reason

logger = logging.getLogger(__name__)


class DynamicHoneypotDetector(BaseDetector):
    """Execute a real buy/approve/sell sequence on an isolated fork."""

    detector_id = "dynamic_honeypot"
    category = DetectorCategory.DYNAMIC_TRAP
    coverage_area = CoverageArea.DYNAMIC_TRADE
    description = (
        "Anvil fork trade simulation measuring buy tax, sell tax, sell reverts, "
        "and gas consumption for a clean impersonated wallet."
    )
    required = True

    async def detect(
        self,
        context: TokenContext,
        dependencies: DetectorDependencies,
    ) -> DetectorOutcome:
        started = time.perf_counter()

        def elapsed() -> float:
            return (time.perf_counter() - started) * 1000

        if dependencies.simulator is None:
            return self.make_outcome(
                status=DetectorStatus.SKIPPED,
                limitations=("Trade simulator is not configured.",),
                error="trade simulator unavailable",
                duration_ms=elapsed(),
            )
        if not context.pair_address:
            return self.make_outcome(
                status=DetectorStatus.SKIPPED,
                limitations=(
                    "No Uniswap V2 / PancakeSwap V2 pair was discovered; "
                    "honeypot simulation cannot be performed.",
                ),
                error="no V2 pair",
                duration_ms=elapsed(),
            )
        if context.decimals is None:
            return self.make_outcome(
                status=DetectorStatus.SKIPPED,
                limitations=("Token decimals are unknown; trade amounts cannot be normalized.",),
                error="token decimals unavailable",
                duration_ms=elapsed(),
            )

        try:
            result = await dependencies.simulator.simulate(context)
        except AnvilUnavailableError as exc:
            return self.make_outcome(
                status=DetectorStatus.SKIPPED,
                error=str(exc),
                limitations=(f"Anvil is unavailable: {exc}",),
                duration_ms=elapsed(),
            )
        except SimulationSetupError as exc:
            return self.make_outcome(
                status=DetectorStatus.SKIPPED,
                error=str(exc),
                limitations=(f"Simulation prerequisites missing: {exc}",),
                duration_ms=elapsed(),
            )
        except SimulationTimeoutError as exc:
            return self.make_outcome(
                status=DetectorStatus.TIMEOUT,
                error=str(exc),
                limitations=(f"Trade simulation timed out: {exc}",),
                duration_ms=elapsed(),
            )
        except SimulationError as exc:
            return self.make_outcome(
                status=DetectorStatus.FAILED,
                error=str(exc),
                limitations=(f"Trade simulation failed: {exc}",),
                duration_ms=elapsed(),
            )
        except Exception as exc:
            logger.exception("Unexpected trade simulation failure for %s", context.token_address)
            return self.make_outcome(
                status=DetectorStatus.FAILED,
                error=sanitize_reason(str(exc)) or exc.__class__.__name__,
                limitations=("Trade simulation raised an unexpected error.",),
                duration_ms=elapsed(),
            )

        findings: list[Finding] = []
        evidence: dict[str, Any] = {
            "buy_success": result.buy_success,
            "sell_success": result.sell_success,
            "buy_tax": result.buy_tax,
            "sell_tax": result.sell_tax,
            "expected_buy_amount": result.expected_buy_amount,
            "buy_amount_received": result.buy_amount_received,
            "expected_sell_amount": result.expected_sell_amount,
            "sell_amount_received": result.sell_amount_received,
            "buy_gas_used": result.buy_gas_used,
            "sell_gas_used": result.sell_gas_used,
            "buy_revert_reason": result.buy_revert_reason,
            "sell_revert_reason": result.sell_revert_reason,
            "pair": result.pair,
            "router": result.router,
            "wallet": result.wallet,
            "block_number": result.block_number,
            "notes": result.notes,
        }

        if result.buy_success and result.is_honeypot:
            reason = result.sell_revert_reason or "sell output was below 1% of the quoted amount"
            findings.append(
                Finding.create(
                    rule_id="DYN-HONEYPOT-001",
                    detector_id=self.detector_id,
                    category=DetectorCategory.DYNAMIC_TRAP,
                    severity=Severity.CRITICAL,
                    confidence=0.98,
                    title="Confirmed honeypot: buy succeeds, sell fails",
                    description=(
                        "A clean wallet bought the token successfully but could not sell it "
                        f"({reason}). This is direct, executable evidence of an active "
                        "transfer trap against holders."
                    ),
                    evidence=evidence,
                    target=context.token_address,
                    block_number=context.block_number,
                )
            )
        elif not result.buy_success:
            findings.append(
                Finding.create(
                    rule_id="DYN-BUY-REVERT-001",
                    detector_id=self.detector_id,
                    category=DetectorCategory.DYNAMIC_TRAP,
                    severity=Severity.MEDIUM,
                    confidence=0.65,
                    title="Simulated buy reverted",
                    description=(
                        "The router buy transaction reverted from a clean funded wallet. "
                        "Trading may be disabled, liquidity may be unusable, or the token "
                        "may reject unknown buyers. A honeypot cannot be confirmed without "
                        "a successful buy."
                    ),
                    evidence=evidence,
                    target=context.token_address,
                    block_number=context.block_number,
                )
            )
        else:
            buy_severity = self._tax_severity(
                result.buy_tax,
                self.settings.buy_tax_medium_threshold,
                self.settings.buy_tax_high_threshold,
                self.settings.buy_tax_critical_threshold,
            )
            sell_severity = self._tax_severity(
                result.sell_tax,
                self.settings.sell_tax_medium_threshold,
                self.settings.sell_tax_high_threshold,
                self.settings.sell_tax_critical_threshold,
            )
            severity = max(
                (item for item in (buy_severity, sell_severity) if item is not None),
                key=lambda value: value.rank,
                default=None,
            )
            if severity is not None:
                max_tax = max(
                    value for value in (result.buy_tax, result.sell_tax, 0.0) if value is not None
                )
                rule_id = {
                    Severity.CRITICAL: "DYN-TAX-001",
                    Severity.HIGH: "DYN-TAX-002",
                    Severity.MEDIUM: "DYN-TAX-003",
                }[severity]
                findings.append(self._tax_finding(context, evidence, max_tax, severity, rule_id))

            if result.approve_success is False:
                findings.append(
                    Finding.create(
                        rule_id="DYN-APPROVE-FAIL-001",
                        detector_id=self.detector_id,
                        category=DetectorCategory.DYNAMIC_TRAP,
                        severity=Severity.MEDIUM,
                        confidence=0.7,
                        title="Router approval failed in simulation",
                        description=(
                            "Buying succeeded, but approving the DEX router failed. Holders "
                            "may be unable to grant sell allowance, effectively trapping the "
                            "position. This is weaker than a confirmed sell revert and is "
                            "reported as a medium-severity trading restriction."
                        ),
                        evidence=evidence,
                        target=context.token_address,
                        block_number=context.block_number,
                    )
                )

            if (
                result.sell_gas_used is not None
                and result.sell_gas_used > self.settings.gas_griefing_threshold
            ):
                findings.append(
                    Finding.create(
                        rule_id="DYN-GAS-001",
                        detector_id=self.detector_id,
                        category=DetectorCategory.DYNAMIC_TRAP,
                        severity=Severity.MEDIUM,
                        confidence=0.8,
                        title="Sell gas consumption indicates gas griefing",
                        description=(
                            f"Selling consumed {result.sell_gas_used:,} gas "
                            f"(threshold {self.settings.gas_griefing_threshold:,}). "
                            "Standard wallets with default gas limits may fail the sell."
                        ),
                        evidence=evidence,
                        target=context.token_address,
                        block_number=context.block_number,
                    )
                )

        findings = findings[: self.settings.max_findings_per_detector]
        return self.make_outcome(
            findings=findings,
            details={
                "buy_tax": result.buy_tax,
                "sell_tax": result.sell_tax,
                "honeypot": result.is_honeypot,
                "sell_gas_used": result.sell_gas_used,
                "buy_gas_used": result.buy_gas_used,
            },
            duration_ms=elapsed(),
        )

    @staticmethod
    def _tax_severity(
        tax: float | None,
        medium: float,
        high: float,
        critical: float,
    ) -> Severity | None:
        if tax is None:
            return None
        if tax > critical:
            return Severity.CRITICAL
        if tax > high:
            return Severity.HIGH
        if tax > medium:
            return Severity.MEDIUM
        return None

    def _tax_finding(
        self,
        context: TokenContext,
        evidence: dict[str, object],
        max_tax: float,
        severity: Severity,
        rule_id: str,
    ) -> Finding:
        label = severity.value.lower()
        return Finding.create(
            rule_id=rule_id,
            detector_id=self.detector_id,
            category=DetectorCategory.DYNAMIC_TRAP,
            severity=severity,
            confidence=0.95 if severity is Severity.CRITICAL else 0.9,
            title=f"Measured {label} trading tax",
            description=(
                f"The simulated round trip measured a maximum tax of {max_tax:.2%}. "
                "Taxes are measured against router quotes for the exact trade size and "
                "include fee-on-transfer deductions."
            ),
            evidence=evidence,
            target=context.token_address,
            block_number=context.block_number,
        )
