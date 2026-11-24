"""Static bytecode selector and opcode detector."""

from __future__ import annotations

import logging
import time

from ruglens.core.enums import CoverageArea, DetectorCategory, DetectorStatus, Severity
from ruglens.core.interfaces import BaseDetector, DetectorDependencies
from ruglens.core.models import DetectorOutcome, Finding, TokenContext
from ruglens.detectors.static.selectors import RISK_GROUPS, SelectorScan, scan_bytecode

logger = logging.getLogger(__name__)


class BytecodeSelectorDetector(BaseDetector):
    """Extract SWC-style risk capabilities directly from EVM bytecode."""

    detector_id = "bytecode_selectors"
    category = DetectorCategory.STATIC
    coverage_area = CoverageArea.BYTECODE
    description = (
        "pyevmasm disassembly: curated 4-byte selectors plus DELEGATECALL, "
        "SELFDESTRUCT, and CREATE2 opcode evidence."
    )
    required = True

    async def detect(
        self,
        context: TokenContext,
        dependencies: DetectorDependencies,
    ) -> DetectorOutcome:
        started = time.perf_counter()
        if not context.bytecode:
            return self.make_outcome(
                status=DetectorStatus.FAILED,
                error="No runtime bytecode to analyse",
                duration_ms=(time.perf_counter() - started) * 1000,
            )
        try:
            scan = scan_bytecode(context.bytecode)
        except Exception as exc:
            logger.warning("Bytecode disassembly failed for %s: %s", context.token_address, exc)
            return self.make_outcome(
                status=DetectorStatus.FAILED,
                error=f"Bytecode disassembly failed: {exc}",
                duration_ms=(time.perf_counter() - started) * 1000,
            )

        findings: list[Finding] = []
        for group_name, signatures in scan.matched_groups.items():
            group = RISK_GROUPS[group_name]
            findings.append(
                Finding.create(
                    rule_id=group.rule_id,
                    detector_id=self.detector_id,
                    category=group.category,
                    severity=group.severity,
                    confidence=group.confidence,
                    title=group.title,
                    description=group.description,
                    evidence={
                        "selectors": [
                            {
                                "selector": item.selector,
                                "signature": item.signature,
                                "name": item.name,
                            }
                            for item in signatures
                        ],
                        "detection": "PUSH4 selector match",
                        "bytecode_size": len(context.bytecode),
                        "instruction_count": scan.instruction_count,
                    },
                    target=context.token_address,
                    block_number=context.block_number,
                    references=list(group.references),
                )
            )

        findings.extend(self._opcode_findings(scan, context))
        findings = findings[: self.settings.max_findings_per_detector]
        duration = (time.perf_counter() - started) * 1000
        return self.make_outcome(
            findings=findings,
            details={
                "selector_count": scan.selector_count,
                "dispatch_selectors": list(scan.selectors[:200]),
                "matched_groups": sorted(scan.matched_groups),
                "opcode_counts": scan.opcode_counts,
                "instruction_count": scan.instruction_count,
            },
            duration_ms=duration,
        )

    def _opcode_findings(
        self,
        scan: SelectorScan,
        context: TokenContext,
    ) -> list[Finding]:
        findings: list[Finding] = []
        selfdestructs = scan.opcode_counts.get("SELFDESTRUCT", 0)
        if selfdestructs:
            findings.append(
                Finding.create(
                    rule_id="STATIC-SELFDESTRUCT-001",
                    detector_id=self.detector_id,
                    category=DetectorCategory.STATIC,
                    severity=Severity.MEDIUM,
                    confidence=0.6,
                    title="SELFDESTRUCT opcode present",
                    description=(
                        "The runtime bytecode contains SELFDESTRUCT. It may be unreachable "
                        "or legacy library code, but a reachable path can destroy the "
                        "contract or force-send its balance."
                    ),
                    evidence={
                        "opcode": "SELFDESTRUCT",
                        "count": selfdestructs,
                        "program_counters": list(scan.opcode_pcs.get("SELFDESTRUCT", ())),
                    },
                    target=context.token_address,
                    block_number=context.block_number,
                )
            )
        delegatecalls = scan.opcode_counts.get("DELEGATECALL", 0)
        if delegatecalls:
            findings.append(
                Finding.create(
                    rule_id="STATIC-DELEGATECALL-001",
                    detector_id=self.detector_id,
                    category=DetectorCategory.PROXY,
                    severity=Severity.LOW,
                    confidence=0.55,
                    title="DELEGATECALL opcode present",
                    description=(
                        "DELEGATECALL executes external code in the token's storage context. "
                        "It is expected in proxies and libraries, so this is only an "
                        "indicator; active EIP-1967 slots are evaluated separately."
                    ),
                    evidence={
                        "opcode": "DELEGATECALL",
                        "count": delegatecalls,
                        "program_counters": list(scan.opcode_pcs.get("DELEGATECALL", ())),
                    },
                    target=context.token_address,
                    block_number=context.block_number,
                    references=["https://eips.ethereum.org/EIPS/eip-1967"],
                )
            )
        create2 = scan.opcode_counts.get("CREATE2", 0)
        if create2:
            findings.append(
                Finding.create(
                    rule_id="STATIC-CREATE2-001",
                    detector_id=self.detector_id,
                    category=DetectorCategory.PROXY,
                    severity=Severity.LOW,
                    confidence=0.5,
                    title="CREATE2 opcode present",
                    description=(
                        "CREATE2 can deploy contracts at deterministic addresses. This is "
                        "used by factories and some proxies; context is required to judge it."
                    ),
                    evidence={
                        "opcode": "CREATE2",
                        "count": create2,
                        "program_counters": list(scan.opcode_pcs.get("CREATE2", ())),
                    },
                    target=context.token_address,
                    block_number=context.block_number,
                )
            )
        return findings
