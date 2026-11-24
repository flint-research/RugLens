"""Ownership, governance, and EIP-1967 proxy inspection."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Sequence

from eth_utils.address import is_address, to_checksum_address

from ruglens.chains.evm.abi import (
    DEAD_ADDRESS,
    EIP1967_ADMIN_SLOT,
    EIP1967_BEACON_SLOT,
    EIP1967_IMPLEMENTATION_SLOT,
    ZERO_ADDRESS,
    Selectors,
    decode_address,
    decode_uint,
)
from ruglens.core.enums import CoverageArea, DetectorCategory, DetectorStatus, Severity
from ruglens.core.exceptions import RpcError
from ruglens.core.interfaces import BaseDetector, DetectorDependencies
from ruglens.core.models import DetectorOutcome, Finding, RpcCall, RpcCallResult, TokenContext
from ruglens.detectors.static.selectors import scan_bytecode

logger = logging.getLogger(__name__)

_BURN_OWNERS = {ZERO_ADDRESS.lower(), DEAD_ADDRESS.lower()}


def _decode_owner(result: RpcCallResult) -> str | None:
    if not result.success or len(result.return_data) < 32:
        return None
    try:
        return decode_address(result.return_data)
    except ValueError:
        return None


def _slot_address(raw: str) -> str | None:
    if not raw or raw == "0x":
        return None
    hex_value = raw[2:] if raw.startswith("0x") else raw
    try:
        if not hex_value or int(hex_value, 16) == 0:
            return None
    except ValueError:
        return None
    padded = hex_value.rjust(64, "0")
    candidate = to_checksum_address("0x" + padded[-40:])
    return candidate if is_address(candidate) else None


class OwnershipDetector(BaseDetector):
    """Classify owner type and detect active upgradeability."""

    detector_id = "ownership"
    category = DetectorCategory.OWNERSHIP
    coverage_area = CoverageArea.OWNERSHIP
    description = (
        "owner()/getOwner() classification (burn, EOA, multisig, timelock, contract), "
        "mint capability contextualization, and EIP-1967 implementation/admin/beacon slots."
    )
    required = True

    async def detect(
        self,
        context: TokenContext,
        dependencies: DetectorDependencies,
    ) -> DetectorOutcome:
        started = time.perf_counter()
        findings: list[Finding] = []
        limitations: list[str] = []
        owner_known = True
        proxy_known = True

        owner, owner_known, owner_notes = await self._resolve_owner(context, dependencies)
        limitations.extend(owner_notes)
        owner_type = "none"
        owner_code: bytes | None = None
        governance: str | None = None

        if owner is not None:
            if owner.lower() in _BURN_OWNERS:
                owner_type = "burn"
            else:
                try:
                    owner_code = await dependencies.chain.get_code(owner, context.block_number)
                except RpcError as exc:
                    owner_known = False
                    limitations.append(f"Could not inspect owner bytecode: {exc}")
                    owner_code = None
                if owner_code is not None:
                    if not owner_code:
                        owner_type = "eoa"
                    else:
                        governance = await self._classify_governance(
                            owner, dependencies, context.block_number
                        )
                        owner_type = governance or "contract"

        if owner_type == "eoa":
            findings.append(
                Finding.create(
                    rule_id="OWN-EOA-001",
                    detector_id=self.detector_id,
                    category=DetectorCategory.OWNERSHIP,
                    severity=Severity.MEDIUM,
                    confidence=0.85,
                    title="Ownership controlled by an externally owned account",
                    description=(
                        "The contract owner is a single EOA. That wallet can exercise every "
                        "privileged function present in the bytecode without on-chain "
                        "governance delay or multisig approval."
                    ),
                    evidence={
                        "owner": owner,
                        "owner_type": "EOA",
                        "owner_has_code": False,
                    },
                    target=context.token_address,
                    block_number=context.block_number,
                )
            )
        elif owner_type == "contract":
            findings.append(
                Finding.create(
                    rule_id="OWN-CONTRACT-001",
                    detector_id=self.detector_id,
                    category=DetectorCategory.OWNERSHIP,
                    severity=Severity.MEDIUM,
                    confidence=0.65,
                    title="Ownership controlled by an unrecognized contract",
                    description=(
                        "The owner is a contract, but it does not expose the multisig or "
                        "timelock interfaces RugLens recognizes. Centralization may be "
                        "mitigated by custom governance that cannot be verified here."
                    ),
                    evidence={"owner": owner, "owner_type": "UNKNOWN_CONTRACT"},
                    target=context.token_address,
                    block_number=context.block_number,
                )
            )
        elif owner_type in {"multisig", "timelock"}:
            limitations.append(
                f"Owner classified as {owner_type}; administrative findings are contextualized."
            )

        if context.bytecode:
            try:
                scan = scan_bytecode(context.bytecode)
            except Exception as exc:
                limitations.append(f"Mint capability check failed: {exc}")
            else:
                mint_signatures = scan.matched_groups.get("mint", ())
                if mint_signatures and owner_type != "burn":
                    findings.append(self._mint_finding(context, owner, owner_type, mint_signatures))

        impl, admin, beacon, proxy_known, proxy_notes = await self._proxy_state(
            context, dependencies
        )
        limitations.extend(proxy_notes)
        if impl is not None:
            try:
                impl_code = await dependencies.chain.get_code(impl, context.block_number)
            except RpcError as exc:
                limitations.append(f"Could not inspect proxy implementation: {exc}")
                impl_code = None
                proxy_known = False
            if impl_code == b"":
                findings.append(
                    Finding.create(
                        rule_id="PROXY-IMPL-NO-CODE-001",
                        detector_id=self.detector_id,
                        category=DetectorCategory.PROXY,
                        severity=Severity.LOW,
                        confidence=0.6,
                        title="Proxy points at an address without bytecode",
                        description=(
                            "The EIP-1967 implementation slot is populated but the target "
                            "has no runtime code. Calls may fail or fall back to a "
                            "placeholder until the implementation is replaced."
                        ),
                        evidence={
                            "implementation": impl,
                            "slot": EIP1967_IMPLEMENTATION_SLOT,
                            "implementation_has_code": False,
                        },
                        target=context.token_address,
                        block_number=context.block_number,
                    )
                )
            else:
                findings.append(
                    Finding.create(
                        rule_id="PROXY-IMPL-001",
                        detector_id=self.detector_id,
                        category=DetectorCategory.PROXY,
                        severity=Severity.MEDIUM,
                        confidence=0.88,
                        title="Active upgradeable proxy",
                        description=(
                            "An EIP-1967 implementation address is set. The token's logic "
                            "can be replaced by whoever controls the proxy admin or upgrade "
                            "function."
                        ),
                        evidence={
                            "implementation": impl,
                            "slot": EIP1967_IMPLEMENTATION_SLOT,
                            "implementation_has_code": impl_code is not None,
                        },
                        target=context.token_address,
                        block_number=context.block_number,
                        references=["https://eips.ethereum.org/EIPS/eip-1967"],
                    )
                )
        if beacon is not None:
            findings.append(
                Finding.create(
                    rule_id="PROXY-BEACON-001",
                    detector_id=self.detector_id,
                    category=DetectorCategory.PROXY,
                    severity=Severity.MEDIUM,
                    confidence=0.82,
                    title="Beacon upgradeable proxy",
                    description=(
                        "An EIP-1967 beacon slot is active. Upgrading the shared beacon "
                        "changes this token's implementation."
                    ),
                    evidence={"beacon": beacon, "slot": EIP1967_BEACON_SLOT},
                    target=context.token_address,
                    block_number=context.block_number,
                )
            )
        if admin is not None and (impl is not None or beacon is not None):
            try:
                admin_code = await dependencies.chain.get_code(admin, context.block_number)
            except RpcError as exc:
                limitations.append(f"Could not inspect proxy admin: {exc}")
                admin_code = None
                proxy_known = False
            if admin_code == b"":
                findings.append(
                    Finding.create(
                        rule_id="PROXY-ADMIN-EOA-001",
                        detector_id=self.detector_id,
                        category=DetectorCategory.PROXY,
                        severity=Severity.HIGH,
                        confidence=0.88,
                        title="Proxy admin is an externally owned account",
                        description=(
                            "The EIP-1967 admin is a single EOA. It can upgrade the token's "
                            "implementation to arbitrary code without governance delay."
                        ),
                        evidence={"admin": admin, "slot": EIP1967_ADMIN_SLOT},
                        target=context.token_address,
                        block_number=context.block_number,
                    )
                )
            elif admin_code:
                findings.append(
                    Finding.create(
                        rule_id="PROXY-ADMIN-CONTRACT-001",
                        detector_id=self.detector_id,
                        category=DetectorCategory.PROXY,
                        severity=Severity.LOW,
                        confidence=0.6,
                        title="Proxy admin is a contract",
                        description=(
                            "The proxy admin is a contract. This is safer than an EOA only "
                            "if that contract enforces meaningful controls."
                        ),
                        evidence={"admin": admin, "slot": EIP1967_ADMIN_SLOT},
                        target=context.token_address,
                        block_number=context.block_number,
                    )
                )

        if not owner_known and not proxy_known:
            return self.make_outcome(
                status=DetectorStatus.FAILED,
                error="Ownership and proxy state could not be read",
                limitations=limitations,
                duration_ms=(time.perf_counter() - started) * 1000,
            )
        components = (float(owner_known), float(proxy_known))
        coverage_fraction = sum(components) / len(components)
        if coverage_fraction < 1.0:
            limitations.append("Ownership inspection completed only partially.")
        findings = findings[: self.settings.max_findings_per_detector]
        return self.make_outcome(
            findings=findings,
            coverage_fraction=coverage_fraction,
            limitations=limitations,
            details={
                "owner": owner,
                "owner_type": owner_type,
                "governance": governance,
                "proxy_implementation": impl,
                "proxy_admin": admin,
                "proxy_beacon": beacon,
            },
            duration_ms=(time.perf_counter() - started) * 1000,
        )

    async def _resolve_owner(
        self,
        context: TokenContext,
        dependencies: DetectorDependencies,
    ) -> tuple[str | None, bool, list[str]]:
        notes: list[str] = []
        if context.owner is not None:
            try:
                return to_checksum_address(context.owner), True, notes
            except ValueError:
                notes.append("Context contained a malformed owner address.")
        try:
            results = await dependencies.chain.multicall(
                [
                    RpcCall(to=context.token_address, data=Selectors.OWNER),
                    RpcCall(to=context.token_address, data=Selectors.GET_OWNER),
                ],
                context.block_number,
            )
        except RpcError as exc:
            return None, False, [f"Owner RPC read failed: {exc}"]
        if len(results) < 2:
            return None, False, ["Owner multicall returned too few results."]
        owner = _decode_owner(results[0]) or _decode_owner(results[1])
        if owner is None:
            notes.append("No owner()/getOwner() function was detected.")
        return owner, True, notes

    async def _classify_governance(
        self,
        owner: str,
        dependencies: DetectorDependencies,
        block_number: int,
    ) -> str | None:
        try:
            results = await dependencies.chain.multicall(
                [
                    RpcCall(to=owner, data=Selectors.GET_THRESHOLD),
                    RpcCall(to=owner, data=Selectors.GET_OWNERS),
                    RpcCall(to=owner, data=Selectors.GET_MIN_DELAY),
                    RpcCall(to=owner, data=Selectors.DELAY),
                ],
                block_number,
            )
        except RpcError:
            return None
        if len(results) < 4:
            return None
        threshold_result, owners_result, min_delay_result, delay_result = results[:4]
        try:
            threshold = decode_uint(threshold_result.return_data) if threshold_result.success else 0
        except ValueError:
            threshold = 0
        if threshold > 0 and owners_result.success and len(owners_result.return_data) >= 64:
            return "multisig"
        for result in (min_delay_result, delay_result):
            if result.success and len(result.return_data) >= 32:
                try:
                    if decode_uint(result.return_data) > 0:
                        return "timelock"
                except ValueError:
                    continue
        return None

    async def _proxy_state(
        self,
        context: TokenContext,
        dependencies: DetectorDependencies,
    ) -> tuple[str | None, str | None, str | None, bool, list[str]]:
        notes: list[str] = []
        impl = context.proxy_implementation
        admin = context.proxy_admin
        beacon = context.proxy_beacon
        known = True
        if impl is None and admin is None and beacon is None:
            try:
                raw_values = await asyncio.gather(
                    dependencies.chain.get_storage_at(
                        context.token_address, EIP1967_IMPLEMENTATION_SLOT, context.block_number
                    ),
                    dependencies.chain.get_storage_at(
                        context.token_address, EIP1967_ADMIN_SLOT, context.block_number
                    ),
                    dependencies.chain.get_storage_at(
                        context.token_address, EIP1967_BEACON_SLOT, context.block_number
                    ),
                )
            except RpcError as exc:
                return None, None, None, False, [f"EIP-1967 slot read failed: {exc}"]
            impl, admin, beacon = (_slot_address(raw) for raw in raw_values)
        return impl, admin, beacon, known, notes

    def _mint_finding(
        self,
        context: TokenContext,
        owner: str | None,
        owner_type: str,
        signatures: Sequence[object],
    ) -> Finding:
        selectors = [
            {
                "selector": getattr(item, "selector", ""),
                "signature": getattr(item, "signature", ""),
            }
            for item in signatures
        ]
        if owner_type == "eoa":
            severity = Severity.HIGH
            confidence = 0.88
            description = (
                "Mint-like functions exist and the owner is a single EOA. The owner can "
                "dilute holders at will; this is a high-severity control capability, not "
                "a confirmed exploit."
            )
            rule_id = "OWN-MINT-EOA-001"
        elif owner_type in {"multisig", "timelock"}:
            severity = Severity.MEDIUM
            confidence = 0.75
            description = (
                "Mint-like functions exist under a recognized multisig/timelock owner. "
                "The capability is real but requires governance approval."
            )
            rule_id = "OWN-MINT-GOVERNED-001"
        elif owner_type == "contract":
            severity = Severity.MEDIUM
            confidence = 0.72
            description = (
                "Mint-like functions exist under an unrecognized contract owner. "
                "The access-control model could not be verified."
            )
            rule_id = "OWN-MINT-CONTRACT-001"
        else:
            severity = Severity.MEDIUM
            confidence = 0.6
            description = (
                "Mint-like selectors exist but no standard owner was detected. "
                "The function may be role-gated, public, or dormant."
            )
            rule_id = "OWN-MINT-NO-OWNER-001"
        return Finding.create(
            rule_id=rule_id,
            detector_id=self.detector_id,
            category=DetectorCategory.OWNERSHIP,
            severity=severity,
            confidence=confidence,
            title="Minting capability with live ownership",
            description=description,
            evidence={
                "owner": owner,
                "owner_type": owner_type.upper(),
                "selectors": selectors,
            },
            target=context.token_address,
            block_number=context.block_number,
        )
