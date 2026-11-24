"""Solana token authority, metadata, and Token-2022 extension detector."""

from __future__ import annotations

import time
from typing import Any

from ruglens.chains.solana.base58 import decode_pubkey, is_valid_pubkey
from ruglens.chains.solana.parsers import extension_state
from ruglens.chains.solana.pda import is_on_curve
from ruglens.chains.solana.registry import SYSTEM_PROGRAM_ID
from ruglens.core.enums import CoverageArea, DetectorCategory, Severity
from ruglens.core.exceptions import RpcError
from ruglens.core.interfaces import BaseSolanaDetector, SolanaDetectorDependencies
from ruglens.core.models import DetectorOutcome, Finding
from ruglens.core.solana_models import SolanaTokenContext

_RISK_REFERENCES = (
    "https://docs.solanatracker.io/data-api/risk",
    "https://data.birdeye.so/docs/use-cases/risk-and-integrity/rug-checker",
    "https://neodyme.io/en/blog/token-2022/",
)


def _find_value(value: Any, keys: set[str]) -> Any:
    """Recursively find the first mapping key in ``keys``."""
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in keys:
                return item
        for item in value.values():
            found = _find_value(item, keys)
            if found is not None:
                return found
    elif isinstance(value, list):
        for item in value:
            found = _find_value(item, keys)
            if found is not None:
                return found
    return None


class SolanaAuthoritiesDetector(BaseSolanaDetector):
    """Inspect mint/freeze authorities, metadata mutability, and Token-2022 extensions."""

    detector_id = "solana_authorities"
    category = DetectorCategory.AUTHORITIES
    coverage_area = CoverageArea.SOLANA_AUTHORITIES
    description = (
        "Mint/freeze authorities, Metaplex update authority, and dangerous Token-2022 "
        "extensions (permanent delegate, transfer hook, pause, default freeze, transfer fee)."
    )
    required = True

    async def detect(
        self,
        context: SolanaTokenContext,
        dependencies: SolanaDetectorDependencies,
    ) -> DetectorOutcome:
        started = time.perf_counter()
        findings: list[Finding] = []
        limitations: list[str] = []
        mint = context.mint
        coverage = 1.0
        authority_types: dict[str, str] = {}
        authority_fetch_failed = False
        authority_addresses = [
            address
            for address in (mint.mint_authority, mint.freeze_authority)
            if address and is_valid_pubkey(address)
        ]
        metadata = context.metadata
        if metadata and metadata.update_authority and is_valid_pubkey(metadata.update_authority):
            authority_addresses.append(metadata.update_authority)
        if authority_addresses:
            unique_authorities = list(dict.fromkeys(authority_addresses))
            try:
                infos = await dependencies.chain.get_multiple_accounts(unique_authorities)
                info_by_address = dict(zip(unique_authorities, infos, strict=False))
                if len(infos) != len(unique_authorities):
                    authority_fetch_failed = True
                    limitations.append(
                        "Authority account classification returned an incomplete result set."
                    )
                    coverage = min(coverage, 0.8)
                for address in unique_authorities:
                    authority_types[address] = self._classify_authority(
                        address, info_by_address.get(address)
                    )
            except RpcError as exc:
                authority_fetch_failed = True
                limitations.append(f"Authority account types could not be classified: {exc}")
                coverage = min(coverage, 0.8)

        if mint.mint_authority:
            authority_type = authority_types.get(mint.mint_authority, "unknown")
            if authority_type == "wallet":
                findings.append(
                    self._finding(
                        context,
                        rule_id="SOL-MINT-AUTHORITY-001",
                        severity=Severity.HIGH,
                        confidence=0.92,
                        title="Mint authority is a single wallet",
                        description=(
                            "The mint authority is an EOA-like wallet and can create more tokens "
                            "at any time, diluting existing holders. This is a capability, not "
                            "proof of an executed rug."
                        ),
                        evidence={
                            "mint_authority": mint.mint_authority,
                            "authority_type": authority_type,
                            "token_program": mint.program_name,
                        },
                    )
                )
            else:
                findings.append(
                    self._finding(
                        context,
                        rule_id="SOL-MINT-AUTHORITY-GOVERNED-001"
                        if authority_type != "unknown"
                        else "SOL-MINT-AUTHORITY-UNVERIFIED-001",
                        severity=Severity.MEDIUM,
                        confidence=0.76 if authority_type != "unknown" else 0.6,
                        title=(
                            "Mint authority is active under a multisig/program"
                            if authority_type != "unknown"
                            else "Mint authority type could not be verified"
                        ),
                        description=(
                            "The mint authority can create more tokens, but the authority "
                            "account is not a single wallet. Governance reduces immediate "
                            "unilateral dilution risk; it does not remove the capability."
                        ),
                        evidence={
                            "mint_authority": mint.mint_authority,
                            "authority_type": authority_type,
                            "token_program": mint.program_name,
                        },
                    )
                )
        if mint.freeze_authority:
            authority_type = authority_types.get(mint.freeze_authority, "unknown")
            if authority_type == "wallet":
                findings.append(
                    self._finding(
                        context,
                        rule_id="SOL-FREEZE-AUTHORITY-001",
                        severity=Severity.HIGH,
                        confidence=0.92,
                        title="Freeze authority is a single wallet",
                        description=(
                            "The freeze authority is an EOA-like wallet and can freeze token "
                            "accounts, preventing holders from transferring or selling."
                        ),
                        evidence={
                            "freeze_authority": mint.freeze_authority,
                            "authority_type": authority_type,
                            "token_program": mint.program_name,
                        },
                    )
                )
            else:
                findings.append(
                    self._finding(
                        context,
                        rule_id="SOL-FREEZE-AUTHORITY-GOVERNED-001"
                        if authority_type != "unknown"
                        else "SOL-FREEZE-AUTHORITY-UNVERIFIED-001",
                        severity=Severity.MEDIUM,
                        confidence=0.76 if authority_type != "unknown" else 0.6,
                        title=(
                            "Freeze authority is active under a multisig/program"
                            if authority_type != "unknown"
                            else "Freeze authority type could not be verified"
                        ),
                        description=(
                            "The freeze authority can freeze token accounts, but the authority "
                            "is not a single wallet. Governance reduces immediate unilateral "
                            "freeze risk; the capability remains."
                        ),
                        evidence={
                            "freeze_authority": mint.freeze_authority,
                            "authority_type": authority_type,
                            "token_program": mint.program_name,
                        },
                    )
                )

        if authority_fetch_failed:
            limitations.append(
                "Authority types were not fully verifiable; EOA/governance findings are conservative."
            )

        metadata = context.metadata
        if metadata is None:
            limitations.append(
                "Metaplex metadata was unavailable; metadata mutability and creator links "
                "are less certain."
            )
            coverage = min(coverage, 0.75)
        elif metadata.update_authority and metadata.is_mutable is not False:
            update_type = authority_types.get(metadata.update_authority, "unknown")
            governed = update_type in {"multisig", "program_controlled", "program"}
            findings.append(
                self._finding(
                    context,
                    rule_id=(
                        "SOL-METADATA-GOVERNED-001" if governed else "SOL-METADATA-MUTABLE-001"
                    ),
                    severity=Severity.LOW if governed else Severity.MEDIUM,
                    confidence=0.72 if governed else 0.6,
                    title="Token metadata remains mutable",
                    description=(
                        "An active update authority can change the token name, symbol, or URI. "
                        "This is common for new launches; the authority classification "
                        "determines whether the capability is controlled by one wallet or "
                        "by a multisig/program."
                    ),
                    evidence={
                        "metadata_address": metadata.address,
                        "update_authority": metadata.update_authority,
                        "authority_type": update_type,
                        "is_mutable": metadata.is_mutable,
                    },
                )
            )

        if mint.program_name == "Token-2022" and not mint.extensions_complete:
            limitations.append(
                "Token-2022 extensions could not be completely decoded; dangerous "
                "extensions may be missing from this assessment."
            )
            coverage = min(coverage, 0.70)
        if mint.extensions:
            # Evaluate every extension the RPC did expose, even when the list is
            # incomplete; coverage above records the remaining blind spot.
            findings.extend(self._extension_findings(context, limitations))

        metrics = {
            "mint_authority": mint.mint_authority,
            "freeze_authority": mint.freeze_authority,
            "mint_authority_active": mint.mint_authority is not None,
            "freeze_authority_active": mint.freeze_authority is not None,
            "mint_authority_type": authority_types.get(mint.mint_authority or "", "none"),
            "freeze_authority_type": authority_types.get(mint.freeze_authority or "", "none"),
            "token_program": mint.program_name,
            "is_token_2022": mint.program_name == "Token-2022",
            "metadata_available": metadata is not None,
            "metadata_mutable": metadata.is_mutable if metadata else None,
            "metadata_update_authority": metadata.update_authority if metadata else None,
            "metadata_update_authority_type": authority_types.get(
                metadata.update_authority or "", "none"
            )
            if metadata
            else "none",
            "extension_names": list(mint.extension_names),
        }
        return self.make_outcome(
            findings=findings[: self.settings.max_findings_per_detector],
            coverage_fraction=coverage,
            limitations=limitations,
            details={"metrics": metrics},
            duration_ms=(time.perf_counter() - started) * 1000,
        )

    @staticmethod
    def _classify_authority(address: str, info: dict[str, Any] | None) -> str:
        """Classify an authority as wallet, SPL multisig, or program-controlled."""
        try:
            on_curve = is_on_curve(decode_pubkey(address))
        except ValueError:
            return "unknown"
        if info is None:
            return "wallet" if on_curve else "program_controlled"
        data = info.get("data")
        if isinstance(data, dict):
            parsed = data.get("parsed")
            if isinstance(parsed, dict) and parsed.get("type") == "multisig":
                return "multisig"
        if bool(info.get("executable", False)):
            return "program"
        owner_program = str(info.get("owner", ""))
        if not on_curve:
            return "program_controlled"
        if owner_program == SYSTEM_PROGRAM_ID:
            return "wallet"
        if owner_program:
            return "program_controlled"
        return "wallet"

    def _extension_findings(
        self,
        context: SolanaTokenContext,
        limitations: list[str],
    ) -> list[Finding]:
        findings: list[Finding] = []
        extensions = context.mint.extensions
        if not extensions:
            return findings

        if extension_state(extensions, "permanentDelegate") is not None:
            state = extension_state(extensions, "permanentDelegate")
            delegate = _find_value(state, {"delegate"})
            findings.append(
                self._finding(
                    context,
                    rule_id="SOL-PERMANENT-DELEGATE-001",
                    severity=Severity.HIGH,
                    confidence=0.9,
                    title="Token-2022 permanent delegate can seize balances",
                    description=(
                        "A permanent delegate can transfer or burn tokens from any holder's "
                        "account without their approval. Raydium rejects this extension for "
                        "normal pool creation because reserves can be drained."
                    ),
                    evidence={"delegate": str(delegate) if delegate else None},
                )
            )

        if extension_state(extensions, "defaultAccountState") is not None:
            state = extension_state(extensions, "defaultAccountState")
            account_state = _find_value(state, {"accountstate", "state"})
            if str(account_state).lower() == "frozen" or "frozen" in str(state).lower():
                findings.append(
                    self._finding(
                        context,
                        rule_id="SOL-DEFAULT-FROZEN-001",
                        severity=Severity.HIGH,
                        confidence=0.9,
                        title="New token accounts are frozen by default",
                        description=(
                            "The mint's default account state is frozen. New holders cannot "
                            "transfer until the freeze authority thaws their accounts."
                        ),
                        evidence={"state": state},
                    )
                )

        if extension_state(extensions, "nonTransferable") is not None:
            findings.append(
                self._finding(
                    context,
                    rule_id="SOL-NONTRANSFERABLE-001",
                    severity=Severity.HIGH,
                    confidence=0.95,
                    title="Token-2022 mint is non-transferable",
                    description=(
                        "The non-transferable extension prevents token movement. A fungible "
                        "token with this extension cannot be sold through a normal venue."
                    ),
                    evidence={"extension": "nonTransferable"},
                )
            )

        if extension_state(extensions, "transferHook") is not None:
            state = extension_state(extensions, "transferHook")
            program = _find_value(state, {"programid", "program", "transferhookprogram"})
            if program:
                findings.append(
                    self._finding(
                        context,
                        rule_id="SOL-TRANSFER-HOOK-001",
                        severity=Severity.MEDIUM,
                        confidence=0.75,
                        title="Token-2022 transfer hook can restrict transfers",
                        description=(
                            "A transfer hook program runs on every transfer and can reject sells "
                            "or apply custom restrictions. Its code is not verified by RugLens."
                        ),
                        evidence={"program": str(program), "state": state},
                    )
                )

        if extension_state(extensions, "pausable") is not None:
            state = extension_state(extensions, "pausable")
            findings.append(
                self._finding(
                    context,
                    rule_id="SOL-PAUSABLE-001",
                    severity=Severity.HIGH,
                    confidence=0.85,
                    title="Token-2022 transfers can be paused",
                    description=(
                        "The pausable extension lets an authority pause minting, burning, or "
                        "transfers globally."
                    ),
                    evidence={"state": state},
                )
            )

        if extension_state(extensions, "mintCloseAuthority") is not None:
            state = extension_state(extensions, "mintCloseAuthority")
            authority = _find_value(state, {"closeauthority", "authority"})
            findings.append(
                self._finding(
                    context,
                    rule_id="SOL-MINT-CLOSE-001",
                    severity=Severity.MEDIUM,
                    confidence=0.7,
                    title="Token-2022 mint close authority is present",
                    description=(
                        "A mint close authority can close the mint when supply reaches zero. "
                        "This is usually not a direct holder-liquidity drain but is a "
                        "privileged capability."
                    ),
                    evidence={"authority": str(authority) if authority else None},
                )
            )

        fee_state = extension_state(extensions, "transferFeeConfig")
        if fee_state is not None:
            basis_points = _find_value(fee_state, {"transferfeebasispoints", "feebasispoints"})
            try:
                bps = int(basis_points) if basis_points is not None else None
            except (TypeError, ValueError):
                bps = None
            if bps is None:
                limitations.append(
                    "A Token-2022 transfer fee extension is present but its fee rate "
                    "could not be decoded."
                )
            elif bps > 0:
                fee = bps / 10_000
                if fee > 0.50:
                    severity = Severity.CRITICAL
                elif fee > 0.25:
                    severity = Severity.HIGH
                elif fee > 0.10:
                    severity = Severity.MEDIUM
                else:
                    severity = Severity.LOW
                findings.append(
                    self._finding(
                        context,
                        rule_id="SOL-TRANSFER-FEE-001",
                        severity=severity,
                        confidence=0.9,
                        title=f"Token-2022 transfer fee is {fee:.2%}",
                        description=(
                            "A protocol-level transfer fee is deducted on every transfer. "
                            "The current decoded rate is reported; the fee authority may be "
                            "able to change it."
                        ),
                        evidence={"basis_points": bps, "fee": fee, "state": fee_state},
                    )
                )

        if extension_state(extensions, "confidentialTransferMint") is not None:
            findings.append(
                self._finding(
                    context,
                    rule_id="SOL-CONFIDENTIAL-TRANSFER-001",
                    severity=Severity.LOW,
                    confidence=0.6,
                    title="Confidential transfers are enabled",
                    description=(
                        "Confidential transfer hides amounts from public holder analysis. "
                        "This does not prove fraud but materially reduces transparency."
                    ),
                    evidence={"extension": "confidentialTransferMint"},
                )
            )

        known_names = {
            "permanentdelegate",
            "defaultaccountstate",
            "nontransferable",
            "transferhook",
            "pausable",
            "mintcloseauthority",
            "transferfeeconfig",
            "confidentialtransfermint",
            "metadatapointer",
            "tokenmetadata",
            "interestbearingconfig",
            "scaleduiamount",
            "transferfeeamount",
            "immutableowner",
            "memotransfer",
            "cpiguard",
            "confidentialtransferfeeconfig",
            "confidentialtransferfeeamount",
            "nontransferableaccount",
            "transferhookaccount",
            "pausableaccount",
            "group",
            "groupmember",
            "grouppointer",
            "groupmemberpointer",
        }
        unknown = [name for name in context.mint.extension_names if name.lower() not in known_names]
        if unknown:
            limitations.append(
                "Unrecognized Token-2022 extensions were present: " + ", ".join(sorted(unknown))
            )
        return findings

    def _finding(
        self,
        context: SolanaTokenContext,
        *,
        rule_id: str,
        severity: Severity,
        confidence: float,
        title: str,
        description: str,
        evidence: dict[str, Any],
    ) -> Finding:
        return Finding.create(
            rule_id=rule_id,
            detector_id=self.detector_id,
            category=DetectorCategory.AUTHORITIES,
            severity=severity,
            confidence=confidence,
            title=title,
            description=description,
            evidence=evidence,
            target=context.token_address,
            block_number=context.slot,
            references=list(_RISK_REFERENCES),
        )
