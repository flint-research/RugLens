"""Typed domain models used across RugLens.

The models in this module are the stable contract between detectors, the risk
engine, storage, the CLI/API, and downstream Flint Research products.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any, Self
from uuid import UUID, uuid4

from eth_utils.address import is_address, to_checksum_address
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ruglens.core.enums import (
    CoverageArea,
    DetectorCategory,
    DetectorStatus,
    RiskLevel,
    Severity,
)
from ruglens.core.sanitization import (
    sanitize_reason,
    sanitize_token_name,
    sanitize_token_symbol,
)

ENGINE_VERSION = "0.2.0"
RULE_VERSION = "1.0.0"


def compute_finding_id(rule_id: str, target: str, block_number: int) -> str:
    """Compute the deterministic evidence identifier.

    The identifier is a SHA-256 over the rule, normalized target address, and
    pinned block height, making every finding reproducible and stable.
    """
    payload = f"{rule_id}|{target.lower()}|{block_number}".encode()
    return hashlib.sha256(payload).hexdigest()


class Finding(BaseModel):
    """A single, reproducible piece of evidence about a token."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_id: str
    rule_id: str
    rule_version: str = RULE_VERSION
    detector_id: str
    category: DetectorCategory
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    title: str
    description: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    references: list[str] = Field(default_factory=list)
    target: str
    block_number: int = Field(ge=0)

    @classmethod
    def create(
        cls,
        *,
        rule_id: str,
        detector_id: str,
        category: DetectorCategory,
        severity: Severity,
        confidence: float,
        title: str,
        description: str,
        evidence: dict[str, Any],
        target: str,
        block_number: int,
        references: list[str] | None = None,
        rule_version: str = RULE_VERSION,
    ) -> Self:
        """Build a finding with a deterministic identifier."""
        return cls(
            finding_id=compute_finding_id(rule_id, target, block_number),
            rule_id=rule_id,
            rule_version=rule_version,
            detector_id=detector_id,
            category=category,
            severity=severity,
            confidence=confidence,
            title=title,
            description=description,
            evidence=evidence,
            references=references or [],
            target=target,
            block_number=block_number,
        )


class TokenMetadata(BaseModel):
    """Sanitized ERC-20 metadata."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = "Unknown Token"
    symbol: str = "UNKNOWN"
    decimals: int | None = Field(default=None, ge=0, le=255)
    total_supply: int | None = Field(default=None, ge=0)

    @field_validator("name", mode="before")
    @classmethod
    def _sanitize_name(cls, value: Any) -> str:
        return sanitize_token_name(value)

    @field_validator("symbol", mode="before")
    @classmethod
    def _sanitize_symbol(cls, value: Any) -> str:
        return sanitize_token_symbol(value)


class HolderBalance(BaseModel):
    """A token holder and its current balance."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    address: str
    balance: int = Field(ge=0)

    @field_validator("address")
    @classmethod
    def _checksum(cls, value: str) -> str:
        if not is_address(value):
            raise ValueError(f"invalid holder address: {value}")
        return to_checksum_address(value)


class RpcCall(BaseModel):
    """A single call to be packed into Multicall3.aggregate3."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    to: str
    data: bytes


class RpcCallResult(BaseModel):
    """Result of one Multicall3 sub-call."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    success: bool
    return_data: bytes = b""


class TradeSimulationResult(BaseModel):
    """Measured outcome of an isolated DEX V2 buy/approve/sell sequence."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    executed: bool
    buy_success: bool
    sell_success: bool
    approve_success: bool | None = None
    router: str
    pair: str
    wallet: str
    block_number: int
    buy_tax: float | None = Field(default=None, ge=0.0, le=1.0)
    sell_tax: float | None = Field(default=None, ge=0.0, le=1.0)
    expected_buy_amount: int | None = Field(default=None, ge=0)
    buy_amount_received: int | None = Field(default=None, ge=0)
    expected_sell_amount: int | None = Field(default=None, ge=0)
    sell_amount_received: int | None = Field(default=None, ge=0)
    buy_gas_used: int | None = Field(default=None, ge=0)
    sell_gas_used: int | None = Field(default=None, ge=0)
    buy_revert_reason: str | None = None
    sell_revert_reason: str | None = None
    notes: list[str] = Field(default_factory=list)

    @field_validator("buy_revert_reason", "sell_revert_reason", mode="before")
    @classmethod
    def _sanitize_revert(cls, value: Any) -> str | None:
        if value is None:
            return None
        return sanitize_reason(value) or None

    @property
    def is_honeypot(self) -> bool:
        """A buy succeeded but selling failed or returned almost nothing."""
        if not self.buy_success:
            return False
        if self.approve_success is False:
            return False
        if not self.sell_success:
            return True
        if self.expected_sell_amount and self.expected_sell_amount > 0:
            received = self.sell_amount_received or 0
            return received * 100 < self.expected_sell_amount
        return False


class DetectorOutcome(BaseModel):
    """Result of one detector execution.

    Coverage is only attributed for SUCCESS outcomes. A detector may report a
    SUCCESS with a coverage fraction below 1.0 when it completed only part of
    its work (for example, a truncated holder-log window); it must then add a
    limitation explaining the gap.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    detector_id: str
    category: DetectorCategory
    coverage_area: CoverageArea | None
    status: DetectorStatus
    findings: tuple[Finding, ...] = ()
    coverage_fraction: float = Field(default=0.0, ge=0.0, le=1.0)
    limitations: tuple[str, ...] = ()
    details: dict[str, Any] = Field(default_factory=dict)
    duration_ms: float = Field(default=0.0, ge=0.0)
    error: str | None = None

    @model_validator(mode="after")
    def _validate_status_coverage(self) -> Self:
        if self.status is not DetectorStatus.SUCCESS and self.coverage_fraction > 0:
            object.__setattr__(self, "coverage_fraction", 0.0)
        return self

    @property
    def succeeded(self) -> bool:
        """Whether the detector completed successfully."""
        return self.status is DetectorStatus.SUCCESS


class TokenContext(BaseModel):
    """Hydrated, block-pinned context shared by every detector."""

    model_config = ConfigDict(extra="forbid")

    chain_id: int
    token_address: str
    block_number: int = Field(ge=0)
    bytecode: bytes = b""
    bytecode_hash: str = ""
    metadata: TokenMetadata | None = None
    owner: str | None = None
    router: str | None = None
    weth: str | None = None
    pair_address: str | None = None
    pair_token0: str | None = None
    pair_token1: str | None = None
    pair_reserves: tuple[int, int] | None = None
    lp_total_supply: int | None = None
    lp_balances: dict[str, int] = Field(default_factory=dict)
    holders: list[HolderBalance] = Field(default_factory=list)
    proxy_implementation: str | None = None
    proxy_admin: str | None = None
    proxy_beacon: str | None = None
    deployer: str | None = None
    verified_source: bool = False
    source_files: dict[str, str] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)

    @property
    def has_bytecode(self) -> bool:
        """Whether the target has runtime bytecode."""
        return bool(self.bytecode)

    @property
    def decimals(self) -> int | None:
        """Token decimals, when known."""
        return self.metadata.decimals if self.metadata else None

    @property
    def total_supply(self) -> int | None:
        """Token total supply, when known."""
        return self.metadata.total_supply if self.metadata else None


class AssessmentReport(BaseModel):
    """Immutable, serializable result of one complete token assessment."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    assessment_id: UUID = Field(default_factory=uuid4)
    engine_version: str = ENGINE_VERSION
    chain_id: int
    token_address: str
    block_number: int = Field(ge=0)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    risk_level: RiskLevel
    confidence_score: float = Field(ge=0.0, le=1.0)
    data_coverage: float = Field(ge=0.0, le=1.0)

    findings: tuple[Finding, ...] = ()
    detector_statuses: dict[str, DetectorStatus] = Field(default_factory=dict)
    limitations: tuple[str, ...] = ()
    token: TokenMetadata | None = None
    summary: str = ""
    metrics: dict[str, Any] = Field(default_factory=dict)
    duration_ms: float = Field(default=0.0, ge=0.0)
    rpc_calls: int = Field(default=0, ge=0)

    @field_validator("timestamp")
    @classmethod
    def _require_aware_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def to_json(self, *, indent: int | None = 2) -> str:
        """Serialize with a stable, deterministic contract."""
        return self.model_dump_json(indent=indent)

    @classmethod
    def from_json(cls, payload: str | bytes) -> Self:
        """Parse a previously serialized report."""
        return cls.model_validate_json(payload)

    @property
    def critical_findings(self) -> tuple[Finding, ...]:
        """Findings classified as CRITICAL."""
        return tuple(f for f in self.findings if f.severity is Severity.CRITICAL)
