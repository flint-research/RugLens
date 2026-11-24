"""Core enumerations shared across RugLens.

This module has no internal dependencies and must remain import-safe from every
other RugLens subsystem.
"""

from __future__ import annotations

from enum import IntEnum, StrEnum


class ChainId(IntEnum):
    """Chains supported by the engine."""

    ETHEREUM = 1
    BSC = 56
    BASE = 8453
    # Synthetic RugLens chain selector for Solana mainnet. Solana has no
    # EIP-155 chain id; 101 is used consistently as the engine's internal id.
    SOLANA = 101


class Severity(StrEnum):
    """Severity of a single evidence-backed finding."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Numeric rank where larger values are more severe."""
        return _SEVERITY_RANK[self]

    @classmethod
    def from_value(cls, value: str) -> Severity:
        """Parse a severity case-insensitively."""
        try:
            return cls(value.strip().upper())
        except ValueError as exc:
            raise ValueError(f"Unknown severity: {value!r}") from exc


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class RiskLevel(StrEnum):
    """Final, non-numeric risk classification for a token assessment."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MODERATE = "MODERATE"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

    @property
    def is_dangerous(self) -> bool:
        """Whether the level represents a proven or strongly indicated danger."""
        return self in {RiskLevel.CRITICAL, RiskLevel.HIGH}

    @property
    def is_actionable(self) -> bool:
        """Whether the level is supported by enough evidence to act on."""
        return self is not RiskLevel.UNKNOWN


class DetectorStatus(StrEnum):
    """Execution status of a detector.

    A detector that cannot run must never silently disappear: its non-SUCCESS
    status drives the weighted data-coverage calculation.
    """

    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    TIMEOUT = "TIMEOUT"

    @property
    def contributes_coverage(self) -> bool:
        """Only successful detector executions contribute coverage."""
        return self is DetectorStatus.SUCCESS


class DetectorCategory(StrEnum):
    """Evidence category attached to findings."""

    DYNAMIC_TRAP = "DYNAMIC_TRAP"
    STATIC = "STATIC"
    OWNERSHIP = "OWNERSHIP"
    PROXY = "PROXY"
    LIQUIDITY = "LIQUIDITY"
    HOLDERS = "HOLDERS"
    AUTHORITIES = "AUTHORITIES"
    CLUSTERS = "CLUSTERS"
    SOURCE = "SOURCE"
    METADATA = "METADATA"


class CoverageArea(StrEnum):
    """Required assessment areas used by the weighted coverage model."""

    DYNAMIC_TRADE = "DYNAMIC_TRADE"
    BYTECODE = "BYTECODE"
    LIQUIDITY = "LIQUIDITY"
    OWNERSHIP = "OWNERSHIP"
    HOLDERS = "HOLDERS"
    # Solana-specific assessment profile.
    SOLANA_AUTHORITIES = "SOLANA_AUTHORITIES"
    SOLANA_HOLDERS = "SOLANA_HOLDERS"
    SOLANA_CLUSTERS = "SOLANA_CLUSTERS"
    SOLANA_LIQUIDITY = "SOLANA_LIQUIDITY"
