"""Internal interface contracts.

The boundaries here enforce the one-way dependency rules described in
``docs/ARCHITECTURE.md``. Implementations live in ``chains``, ``simulation``,
``storage``, and ``detectors``; ``core`` never imports those packages.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, ClassVar, Protocol

from ruglens.core.config import RugLensSettings
from ruglens.core.enums import CoverageArea, DetectorCategory, DetectorStatus
from ruglens.core.models import (
    AssessmentReport,
    DetectorOutcome,
    Finding,
    RpcCall,
    RpcCallResult,
    TokenContext,
    TradeSimulationResult,
)
from ruglens.core.solana_models import SolanaTokenContext


class ChainAdapter(Protocol):
    """Read-only, block-pinned EVM chain access."""

    @property
    def chain_id(self) -> int: ...

    @property
    def rpc_calls(self) -> int: ...

    async def get_block_number(self) -> int: ...

    async def get_code(self, address: str, block_number: int) -> bytes: ...

    async def get_balance(self, address: str, block_number: int) -> int: ...

    async def get_storage_at(self, address: str, slot: str, block_number: int) -> str: ...

    async def eth_call(self, to: str, data: bytes, block_number: int) -> bytes: ...

    async def multicall(
        self,
        calls: Sequence[RpcCall],
        block_number: int,
        *,
        allow_failure: bool = True,
    ) -> list[RpcCallResult]: ...

    async def get_logs(
        self,
        address: str,
        topics: Sequence[str | None],
        from_block: int,
        to_block: int,
    ) -> list[dict[str, Any]]: ...

    async def close(self) -> None: ...


class ChainAdapterFactory(Protocol):
    """Creates chain adapters on demand (one per chain/RPC set)."""

    async def get_adapter(
        self,
        chain_id: int,
        rpc_urls: Sequence[str] | None = None,
    ) -> ChainAdapter: ...

    async def close(self) -> None: ...


class TradeSimulator(Protocol):
    """Isolated local-EVM trade simulator."""

    async def simulate(self, context: TokenContext) -> TradeSimulationResult: ...


class TradeSimulatorFactory(Protocol):
    """Supplies a simulator for a chain and optional RPC URL override."""

    def get_simulator(
        self,
        chain_id: int,
        rpc_urls: Sequence[str] | None = None,
    ) -> TradeSimulator | None: ...


@dataclass(frozen=True, slots=True)
class DetectorDependencies:
    """Services made available to detectors for one assessment."""

    chain: ChainAdapter
    simulator: TradeSimulator | None = None


class BaseDetector(ABC):
    """Base class for every built-in and plugin detector.

    Detector classes must be stateless beyond configuration. They never
    calculate the final risk level; that belongs exclusively to ``risk``.
    """

    detector_id: ClassVar[str]
    category: ClassVar[DetectorCategory]
    coverage_area: ClassVar[CoverageArea | None]
    description: ClassVar[str]
    required: ClassVar[bool] = True

    def __init__(self, settings: RugLensSettings) -> None:
        self.settings = settings

    @abstractmethod
    async def detect(
        self,
        context: TokenContext,
        dependencies: DetectorDependencies,
    ) -> DetectorOutcome:
        """Inspect one token and return evidence plus an execution status."""

    def make_outcome(
        self,
        *,
        findings: Sequence[Finding] = (),
        status: DetectorStatus = DetectorStatus.SUCCESS,
        coverage_fraction: float | None = None,
        limitations: Sequence[str] = (),
        details: dict[str, Any] | None = None,
        duration_ms: float = 0.0,
        error: str | None = None,
    ) -> DetectorOutcome:
        """Construct an outcome with this detector's metadata populated."""
        if coverage_fraction is None:
            coverage_fraction = 1.0 if status is DetectorStatus.SUCCESS else 0.0
        return DetectorOutcome(
            detector_id=self.detector_id,
            category=self.category,
            coverage_area=self.coverage_area,
            status=status,
            findings=tuple(findings),
            coverage_fraction=coverage_fraction,
            limitations=tuple(limitations),
            details=details or {},
            duration_ms=duration_ms,
            error=error,
        )


class SolanaChainAdapter(Protocol):
    """Read-only Solana JSON-RPC access needed by the native Solana engine."""

    @property
    def rpc_calls(self) -> int: ...

    async def get_slot(self) -> int: ...

    async def get_account_info(
        self,
        address: str,
        *,
        encoding: str = "jsonParsed",
    ) -> dict[str, Any] | None: ...

    async def get_multiple_accounts(
        self,
        addresses: Sequence[str],
        *,
        encoding: str = "jsonParsed",
    ) -> list[dict[str, Any] | None]: ...

    async def get_token_largest_accounts(self, mint: str) -> list[dict[str, Any]]: ...

    async def get_token_supply(self, mint: str) -> dict[str, Any]: ...

    async def get_signatures_for_address(
        self,
        address: str,
        *,
        limit: int,
        before: str | None = None,
    ) -> list[dict[str, Any]]: ...

    async def get_transaction(self, signature: str) -> dict[str, Any] | None: ...

    async def get_token_accounts_by_owner(
        self,
        owner: str,
        mint: str,
    ) -> list[dict[str, Any]]: ...

    async def close(self) -> None: ...


class SolanaRpcFactory(Protocol):
    """Creates Solana RPC clients for a token assessment."""

    def get_client(
        self,
        rpc_urls: Sequence[str] | None = None,
    ) -> SolanaChainAdapter: ...

    async def close(self) -> None: ...


@dataclass(frozen=True, slots=True)
class SolanaDetectorDependencies:
    """Services available to Solana detectors."""

    chain: SolanaChainAdapter


class BaseSolanaDetector(ABC):
    """Base class for Solana-native detectors."""

    detector_id: ClassVar[str]
    category: ClassVar[DetectorCategory]
    coverage_area: ClassVar[CoverageArea | None]
    description: ClassVar[str]
    required: ClassVar[bool] = True

    def __init__(self, settings: RugLensSettings) -> None:
        self.settings = settings

    @abstractmethod
    async def detect(
        self,
        context: SolanaTokenContext,
        dependencies: SolanaDetectorDependencies,
    ) -> DetectorOutcome:
        """Inspect one Solana token and return evidence plus an execution status."""

    def make_outcome(
        self,
        *,
        findings: Sequence[Finding] = (),
        status: DetectorStatus = DetectorStatus.SUCCESS,
        coverage_fraction: float | None = None,
        limitations: Sequence[str] = (),
        details: dict[str, Any] | None = None,
        duration_ms: float = 0.0,
        error: str | None = None,
    ) -> DetectorOutcome:
        """Construct a Solana detector outcome."""
        if coverage_fraction is None:
            coverage_fraction = 1.0 if status is DetectorStatus.SUCCESS else 0.0
        return DetectorOutcome(
            detector_id=self.detector_id,
            category=self.category,
            coverage_area=self.coverage_area,
            status=status,
            findings=tuple(findings),
            coverage_fraction=coverage_fraction,
            limitations=tuple(limitations),
            details=details or {},
            duration_ms=duration_ms,
            error=error,
        )


class ReportRepository(Protocol):
    """Persistence contract for immutable assessment reports."""

    async def save(self, report: AssessmentReport) -> None: ...

    async def get(self, assessment_id: str) -> AssessmentReport | None: ...

    async def find_latest(
        self,
        chain_id: int,
        token_address: str,
        block_number: int | None = None,
    ) -> AssessmentReport | None: ...

    async def close(self) -> None: ...
