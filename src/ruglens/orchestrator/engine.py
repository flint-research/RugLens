"""End-to-end assessment orchestrator.

The engine validates input, pins a block, hydrates a shared token context,
executes detectors concurrently with per-detector deadlines, and delegates risk
synthesis exclusively to the risk layer.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import time
from collections.abc import Mapping, Sequence
from typing import Any
from uuid import UUID

from eth_utils.address import is_address, to_checksum_address

from ruglens.chains.evm.abi import (
    BURN_ADDRESSES,
    Selectors,
    decode_address,
    decode_reserves,
    decode_string_or_bytes32,
    decode_uint,
    encode_call,
)
from ruglens.chains.evm.factory import EvmChainFactory
from ruglens.chains.evm.registry import ChainConfig, normalize_chain
from ruglens.chains.registry import is_solana_chain
from ruglens.chains.solana.factory import SolanaRpcFactory
from ruglens.core.config import RugLensSettings
from ruglens.core.enums import DetectorStatus
from ruglens.core.exceptions import (
    InvalidAddressError,
    InvalidTokenError,
    RepositoryError,
    RpcError,
    RugLensError,
    UnsupportedChainError,
    ValidationError,
)
from ruglens.core.interfaces import (
    BaseDetector,
    ChainAdapter,
    ChainAdapterFactory,
    DetectorDependencies,
    ReportRepository,
    TradeSimulatorFactory,
)
from ruglens.core.models import (
    AssessmentReport,
    DetectorOutcome,
    RpcCall,
    TokenContext,
    TokenMetadata,
)
from ruglens.core.sanitization import sanitize_reason, sanitize_text
from ruglens.detectors.registry import DetectorDescriptor, DetectorRegistry, build_registry
from ruglens.detectors.solana import build_solana_detectors
from ruglens.orchestrator.solana_engine import SolanaAssessmentService
from ruglens.risk.evaluator import RiskEvaluation, RiskEvaluator
from ruglens.simulation.provider import TradeSimulatorProvider
from ruglens.storage.database import Database
from ruglens.storage.repositories import SQLAlchemyReportRepository

logger = logging.getLogger(__name__)

_MAX_SOURCE_FILES = 50
_MAX_SOURCE_BYTES = 2_000_000


class AssessmentEngine:
    """Stateless token assessment coordinator."""

    def __init__(
        self,
        settings: RugLensSettings,
        chain_factory: ChainAdapterFactory,
        registry: DetectorRegistry,
        *,
        repository: ReportRepository | None = None,
        simulator_factory: TradeSimulatorFactory | None = None,
        evaluator: RiskEvaluator | None = None,
        solana_service: SolanaAssessmentService | None = None,
    ) -> None:
        self.settings = settings
        self._chain_factory = chain_factory
        self._registry = registry
        self._repository = repository
        self._simulator_factory = simulator_factory
        self._evaluator = evaluator or RiskEvaluator()
        self._solana_service = solana_service
        self._closed = False

    @classmethod
    async def build(
        cls,
        settings: RugLensSettings | None = None,
        *,
        rpc_overrides: Mapping[int, Sequence[str]] | None = None,
        enable_repository: bool = True,
    ) -> AssessmentEngine:
        """Construct the production engine with local cache and persistence."""
        resolved = settings or RugLensSettings.from_env()
        resolved.ensure_directories()
        chain_factory = EvmChainFactory(resolved, rpc_overrides=rpc_overrides)
        registry = build_registry(resolved)
        simulator_factory = TradeSimulatorProvider(resolved)
        solana_service: SolanaAssessmentService | None = None
        if resolved.solana_enabled:
            solana_service = SolanaAssessmentService(
                resolved,
                SolanaRpcFactory(resolved),
                build_solana_detectors(resolved),
            )
        repository: SQLAlchemyReportRepository | None = None
        if enable_repository and resolved.persist_reports:
            repository = SQLAlchemyReportRepository(Database(resolved.resolved_database_url()))
            await repository.initialize()
        return cls(
            resolved,
            chain_factory,
            registry,
            repository=repository,
            simulator_factory=simulator_factory,
            solana_service=solana_service,
        )

    @property
    def registry(self) -> DetectorRegistry:
        """Registered detectors."""
        return self._registry

    def detector_descriptors(self) -> list[DetectorDescriptor]:
        """Metadata for every EVM and Solana detector."""
        descriptors = self._registry.descriptors()
        if self._solana_service is not None:
            descriptors.extend(self._solana_service.detector_descriptors())
        return descriptors

    @property
    def detector_count(self) -> int:
        """Number of registered EVM and Solana detectors."""
        solana_count = (
            len(self._solana_service.detectors) if self._solana_service is not None else 0
        )
        return len(self._registry.detectors) + solana_count

    async def assess_token(
        self,
        chain_id: int,
        address: str,
        block_number: int | None = None,
        *,
        rpc_urls: Sequence[str] | None = None,
        source_files: Mapping[str, str] | None = None,
        use_cached_report: bool = True,
    ) -> AssessmentReport:
        """Assess one token and return an immutable report."""
        if self._closed:
            raise RugLensError("Assessment engine is closed")
        started = time.perf_counter()
        if block_number is not None and block_number < 0:
            raise ValidationError("block_number must be non-negative")
        if is_solana_chain(chain_id):
            if self._solana_service is None:
                raise UnsupportedChainError("Solana support is disabled")
            if source_files:
                raise ValidationError("Slither source analysis is EVM-only")
            report = await self._solana_service.assess(
                address,
                rpc_urls=rpc_urls,
                block_number=block_number,
            )
            if self._repository is not None and self.settings.persist_reports:
                try:
                    await self._repository.save(report)
                except RepositoryError as exc:
                    logger.error("Assessment persistence failed: %s", exc)
            return report
        if not isinstance(address, str) or not is_address(address):
            raise InvalidAddressError(f"Invalid EVM token address: {address!r}")
        token_address = to_checksum_address(address)
        chain: ChainConfig = normalize_chain(chain_id)
        sources = self._validate_sources(source_files)

        adapter = await self._chain_factory.get_adapter(int(chain.chain_id), rpc_urls)
        pinned_block = (
            block_number if block_number is not None else await adapter.get_block_number()
        )

        if (
            block_number is not None
            and use_cached_report
            and self._repository is not None
            and self.settings.load_cached_reports
        ):
            try:
                cached = await self._repository.find_latest(
                    int(chain.chain_id), token_address, block_number
                )
            except RepositoryError as exc:
                logger.warning("Cached report lookup failed: %s", exc)
            else:
                if cached is not None:
                    return cached

        context = await self._hydrate_context(
            adapter,
            chain,
            token_address,
            pinned_block,
            sources,
        )
        simulator = None
        if self._simulator_factory is not None and self.settings.simulation_enabled:
            try:
                simulator = self._simulator_factory.get_simulator(int(chain.chain_id), rpc_urls)
            except Exception as exc:
                logger.warning("Could not construct trade simulator: %s", exc)
                context.notes.append(f"Trade simulator unavailable: {sanitize_reason(str(exc))}")

        dependencies = DetectorDependencies(chain=adapter, simulator=simulator)
        outcomes = await asyncio.gather(
            *(
                self._run_detector(detector, context, dependencies)
                for detector in self._registry.detectors
            )
        )
        evaluation = self._evaluator.evaluate(
            outcomes,
            extra_limitations=[
                *context.notes,
                *self._registry.plugin_errors,
            ],
        )
        report = self._build_report(
            chain,
            context,
            evaluation,
            outcomes,
            duration_ms=(time.perf_counter() - started) * 1000,
            rpc_calls=adapter.rpc_calls,
        )
        if self._repository is not None and self.settings.persist_reports:
            try:
                await self._repository.save(report)
            except RepositoryError as exc:
                logger.error("Assessment persistence failed: %s", exc)
        return report

    # Alias matching the Flint Cloud integration contract.
    async def assess(
        self, chain_id: int, address: str, block_number: int | None = None
    ) -> AssessmentReport:
        """Alias for :meth:`assess_token`."""
        return await self.assess_token(chain_id, address, block_number)

    async def _run_detector(
        self,
        detector: BaseDetector,
        context: TokenContext,
        dependencies: DetectorDependencies,
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
                error=(f"Detector exceeded {self.settings.anomaly_detector_timeout:.0f}s deadline"),
                duration_ms=(time.perf_counter() - started) * 1000,
            )
        except Exception as exc:
            logger.exception("Detector %s failed", detector.detector_id)
            return detector.make_outcome(
                status=DetectorStatus.FAILED,
                error=sanitize_reason(str(exc)) or exc.__class__.__name__,
                duration_ms=(time.perf_counter() - started) * 1000,
            )
        updates: dict[str, Any] = {}
        if outcome.detector_id != detector.detector_id:
            updates["detector_id"] = detector.detector_id
        if not detector.required and outcome.coverage_area is not None:
            updates["coverage_area"] = None
        if updates:
            outcome = outcome.model_copy(update=updates)
        return outcome

    async def _hydrate_context(
        self,
        adapter: ChainAdapter,
        chain: ChainConfig,
        token_address: str,
        block_number: int,
        source_files: Mapping[str, str],
    ) -> TokenContext:
        notes: list[str] = []
        bytecode = await adapter.get_code(token_address, block_number)
        if not bytecode:
            raise InvalidTokenError(
                f"No contract bytecode at {token_address} on {chain.name} block {block_number}"
            )
        metadata = await self._hydrate_metadata(adapter, token_address, block_number, notes)
        pair_data = await self._hydrate_pair(adapter, chain, token_address, block_number, notes)
        return TokenContext(
            chain_id=int(chain.chain_id),
            token_address=token_address,
            block_number=block_number,
            bytecode=bytecode,
            bytecode_hash=hashlib.sha256(bytecode).hexdigest(),
            metadata=metadata,
            router=chain.v2_router,
            weth=chain.weth,
            source_files=dict(source_files),
            notes=notes,
            **pair_data,
        )

    async def _hydrate_metadata(
        self,
        adapter: ChainAdapter,
        token_address: str,
        block_number: int,
        notes: list[str],
    ) -> TokenMetadata | None:
        calls = [
            RpcCall(to=token_address, data=Selectors.NAME),
            RpcCall(to=token_address, data=Selectors.SYMBOL),
            RpcCall(to=token_address, data=Selectors.DECIMALS),
            RpcCall(to=token_address, data=Selectors.TOTAL_SUPPLY),
        ]
        try:
            results = await adapter.multicall(calls, block_number)
        except RpcError as exc:
            notes.append(f"Token metadata could not be read: {exc}")
            return None
        if len(results) < 4:
            notes.append("Token metadata multicall returned incomplete results.")
            return None
        name: str | None = None
        symbol: str | None = None
        decimals: int | None = None
        total_supply: int | None = None
        labels = ("name", "symbol", "decimals", "totalSupply")
        for label, result in zip(labels, results[:4], strict=False):
            if not result.success:
                notes.append(f"ERC-20 {label}() call failed.")
                continue
            try:
                if label == "name":
                    name = decode_string_or_bytes32(result.return_data)
                elif label == "symbol":
                    symbol = decode_string_or_bytes32(result.return_data)
                elif label == "decimals":
                    value = decode_uint(result.return_data)
                    decimals = value if 0 <= value <= 255 else None
                else:
                    total_supply = decode_uint(result.return_data)
            except ValueError:
                notes.append(f"Malformed ERC-20 {label} return data.")
        if name is None and symbol is None and decimals is None and total_supply is None:
            return None
        return TokenMetadata(
            name=name or "Unknown Token",
            symbol=symbol or "UNKNOWN",
            decimals=decimals,
            total_supply=total_supply,
        )

    async def _hydrate_pair(
        self,
        adapter: ChainAdapter,
        chain: ChainConfig,
        token_address: str,
        block_number: int,
        notes: list[str],
    ) -> dict[str, Any]:
        get_pair = encode_call(
            "getPair(address,address)",
            ["address", "address"],
            [token_address, chain.weth],
        )
        try:
            raw_pair = await adapter.eth_call(chain.v2_factory, get_pair, block_number)
        except RpcError as exc:
            notes.append(f"V2 pair discovery failed: {exc}")
            return {}
        pair_address: str | None
        try:
            if not raw_pair or int.from_bytes(raw_pair, "big") == 0:
                pair_address = None
            else:
                pair_address = decode_address(raw_pair)
        except ValueError:
            notes.append("V2 factory returned a malformed pair address.")
            return {}
        if pair_address is None:
            return {"pair_address": None}

        lockers: list[str] = list(chain.known_lp_lockers)
        for address in self.settings.extra_lp_lockers:
            if is_address(address):
                lockers.append(to_checksum_address(address))
        balance_targets = list(dict.fromkeys([*BURN_ADDRESSES, *lockers]))
        calls = [
            RpcCall(to=pair_address, data=Selectors.TOKEN0),
            RpcCall(to=pair_address, data=Selectors.TOKEN1),
            RpcCall(to=pair_address, data=Selectors.GET_RESERVES),
            RpcCall(to=pair_address, data=Selectors.TOTAL_SUPPLY),
            *(
                RpcCall(
                    to=pair_address,
                    data=encode_call("balanceOf(address)", ["address"], [target]),
                )
                for target in balance_targets
            ),
        ]
        try:
            results = await adapter.multicall(calls, block_number)
        except RpcError as exc:
            notes.append(f"V2 pair state could not be read: {exc}")
            return {"pair_address": pair_address}
        token0 = token1 = None
        reserves: tuple[int, int] | None = None
        lp_total: int | None = None
        lp_balances: dict[str, int] = {}
        if len(results) >= 3:
            if results[0].success:
                try:
                    token0 = decode_address(results[0].return_data)
                except ValueError:
                    notes.append("Pair token0 could not be decoded.")
            if results[1].success:
                try:
                    token1 = decode_address(results[1].return_data)
                except ValueError:
                    notes.append("Pair token1 could not be decoded.")
            if results[2].success:
                try:
                    reserve0, reserve1, _ = decode_reserves(results[2].return_data)
                    reserves = (reserve0, reserve1)
                except ValueError:
                    notes.append("Pair reserves could not be decoded.")
        if len(results) >= 4 and results[3].success:
            try:
                lp_total = decode_uint(results[3].return_data)
            except ValueError:
                notes.append("Pair LP total supply could not be decoded.")
        for target, result in zip(balance_targets, results[4:], strict=False):
            if result.success:
                with contextlib.suppress(ValueError):
                    lp_balances[target] = decode_uint(result.return_data)
        return {
            "pair_address": pair_address,
            "pair_token0": token0,
            "pair_token1": token1,
            "pair_reserves": reserves,
            "lp_total_supply": lp_total,
            "lp_balances": lp_balances,
        }

    @staticmethod
    def _validate_sources(source_files: Mapping[str, str] | None) -> dict[str, str]:
        if not source_files:
            return {}
        if len(source_files) > _MAX_SOURCE_FILES:
            raise ValidationError(f"At most {_MAX_SOURCE_FILES} source files are allowed")
        total = 0
        sanitized: dict[str, str] = {}
        for name, content in source_files.items():
            if not isinstance(name, str) or not isinstance(content, str):
                raise ValidationError("Source files must map string paths to string contents")
            total += len(content.encode("utf-8", errors="ignore"))
            if total > _MAX_SOURCE_BYTES:
                raise ValidationError(f"Source files exceed {_MAX_SOURCE_BYTES} bytes")
            sanitized[sanitize_text(name, max_length=160)] = content
        return sanitized

    def _build_report(
        self,
        chain: ChainConfig,
        context: TokenContext,
        evaluation: RiskEvaluation,
        outcomes: Sequence[DetectorOutcome],
        *,
        duration_ms: float,
        rpc_calls: int,
    ) -> AssessmentReport:
        summary = (
            f"{evaluation.risk_level.value} risk; {len(evaluation.findings)} finding(s); "
            f"data coverage {evaluation.data_coverage:.0%} across {len(outcomes)} detectors."
        )
        return AssessmentReport(
            chain_id=int(chain.chain_id),
            token_address=context.token_address,
            block_number=context.block_number,
            risk_level=evaluation.risk_level,
            confidence_score=evaluation.confidence_score,
            data_coverage=evaluation.data_coverage,
            findings=evaluation.findings,
            detector_statuses=dict(evaluation.detector_statuses),
            limitations=evaluation.limitations,
            token=context.metadata,
            summary=summary,
            duration_ms=duration_ms,
            rpc_calls=rpc_calls,
        )

    async def get_report(self, assessment_id: str) -> AssessmentReport | None:
        """Retrieve a stored report, when persistence is configured."""
        if self._repository is None:
            return None
        if not isinstance(assessment_id, str):
            raise ValidationError("assessment_id must be a string")
        try:
            UUID(assessment_id)
        except ValueError as exc:
            raise ValidationError("assessment_id must be a UUID") from exc
        return await self._repository.get(assessment_id)

    async def close(self) -> None:
        """Release RPC sessions and database connections."""
        if self._closed:
            return
        self._closed = True
        if self._solana_service is not None:
            await self._solana_service.close()
        await self._chain_factory.close()
        if self._repository is not None:
            await self._repository.close()

    async def __aenter__(self) -> AssessmentEngine:
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        await self.close()
