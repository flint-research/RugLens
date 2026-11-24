"""Test doubles and builders used across the suite."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from typing import Any

from eth_abi.abi import encode
from eth_utils.address import to_checksum_address

from ruglens.core.enums import (
    CoverageArea,
    DetectorCategory,
    DetectorStatus,
    Severity,
)
from ruglens.core.exceptions import RpcError
from ruglens.core.models import (
    DetectorOutcome,
    Finding,
    HolderBalance,
    RpcCall,
    RpcCallResult,
    TokenContext,
    TokenMetadata,
    TradeSimulationResult,
)

TOKEN = "0x1111111111111111111111111111111111111111"
PAIR = "0x2222222222222222222222222222222222222222"
OWNER = "0x3333333333333333333333333333333333333333"
WETH = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
ROUTER = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
FACTORY = "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f"


def make_finding(
    *,
    rule_id: str = "TEST-RULE-001",
    severity: Severity = Severity.MEDIUM,
    confidence: float = 0.8,
    detector_id: str = "test_detector",
    category: DetectorCategory = DetectorCategory.STATIC,
    target: str = TOKEN,
    block_number: int = 100,
    title: str = "Test finding",
    evidence: dict[str, Any] | None = None,
) -> Finding:
    """Build a deterministic finding."""
    return Finding.create(
        rule_id=rule_id,
        detector_id=detector_id,
        category=category,
        severity=severity,
        confidence=confidence,
        title=title,
        description="Test evidence description.",
        evidence=evidence or {"detail": "test"},
        target=target,
        block_number=block_number,
    )


def make_outcome(
    *,
    area: CoverageArea | None = CoverageArea.BYTECODE,
    detector_id: str | None = None,
    category: DetectorCategory = DetectorCategory.STATIC,
    status: DetectorStatus = DetectorStatus.SUCCESS,
    coverage_fraction: float | None = None,
    findings: Sequence[Finding] = (),
    limitations: Sequence[str] = (),
) -> DetectorOutcome:
    """Build a detector outcome with a unique default detector id."""
    identifier = detector_id or (f"det_{area.value.lower()}" if area else "optional_detector")
    if coverage_fraction is None:
        coverage_fraction = 1.0 if status is DetectorStatus.SUCCESS else 0.0
    return DetectorOutcome(
        detector_id=identifier,
        category=category,
        coverage_area=area,
        status=status,
        findings=tuple(findings),
        coverage_fraction=coverage_fraction,
        limitations=tuple(limitations),
    )


def make_context(
    *,
    chain_id: int = 1,
    token_address: str = TOKEN,
    block_number: int = 100,
    bytecode: bytes = b"\x60\x80\x60\x40\x52\x00",
    pair: str | None = PAIR,
    owner: str | None = None,
    decimals: int | None = 18,
    total_supply: int | None = 1_000_000 * 10**18,
    holders: Sequence[HolderBalance] = (),
) -> TokenContext:
    """Build a hydrated token context for detector tests."""
    return TokenContext(
        chain_id=chain_id,
        token_address=to_checksum_address(token_address),
        block_number=block_number,
        bytecode=bytecode,
        metadata=TokenMetadata(
            name="Test Token",
            symbol="TEST",
            decimals=decimals,
            total_supply=total_supply,
        ),
        owner=owner,
        router=ROUTER,
        weth=WETH,
        pair_address=to_checksum_address(pair) if pair else None,
        pair_token0=WETH,
        pair_token1=to_checksum_address(token_address),
        pair_reserves=(100 * 10**18, 1_000_000 * 10**18),
        lp_total_supply=1_000 * 10**18,
        holders=list(holders),
    )


def clean_simulation(**overrides: Any) -> TradeSimulationResult:
    """Return a successful low-tax simulation result."""
    values: dict[str, Any] = {
        "executed": True,
        "buy_success": True,
        "sell_success": True,
        "approve_success": True,
        "router": ROUTER,
        "pair": PAIR,
        "wallet": OWNER,
        "block_number": 100,
        "buy_tax": 0.0,
        "sell_tax": 0.0,
        "expected_buy_amount": 1_000 * 10**18,
        "buy_amount_received": 1_000 * 10**18,
        "expected_sell_amount": 10**17,
        "sell_amount_received": 10**17,
        "buy_gas_used": 120_000,
        "sell_gas_used": 130_000,
    }
    values.update(overrides)
    return TradeSimulationResult(**values)


class FakeChainAdapter:
    """Scriptable in-memory chain adapter implementing the ChainAdapter protocol."""

    def __init__(self, *, chain_id: int = 1, block_number: int = 100) -> None:
        self._chain_id = chain_id
        self._block_number = block_number
        self.code: dict[str, bytes] = {}
        self.storage: dict[tuple[str, str], str] = {}
        self.handlers: dict[tuple[str, bytes], bytes] = {}
        self.selector_handlers: dict[tuple[str, bytes], bytes] = {}
        self.balances: dict[str, int] = {}
        self.logs: list[dict[str, Any]] = []
        self._calls = 0
        self.closed = False

    @property
    def chain_id(self) -> int:
        return self._chain_id

    @property
    def rpc_calls(self) -> int:
        return self._calls

    def set_code(self, address: str, code: bytes) -> None:
        self.code[address.lower()] = code

    def set_storage(self, address: str, slot: str, value: str) -> None:
        self.storage[(address.lower(), slot.lower())] = value

    def set_call(self, to: str, data: bytes, result: bytes) -> None:
        self.handlers[(to.lower(), data)] = result

    def set_selector(self, to: str, selector: bytes, result: bytes) -> None:
        self.selector_handlers[(to.lower(), selector)] = result

    def set_uint(self, to: str, selector: bytes, value: int) -> None:
        self.set_selector(to, selector, encode(["uint256"], [value]))

    def set_address(self, to: str, selector: bytes, value: str) -> None:
        self.set_selector(to, selector, encode(["address"], [to_checksum_address(value)]))

    def set_string(self, to: str, selector: bytes, value: str) -> None:
        self.set_selector(to, selector, encode(["string"], [value]))

    def add_log(self, log: dict[str, Any]) -> None:
        self.logs.append(log)

    async def get_block_number(self) -> int:
        return self._block_number

    async def get_code(self, address: str, block_number: int) -> bytes:
        self._calls += 1
        return self.code.get(address.lower(), b"")

    async def get_balance(self, address: str, block_number: int) -> int:
        self._calls += 1
        return self.balances.get(address.lower(), 0)

    async def get_storage_at(self, address: str, slot: str, block_number: int) -> str:
        self._calls += 1
        return self.storage.get(
            (address.lower(), slot.lower()),
            "0x" + "00" * 32,
        )

    async def eth_call(self, to: str, data: bytes, block_number: int) -> bytes:
        self._calls += 1
        exact = self.handlers.get((to.lower(), data))
        if exact is not None:
            return exact
        selector = self.selector_handlers.get((to.lower(), data[:4]))
        if selector is not None:
            return selector
        raise RpcError(f"execution reverted: no fake response for {to} {data[:4].hex()}")

    async def multicall(
        self,
        calls: Sequence[RpcCall],
        block_number: int,
        *,
        allow_failure: bool = True,
    ) -> list[RpcCallResult]:
        results: list[RpcCallResult] = []
        for call in calls:
            try:
                data = await self.eth_call(call.to, call.data, block_number)
            except RpcError:
                if not allow_failure:
                    raise
                results.append(RpcCallResult(success=False))
            else:
                results.append(RpcCallResult(success=True, return_data=data))
        return results

    async def get_logs(
        self,
        address: str,
        topics: Sequence[str | None],
        from_block: int,
        to_block: int,
    ) -> list[dict[str, Any]]:
        self._calls += 1
        selected: list[dict[str, Any]] = []
        for log in self.logs:
            if str(log.get("address", "")).lower() != address.lower():
                continue
            number = log.get("blockNumber", 0)
            if isinstance(number, str):
                number = int(number, 16)
            if from_block <= number <= to_block:
                selected.append(log)
        return selected

    async def close(self) -> None:
        self.closed = True


class FakeChainFactory:
    """Returns one prebuilt adapter."""

    def __init__(self, adapter: FakeChainAdapter) -> None:
        self.adapter = adapter
        self.closed = False

    async def get_adapter(
        self,
        chain_id: int,
        rpc_urls: Sequence[str] | None = None,
    ) -> FakeChainAdapter:
        return self.adapter

    async def close(self) -> None:
        self.closed = True


class FakeSimulator:
    """Returns a fixed simulation, or raises a configured exception."""

    def __init__(
        self,
        result: TradeSimulationResult | None = None,
        *,
        error: Exception | None = None,
        delay: float = 0.0,
    ) -> None:
        self.result = result or clean_simulation()
        self.error = error
        self.delay = delay
        self.calls = 0
        self.last_context: TokenContext | None = None

    async def simulate(self, context: TokenContext) -> TradeSimulationResult:
        self.calls += 1
        self.last_context = context
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.error is not None:
            raise self.error if not isinstance(self.error, type) else self.error()
        return self.result


class FakeSimulatorFactory:
    """Returns one fixed simulator."""

    def __init__(self, simulator: FakeSimulator | None) -> None:
        self.simulator = simulator

    def get_simulator(
        self,
        chain_id: int,
        rpc_urls: Sequence[str] | None = None,
    ) -> FakeSimulator | None:
        return self.simulator


def mint_log(
    token: str,
    to: str,
    value: int,
    *,
    block_number: int = 100,
    log_index: int = 0,
) -> dict[str, Any]:
    """Build a standard ERC-20 Transfer event from the zero address."""
    from ruglens.chains.evm.abi import TRANSFER_EVENT_TOPIC

    return {
        "address": to_checksum_address(token),
        "blockNumber": block_number,
        "logIndex": log_index,
        "transactionIndex": 0,
        "topics": [
            TRANSFER_EVENT_TOPIC,
            "0x" + "00" * 32,
            "0x" + to[2:].rjust(64, "0"),
        ],
        "data": "0x" + value.to_bytes(32, "big").hex(),
    }


__all__ = [
    "FACTORY",
    "OWNER",
    "PAIR",
    "ROUTER",
    "TOKEN",
    "WETH",
    "FakeChainAdapter",
    "FakeChainFactory",
    "FakeSimulator",
    "FakeSimulatorFactory",
    "clean_simulation",
    "make_context",
    "make_finding",
    "make_outcome",
    "mint_log",
]
