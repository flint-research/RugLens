"""Measured DEX V2 trade simulation on an isolated Anvil fork.

The simulator impersonates a clean wallet, buys the target token with native
currency, approves the router, and sells the entire received balance. Buy and
sell taxes are measured against router quotes; sell reverts are evidence of an
active honeypot. Nothing is ever broadcast to the live network.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
from typing import Any, cast
from urllib.parse import urlparse

from eth_utils.address import is_address, to_checksum_address
from web3 import AsyncWeb3
from web3.providers.rpc import AsyncHTTPProvider

from ruglens.chains.evm.abi import (
    Selectors,
    decode_reserves,
    decode_uint,
    decode_uint_array,
    encode_call,
    hex_data_to_bytes,
)
from ruglens.chains.evm.registry import ChainConfig
from ruglens.core.config import RugLensSettings
from ruglens.core.exceptions import (
    ConfigurationError,
    SimulationError,
    SimulationSetupError,
    SimulationTimeoutError,
)
from ruglens.core.models import TokenContext, TradeSimulationResult
from ruglens.core.sanitization import sanitize_reason
from ruglens.simulation.anvil import AnvilInstance, AnvilManager

logger = logging.getLogger(__name__)

MAX_UINT256 = 2**256 - 1
_RECEIPT_POLL_ATTEMPTS = 200
_RECEIPT_POLL_INTERVAL = 0.05


def _hex_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 16)
    raise SimulationError(f"Expected a hex quantity, got {type(value).__name__}")


def _clean_reason(message: str) -> str:
    text = message.strip()
    lowered = text.lower()
    for prefix in ("execution reverted:", "execution reverted", "revert:"):
        if lowered.startswith(prefix):
            text = text[len(prefix) :].strip()
            break
    return sanitize_reason(text) or "execution reverted"


class _AnvilRpc:
    """Minimal JSON-RPC client bound to one ephemeral Anvil instance."""

    def __init__(self, url: str, timeout: float) -> None:
        self._web3: AsyncWeb3[Any] = AsyncWeb3(
            AsyncHTTPProvider(url, request_kwargs={"timeout": timeout})
        )
        self._timeout = timeout
        self._closed = False

    async def call(self, method: str, params: list[Any]) -> Any:
        if self._closed:
            raise SimulationError("Anvil RPC client is closed")
        try:
            provider = cast(Any, self._web3.provider)
            response = await asyncio.wait_for(
                provider.make_request(method, params),
                timeout=self._timeout,
            )
        except TimeoutError as exc:
            raise SimulationTimeoutError(f"Anvil RPC {method} timed out") from exc
        except Exception as exc:
            raise SimulationError(f"Anvil RPC {method} failed: {exc}") from exc
        if not isinstance(response, dict):
            raise SimulationError(f"Anvil RPC {method} returned a malformed response")
        if "error" in response:
            error = response["error"]
            message = error.get("message", str(error)) if isinstance(error, dict) else str(error)
            raise SimulationError(_clean_reason(str(message)))
        return response.get("result")

    async def eth_call(
        self,
        to: str,
        data: bytes,
        *,
        sender: str | None = None,
        value: int = 0,
        gas: int | None = None,
    ) -> bytes:
        tx: dict[str, Any] = {"to": to, "data": "0x" + data.hex()}
        if sender is not None:
            tx["from"] = sender
        if value:
            tx["value"] = hex(value)
        if gas is not None:
            tx["gas"] = hex(gas)
        result = await self.call("eth_call", [tx, "latest"])
        if not isinstance(result, str):
            raise SimulationError("eth_call returned a non-string result")
        return hex_data_to_bytes(result)

    async def close(self) -> None:
        self._closed = True
        with contextlib.suppress(Exception):
            await self._web3.provider.disconnect()


class TradeSimulator:
    """Executes a reproducible buy -> approve -> sell sequence."""

    def __init__(
        self,
        manager: AnvilManager,
        chain: ChainConfig,
        settings: RugLensSettings,
        *,
        fork_rpc_url: str,
    ) -> None:
        parsed = urlparse(fork_rpc_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ConfigurationError(f"Invalid fork RPC URL: {fork_rpc_url!r}")
        self._manager = manager
        self._chain = chain
        self._settings = settings
        self._fork_rpc_url = fork_rpc_url

    async def simulate(self, context: TokenContext) -> TradeSimulationResult:
        """Run a full trade simulation pinned to the context block."""
        self._validate_context(context)
        try:
            async with asyncio.timeout(self._settings.simulation_timeout):
                return await self._simulate_on_fork(context)
        except TimeoutError as exc:
            raise SimulationTimeoutError(
                f"Trade simulation exceeded {self._settings.simulation_timeout}s"
            ) from exc

    def _validate_context(self, context: TokenContext) -> None:
        if not context.has_bytecode:
            raise SimulationSetupError("Target has no runtime bytecode")
        for name, address in (
            ("router", context.router),
            ("pair", context.pair_address),
            ("weth", context.weth),
        ):
            if not address or not is_address(address):
                raise SimulationSetupError(f"Token context is missing a valid {name}")
        decimals = context.decimals
        if decimals is None:
            raise SimulationSetupError("Token decimals are unavailable; cannot simulate trades")
        if context.pair_reserves is None:
            raise SimulationSetupError("DEX pair reserves are unavailable")

    async def _simulate_on_fork(self, context: TokenContext) -> TradeSimulationResult:
        assert context.router is not None
        assert context.pair_address is not None
        assert context.weth is not None
        router = to_checksum_address(context.router)
        pair = to_checksum_address(context.pair_address)
        weth = to_checksum_address(context.weth)
        token = to_checksum_address(context.token_address)

        async with self._manager.fork(
            self._fork_rpc_url,
            context.block_number,
            context.chain_id,
        ) as instance:
            rpc = _AnvilRpc(instance.url, self._settings.rpc_timeout)
            try:
                return await self._run_sequence(
                    rpc,
                    instance,
                    context,
                    router=router,
                    pair=pair,
                    weth=weth,
                    token=token,
                )
            finally:
                await rpc.close()

    async def _select_wallet(
        self,
        rpc: _AnvilRpc,
        context: TokenContext,
        token: str,
    ) -> str:
        configured = self._settings.trade_wallet.strip()
        candidates: list[str] = []
        if configured:
            if not is_address(configured):
                raise SimulationSetupError("Configured trade wallet is not a valid address")
            candidates.append(to_checksum_address(configured))
        base = f"ruglens-clean-wallet:{context.chain_id}:{token.lower()}:{context.block_number}"
        for nonce in range(6):
            digest = hashlib.sha256(f"{base}:{nonce}".encode()).hexdigest()
            candidates.append(to_checksum_address("0x" + digest[-40:]))

        for candidate in candidates:
            await rpc.call("anvil_setCode", [candidate, "0x"])
            await rpc.call("anvil_setBalance", [candidate, hex(10 * 10**18)])
            await rpc.call("anvil_impersonateAccount", [candidate])
            balance_data = Selectors.BALANCE_OF + bytes.fromhex(candidate[2:].rjust(64, "0"))
            try:
                raw = await rpc.eth_call(token, balance_data)
                if not raw or decode_uint(raw) == 0:
                    return candidate
            except SimulationError:
                return candidate
        return candidates[-1]

    async def _run_sequence(
        self,
        rpc: _AnvilRpc,
        instance: AnvilInstance,
        context: TokenContext,
        *,
        router: str,
        pair: str,
        weth: str,
        token: str,
    ) -> TradeSimulationResult:
        assert context.pair_reserves is not None
        wallet = await self._select_wallet(rpc, context, token)
        notes: list[str] = [f"Forked at block {context.block_number} via {instance.url}"]
        block = await rpc.call("eth_getBlockByNumber", ["latest", False])
        if not isinstance(block, dict):
            raise SimulationError("Could not read Anvil block header")
        deadline = _hex_int(block.get("timestamp", "0x0")) + 1_800
        gas_price = _hex_int(await rpc.call("eth_gasPrice", []))
        amount_in = self._settings.trade_native_amount_wei
        gas_limit = self._settings.trade_gas_limit

        token0 = context.pair_token0
        token1 = context.pair_token1
        if not token0 or not token1:
            token0_raw = await rpc.eth_call(pair, Selectors.TOKEN0)
            token1_raw = await rpc.eth_call(pair, Selectors.TOKEN1)
            token0 = to_checksum_address("0x" + token0_raw[-20:].hex())
            token1 = to_checksum_address("0x" + token1_raw[-20:].hex())

        expected_buy = await self._quote(
            rpc,
            router,
            amount_in,
            [weth, token],
            notes,
        )
        if expected_buy is None:
            expected_buy = await self._reserve_quote(
                rpc,
                pair,
                token0,
                token1,
                weth,
                amount_in,
                buy=True,
            )
            notes.append("Buy quote derived from pair reserves")

        buy_data = encode_call(
            "swapExactETHForTokensSupportingFeeOnTransferTokens(uint256,address[],address,uint256)",
            ["uint256", "address[]", "address", "uint256"],
            [0, [weth, token], wallet, deadline],
        )
        buy_tx = {
            "from": wallet,
            "to": router,
            "data": "0x" + buy_data.hex(),
            "value": hex(amount_in),
            "gas": hex(gas_limit),
            "gasPrice": hex(gas_price),
        }
        buy_revert = await self._preflight(rpc, buy_tx)
        if buy_revert is not None:
            return self._result(
                context,
                wallet,
                router,
                pair,
                buy_success=False,
                sell_success=False,
                buy_revert_reason=buy_revert,
                expected_buy_amount=expected_buy,
                notes=notes,
            )

        buy_receipt = await self._send_and_wait(rpc, buy_tx)
        buy_gas = _hex_int(buy_receipt.get("gasUsed", "0x0"))
        if _hex_int(buy_receipt.get("status", "0x0")) != 1:
            return self._result(
                context,
                wallet,
                router,
                pair,
                buy_success=False,
                sell_success=False,
                buy_revert_reason="buy transaction reverted (status 0)",
                expected_buy_amount=expected_buy,
                buy_gas_used=buy_gas,
                notes=notes,
            )

        balance_data = Selectors.BALANCE_OF + bytes.fromhex(wallet[2:].rjust(64, "0"))
        token_balance = decode_uint(await rpc.eth_call(token, balance_data))
        buy_tax = self._tax(expected_buy, token_balance)
        if token_balance == 0:
            notes.append("Buy succeeded but the wallet received zero tokens")
            return self._result(
                context,
                wallet,
                router,
                pair,
                buy_success=True,
                sell_success=False,
                approve_success=None,
                buy_tax=1.0 if expected_buy else None,
                expected_buy_amount=expected_buy,
                buy_amount_received=0,
                buy_gas_used=buy_gas,
                sell_revert_reason="No tokens received on buy; sell impossible",
                notes=notes,
            )

        approve_data = (
            Selectors.APPROVE
            + bytes.fromhex(router[2:].rjust(64, "0"))
            + MAX_UINT256.to_bytes(32, "big")
        )
        approve_tx = {
            "from": wallet,
            "to": token,
            "data": "0x" + approve_data.hex(),
            "gas": hex(200_000),
            "gasPrice": hex(gas_price),
        }
        approve_revert = await self._preflight(rpc, approve_tx)
        if approve_revert is None:
            approve_receipt = await self._send_and_wait(rpc, approve_tx)
            if _hex_int(approve_receipt.get("status", "0x0")) != 1:
                approve_revert = "approve transaction reverted (status 0)"
        if approve_revert is not None:
            return self._result(
                context,
                wallet,
                router,
                pair,
                buy_success=True,
                sell_success=False,
                approve_success=False,
                buy_tax=buy_tax,
                expected_buy_amount=expected_buy,
                buy_amount_received=token_balance,
                buy_gas_used=buy_gas,
                sell_revert_reason=f"Router approval failed: {approve_revert}",
                notes=notes,
            )

        expected_sell = await self._quote(
            rpc,
            router,
            token_balance,
            [token, weth],
            notes,
        )
        if expected_sell is None:
            expected_sell = await self._reserve_quote(
                rpc,
                pair,
                token0,
                token1,
                weth,
                token_balance,
                buy=False,
            )
            notes.append("Sell quote derived from pair reserves")

        sell_data = encode_call(
            "swapExactTokensForETHSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)",
            ["uint256", "uint256", "address[]", "address", "uint256"],
            [token_balance, 0, [token, weth], wallet, deadline],
        )
        sell_tx = {
            "from": wallet,
            "to": router,
            "data": "0x" + sell_data.hex(),
            "gas": hex(gas_limit),
            "gasPrice": hex(gas_price),
        }
        sell_revert = await self._preflight(rpc, sell_tx)
        if sell_revert is not None:
            return self._result(
                context,
                wallet,
                router,
                pair,
                buy_success=True,
                sell_success=False,
                approve_success=True,
                buy_tax=buy_tax,
                expected_buy_amount=expected_buy,
                buy_amount_received=token_balance,
                buy_gas_used=buy_gas,
                sell_revert_reason=sell_revert,
                notes=notes,
            )

        native_before = await self._native_balance(rpc, wallet)
        sell_receipt = await self._send_and_wait(rpc, sell_tx)
        sell_gas = _hex_int(sell_receipt.get("gasUsed", "0x0"))
        if _hex_int(sell_receipt.get("status", "0x0")) != 1:
            return self._result(
                context,
                wallet,
                router,
                pair,
                buy_success=True,
                sell_success=False,
                approve_success=True,
                buy_tax=buy_tax,
                expected_buy_amount=expected_buy,
                buy_amount_received=token_balance,
                buy_gas_used=buy_gas,
                sell_revert_reason="sell transaction reverted (status 0)",
                sell_gas_used=sell_gas,
                notes=notes,
            )

        native_after = await self._native_balance(rpc, wallet)
        effective_gas_price = _hex_int(
            sell_receipt.get("effectiveGasPrice", sell_receipt.get("gasPrice", hex(gas_price)))
        )
        gas_cost = sell_gas * effective_gas_price
        native_received = max(0, native_after - native_before + gas_cost)
        sell_tax = self._tax(expected_sell, native_received)
        return self._result(
            context,
            wallet,
            router,
            pair,
            buy_success=True,
            sell_success=True,
            approve_success=True,
            buy_tax=buy_tax,
            sell_tax=sell_tax,
            expected_buy_amount=expected_buy,
            buy_amount_received=token_balance,
            expected_sell_amount=expected_sell,
            sell_amount_received=native_received,
            buy_gas_used=buy_gas,
            sell_gas_used=sell_gas,
            notes=notes,
        )

    async def _quote(
        self,
        rpc: _AnvilRpc,
        router: str,
        amount_in: int,
        path: list[str],
        notes: list[str],
    ) -> int | None:
        data = encode_call(
            "getAmountsOut(uint256,address[])",
            ["uint256", "address[]"],
            [amount_in, path],
        )
        try:
            raw = await rpc.eth_call(router, data)
            amounts = decode_uint_array(raw)
            if len(amounts) >= 2:
                return amounts[-1]
        except (SimulationError, ValueError) as exc:
            logger.debug("Router quote failed: %s", exc)
            with contextlib.suppress(Exception):
                notes.append(f"Router quote failed: {sanitize_reason(str(exc))}")
        return None

    async def _reserve_quote(
        self,
        rpc: _AnvilRpc,
        pair: str,
        token0: str,
        token1: str,
        weth_address: str,
        amount_in: int,
        *,
        buy: bool,
    ) -> int:
        raw = await rpc.eth_call(pair, Selectors.GET_RESERVES)
        reserve0, reserve1, _ = decode_reserves(raw)
        weth = to_checksum_address(weth_address)
        if token0.lower() == weth.lower():
            reserve_native, reserve_token = reserve0, reserve1
        elif token1.lower() == weth.lower():
            reserve_native, reserve_token = reserve1, reserve0
        else:
            raise SimulationSetupError("DEX pair does not contain the wrapped native token")
        reserve_in, reserve_out = (
            (reserve_native, reserve_token) if buy else (reserve_token, reserve_native)
        )
        if reserve_in <= 0 or reserve_out <= 0:
            raise SimulationSetupError("DEX pair has empty reserves")
        amount_in_with_fee = amount_in * 997
        denominator = reserve_in * 1_000 + amount_in_with_fee
        if denominator == 0:
            raise SimulationSetupError("DEX pair math failed")
        return amount_in_with_fee * reserve_out // denominator

    async def _native_balance(self, rpc: _AnvilRpc, wallet: str) -> int:
        result = await rpc.call("eth_getBalance", [wallet, "latest"])
        return _hex_int(result)

    async def _preflight(self, rpc: _AnvilRpc, tx: dict[str, Any]) -> str | None:
        call_tx = dict(tx)
        call_tx.pop("gasPrice", None)
        try:
            await rpc.call("eth_call", [call_tx, "latest"])
        except SimulationError as exc:
            return sanitize_reason(str(exc)) or "execution reverted"
        return None

    async def _send_and_wait(self, rpc: _AnvilRpc, tx: dict[str, Any]) -> dict[str, Any]:
        try:
            tx_hash = await rpc.call("eth_sendTransaction", [tx])
        except SimulationError as exc:
            raise SimulationError(f"Transaction submission failed: {exc}") from exc
        if not isinstance(tx_hash, str):
            raise SimulationError("Anvil did not return a transaction hash")
        for _ in range(_RECEIPT_POLL_ATTEMPTS):
            receipt = await rpc.call("eth_getTransactionReceipt", [tx_hash])
            if isinstance(receipt, dict):
                return receipt
            await asyncio.sleep(_RECEIPT_POLL_INTERVAL)
        raise SimulationTimeoutError(f"Timed out waiting for Anvil receipt {tx_hash}")

    @staticmethod
    def _tax(expected: int | None, received: int) -> float | None:
        if expected is None:
            return None
        if expected <= 0:
            return None
        actual = max(0, received)
        if actual >= expected:
            return 0.0
        return min(1.0, max(0.0, 1.0 - (actual / expected)))

    def _result(
        self,
        context: TokenContext,
        wallet: str,
        router: str,
        pair: str,
        *,
        buy_success: bool,
        sell_success: bool,
        approve_success: bool | None = None,
        buy_tax: float | None = None,
        sell_tax: float | None = None,
        expected_buy_amount: int | None = None,
        buy_amount_received: int | None = None,
        expected_sell_amount: int | None = None,
        sell_amount_received: int | None = None,
        buy_gas_used: int | None = None,
        sell_gas_used: int | None = None,
        buy_revert_reason: str | None = None,
        sell_revert_reason: str | None = None,
        notes: list[str] | None = None,
    ) -> TradeSimulationResult:
        return TradeSimulationResult(
            executed=True,
            buy_success=buy_success,
            sell_success=sell_success,
            approve_success=approve_success,
            router=router,
            pair=pair,
            wallet=wallet,
            block_number=context.block_number,
            buy_tax=buy_tax,
            sell_tax=sell_tax,
            expected_buy_amount=expected_buy_amount,
            buy_amount_received=buy_amount_received,
            expected_sell_amount=expected_sell_amount,
            sell_amount_received=sell_amount_received,
            buy_gas_used=buy_gas_used,
            sell_gas_used=sell_gas_used,
            buy_revert_reason=buy_revert_reason,
            sell_revert_reason=sell_revert_reason,
            notes=notes or [],
        )
