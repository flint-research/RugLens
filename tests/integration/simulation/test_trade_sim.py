"""Real Anvil fork tests for buy/approve/sell tax measurement.

Compiled MockERC20/MockRouter bytecode is committed under
``tests/fixtures/simulation_contracts.json``. These tests skip when anvil or
the fixtures are unavailable; they never touch a live network.
"""

from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path
from typing import Any

import httpx
import pytest
from eth_utils.address import to_checksum_address

from ruglens.chains.evm.abi import encode_call
from ruglens.chains.evm.registry import normalize_chain
from ruglens.core.config import RugLensSettings
from ruglens.core.models import TokenContext, TokenMetadata
from ruglens.simulation.anvil import AnvilManager
from ruglens.simulation.trade_sim import TradeSimulator

ROOT = Path(__file__).resolve().parents[3]
CONTRACTS = ROOT / "tests" / "fixtures" / "simulation_contracts.json"
CHAIN = normalize_chain(1)
LOCAL_CHAIN_ID = 31337
NATIVE_RESERVE = 100 * 10**18
TOKEN_RESERVE = 1_000_000 * 10**18


def settings_for(tmp_path: Path) -> RugLensSettings:
    return RugLensSettings(
        data_dir=tmp_path,
        simulation_enabled=True,
        simulation_concurrency=2,
        simulation_timeout=90.0,
        anvil_startup_timeout=30.0,
        rpc_timeout=15.0,
        trade_native_amount_wei=10**17,
        plugins_enabled=False,
        persist_reports=False,
    )


class SourceChain:
    """Tiny JSON-RPC helper for the origin Anvil instance."""

    def __init__(self, url: str) -> None:
        self.url = url
        self.client = httpx.AsyncClient(timeout=15.0)
        self._id = 0

    async def call(self, method: str, params: list[Any]) -> Any:
        self._id += 1
        response = await self.client.post(
            self.url,
            json={"jsonrpc": "2.0", "id": self._id, "method": method, "params": params},
        )
        response.raise_for_status()
        payload = response.json()
        if "error" in payload:
            raise RuntimeError(f"{method} failed: {payload['error']}")
        return payload["result"]

    async def send(self, tx: dict[str, Any]) -> dict[str, Any]:
        gas_price = int(await self.call("eth_gasPrice", []), 16)
        tx = {"gas": hex(5_000_000), "gasPrice": hex(gas_price), **tx}
        tx_hash = await self.call("eth_sendTransaction", [tx])
        for _ in range(200):
            receipt = await self.call("eth_getTransactionReceipt", [tx_hash])
            if isinstance(receipt, dict):
                if int(receipt["status"], 16) != 1:
                    raise RuntimeError(f"transaction reverted: {tx_hash}")
                return receipt
            await asyncio.sleep(0.05)
        raise TimeoutError("receipt not produced")

    async def deploy(self, bytecode: str, sender: str) -> str:
        receipt = await self.send({"from": sender, "data": bytecode})
        return to_checksum_address(receipt["contractAddress"])

    async def close(self) -> None:
        await self.client.aclose()


LP_TOKEN_MINT = 1_000_000 * 10**18


async def _deploy_scenario(
    chain: SourceChain,
    sender: str,
    bytecode: dict[str, dict[str, str]],
    *,
    buy_tax_bps: int,
    sell_tax_bps: int,
    honeypot: bool,
) -> tuple[TokenContext, str]:
    weth = await chain.deploy(bytecode["MockERC20"]["bytecode"], sender)
    token = await chain.deploy(bytecode["MockERC20"]["bytecode"], sender)
    router = await chain.deploy(bytecode["MockRouter"]["bytecode"], sender)

    await chain.send(
        {
            "from": sender,
            "to": router,
            "data": "0x"
            + encode_call(
                "initialize(address,address,uint256,uint256)",
                ["address", "address", "uint256", "uint256"],
                [token, weth, NATIVE_RESERVE, TOKEN_RESERVE],
            ).hex(),
        }
    )
    await chain.send(
        {
            "from": sender,
            "to": token,
            "data": "0x" + encode_call("setRouter(address)", ["address"], [router]).hex(),
        }
    )
    if buy_tax_bps or sell_tax_bps:
        await chain.send(
            {
                "from": sender,
                "to": token,
                "data": "0x"
                + encode_call(
                    "setTaxes(uint256,uint256)",
                    ["uint256", "uint256"],
                    [buy_tax_bps, sell_tax_bps],
                ).hex(),
            }
        )
    if honeypot:
        await chain.send(
            {
                "from": sender,
                "to": token,
                "data": "0x" + encode_call("setHoneypot(bool)", ["bool"], [True]).hex(),
            }
        )
    await chain.send(
        {
            "from": sender,
            "to": token,
            "data": "0x"
            + encode_call(
                "mint(address,uint256)", ["address", "uint256"], [router, LP_TOKEN_MINT]
            ).hex(),
        }
    )
    await chain.call("anvil_setBalance", [router, hex(NATIVE_RESERVE)])
    code = await chain.call("eth_getCode", [token, "latest"])
    block = int(await chain.call("eth_blockNumber", []), 16)
    context = TokenContext(
        chain_id=LOCAL_CHAIN_ID,
        token_address=token,
        block_number=block,
        bytecode=bytes.fromhex(code[2:]),
        metadata=TokenMetadata(
            name="Mock Token",
            symbol="MOCK",
            decimals=18,
            total_supply=LP_TOKEN_MINT,
        ),
        router=router,
        weth=weth,
        pair_address=router,
        pair_token0=weth,
        pair_token1=token,
        pair_reserves=(NATIVE_RESERVE, TOKEN_RESERVE),
        lp_total_supply=LP_TOKEN_MINT,
    )
    return context, router


@pytest.mark.asyncio
@pytest.mark.simulation
@pytest.mark.skipif(shutil.which("anvil") is None, reason="Anvil is not installed")
@pytest.mark.skipif(not CONTRACTS.exists(), reason="Compiled simulation contracts missing")
async def test_measured_taxes_and_honeypot_on_real_fork(tmp_path: Path) -> None:
    bytecode = json.loads(CONTRACTS.read_text(encoding="utf-8"))
    settings = settings_for(tmp_path)
    manager = AnvilManager(settings)
    async with manager.fork(None, None, LOCAL_CHAIN_ID) as origin:
        source = SourceChain(origin.url)
        try:
            sender = (await source.call("eth_accounts", []))[0]
            clean_ctx, _ = await _deploy_scenario(
                source,
                sender,
                bytecode,
                buy_tax_bps=0,
                sell_tax_bps=0,
                honeypot=False,
            )
            tax_ctx, _ = await _deploy_scenario(
                source,
                sender,
                bytecode,
                buy_tax_bps=1_000,
                sell_tax_bps=1_000,
                honeypot=False,
            )
            honeypot_ctx, _ = await _deploy_scenario(
                source,
                sender,
                bytecode,
                buy_tax_bps=0,
                sell_tax_bps=0,
                honeypot=True,
            )
            simulator = TradeSimulator(
                manager,
                CHAIN,
                settings,
                fork_rpc_url=origin.url,
            )
            clean = await simulator.simulate(clean_ctx)
            taxed = await simulator.simulate(tax_ctx)
            honeypot = await simulator.simulate(honeypot_ctx)
        finally:
            await source.close()

    assert clean.buy_success and clean.sell_success
    assert clean.buy_tax is not None and clean.buy_tax < 0.02
    assert clean.sell_tax is not None and clean.sell_tax < 0.02
    assert clean.sell_gas_used is not None and clean.sell_gas_used < 1_000_000

    assert taxed.buy_success and taxed.sell_success
    assert taxed.buy_tax is not None and 0.05 < taxed.buy_tax < 0.15
    assert taxed.sell_tax is not None and 0.05 < taxed.sell_tax < 0.20

    assert honeypot.buy_success is True
    assert honeypot.sell_success is False
    assert honeypot.is_honeypot is True
    assert "blocked sell" in (honeypot.sell_revert_reason or "")
    assert manager.active_instances == 0
