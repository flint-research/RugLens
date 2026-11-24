"""Load synthetic offline integration fixtures into a fake chain adapter."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from eth_abi.abi import encode
from eth_utils.address import to_checksum_address

from ruglens.chains.evm.abi import (
    BURN_ADDRESSES,
    EIP1967_ADMIN_SLOT,
    EIP1967_IMPLEMENTATION_SLOT,
    ZERO_ADDRESS,
    Selectors,
    encode_call,
)
from ruglens.chains.evm.registry import normalize_chain
from ruglens.core.models import TradeSimulationResult
from tests.helpers import FakeChainAdapter, FakeSimulator, FakeSimulatorFactory, mint_log

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "datasets" / "fixtures" / "integration"


@dataclass(frozen=True, slots=True)
class FixtureCase:
    name: str
    path: Path
    token: str
    block_number: int
    adapter: FakeChainAdapter
    simulator: FakeSimulator
    simulator_factory: FakeSimulatorFactory
    expected: dict[str, Any]
    raw: dict[str, Any]


def _uint(value: int) -> bytes:
    return value.to_bytes(32, "big")


def load_case(path: Path) -> FixtureCase:
    raw: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    chain = normalize_chain(raw["chain_id"])
    token = to_checksum_address(raw["token_address"])
    block_number = int(raw["block_number"])
    adapter = FakeChainAdapter(chain_id=raw["chain_id"], block_number=block_number)
    adapter.set_code(token, bytes.fromhex(raw["bytecode"][2:]))

    metadata = raw.get("metadata")
    if metadata:
        adapter.set_string(token, Selectors.NAME, metadata["name"])
        adapter.set_string(token, Selectors.SYMBOL, metadata["symbol"])
        adapter.set_uint(token, Selectors.DECIMALS, int(metadata["decimals"]))
        adapter.set_uint(token, Selectors.TOTAL_SUPPLY, int(metadata["total_supply"]))

    owner = raw.get("owner")
    owner_kind = raw.get("owner_kind")
    if owner:
        owner = to_checksum_address(owner)
        adapter.set_address(token, Selectors.OWNER, owner)
        if owner_kind == "multisig":
            adapter.set_code(owner, b"\x60\x00")
            adapter.set_uint(owner, Selectors.GET_THRESHOLD, 2)
            adapter.set_selector(owner, Selectors.GET_OWNERS, encode(["address[]"], [[owner]]))
        elif owner_kind == "timelock":
            adapter.set_code(owner, b"\x60\x00")
            adapter.set_uint(owner, Selectors.GET_MIN_DELAY, 86_400)
        elif owner_kind == "contract":
            adapter.set_code(owner, b"\x60\x00")

    proxy = raw.get("proxy") or {}
    implementation = proxy.get("implementation")
    admin = proxy.get("admin")
    if implementation:
        implementation = to_checksum_address(implementation)
        adapter.set_storage(
            token,
            EIP1967_IMPLEMENTATION_SLOT,
            "0x" + implementation[2:].rjust(64, "0"),
        )
        adapter.set_code(implementation, bytes.fromhex(proxy["implementation_code"][2:]))
    if admin:
        admin = to_checksum_address(admin)
        adapter.set_storage(token, EIP1967_ADMIN_SLOT, "0x" + admin[2:].rjust(64, "0"))

    pair_data = raw.get("pair")
    pair_address = to_checksum_address(pair_data["address"]) if pair_data else None
    adapter.set_selector(
        to_checksum_address(chain.v2_factory),
        Selectors.GET_PAIR,
        encode(["address"], [pair_address or ZERO_ADDRESS]),
    )

    token_balances = raw.get("token_balances", {})
    if pair_data and pair_address:
        adapter.set_address(
            pair_address, Selectors.TOKEN0, to_checksum_address(pair_data["token0"])
        )
        adapter.set_address(
            pair_address, Selectors.TOKEN1, to_checksum_address(pair_data["token1"])
        )
        native, token_reserve = (int(value) for value in pair_data["reserves"])
        adapter.set_selector(
            pair_address,
            Selectors.GET_RESERVES,
            encode(["uint112", "uint112", "uint32"], [native, token_reserve, block_number]),
        )
        adapter.set_uint(pair_address, Selectors.TOTAL_SUPPLY, int(pair_data["lp_total_supply"]))
        lp_balances = {
            to_checksum_address(address): int(value)
            for address, value in pair_data.get("lp_balances", {}).items()
        }
        for address in [*BURN_ADDRESSES, *chain.known_lp_lockers]:
            checksum = to_checksum_address(address)
            adapter.set_call(
                pair_address,
                encode_balance_of(checksum),
                _uint(lp_balances.get(checksum, 0)),
            )
        top_lp_holder = pair_data.get("lp_top_holder")
        if top_lp_holder:
            holder = to_checksum_address(top_lp_holder)
            lp_supply = int(pair_data["lp_total_supply"])
            adapter.set_call(pair_address, encode_balance_of(holder), _uint(lp_supply))
            adapter.add_log(
                mint_log(
                    pair_address,
                    holder,
                    lp_supply,
                    block_number=block_number - 1,
                    log_index=999,
                )
            )

    holders = raw.get("holders", [])
    holder_balances = {
        to_checksum_address(record["address"]): int(record["balance"]) for record in holders
    }
    adapter.set_call(
        token,
        encode_balance_of(ZERO_ADDRESS),
        _uint(int(token_balances.get("burn", 0))),
    )
    adapter.set_call(
        token,
        encode_balance_of(to_checksum_address("0x000000000000000000000000000000000000dEaD")),
        _uint(0),
    )
    pair_token_balance = int(token_balances.get("pair", 0))
    if pair_address:
        adapter.set_call(token, encode_balance_of(pair_address), _uint(pair_token_balance))
    for address, balance in holder_balances.items():
        adapter.set_call(token, encode_balance_of(address), _uint(balance))

    for log in raw.get("logs", []):
        adapter.add_log(
            {
                **log,
                "address": token,
                "topics": list(log["topics"]),
            }
        )

    simulation_raw = dict(raw.get("simulation") or {})
    simulation = TradeSimulationResult(
        executed=bool(simulation_raw.get("executed", True)),
        buy_success=bool(simulation_raw.get("buy_success", True)),
        sell_success=bool(simulation_raw.get("sell_success", True)),
        approve_success=simulation_raw.get("approve_success"),
        router=chain.v2_router,
        pair=pair_address or ZERO_ADDRESS,
        wallet=to_checksum_address("0x000000000000000000000000000000000000bEEF"),
        block_number=block_number,
        buy_tax=simulation_raw.get("buy_tax"),
        sell_tax=simulation_raw.get("sell_tax"),
        expected_buy_amount=simulation_raw.get("expected_buy_amount"),
        buy_amount_received=simulation_raw.get("buy_amount_received"),
        expected_sell_amount=simulation_raw.get("expected_sell_amount"),
        sell_amount_received=simulation_raw.get("sell_amount_received"),
        buy_gas_used=simulation_raw.get("buy_gas_used"),
        sell_gas_used=simulation_raw.get("sell_gas_used"),
        buy_revert_reason=simulation_raw.get("buy_revert_reason"),
        sell_revert_reason=simulation_raw.get("sell_revert_reason"),
        notes=list(simulation_raw.get("notes", [])),
    )
    simulator = FakeSimulator(simulation)
    return FixtureCase(
        name=raw["name"],
        path=path,
        token=token,
        block_number=block_number,
        adapter=adapter,
        simulator=simulator,
        simulator_factory=FakeSimulatorFactory(simulator),
        expected=raw["expected"],
        raw=raw,
    )


def encode_balance_of(address: str) -> bytes:
    return encode_call("balanceOf(address)", ["address"], [to_checksum_address(address)])


def all_cases() -> list[FixtureCase]:
    """Load every committed integration fixture."""
    return [load_case(path) for path in sorted(FIXTURE_DIR.glob("*.json"))]


__all__ = [
    "FIXTURE_DIR",
    "FixtureCase",
    "all_cases",
    "encode_balance_of",
    "load_case",
]
