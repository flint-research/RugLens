"""Generate deterministic offline integration fixtures for RugLens.

These fixtures are synthetic, bytecode-level test cases. They are not claims
about real tokens and never feed benchmark accuracy metrics.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from eth_utils.address import to_checksum_address

from ruglens.chains.evm.abi import (
    DEAD_ADDRESS,
    TRANSFER_EVENT_TOPIC,
    ZERO_ADDRESS,
    selector,
)
from ruglens.chains.evm.registry import normalize_chain

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "datasets" / "fixtures" / "integration"
CHAIN = normalize_chain(1)
TOTAL = 1_000_000 * 10**18
BLOCK = 1_000_000


def token_address(index: int) -> str:
    return to_checksum_address(f"0x{0x1000 + index:040x}")


def pair_address(index: int) -> str:
    return to_checksum_address(f"0x{0x2000 + index:040x}")


def owner_address(index: int) -> str:
    return to_checksum_address(f"0x{0x4000 + index:040x}")


def impl_address(index: int) -> str:
    return to_checksum_address(f"0x{0x5000 + index:040x}")


def holder_addresses(index: int, count: int) -> list[str]:
    return [
        to_checksum_address(f"0x{0x7000 + index * 100 + offset:040x}")
        for offset in range(count)
    ]


def bytecode(*signatures: str, opcodes: str = "") -> str:
    payload = b""
    for signature in signatures:
        payload += b"\x63" + selector(signature) + b"\x14"
    if opcodes:
        payload += bytes.fromhex(opcodes)
    payload += b"\x00"
    return "0x" + payload.hex()


def transfer_log(token: str, to: str, value: int) -> dict[str, Any]:
    return {
        "address": token,
        "blockNumber": BLOCK - 1,
        "logIndex": 0,
        "transactionIndex": 0,
        "topics": [
            TRANSFER_EVENT_TOPIC,
            "0x" + "00" * 32,
            "0x" + to[2:].rjust(64, "0"),
        ],
        "data": "0x" + value.to_bytes(32, "big").hex(),
    }


def simulation(
    *,
    buy_success: bool = True,
    sell_success: bool = True,
    approve_success: bool | None = True,
    buy_tax: float = 0.0,
    sell_tax: float = 0.0,
    sell_gas: int = 130_000,
    sell_revert: str | None = None,
) -> dict[str, Any]:
    expected_buy = 1_000 * 10**18
    expected_sell = 10**17
    return {
        "executed": True,
        "buy_success": buy_success,
        "sell_success": sell_success,
        "approve_success": approve_success,
        "buy_tax": buy_tax,
        "sell_tax": sell_tax,
        "expected_buy_amount": expected_buy,
        "buy_amount_received": int(expected_buy * (1 - buy_tax)) if buy_success else 0,
        "expected_sell_amount": expected_sell,
        "sell_amount_received": int(expected_sell * (1 - sell_tax)) if sell_success else 0,
        "buy_gas_used": 120_000,
        "sell_gas_used": sell_gas if sell_success else 0,
        "buy_revert_reason": None,
        "sell_revert_reason": sell_revert,
    }


def make(
    index: int,
    name: str,
    *,
    ground_truth: str,
    expected_risk: str,
    expected_rules: list[str],
    forbidden_rules: list[str] | None = None,
    expected_statuses: dict[str, str] | None = None,
    coverage_min: float = 0.0,
    coverage_max: float = 1.0,
    sim: dict[str, Any] | None = None,
    bytecode_hex: str | None = None,
    owner_kind: str = "burn",
    proxy: bool = False,
    pair: bool = True,
    metadata: bool = True,
    native_reserve: int = 100 * 10**18,
    lp_burned: bool = True,
    lp_top_holder: str | None = None,
    holder_kind: str = "dispersed",
) -> dict[str, Any]:
    token = token_address(index)
    pair_addr = pair_address(index)
    owner = owner_address(index) if owner_kind in {"eoa", "multisig", "timelock", "contract"} else None

    if pair:
        holders_total = 400_000 * 10**18
    else:
        holders_total = TOTAL
    if holder_kind == "concentrated":
        top = int(holders_total * 0.999)
        rest = holders_total - top
        holders = [top, *[rest // 10] * 10]
    else:
        holders = [holders_total // 25] * 25
    addresses = holder_addresses(index, len(holders))
    holder_records = [
        {"address": address, "balance": str(balance)}
        for address, balance in zip(addresses, holders, strict=True)
    ]
    logs = [
        transfer_log(token, record["address"], int(record["balance"]))
        for record in holder_records
    ]
    for log_index, log in enumerate(logs):
        log["logIndex"] = log_index

    if pair:
        pair_balance = 500_000 * 10**18
        burn_balance = 100_000 * 10**18
    else:
        pair_balance = 0
        burn_balance = 0

    fixture: dict[str, Any] = {
        "name": name,
        "chain_id": 1,
        "block_number": BLOCK,
        "token_address": token,
        "ground_truth": ground_truth,
        "bytecode": bytecode_hex
        if bytecode_hex is not None
        else bytecode(),
        "metadata": {
            "name": name.replace("_", " ").title(),
            "symbol": name[:6].upper(),
            "decimals": 18,
            "total_supply": str(TOTAL),
        }
        if metadata
        else None,
        "owner": owner,
        "owner_kind": owner_kind if owner_kind != "burn" else None,
        "holders": holder_records,
        "logs": logs,
        "pair": {
            "address": pair_addr,
            "token0": CHAIN.weth,
            "token1": token,
            "reserves": [str(native_reserve), str(500_000 * 10**18)],
            "lp_total_supply": str(1_000 * 10**18),
            "lp_balances": {
                ZERO_ADDRESS: str(1_000 * 10**18) if lp_burned else "0",
                DEAD_ADDRESS: "0",
            },
            "lp_top_holder": lp_top_holder,
            "token_balance": str(pair_balance),
        }
        if pair
        else None,
        "token_balances": {
            "burn": str(burn_balance),
            "pair": str(pair_balance),
            "holders": {record["address"]: record["balance"] for record in holder_records},
        },
        "proxy": {
            "implementation": impl_address(index) if proxy else None,
            "admin": owner_address(index + 50) if proxy else None,
            "beacon": None,
            "implementation_code": "0x6000" if proxy else None,
        },
        "simulation": sim if sim is not None else simulation(),
        "expected": {
            "risk": expected_risk,
            "rules": expected_rules,
            "forbidden_rules": forbidden_rules or [],
            "statuses": expected_statuses or {},
            "coverage_min": coverage_min,
            "coverage_max": coverage_max,
        },
    }
    return fixture


def build() -> list[dict[str, Any]]:
    fixtures: list[dict[str, Any]] = []

    fixtures.append(
        make(
            1,
            "clean_token",
            ground_truth="BENIGN",
            expected_risk="LOW",
            expected_rules=[],
            coverage_min=0.99,
            coverage_max=1.0,
        )
    )
    fixtures.append(
        make(
            2,
            "honeypot_token",
            ground_truth="SCAM_HONEYPOT",
            expected_risk="CRITICAL",
            expected_rules=["DYN-HONEYPOT-001"],
            coverage_min=0.99,
            bytecode_hex=bytecode("mint(address,uint256)", "pause()"),
            sim=simulation(
                sell_success=False,
                sell_revert="blocked sell",
                sell_tax=1.0,
                sell_gas=0,
            ),
        )
    )
    fixtures.append(
        make(
            3,
            "tax_12pct",
            ground_truth="SCAM_HIGH_TAX",
            expected_risk="MODERATE",
            expected_rules=["DYN-TAX-003"],
            coverage_min=0.99,
            sim=simulation(sell_tax=0.12),
        )
    )
    fixtures.append(
        make(
            4,
            "tax_30pct",
            ground_truth="SCAM_HIGH_TAX",
            expected_risk="HIGH",
            expected_rules=["DYN-TAX-002"],
            coverage_min=0.99,
            sim=simulation(sell_tax=0.30),
        )
    )
    fixtures.append(
        make(
            5,
            "tax_60pct",
            ground_truth="SCAM_HIGH_TAX",
            expected_risk="CRITICAL",
            expected_rules=["DYN-TAX-001"],
            coverage_min=0.99,
            sim=simulation(sell_tax=0.60),
        )
    )
    fixtures.append(
        make(
            6,
            "mintable_eoa",
            ground_truth="SCAM_MINT",
            expected_risk="HIGH",
            expected_rules=["STATIC-MINT-001", "OWN-EOA-001", "OWN-MINT-EOA-001"],
            coverage_min=0.99,
            bytecode_hex=bytecode("mint(address,uint256)"),
            owner_kind="eoa",
        )
    )
    fixtures.append(
        make(
            7,
            "blacklist_eoa",
            ground_truth="SCAM_BLACKLIST",
            expected_risk="MODERATE",
            expected_rules=["STATIC-BLACKLIST-001", "OWN-EOA-001"],
            coverage_min=0.99,
            bytecode_hex=bytecode("blacklist(address)"),
            owner_kind="eoa",
        )
    )
    fixtures.append(
        make(
            8,
            "proxy_admin_eoa",
            ground_truth="SCAM_PROXY",
            expected_risk="HIGH",
            expected_rules=["PROXY-IMPL-001", "PROXY-ADMIN-EOA-001", "STATIC-UPGRADE-001"],
            coverage_min=0.99,
            bytecode_hex=bytecode("upgradeTo(address)", opcodes="f4"),
            proxy=True,
        )
    )
    fixtures.append(
        make(
            9,
            "unlocked_lp",
            ground_truth="SCAM_LIQUIDITY",
            expected_risk="HIGH",
            expected_rules=["LIQ-UNLOCKED-HIGH-001"],
            coverage_min=0.99,
            lp_burned=False,
            lp_top_holder=holder_addresses(9, 1)[0],
        )
    )
    fixtures.append(
        make(
            10,
            "low_liquidity",
            ground_truth="SCAM_LIQUIDITY",
            expected_risk="HIGH",
            expected_rules=["LIQ-LOW-DEPTH-HIGH-001"],
            coverage_min=0.99,
            native_reserve=5 * 10**16,
        )
    )
    fixtures.append(
        make(
            11,
            "concentrated_holders",
            ground_truth="SCAM_CONCENTRATION",
            expected_risk="HIGH",
            expected_rules=["HOLDER-CONC-001"],
            coverage_min=0.99,
            holder_kind="concentrated",
        )
    )
    fixtures.append(
        make(
            12,
            "no_v2_pair",
            ground_truth="UNKNOWN",
            expected_risk="UNKNOWN",
            expected_rules=["LIQ-NO-V2-PAIR-001"],
            expected_statuses={"dynamic_honeypot": "SKIPPED"},
            coverage_min=0.60,
            coverage_max=0.65,
            pair=False,
        )
    )
    fixtures.append(
        make(
            13,
            "partial_data",
            ground_truth="UNKNOWN",
            expected_risk="UNKNOWN",
            expected_rules=["LIQ-NO-V2-PAIR-001"],
            expected_statuses={"dynamic_honeypot": "SKIPPED", "holder_distribution": "FAILED"},
            coverage_min=0.55,
            coverage_max=0.64,
            pair=False,
            metadata=False,
            owner_kind="none",
        )
    )
    fixtures.append(
        make(
            14,
            "multisig_mint",
            ground_truth="GOVERNED",
            expected_risk="MODERATE",
            expected_rules=["OWN-MINT-GOVERNED-001", "STATIC-MINT-001"],
            forbidden_rules=["OWN-EOA-001"],
            coverage_min=0.99,
            bytecode_hex=bytecode("mint(address,uint256)"),
            owner_kind="multisig",
        )
    )
    fixtures.append(
        make(
            15,
            "gas_griefing",
            ground_truth="SCAM_GAS",
            expected_risk="MODERATE",
            expected_rules=["DYN-GAS-001"],
            coverage_min=0.99,
            sim=simulation(sell_gas=1_500_000),
        )
    )
    return fixtures


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for fixture in build():
        path = OUT / f"{fixture['name']}.json"
        path.write_text(
            json.dumps(fixture, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    print(f"Wrote {len(build())} fixtures to {OUT}")


if __name__ == "__main__":
    main()
