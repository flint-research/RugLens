"""Bytecode selector extraction tests."""

from __future__ import annotations

import pytest

from ruglens.chains.evm.abi import selector
from ruglens.detectors.static.selectors import RISK_GROUPS, scan_bytecode


def dispatch(signature: str) -> bytes:
    return b"\x63" + selector(signature) + b"\x14"


def test_extracts_known_selector_groups_and_opcodes() -> None:
    bytecode = (
        dispatch("mint(address,uint256)")
        + dispatch("blacklist(address)")
        + dispatch("pause()")
        + dispatch("setTax(uint256)")
        + dispatch("upgradeTo(address)")
        + b"\xf4\xff\xf5\x00"
    )
    scan = scan_bytecode(bytecode)
    assert set(scan.matched_groups) == {"mint", "blacklist", "pause", "tax", "upgrade"}
    assert scan.opcode_counts == {"DELEGATECALL": 1, "SELFDESTRUCT": 1, "CREATE2": 1}
    assert scan.instruction_count >= 10
    assert scan.selector_count >= 5


def test_known_signature_is_detected_without_adjacent_eq() -> None:
    # Dispatch tables using a comparison other than EQ still expose the selector.
    bytecode = b"\x63" + selector("mint(uint256)") + b"\x50\x00"
    scan = scan_bytecode(bytecode)
    assert "mint" in scan.matched_groups


def test_unrelated_push4_is_not_a_risk_match() -> None:
    bytecode = b"\x63" + b"\xde\xad\xbe\xef" + b"\x14\x00"
    scan = scan_bytecode(bytecode)
    assert scan.matched_groups == {}
    assert scan.selector_count == 1


def test_empty_bytecode_rejected() -> None:
    with pytest.raises(ValueError):
        scan_bytecode(b"")


def test_every_risk_group_has_unique_rule_id() -> None:
    rule_ids = [group.rule_id for group in RISK_GROUPS.values()]
    assert len(rule_ids) == len(set(rule_ids))
