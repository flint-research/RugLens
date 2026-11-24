"""Ownership and proxy detector tests."""

from __future__ import annotations

from eth_abi.abi import encode
from tests.helpers import OWNER, TOKEN, FakeChainAdapter, make_context

from ruglens.chains.evm.abi import (
    EIP1967_ADMIN_SLOT,
    EIP1967_IMPLEMENTATION_SLOT,
    ZERO_ADDRESS,
    Selectors,
)
from ruglens.core.enums import DetectorStatus, Severity
from ruglens.core.interfaces import DetectorDependencies
from ruglens.detectors.onchain.ownership import OwnershipDetector


def dispatch(selector: bytes) -> bytes:
    return b"\x63" + selector + b"\x14"


async def test_eoa_owner_and_mint_is_high(settings) -> None:
    adapter = FakeChainAdapter()
    adapter.set_address(TOKEN, Selectors.OWNER, OWNER)
    context = make_context(owner=None, bytecode=dispatch(b"\x40\xc1\x0f\x19"))
    outcome = await OwnershipDetector(settings).detect(context, DetectorDependencies(chain=adapter))
    rules = {finding.rule_id: finding for finding in outcome.findings}
    assert outcome.status is DetectorStatus.SUCCESS
    assert rules["OWN-EOA-001"].severity is Severity.MEDIUM
    assert rules["OWN-MINT-EOA-001"].severity is Severity.HIGH
    assert outcome.details["owner_type"] == "eoa"


async def test_burned_owner_suppresses_mint_finding(settings) -> None:
    adapter = FakeChainAdapter()
    adapter.set_address(TOKEN, Selectors.OWNER, ZERO_ADDRESS)
    context = make_context(owner=None, bytecode=dispatch(b"\x40\xc1\x0f\x19"))
    outcome = await OwnershipDetector(settings).detect(context, DetectorDependencies(chain=adapter))
    assert outcome.status is DetectorStatus.SUCCESS
    assert outcome.findings == ()
    assert outcome.details["owner_type"] == "burn"


async def test_multisig_owner_downgrades_mint(settings) -> None:
    adapter = FakeChainAdapter()
    adapter.set_address(TOKEN, Selectors.OWNER, OWNER)
    adapter.set_code(OWNER, b"\x60\x00")
    adapter.set_uint(OWNER, Selectors.GET_THRESHOLD, 2)
    adapter.set_selector(OWNER, Selectors.GET_OWNERS, encode(["address[]"], [[OWNER]]))
    context = make_context(bytecode=dispatch(b"\x40\xc1\x0f\x19"))
    outcome = await OwnershipDetector(settings).detect(context, DetectorDependencies(chain=adapter))
    rules = {finding.rule_id: finding for finding in outcome.findings}
    assert "OWN-EOA-001" not in rules
    assert rules["OWN-MINT-GOVERNED-001"].severity is Severity.MEDIUM
    assert outcome.details["owner_type"] == "multisig"


async def test_timelock_owner_is_recognized(settings) -> None:
    adapter = FakeChainAdapter()
    adapter.set_address(TOKEN, Selectors.OWNER, OWNER)
    adapter.set_code(OWNER, b"\x60\x00")
    adapter.set_uint(OWNER, Selectors.GET_MIN_DELAY, 86_400)
    outcome = await OwnershipDetector(settings).detect(
        make_context(), DetectorDependencies(chain=adapter)
    )
    assert outcome.details["owner_type"] == "timelock"
    assert outcome.findings == ()


async def test_unknown_contract_owner_is_medium(settings) -> None:
    adapter = FakeChainAdapter()
    adapter.set_address(TOKEN, Selectors.OWNER, OWNER)
    adapter.set_code(OWNER, b"\x60\x00")
    outcome = await OwnershipDetector(settings).detect(
        make_context(), DetectorDependencies(chain=adapter)
    )
    assert {finding.rule_id for finding in outcome.findings} == {"OWN-CONTRACT-001"}
    assert outcome.findings[0].severity is Severity.MEDIUM


async def test_eip1967_admin_eoa_is_high(settings) -> None:
    adapter = FakeChainAdapter()
    impl = "0x4444444444444444444444444444444444444444"
    adapter.set_storage(TOKEN, EIP1967_IMPLEMENTATION_SLOT, "0x" + impl[2:].rjust(64, "0"))
    adapter.set_storage(TOKEN, EIP1967_ADMIN_SLOT, "0x" + OWNER[2:].rjust(64, "0"))
    adapter.set_code(impl, b"\x60\x00")
    context = make_context(bytecode=dispatch(b"\x36\x59\xcf\xe6") + b"\xf4")
    outcome = await OwnershipDetector(settings).detect(context, DetectorDependencies(chain=adapter))
    rules = {finding.rule_id: finding for finding in outcome.findings}
    assert rules["PROXY-IMPL-001"].severity is Severity.MEDIUM
    assert rules["PROXY-ADMIN-EOA-001"].severity is Severity.HIGH
    assert outcome.details["proxy_implementation"] == impl


async def test_proxy_admin_without_implementation_is_ignored(settings) -> None:
    adapter = FakeChainAdapter()
    adapter.set_storage(TOKEN, EIP1967_ADMIN_SLOT, "0x" + OWNER[2:].rjust(64, "0"))
    outcome = await OwnershipDetector(settings).detect(
        make_context(), DetectorDependencies(chain=adapter)
    )
    assert "PROXY-ADMIN-EOA-001" not in {f.rule_id for f in outcome.findings}


async def test_owner_rpc_failure_marks_partial_coverage(settings) -> None:
    adapter = FakeChainAdapter()

    async def fail_multicall(*args, **kwargs):
        from ruglens.core.exceptions import RpcError

        raise RpcError("network down")

    adapter.multicall = fail_multicall  # type: ignore[method-assign]
    outcome = await OwnershipDetector(settings).detect(
        make_context(), DetectorDependencies(chain=adapter)
    )
    assert outcome.status is DetectorStatus.SUCCESS
    assert outcome.coverage_fraction == 0.5
    assert any("Owner RPC read failed" in limitation for limitation in outcome.limitations)
