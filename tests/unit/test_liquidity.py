"""Liquidity detector tests."""

from __future__ import annotations

from eth_abi.abi import encode
from tests.helpers import FACTORY, PAIR, FakeChainAdapter, make_context, mint_log

from ruglens.chains.evm.abi import DEAD_ADDRESS, ZERO_ADDRESS, Selectors, encode_call
from ruglens.chains.evm.registry import normalize_chain
from ruglens.core.enums import DetectorStatus, Severity
from ruglens.core.interfaces import DetectorDependencies
from ruglens.detectors.onchain.liquidity import LiquidityDetector

LOCKERS = normalize_chain(1).known_lp_lockers


def all_balances(burn: int, dead: int = 0) -> dict[str, int]:
    balances = {ZERO_ADDRESS: burn, DEAD_ADDRESS: dead}
    for locker in LOCKERS:
        balances[locker] = 0
    return balances


def context_with(
    *,
    native: int = 100 * 10**18,
    lp_total: int = 1_000 * 10**18,
    balances: dict[str, int] | None = None,
    pair: str | None = "0x2222222222222222222222222222222222222222",
):
    ctx = make_context(pair=pair)
    return ctx.model_copy(
        update={
            "pair_reserves": (native, 1_000_000 * 10**18),
            "lp_total_supply": lp_total,
            "lp_balances": balances if balances is not None else all_balances(lp_total),
        }
    )


async def test_deep_locked_pool_has_no_findings(settings) -> None:
    outcome = await LiquidityDetector(settings).detect(
        context_with(), DetectorDependencies(chain=FakeChainAdapter())
    )
    assert outcome.status is DetectorStatus.SUCCESS
    assert outcome.findings == ()
    assert outcome.coverage_fraction == 1.0


async def test_critically_low_depth_is_high(settings) -> None:
    outcome = await LiquidityDetector(settings).detect(
        context_with(native=5 * 10**16), DetectorDependencies(chain=FakeChainAdapter())
    )
    finding = next(f for f in outcome.findings if f.rule_id == "LIQ-LOW-DEPTH-HIGH-001")
    assert finding.severity is Severity.HIGH


async def test_low_depth_is_medium(settings) -> None:
    outcome = await LiquidityDetector(settings).detect(
        context_with(native=5 * 10**17), DetectorDependencies(chain=FakeChainAdapter())
    )
    finding = next(f for f in outcome.findings if f.rule_id == "LIQ-LOW-DEPTH-001")
    assert finding.severity is Severity.MEDIUM


async def test_fully_unlocked_lp_held_by_eoa_is_high(settings) -> None:
    context = context_with(balances=all_balances(0))
    adapter = FakeChainAdapter()
    holder = "0x9999999999999999999999999999999999999999"
    adapter.add_log(mint_log(PAIR, holder, context.lp_total_supply or 0, block_number=99))
    adapter.set_call(
        PAIR,
        encode_call("balanceOf(address)", ["address"], [holder]),
        (context.lp_total_supply or 0).to_bytes(32, "big"),
    )
    outcome = await LiquidityDetector(settings).detect(context, DetectorDependencies(chain=adapter))
    finding = next(f for f in outcome.findings if f.rule_id == "LIQ-UNLOCKED-HIGH-001")
    assert finding.severity is Severity.HIGH
    assert finding.evidence["unlocked_fraction"] == 1.0
    assert finding.evidence["top_lp_holder_is_eoa"] is True


async def test_unlocked_lp_without_eoa_proof_is_medium(settings) -> None:
    outcome = await LiquidityDetector(settings).detect(
        context_with(balances=all_balances(0)), DetectorDependencies(chain=FakeChainAdapter())
    )
    finding = next(f for f in outcome.findings if f.rule_id == "LIQ-UNLOCKED-001")
    assert finding.severity is Severity.MEDIUM
    assert any("MEDIUM rather than HIGH" in item for item in outcome.limitations)


async def test_partially_unlocked_lp_is_medium(settings) -> None:
    outcome = await LiquidityDetector(settings).detect(
        context_with(balances=all_balances(4 * 10**20)),
        DetectorDependencies(chain=FakeChainAdapter()),
    )
    finding = next(f for f in outcome.findings if f.rule_id == "LIQ-UNLOCKED-001")
    assert finding.severity is Severity.MEDIUM


async def test_no_pair_is_reported_as_medium(settings) -> None:
    adapter = FakeChainAdapter()
    adapter.set_selector(FACTORY, Selectors.GET_PAIR, encode(["address"], [ZERO_ADDRESS]))
    context = make_context(pair=None)
    outcome = await LiquidityDetector(settings).detect(context, DetectorDependencies(chain=adapter))
    finding = next(f for f in outcome.findings if f.rule_id == "LIQ-NO-V2-PAIR-001")
    assert finding.severity is Severity.MEDIUM
    assert outcome.status is DetectorStatus.SUCCESS


async def test_pair_discovery_rpc_failure_is_failed(settings) -> None:
    context = make_context(pair=None)
    outcome = await LiquidityDetector(settings).detect(
        context, DetectorDependencies(chain=FakeChainAdapter())
    )
    assert outcome.status is DetectorStatus.FAILED
    assert outcome.coverage_fraction == 0.0


async def test_unreadable_lp_balances_produce_unverified_finding(settings) -> None:
    context = context_with(balances={})
    outcome = await LiquidityDetector(settings).detect(
        context, DetectorDependencies(chain=FakeChainAdapter())
    )
    finding = next(f for f in outcome.findings if f.rule_id == "LIQ-LOCK-UNVERIFIED-001")
    assert finding.severity is Severity.MEDIUM
    assert outcome.status is DetectorStatus.SUCCESS
    assert outcome.coverage_fraction < 1.0
