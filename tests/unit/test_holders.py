"""Holder distribution detector tests."""

from __future__ import annotations

from tests.helpers import PAIR, TOKEN, FakeChainAdapter, make_context, mint_log

from ruglens.chains.evm.abi import BURN_ADDRESSES, ZERO_ADDRESS, encode_call
from ruglens.core.enums import DetectorStatus, Severity
from ruglens.core.interfaces import DetectorDependencies
from ruglens.core.models import HolderBalance
from ruglens.detectors.onchain.holders import HolderDistributionDetector


def holders_with_shares(shares: list[float], total: int) -> list[HolderBalance]:
    return [
        HolderBalance(address=f"0x{index + 0x100:040x}", balance=int(total * share))
        for index, share in enumerate(shares)
    ]


async def test_concentrated_holders_are_high(settings) -> None:
    total = 1_000_000 * 10**18
    holders = holders_with_shares([0.8, 0.04, 0.04, 0.04, 0.04, 0.04], total)
    outcome = await HolderDistributionDetector(settings).detect(
        make_context(holders=holders, total_supply=total),
        DetectorDependencies(chain=FakeChainAdapter()),
    )
    finding = next(f for f in outcome.findings if f.rule_id == "HOLDER-CONC-001")
    assert finding.severity is Severity.HIGH
    assert finding.evidence["top1_share"] >= 0.5
    assert outcome.status is DetectorStatus.SUCCESS
    assert outcome.coverage_fraction == 1.0


async def test_dispersed_holders_are_clean(settings) -> None:
    total = 1_000_000 * 10**18
    holders = holders_with_shares([0.04] * 25, total)
    outcome = await HolderDistributionDetector(settings).detect(
        make_context(holders=holders, total_supply=total),
        DetectorDependencies(chain=FakeChainAdapter()),
    )
    assert outcome.findings == ()
    assert outcome.coverage_fraction == 1.0


async def test_no_holder_data_degrades_coverage(settings) -> None:
    outcome = await HolderDistributionDetector(settings).detect(
        make_context(), DetectorDependencies(chain=FakeChainAdapter())
    )
    assert outcome.status is DetectorStatus.SUCCESS
    assert outcome.coverage_fraction == 0.5
    assert outcome.findings == ()
    assert any("No positive holder" in limitation for limitation in outcome.limitations)


async def test_transfer_log_replay_and_balance_verification(settings) -> None:
    total = 1_200 * 10**18
    holders = [
        HolderBalance(address=f"0x{index + 0x500:040x}", balance=400 * 10**18) for index in range(3)
    ]
    adapter = FakeChainAdapter()
    for index, holder in enumerate(holders):
        adapter.add_log(
            mint_log(TOKEN, holder.address, holder.balance, block_number=90, log_index=index)
        )
        adapter.set_call(
            TOKEN,
            encode_call("balanceOf(address)", ["address"], [holder.address]),
            holder.balance.to_bytes(32, "big"),
        )
    for address in (ZERO_ADDRESS, BURN_ADDRESSES[1], PAIR):
        adapter.set_call(
            TOKEN,
            encode_call("balanceOf(address)", ["address"], [address]),
            (0).to_bytes(32, "big"),
        )
    context = make_context(holders=[], total_supply=total)
    outcome = await HolderDistributionDetector(settings).detect(
        context, DetectorDependencies(chain=adapter)
    )
    assert outcome.status is DetectorStatus.SUCCESS
    assert outcome.details["event_count"] == 3
    finding = next(f for f in outcome.findings if f.rule_id == "HOLDER-CONC-001")
    assert finding.severity is Severity.HIGH
    assert finding.evidence["transfer_events"] == 3
