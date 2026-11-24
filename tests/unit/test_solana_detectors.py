"""Unit tests for Solana authorities, holders, and liquidity detectors."""

from __future__ import annotations

import pytest
from tests.solana_helpers import FakeSolanaChain, on_curve_address

from ruglens.chains.solana.registry import TOKEN_PROGRAM_ID
from ruglens.core.enums import DetectorStatus, Severity
from ruglens.core.interfaces import SolanaDetectorDependencies
from ruglens.core.solana_models import (
    SolanaHolder,
    SolanaMetadata,
    SolanaMintState,
    SolanaTokenContext,
)
from ruglens.detectors.solana.authorities import SolanaAuthoritiesDetector
from ruglens.detectors.solana.holders import SolanaHolderDetector
from ruglens.detectors.solana.liquidity import SolanaLiquidityDetector

MINT = on_curve_address("detector-mint")


def wallet(index: int) -> str:
    return on_curve_address(f"detector-wallet:{index}")


def make_context(
    *,
    extensions: list[dict] | None = None,
    token_2022: bool = False,
    mint_authority: str | None = None,
    freeze_authority: str | None = None,
    update_authority: str | None = None,
    mutable: bool = False,
    holders: list[SolanaHolder] | None = None,
    creator: str | None = None,
    creator_holdings: int = 0,
    supply: int = 1_000_000_000,
    program_amount: int = 0,
    burn_amount: int = 0,
) -> SolanaTokenContext:
    holder_list = tuple(holders or [])
    circulating = supply - program_amount - burn_amount
    creator_pct = creator_holdings / circulating if circulating > 0 else 0.0
    return SolanaTokenContext(
        token_address=MINT,
        slot=123,
        mint=SolanaMintState(
            address=MINT,
            program_id="TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
            if token_2022
            else "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            program_name="Token-2022" if token_2022 else "SPL Token",
            mint_authority=mint_authority,
            freeze_authority=freeze_authority,
            supply=supply,
            decimals=9,
            extensions=tuple(extensions or []),
            extension_names=tuple(
                str(item.get("extension", item.get("name", ""))) for item in extensions or []
            ),
            extensions_complete=True,
        ),
        metadata=SolanaMetadata(
            address="meta",
            name="Test",
            symbol="TEST",
            update_authority=update_authority,
            is_mutable=mutable,
        ),
        creator=creator,
        creator_holdings=creator_holdings,
        creator_pct_total=creator_holdings / supply,
        creator_pct_circulating=creator_pct,
        top_holders=holder_list,
        circulating_supply=circulating,
        burn_amount=burn_amount,
        burn_pct=burn_amount / supply,
        program_controlled_amount=program_amount,
        program_controlled_pct=program_amount / supply,
        unique_retail_owners=len({holder.owner for holder in holder_list}),
        holders_classified=len(holder_list),
        holders_expected=max(1, len(holder_list)),
        holder_data_complete=True,
    )


def holder(address: str, amount: int, supply: int = 1_000_000_000, **kwargs) -> SolanaHolder:
    return SolanaHolder(
        token_account=on_curve_address(f"token:{address}:{amount}"),
        owner=address,
        amount=amount,
        pct_total=amount / supply,
        **kwargs,
    )


@pytest.mark.asyncio
async def test_token_2022_dangerous_extensions(settings) -> None:
    authority = wallet(99)
    extensions = [
        {"extension": "permanentDelegate", "state": {"delegate": authority}},
        {"extension": "defaultAccountState", "state": {"accountState": "frozen"}},
        {"extension": "transferHook", "state": {"programId": authority}},
    ]
    context = make_context(
        token_2022=True,
        extensions=extensions,
        mint_authority=authority,
        freeze_authority=authority,
    )
    outcome = await SolanaAuthoritiesDetector(settings).detect(
        context, SolanaDetectorDependencies(chain=FakeSolanaChain())
    )
    rules = {finding.rule_id: finding for finding in outcome.findings}
    assert rules["SOL-MINT-AUTHORITY-001"].severity is Severity.HIGH
    assert rules["SOL-FREEZE-AUTHORITY-001"].severity is Severity.HIGH
    assert rules["SOL-PERMANENT-DELEGATE-001"].severity is Severity.HIGH
    assert rules["SOL-DEFAULT-FROZEN-001"].severity is Severity.HIGH
    assert rules["SOL-TRANSFER-HOOK-001"].severity is Severity.MEDIUM
    assert outcome.status is DetectorStatus.SUCCESS


@pytest.mark.asyncio
async def test_transfer_fee_severity_and_mutable_metadata(settings) -> None:
    extensions = [
        {
            "extension": "transferFeeConfig",
            "state": {"newerTransferFee": {"transferFeeBasisPoints": 6000}},
        }
    ]
    context = make_context(
        token_2022=True,
        extensions=extensions,
        update_authority=wallet(98),
        mutable=True,
    )
    outcome = await SolanaAuthoritiesDetector(settings).detect(
        context, SolanaDetectorDependencies(chain=FakeSolanaChain())
    )
    rules = {finding.rule_id: finding for finding in outcome.findings}
    assert rules["SOL-TRANSFER-FEE-001"].severity is Severity.CRITICAL
    assert rules["SOL-METADATA-MUTABLE-001"].severity is Severity.MEDIUM
    assert outcome.details["metrics"]["metadata_mutable"] is True


@pytest.mark.asyncio
async def test_multisig_authority_is_downgraded(settings) -> None:
    authority = wallet(97)
    chain = FakeSolanaChain()
    chain.owner_infos[authority] = {
        "owner": TOKEN_PROGRAM_ID,
        "executable": False,
        "data": {
            "program": "spl-token",
            "parsed": {
                "type": "multisig",
                "info": {"numRequiredSigners": 2, "numValidSigners": 4},
            },
            "space": 355,
        },
    }
    context = make_context(mint_authority=authority, freeze_authority=authority)
    outcome = await SolanaAuthoritiesDetector(settings).detect(
        context, SolanaDetectorDependencies(chain=chain)
    )
    rules = {finding.rule_id: finding for finding in outcome.findings}
    assert "SOL-MINT-AUTHORITY-001" not in rules
    assert "SOL-FREEZE-AUTHORITY-001" not in rules
    assert rules["SOL-MINT-AUTHORITY-GOVERNED-001"].severity is Severity.MEDIUM
    assert rules["SOL-FREEZE-AUTHORITY-GOVERNED-001"].severity is Severity.MEDIUM
    assert outcome.details["metrics"]["mint_authority_type"] == "multisig"


@pytest.mark.asyncio
async def test_creator_and_top10_holder_high_thresholds(settings) -> None:
    creator = wallet(90)
    holders = [holder(wallet(index), 60_000_000) for index in range(10)]
    context = make_context(
        holders=holders,
        creator=creator,
        creator_holdings=250_000_000,
    )
    outcome = await SolanaHolderDetector(settings).detect(
        context, SolanaDetectorDependencies(chain=FakeSolanaChain())
    )
    rules = {finding.rule_id: finding for finding in outcome.findings}
    assert rules["SOL-CREATOR-HOLDINGS-001"].severity is Severity.HIGH
    assert rules["SOL-TOP10-HOLDINGS-001"].severity is Severity.HIGH
    assert outcome.details["metrics"]["creator_holdings_pct"] == 25.0
    assert outcome.details["metrics"]["top10_holder_pct"] == 60.0


@pytest.mark.asyncio
async def test_holder_analysis_excludes_program_controlled_accounts(settings) -> None:
    pool = holder(
        on_curve_address("pool-owner"),
        800_000_000,
        program_controlled=True,
        owner_on_curve=False,
        tag="program_controlled",
    )
    holders = [holder(wallet(index), 10_000_000) for index in range(5)]
    context = make_context(
        holders=[pool, *holders],
        creator=wallet(90),
        creator_holdings=1_000_000,
        program_amount=800_000_000,
    )
    outcome = await SolanaHolderDetector(settings).detect(
        context, SolanaDetectorDependencies(chain=FakeSolanaChain())
    )
    assert outcome.findings == ()
    assert outcome.details["metrics"]["top10_holder_pct"] == 25.0


@pytest.mark.asyncio
async def test_no_program_custody_is_medium_liquidity_gap(settings) -> None:
    context = make_context(holders=[holder(wallet(index), 1_000_000) for index in range(3)])
    outcome = await SolanaLiquidityDetector(settings).detect(
        context, SolanaDetectorDependencies(chain=FakeSolanaChain())
    )
    finding = next(f for f in outcome.findings if f.rule_id == "SOL-LIQUIDITY-UNVERIFIED-001")
    assert finding.severity is Severity.MEDIUM
    assert outcome.coverage_fraction == 0.25


@pytest.mark.asyncio
async def test_program_custody_yields_info_and_partial_depth_coverage(settings) -> None:
    pool = holder(
        on_curve_address("pool-owner"),
        300_000_000,
        program_controlled=True,
        owner_on_curve=False,
        tag="program_controlled",
    )
    context = make_context(
        holders=[pool, *[holder(wallet(index), 1_000_000) for index in range(3)]],
        program_amount=300_000_000,
    )
    outcome = await SolanaLiquidityDetector(settings).detect(
        context, SolanaDetectorDependencies(chain=FakeSolanaChain())
    )
    finding = next(f for f in outcome.findings if f.rule_id == "SOL-LIQUIDITY-CUSTODY-001")
    assert finding.severity is Severity.INFO
    assert outcome.coverage_fraction == 0.8
    assert outcome.details["metrics"]["liquidity_depth_verified"] is False
