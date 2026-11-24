"""Hydrate a Solana token context from direct JSON-RPC state."""

from __future__ import annotations

import logging
from typing import Any

from ruglens.chains.solana.base58 import decode_pubkey, is_valid_pubkey
from ruglens.chains.solana.parsers import (
    extension_state,
    metadata_address,
    parse_metaplex_metadata,
    parse_mint_account,
    parse_token_account,
    transaction_fee_payer,
)
from ruglens.chains.solana.pda import is_on_curve
from ruglens.chains.solana.registry import (
    BURN_ADDRESSES,
    KNOWN_PROGRAMS,
    SYSTEM_PROGRAM_ID,
    TOKEN_2022_PROGRAM_ID,
    TOKEN_PROGRAM_ID,
    normalize_solana_address,
)
from ruglens.core.exceptions import InvalidTokenError, RpcError
from ruglens.core.interfaces import SolanaChainAdapter
from ruglens.core.sanitization import sanitize_text, sanitize_token_name, sanitize_token_symbol
from ruglens.core.solana_models import SolanaHolder, SolanaMetadata, SolanaTokenContext

logger = logging.getLogger(__name__)


async def hydrate_solana_context(
    chain: SolanaChainAdapter,
    mint: str,
    *,
    discover_creator: bool = True,
) -> SolanaTokenContext:
    """Read mint, metadata, creator, and largest-holder state."""
    mint = normalize_solana_address(mint)
    notes: list[str] = []
    try:
        slot = await chain.get_slot()
    except RpcError:
        slot = 0
        notes.append("Solana slot could not be read; report uses slot 0.")

    try:
        mint_account = await chain.get_account_info(mint)
    except RpcError as exc:
        raise InvalidTokenError(f"Could not read Solana mint {mint}: {exc}") from exc
    if mint_account is None:
        raise InvalidTokenError(f"Solana mint account does not exist: {mint}")
    if str(mint_account.get("owner", "")) not in {TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID}:
        raise InvalidTokenError(f"Address {mint} is not an SPL token mint")
    mint_state = parse_mint_account(mint, mint_account)

    metadata: SolanaMetadata | None = None
    try:
        metadata_address_value = metadata_address(mint)
        metadata_account = await chain.get_account_info(metadata_address_value, encoding="base64")
        if metadata_account is not None:
            metadata = parse_metaplex_metadata(metadata_address_value, metadata_account)
            if metadata.name in {"Unknown Token", ""}:
                notes.append("Metaplex metadata name is empty or placeholders.")
        else:
            notes.append("No Metaplex metadata account was found for this mint.")
    except (RpcError, ValueError) as exc:
        notes.append(f"Metaplex metadata could not be parsed: {exc}")

    if metadata is None and mint_state.program_name == "Token-2022":
        token_metadata = extension_state(mint_state.extensions, "tokenMetadata")
        if isinstance(token_metadata, dict):
            update_authority = token_metadata.get("updateAuthority")
            metadata = SolanaMetadata(
                address=mint,
                name=sanitize_token_name(token_metadata.get("name")),
                symbol=sanitize_token_symbol(token_metadata.get("symbol")),
                uri=sanitize_text(token_metadata.get("uri"), max_length=200),
                update_authority=str(update_authority) if update_authority else None,
                is_mutable=bool(update_authority),
                creators=(),
            )
            notes.append("Metadata came from the Token-2022 metadata extension.")

    creator: str | None = None
    creator_source: str | None = None
    creator_verified: bool | None = None
    if metadata and metadata.creators:
        ordered = sorted(
            metadata.creators, key=lambda item: (item.verified, item.share), reverse=True
        )
        for candidate in ordered:
            if is_valid_pubkey(candidate.address) and candidate.address not in KNOWN_PROGRAMS:
                creator = candidate.address
                creator_source = "metaplex_creators"
                creator_verified = candidate.verified
                break
    if creator is None and discover_creator:
        try:
            signatures = await chain.get_signatures_for_address(mint, limit=100)
            if len(signatures) >= 100:
                notes.append(
                    "Creator inference was skipped because the mint has more than 100 "
                    "signatures; the oldest bounded-window fee payer is not a reliable "
                    "creation identity."
                )
            elif signatures:
                oldest = signatures[-1].get("signature")
                if isinstance(oldest, str):
                    transaction = await chain.get_transaction(oldest)
                    if transaction is not None:
                        fee_payer = transaction_fee_payer(transaction)
                        if (
                            fee_payer
                            and is_valid_pubkey(fee_payer)
                            and fee_payer not in KNOWN_PROGRAMS
                        ):
                            creator = fee_payer
                            creator_source = "earliest_mint_transaction"
            else:
                notes.append("No mint transaction history was available for creator inference.")
        except RpcError as exc:
            notes.append(f"Creator inference from transaction history failed: {exc}")

    largest: list[dict[str, Any]] = []
    top_holders: list[SolanaHolder] = []
    holders_classified = 0
    holders_expected = 0
    owner_data_complete = True
    try:
        largest = await chain.get_token_largest_accounts(mint)
        holders_expected = len(largest)
    except RpcError as exc:
        notes.append(f"Largest token accounts could not be read: {exc}")

    if largest:
        addresses = [str(item.get("address", "")) for item in largest]
        addresses = [address for address in addresses if is_valid_pubkey(address)]
        try:
            account_infos = await chain.get_multiple_accounts(addresses)
        except RpcError as exc:
            account_infos = [None] * len(addresses)
            notes.append(f"Largest token account details could not be read: {exc}")
        parsed: list[tuple[str, str, int, str]] = []
        for address, info in zip(addresses, account_infos, strict=False):
            if info is None:
                continue
            values = parse_token_account(info)
            if values is None:
                continue
            owner, amount, state = values
            if not is_valid_pubkey(owner):
                continue
            parsed.append((address, owner, amount, state))
            holders_classified += 1

        unique_owners = list(dict.fromkeys(owner for _, owner, _, _ in parsed))
        owner_infos: dict[str, dict[str, Any] | None] = {}
        if unique_owners:
            try:
                fetched = await chain.get_multiple_accounts(unique_owners)
                owner_infos = dict(zip(unique_owners, fetched, strict=False))
            except RpcError as exc:
                owner_data_complete = False
                notes.append(f"Holder owner accounts could not be classified: {exc}")

        supply = max(1, mint_state.supply)
        for token_account, owner, amount, state in parsed:
            is_burn = owner in BURN_ADDRESSES
            try:
                on_curve = is_on_curve(decode_pubkey(owner))
            except ValueError:
                on_curve = False
            owner_info = owner_infos.get(owner)
            owner_program = str(owner_info.get("owner")) if owner_info else None
            executable = bool(owner_info.get("executable", False)) if owner_info else False
            program_controlled = False
            tag = "wallet"
            if is_burn:
                tag = "burn"
            elif owner in KNOWN_PROGRAMS or executable:
                program_controlled = True
                tag = "program"
            elif not on_curve or (owner_program and owner_program != SYSTEM_PROGRAM_ID):
                program_controlled = True
                tag = "program_controlled"
            if state == "frozen":
                notes.append(f"Token account {token_account} is frozen.")
            top_holders.append(
                SolanaHolder(
                    token_account=token_account,
                    owner=owner,
                    amount=amount,
                    pct_total=min(1.0, amount / supply),
                    owner_on_curve=on_curve,
                    owner_program=owner_program,
                    program_controlled=program_controlled,
                    is_burn=is_burn,
                    tag=tag,
                )
            )
        top_holders.sort(key=lambda holder: -holder.amount)

    burn_amount = sum(holder.amount for holder in top_holders if holder.is_burn)
    program_amount = sum(holder.amount for holder in top_holders if holder.program_controlled)
    supply = max(0, mint_state.supply)
    circulating = max(0, supply - burn_amount - program_amount)

    creator_holdings = 0
    if creator:
        try:
            creator_accounts = await chain.get_token_accounts_by_owner(creator, mint)
            for account in creator_accounts:
                values = parse_token_account(account)
                if values is not None:
                    creator_holdings += values[1]
        except RpcError as exc:
            notes.append(f"Creator token accounts could not be read: {exc}")

    creator_pct_total = min(1.0, creator_holdings / supply) if supply else 0.0
    creator_pct_circulating = min(1.0, creator_holdings / circulating) if circulating else 0.0

    if not top_holders:
        notes.append("No largest token accounts were classified; holder coverage is missing.")
    if not owner_data_complete:
        notes.append(
            "Program-controlled custody may be understated because owner metadata was incomplete."
        )
    notes.append(
        "Solana state is observed at the current confirmed bank. Standard JSON-RPC does not "
        "offer historical account pinning, so the recorded slot is an observation marker."
    )
    notes.append(
        "Holder concentration uses at most the 20 largest token accounts. Program-controlled "
        "accounts (PDA/executable owners) are excluded from retail circulating supply; exact DEX "
        "venue, depth, and LP lock status are not independently verified in this V1."
    )

    return SolanaTokenContext(
        chain_id=101,
        token_address=mint,
        slot=slot,
        mint=mint_state,
        metadata=metadata,
        creator=creator,
        creator_source=creator_source,
        creator_verified=creator_verified,
        creator_holdings=creator_holdings,
        creator_pct_total=creator_pct_total,
        creator_pct_circulating=creator_pct_circulating,
        top_holders=tuple(top_holders),
        circulating_supply=circulating,
        burn_amount=burn_amount,
        burn_pct=min(1.0, burn_amount / supply) if supply else 0.0,
        program_controlled_amount=program_amount,
        program_controlled_pct=min(1.0, program_amount / supply) if supply else 0.0,
        unique_retail_owners=len(
            {
                holder.owner
                for holder in top_holders
                if holder.tag == "wallet" and not holder.program_controlled and not holder.is_burn
            }
        ),
        holders_classified=holders_classified,
        holders_expected=max(holders_expected, len(top_holders)),
        holder_data_complete=owner_data_complete and holders_classified == max(1, holders_expected),
        notes=notes,
    )


__all__ = ["hydrate_solana_context"]
