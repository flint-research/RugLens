"""Defensive parsers for Solana accounts, metadata, and funding transactions."""

from __future__ import annotations

import base64
from typing import Any

from ruglens.chains.solana.base58 import base58_encode, decode_pubkey
from ruglens.chains.solana.pda import find_program_address
from ruglens.chains.solana.registry import (
    METAPLEX_PROGRAM_ID,
    TOKEN_2022_PROGRAM_ID,
    TOKEN_PROGRAM_ID,
    known_program_name,
)
from ruglens.core.exceptions import InvalidTokenError
from ruglens.core.sanitization import sanitize_text, sanitize_token_name, sanitize_token_symbol
from ruglens.core.solana_models import (
    SolanaCreator,
    SolanaMetadata,
    SolanaMintState,
)


def _raw_account_data(account: dict[str, Any]) -> bytes | None:
    data = account.get("data")
    if isinstance(data, list) and data and isinstance(data[0], str):
        try:
            return base64.b64decode(data[0])
        except (ValueError, TypeError):
            return None
    return None


def _read_optional_pubkey(data: bytes, offset: int) -> str | None:
    if len(data) < offset + 36:
        return None
    tag = int.from_bytes(data[offset : offset + 4], "little")
    if tag != 1:
        return None
    raw = data[offset + 4 : offset + 36]
    if raw == b"\x00" * 32:
        return None
    return base58_encode(raw)


def _parse_base_mint(data: bytes) -> dict[str, Any]:
    if len(data) < 82:
        raise InvalidTokenError("Solana mint account data is shorter than 82 bytes")
    return {
        "mint_authority": _read_optional_pubkey(data, 0),
        "supply": int.from_bytes(data[36:44], "little"),
        "decimals": data[44],
        "is_initialized": data[45] != 0,
        "freeze_authority": _read_optional_pubkey(data, 46),
    }


def _normalize_extensions(raw: Any) -> tuple[tuple[dict[str, Any], ...], tuple[str, ...]]:
    entries: list[dict[str, Any]] = []
    names: list[str] = []
    if isinstance(raw, dict):
        for name, state in raw.items():
            entries.append({"name": str(name), "state": state})
            names.append(str(name))
    elif isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict):
                continue
            name = str(item.get("extension") or item.get("name") or "unknown")
            state = item.get("state", item)
            entries.append({"name": name, "state": state})
            names.append(name)
    return tuple(entries), tuple(names)


def parse_mint_account(address: str, account: dict[str, Any]) -> SolanaMintState:
    """Parse an SPL Token or Token-2022 mint account."""
    program_id = str(account.get("owner", ""))
    if program_id not in {TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID}:
        raise InvalidTokenError(f"Address {address} is not an SPL token mint")
    program_name = known_program_name(program_id) or "SPL Token"

    data_field = account.get("data")
    if isinstance(data_field, dict):
        parsed = data_field.get("parsed")
        if not isinstance(parsed, dict) or parsed.get("type") != "mint":
            raise InvalidTokenError(f"Address {address} is not a parsed token mint")
        info = parsed.get("info")
        if not isinstance(info, dict):
            raise InvalidTokenError("Malformed parsed mint info")
        supply_raw = info.get("supply", "0")
        decimals_raw = info.get("decimals", 0)
        try:
            supply = int(supply_raw)
            decimals = int(decimals_raw)
        except (TypeError, ValueError) as exc:
            raise InvalidTokenError("Malformed mint supply/decimals") from exc
        extensions, names = _normalize_extensions(info.get("extensions"))
        return SolanaMintState(
            address=address,
            program_id=program_id,
            program_name=program_name,
            mint_authority=info.get("mintAuthority") or None,
            freeze_authority=info.get("freezeAuthority") or None,
            supply=supply,
            decimals=decimals,
            is_initialized=bool(info.get("isInitialized", True)),
            extensions=extensions,
            extension_names=names,
            extensions_complete=bool(extensions) or program_id != TOKEN_2022_PROGRAM_ID,
        )

    raw = _raw_account_data(account)
    if raw is None:
        raise InvalidTokenError("Unsupported mint account encoding")
    base = _parse_base_mint(raw)
    return SolanaMintState(
        address=address,
        program_id=program_id,
        program_name=program_name,
        mint_authority=base["mint_authority"],
        freeze_authority=base["freeze_authority"],
        supply=base["supply"],
        decimals=base["decimals"],
        is_initialized=base["is_initialized"],
        extensions=(),
        extension_names=(),
        extensions_complete=program_id != TOKEN_2022_PROGRAM_ID,
    )


def metadata_address(mint: str) -> str:
    """Derive the Metaplex metadata PDA for a mint."""
    program_id = decode_pubkey(METAPLEX_PROGRAM_ID)
    address, _ = find_program_address(
        [b"metadata", program_id, decode_pubkey(mint)],
        program_id,
    )
    return address


def _read_padded_string(raw: bytes) -> str:
    return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")


def _read_borsh_string(data: bytes, offset: int, capacity: int) -> tuple[str, int]:
    if len(data) < offset + 4:
        raise ValueError("Metadata string length prefix is missing")
    length = int.from_bytes(data[offset : offset + 4], "little")
    if length > capacity or len(data) < offset + 4 + capacity:
        raise ValueError("Metadata string exceeds its fixed capacity")
    raw = data[offset + 4 : offset + 4 + length]
    return sanitize_text(_read_padded_string(raw), max_length=capacity), offset + 4 + capacity


def parse_metaplex_metadata(address: str, account: dict[str, Any]) -> SolanaMetadata:
    """Parse a Metaplex Token Metadata account."""
    data = _raw_account_data(account)
    if data is None or len(data) < 323:
        raise ValueError("Metadata account data is unavailable or too short")
    if data[0] != 4:  # MetadataV1 key
        raise ValueError("Unsupported Metaplex metadata account type")
    update_authority_raw = data[1:33]
    update_authority = (
        None if update_authority_raw == b"\x00" * 32 else base58_encode(update_authority_raw)
    )
    name_text, offset = _read_borsh_string(data, 65, 32)
    symbol_text, offset = _read_borsh_string(data, offset, 10)
    uri_text, offset = _read_borsh_string(data, offset, 200)
    name = sanitize_token_name(name_text)
    symbol = sanitize_token_symbol(symbol_text)
    uri = sanitize_text(uri_text, max_length=200)
    # offset now points at seller_fee_basis_points.
    offset += 2
    creators: list[SolanaCreator] = []
    is_mutable: bool | None = None
    if len(data) > offset:
        has_creator = data[offset]
        offset += 1
        if has_creator:
            if len(data) < offset + 4:
                raise ValueError("Metadata creators length is missing")
            count = int.from_bytes(data[offset : offset + 4], "little")
            offset += 4
            if 0 <= count <= 10:
                for _ in range(count):
                    if len(data) < offset + 34:
                        break
                    creator_raw = data[offset : offset + 32]
                    verified = data[offset + 32] != 0
                    share = data[offset + 33]
                    creators.append(
                        SolanaCreator(
                            address=base58_encode(creator_raw),
                            verified=verified,
                            share=min(100, share),
                        )
                    )
                    offset += 34
        if len(data) > offset + 1:
            is_mutable = data[offset + 1] != 0
    return SolanaMetadata(
        address=address,
        name=name,
        symbol=symbol,
        uri=uri,
        update_authority=update_authority,
        is_mutable=is_mutable,
        creators=tuple(creators),
    )


def parse_token_account(account: dict[str, Any]) -> tuple[str, int, str] | None:
    """Return ``(owner, amount, state)`` for a parsed token account."""
    data_field = account.get("data")
    if isinstance(data_field, dict):
        parsed = data_field.get("parsed")
        if not isinstance(parsed, dict) or parsed.get("type") != "account":
            return None
        info = parsed.get("info")
        if not isinstance(info, dict):
            return None
        owner = info.get("owner")
        token_amount = info.get("tokenAmount")
        if not isinstance(owner, str) or not isinstance(token_amount, dict):
            return None
        try:
            amount = int(token_amount.get("amount", "0"))
        except (TypeError, ValueError):
            return None
        return owner, amount, str(info.get("state", "initialized"))
    raw = _raw_account_data(account)
    if raw is None or len(raw) < 72:
        return None
    owner = base58_encode(raw[32:64])
    amount = int.from_bytes(raw[64:72], "little")
    state = "frozen" if len(raw) > 108 and raw[108] == 2 else "initialized"
    return owner, amount, state


def extension_state(extensions: tuple[dict[str, Any], ...], name: str) -> Any:
    """Look up an extension state by case-insensitive name."""
    normalized = name.lower()
    for entry in extensions:
        entry_name = str(entry.get("name") or entry.get("extension") or "").lower()
        if entry_name == normalized:
            return entry.get("state")
    return None


def parse_funding_source(transaction: dict[str, Any], wallet: str) -> str | None:
    """Best-effort original native SOL funder from a wallet's earliest tx.

    Uses pre/post lamport balances. If the wallet gained lamports, the account
    with the largest corresponding decrease is treated as the funder.
    """
    meta = transaction.get("meta")
    tx = transaction.get("transaction")
    if not isinstance(meta, dict) or not isinstance(tx, dict):
        return None
    message = tx.get("message")
    if not isinstance(message, dict):
        return None
    keys = message.get("accountKeys")
    pre = meta.get("preBalances")
    post = meta.get("postBalances")
    if not isinstance(keys, list) or not isinstance(pre, list) or not isinstance(post, list):
        return None
    if len(keys) != len(pre) or len(keys) != len(post):
        return None
    pubkeys: list[str] = []
    for key in keys:
        pubkey = key.get("pubkey") if isinstance(key, dict) else key
        if not isinstance(pubkey, str):
            return None
        pubkeys.append(pubkey)
    if wallet not in pubkeys:
        return None
    wallet_index = pubkeys.index(wallet)
    try:
        wallet_delta = int(post[wallet_index]) - int(pre[wallet_index])
    except (TypeError, ValueError):
        return None
    if wallet_delta <= 0:
        return None
    best_index: int | None = None
    best_decrease = 0
    for index, pubkey in enumerate(pubkeys):
        if index == wallet_index or pubkey == wallet:
            continue
        try:
            delta = int(post[index]) - int(pre[index])
        except (TypeError, ValueError):
            continue
        decrease = -delta
        if decrease > best_decrease:
            best_decrease = decrease
            best_index = index
    if best_index is None:
        return None
    return pubkeys[best_index]


def transaction_fee_payer(transaction: dict[str, Any]) -> str | None:
    """Extract the fee payer from a parsed transaction."""
    tx = transaction.get("transaction")
    if not isinstance(tx, dict):
        return None
    message = tx.get("message")
    if not isinstance(message, dict):
        return None
    keys = message.get("accountKeys")
    if not isinstance(keys, list) or not keys:
        return None
    first = keys[0]
    value = first.get("pubkey") if isinstance(first, dict) else first
    return value if isinstance(value, str) else None
