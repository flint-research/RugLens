"""Solana mainnet configuration and known ecosystem programs."""

from __future__ import annotations

import os
from collections.abc import Sequence

from pydantic import BaseModel, ConfigDict

from ruglens.chains.solana.base58 import decode_pubkey, is_valid_pubkey
from ruglens.core.enums import ChainId
from ruglens.core.exceptions import ConfigurationError

SOLANA_CHAIN_ID = int(ChainId.SOLANA)

TOKEN_PROGRAM_ID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
TOKEN_2022_PROGRAM_ID = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
METAPLEX_PROGRAM_ID = "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s"
ASSOCIATED_TOKEN_PROGRAM_ID = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
SYSTEM_PROGRAM_ID = "11111111111111111111111111111111"
COMPUTE_BUDGET_PROGRAM_ID = "ComputeBudget111111111111111111111111111111"

BURN_ADDRESSES: tuple[str, ...] = (
    "1nc1nerator11111111111111111111111111111111",
    SYSTEM_PROGRAM_ID,
)

# Names are evidence labels, not claims that a holder is a pool. PDA-owned token
# accounts are classified as program-controlled separately.
KNOWN_PROGRAMS: dict[str, str] = {
    TOKEN_PROGRAM_ID: "SPL Token",
    TOKEN_2022_PROGRAM_ID: "Token-2022",
    METAPLEX_PROGRAM_ID: "Metaplex Token Metadata",
    ASSOCIATED_TOKEN_PROGRAM_ID: "Associated Token Account",
    SYSTEM_PROGRAM_ID: "System Program",
    COMPUTE_BUDGET_PROGRAM_ID: "Compute Budget",
    "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8": "Raydium AMM v4",
    "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C": "Raydium CPMM",
    "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK": "Raydium CLMM",
    "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc": "Orca Whirlpool",
    "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo": "Meteora DLMM",
    "Eo7WjKq67rjJQSZxS6z3YkapzY3eMj6Xy8X5EQVn5UaB": "Meteora Dynamic AMM",
    "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P": "Pump.fun",
    "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA": "PumpSwap",
    "srmqPvymJeFKQ4zGQed1GFppgkRHL9kaELCbyksJtPX": "OpenBook",
    "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4": "Jupiter v6",
}

_LOCKER_PROGRAMS: dict[str, str] = {
    # Streamflow is widely used for Solana vesting/locks.
    "strmRqUCoQUgGUan5YhzUZa6KqdzwX5L6FpUxfmKg5m": "Streamflow",
}


class SolanaConfig(BaseModel):
    """Static Solana mainnet configuration."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    chain_id: int = SOLANA_CHAIN_ID
    slug: str = "solana"
    name: str = "Solana Mainnet"
    native_symbol: str = "SOL"
    default_rpc_urls: tuple[str, ...] = (
        "https://api.mainnet-beta.solana.com",
        "https://solana-rpc.publicnode.com",
    )
    rpc_env_vars: tuple[str, ...] = (
        "RUGLENS_RPC_URL_SOLANA",
        "RUGLENS_SOLANA_RPC_URL",
        "RUGLENS_RPC_URL_101",
    )
    explorer_url: str = "https://solscan.io"
    known_programs: dict[str, str] = KNOWN_PROGRAMS
    known_lockers: dict[str, str] = _LOCKER_PROGRAMS
    burn_addresses: tuple[str, ...] = BURN_ADDRESSES


SOLANA = SolanaConfig()


def normalize_solana_address(address: str) -> str:
    """Validate and return a Solana token/owner address."""
    if not isinstance(address, str) or not is_valid_pubkey(address):
        raise ValueError(f"Invalid Solana public key: {address!r}")
    # Base58 has a unique encoding; reject non-canonical representations.
    raw = decode_pubkey(address)
    if len(raw) != 32:  # pragma: no cover - decode_pubkey guarantees this
        raise ValueError("Solana public keys are 32 bytes")
    return address


def resolve_solana_rpc_urls(explicit: Sequence[str] | str | None = None) -> tuple[str, ...]:
    """Resolve Solana RPC URLs from explicit input, environment, or defaults."""
    if explicit is not None:
        provided = [explicit] if isinstance(explicit, str) else list(explicit)
        cleaned = [url.strip() for url in provided if url and url.strip()]
        if not cleaned:
            raise ConfigurationError("Explicit Solana RPC URL list is empty")
        return tuple(cleaned)
    for env_var in SOLANA.rpc_env_vars:
        raw = os.environ.get(env_var, "").strip()
        if raw:
            urls = tuple(part.strip() for part in raw.split(",") if part.strip())
            if urls:
                return urls
    return SOLANA.default_rpc_urls


def known_program_name(program_id: str | None) -> str | None:
    """Return a human-readable program name when known."""
    if not program_id:
        return None
    return SOLANA.known_programs.get(program_id) or SOLANA.known_lockers.get(program_id)
