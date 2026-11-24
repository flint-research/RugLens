"""Solana-native chain support."""

from __future__ import annotations

from ruglens.chains.solana.base58 import (
    base58_decode,
    base58_encode,
    decode_pubkey,
    is_valid_pubkey,
)
from ruglens.chains.solana.client import SolanaRpcClient
from ruglens.chains.solana.factory import SolanaRpcFactory
from ruglens.chains.solana.pda import find_program_address, is_on_curve, is_pda
from ruglens.chains.solana.registry import (
    BURN_ADDRESSES,
    KNOWN_PROGRAMS,
    METAPLEX_PROGRAM_ID,
    SOLANA,
    SOLANA_CHAIN_ID,
    TOKEN_2022_PROGRAM_ID,
    TOKEN_PROGRAM_ID,
    SolanaConfig,
    known_program_name,
    normalize_solana_address,
    resolve_solana_rpc_urls,
)

__all__ = [
    "BURN_ADDRESSES",
    "KNOWN_PROGRAMS",
    "METAPLEX_PROGRAM_ID",
    "SOLANA",
    "SOLANA_CHAIN_ID",
    "TOKEN_2022_PROGRAM_ID",
    "TOKEN_PROGRAM_ID",
    "SolanaConfig",
    "SolanaRpcClient",
    "SolanaRpcFactory",
    "base58_decode",
    "base58_encode",
    "decode_pubkey",
    "find_program_address",
    "is_on_curve",
    "is_pda",
    "is_valid_pubkey",
    "known_program_name",
    "normalize_solana_address",
    "resolve_solana_rpc_urls",
]
