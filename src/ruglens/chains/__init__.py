"""Chain access: EVM and Solana registries."""

from __future__ import annotations

from ruglens.chains.cache import BytecodeCache
from ruglens.chains.evm.client import EvmClient
from ruglens.chains.evm.factory import EvmChainFactory
from ruglens.chains.evm.registry import CHAINS, ChainConfig, normalize_chain, resolve_rpc_urls
from ruglens.chains.registry import (
    chain_display_name,
    chain_slug,
    is_solana_chain,
    resolve_chain_selector,
    supported_chain_ids,
)
from ruglens.chains.solana.registry import SOLANA, SOLANA_CHAIN_ID, SolanaConfig

__all__ = [
    "CHAINS",
    "SOLANA",
    "SOLANA_CHAIN_ID",
    "BytecodeCache",
    "ChainConfig",
    "EvmChainFactory",
    "EvmClient",
    "SolanaConfig",
    "chain_display_name",
    "chain_slug",
    "is_solana_chain",
    "normalize_chain",
    "resolve_chain_selector",
    "resolve_rpc_urls",
    "supported_chain_ids",
]
