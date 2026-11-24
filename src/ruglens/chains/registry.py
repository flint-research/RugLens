"""Family-aware chain selection for EVM and Solana."""

from __future__ import annotations

from ruglens.chains.evm.registry import normalize_chain
from ruglens.chains.solana.registry import SOLANA, SOLANA_CHAIN_ID
from ruglens.core.enums import ChainId
from ruglens.core.exceptions import UnsupportedChainError

_SOLANA_ALIASES = {"solana", "sol", "sol-mainnet", "mainnet-solana", "101"}


def is_solana_chain(chain_id: int) -> bool:
    """Whether a numeric chain selector is Solana."""
    return int(chain_id) == SOLANA_CHAIN_ID


def resolve_chain_selector(value: int | str) -> int:
    """Resolve a chain slug/id to the engine's numeric selector."""
    if isinstance(value, bool):
        raise UnsupportedChainError(f"Unsupported chain: {value!r}")
    if isinstance(value, int):
        if value == SOLANA_CHAIN_ID:
            return value
        return int(normalize_chain(value).chain_id)
    key = value.strip().lower()
    if key in _SOLANA_ALIASES:
        return SOLANA_CHAIN_ID
    return int(normalize_chain(value).chain_id)


def chain_display_name(chain_id: int) -> str:
    """Human-readable chain name."""
    if is_solana_chain(chain_id):
        return SOLANA.name
    return normalize_chain(chain_id).name


def chain_slug(chain_id: int) -> str:
    """Short chain selector used in reports and docs."""
    if is_solana_chain(chain_id):
        return SOLANA.slug
    return normalize_chain(chain_id).slug


def supported_chain_ids() -> tuple[int, ...]:
    """All supported engine chain selectors."""
    return (int(ChainId.ETHEREUM), int(ChainId.BSC), int(ChainId.BASE), SOLANA_CHAIN_ID)
