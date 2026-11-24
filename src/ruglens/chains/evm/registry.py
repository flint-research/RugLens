"""Chain registry for the V1 EVM networks.

Only public, protocol-level constants live here. No third-party security API is
ever consulted.
"""

from __future__ import annotations

import os
from collections.abc import Sequence

from pydantic import BaseModel, ConfigDict

from ruglens.core.enums import ChainId
from ruglens.core.exceptions import ConfigurationError, UnsupportedChainError


class ChainConfig(BaseModel):
    """Static configuration for one EVM chain."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    chain_id: int
    slug: str
    name: str
    native_symbol: str
    weth: str
    v2_router: str
    v2_factory: str
    multicall3: str
    default_rpc_urls: tuple[str, ...]
    rpc_env_vars: tuple[str, ...]
    explorer_url: str
    known_lp_lockers: tuple[str, ...] = ()
    block_time_seconds: int = 12
    notes: str = ""


ETHEREUM = ChainConfig(
    chain_id=ChainId.ETHEREUM,
    slug="ethereum",
    name="Ethereum Mainnet",
    native_symbol="ETH",
    weth="0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
    v2_router="0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
    v2_factory="0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f",
    multicall3="0xcA11bde05977b3631167028862bE2a173976CA11",
    default_rpc_urls=(
        "https://ethereum-rpc.publicnode.com",
        "https://eth.llamarpc.com",
    ),
    rpc_env_vars=("RUGLENS_RPC_URL_ETHEREUM", "RUGLENS_ETH_RPC_URL", "RUGLENS_RPC_URL_1"),
    explorer_url="https://etherscan.io",
    known_lp_lockers=(
        "0x663A5C229c09b049E36dCc11a9B0d4a8Eb9ee9D6",  # Unicrypt liquidity lock
        "0x71B5759d73262FBb223956913ecF4ecC51057641",  # PinkLock V2
        "0xE2fE530C047f2d85298b07D9333C05737f1435fB",  # Team Finance lock
    ),
    block_time_seconds=12,
    notes="Uniswap V2 router/factory.",
)

BSC = ChainConfig(
    chain_id=ChainId.BSC,
    slug="bsc",
    name="BNB Smart Chain",
    native_symbol="BNB",
    weth="0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c",
    v2_router="0x10ED43C718714eb63d5aA57B78B54704E256024E",
    v2_factory="0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73",
    multicall3="0xcA11bde05977b3631167028862bE2a173976CA11",
    default_rpc_urls=(
        "https://bsc-dataseed.binance.org",
        "https://bsc-rpc.publicnode.com",
    ),
    rpc_env_vars=("RUGLENS_RPC_URL_BSC", "RUGLENS_BSC_RPC_URL", "RUGLENS_RPC_URL_56"),
    explorer_url="https://bscscan.com",
    known_lp_lockers=(
        "0x663A5C229c09b049E36dCc11a9B0d4a8Eb9ee9D6",  # Unicrypt liquidity lock
        "0x71B5759d73262FBb223956913ecF4ecC51057641",  # PinkLock V2
    ),
    block_time_seconds=3,
    notes="PancakeSwap V2 router/factory. WBNB is the wrapped native token.",
)

BASE = ChainConfig(
    chain_id=ChainId.BASE,
    slug="base",
    name="Base Mainnet",
    native_symbol="ETH",
    weth="0x4200000000000000000000000000000000000006",
    v2_router="0x327Df1E6de05895d2ab08513aaDD9313Fe505d86",
    v2_factory="0x71524B4f93c58fcbF659783284E38825f0622859",
    multicall3="0xcA11bde05977b3631167028862bE2a173976CA11",
    default_rpc_urls=(
        "https://mainnet.base.org",
        "https://base-rpc.publicnode.com",
    ),
    rpc_env_vars=("RUGLENS_RPC_URL_BASE", "RUGLENS_BASE_RPC_URL", "RUGLENS_RPC_URL_8453"),
    explorer_url="https://basescan.org",
    block_time_seconds=2,
    notes="BaseSwap V2 router/factory. BaseSwap is the dominant V2 venue on Base.",
)

CHAINS: dict[int, ChainConfig] = {
    int(ETHEREUM.chain_id): ETHEREUM,
    int(BSC.chain_id): BSC,
    int(BASE.chain_id): BASE,
}

_ALIASES: dict[str, int] = {
    "eth": int(ChainId.ETHEREUM),
    "ethereum": int(ChainId.ETHEREUM),
    "mainnet": int(ChainId.ETHEREUM),
    "1": int(ChainId.ETHEREUM),
    "bsc": int(ChainId.BSC),
    "bnb": int(ChainId.BSC),
    "binance": int(ChainId.BSC),
    "56": int(ChainId.BSC),
    "base": int(ChainId.BASE),
    "8453": int(ChainId.BASE),
}


def normalize_chain(value: int | str) -> ChainConfig:
    """Resolve a chain id, numeric string, slug, or alias to a config."""
    if isinstance(value, bool):
        raise UnsupportedChainError(f"Unsupported chain: {value!r}")
    if isinstance(value, int):
        chain_id = value
    else:
        key = value.strip().lower()
        if key in _ALIASES:
            chain_id = _ALIASES[key]
        else:
            try:
                chain_id = int(key)
            except ValueError as exc:
                raise UnsupportedChainError(
                    f"Unsupported chain {value!r}; supported: eth, bsc, base"
                ) from exc
    config = CHAINS.get(chain_id)
    if config is None:
        supported = ", ".join(f"{c.slug}({c.chain_id})" for c in CHAINS.values())
        raise UnsupportedChainError(f"Unsupported chain {value!r}; supported: {supported}")
    return config


def resolve_rpc_urls(
    chain: ChainConfig,
    explicit: Sequence[str] | str | None = None,
) -> tuple[str, ...]:
    """Resolve RPC URLs from an explicit value, environment, or defaults."""
    if explicit is not None:
        provided = [explicit] if isinstance(explicit, str) else list(explicit)
        cleaned = [url.strip() for url in provided if url and url.strip()]
        if not cleaned:
            raise ConfigurationError("Explicit RPC URL list is empty")
        return tuple(cleaned)

    for env_var in chain.rpc_env_vars:
        raw = os.environ.get(env_var, "").strip()
        if raw:
            urls = tuple(part.strip() for part in raw.split(",") if part.strip())
            if urls:
                return urls
    return chain.default_rpc_urls


def is_supported_chain(chain_id: int) -> bool:
    """Whether a chain id is registered."""
    return chain_id in CHAINS
