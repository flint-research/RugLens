"""Solana-specific domain models.

Solana has a different account model, so its hydrated context is intentionally
separate from the EVM ``TokenContext``. Risk, findings, reports, persistence,
and interfaces are shared.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class SolanaCreator(BaseModel):
    """A Metaplex creator entry."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    address: str
    verified: bool = False
    share: int = Field(default=0, ge=0, le=100)


class SolanaMintState(BaseModel):
    """Parsed SPL Token or Token-2022 mint state."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    address: str
    program_id: str
    program_name: str
    mint_authority: str | None = None
    freeze_authority: str | None = None
    supply: int = Field(ge=0)
    decimals: int = Field(ge=0, le=255)
    is_initialized: bool = True
    extensions: tuple[dict[str, Any], ...] = ()
    extension_names: tuple[str, ...] = ()
    extensions_complete: bool = True


class SolanaMetadata(BaseModel):
    """Parsed Metaplex metadata account."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    address: str
    name: str = "Unknown Token"
    symbol: str = "UNKNOWN"
    uri: str = ""
    update_authority: str | None = None
    is_mutable: bool | None = None
    creators: tuple[SolanaCreator, ...] = ()


class SolanaHolder(BaseModel):
    """A largest-account token position and its owner classification."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    token_account: str
    owner: str
    amount: int = Field(ge=0)
    pct_total: float = Field(ge=0.0, le=1.0)
    owner_on_curve: bool = True
    owner_program: str | None = None
    program_controlled: bool = False
    is_burn: bool = False
    tag: str = "wallet"


class SolanaTokenContext(BaseModel):
    """Hydrated, slot-observed Solana token context."""

    model_config = ConfigDict(extra="forbid")

    chain_id: int = 101
    token_address: str
    slot: int = Field(ge=0)
    mint: SolanaMintState
    metadata: SolanaMetadata | None = None
    creator: str | None = None
    creator_source: str | None = None
    creator_verified: bool | None = None
    creator_holdings: int = Field(default=0, ge=0)
    creator_pct_total: float = Field(default=0.0, ge=0.0, le=1.0)
    creator_pct_circulating: float = Field(default=0.0, ge=0.0, le=1.0)
    top_holders: tuple[SolanaHolder, ...] = ()
    circulating_supply: int = Field(default=0, ge=0)
    burn_amount: int = Field(default=0, ge=0)
    burn_pct: float = Field(default=0.0, ge=0.0, le=1.0)
    program_controlled_amount: int = Field(default=0, ge=0)
    program_controlled_pct: float = Field(default=0.0, ge=0.0, le=1.0)
    unique_retail_owners: int = 0
    holders_classified: int = 0
    holders_expected: int = 0
    holder_data_complete: bool = False
    notes: list[str] = Field(default_factory=list)

    @property
    def holder_coverage(self) -> float:
        """Fraction of largest token accounts with a usable owner classification."""
        if self.holders_expected <= 0:
            return 0.0
        return min(1.0, self.holders_classified / self.holders_expected)
