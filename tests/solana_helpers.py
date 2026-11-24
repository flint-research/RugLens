"""Offline Solana fixtures and fake JSON-RPC chain adapter for tests."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field
from typing import Any

from ruglens.chains.solana.base58 import base58_encode, decode_pubkey
from ruglens.chains.solana.parsers import metadata_address
from ruglens.chains.solana.pda import find_program_address, is_on_curve
from ruglens.chains.solana.registry import (
    BURN_ADDRESSES,
    METAPLEX_PROGRAM_ID,
    SYSTEM_PROGRAM_ID,
    TOKEN_2022_PROGRAM_ID,
    TOKEN_PROGRAM_ID,
)
from ruglens.core.exceptions import RpcError


def on_curve_address(seed: str) -> str:
    """Deterministically generate an on-curve Solana wallet address."""
    counter = 0
    while True:
        raw = hashlib.sha256(f"ruglens-test:{seed}:{counter}".encode()).digest()
        if is_on_curve(raw):
            return base58_encode(raw)
        counter += 1


def off_curve_address(seed: str) -> str:
    """Deterministically generate an off-curve PDA-like address."""
    address, _ = find_program_address(
        [hashlib.sha256(f"ruglens-pda:{seed}".encode()).digest()],
        decode_pubkey(TOKEN_PROGRAM_ID),
    )
    return address


def token_account_address(seed: str) -> str:
    """Generate a token-account-like address."""
    return off_curve_address(f"token-account:{seed}")


def _padded(value: str, length: int) -> bytes:
    raw = value.encode("utf-8")[:length]
    return raw + b"\x00" * (length - len(raw))


def build_metadata_data(
    *,
    mint: str,
    creator: str | None,
    update_authority: str | None,
    mutable: bool,
    name: str = "Test Token",
    symbol: str = "TEST",
    uri: str = "https://example.invalid/token.json",
) -> bytes:
    """Build a Metaplex MetadataV1 account body."""
    data = bytearray(324)
    data[0] = 4
    if update_authority:
        data[1:33] = decode_pubkey(update_authority)
    data[33:65] = decode_pubkey(mint)
    data[65:69] = len(name.encode("utf-8")[:32]).to_bytes(4, "little")
    data[69:101] = _padded(name, 32)
    data[101:105] = len(symbol.encode("utf-8")[:10]).to_bytes(4, "little")
    data[105:115] = _padded(symbol, 10)
    data[115:119] = len(uri.encode("utf-8")[:200]).to_bytes(4, "little")
    data[119:319] = _padded(uri, 200)
    data[319:321] = (0).to_bytes(2, "little")
    if creator:
        data[321] = 1
        data[322:326] = (1).to_bytes(4, "little")
        data.extend(decode_pubkey(creator))
        data.append(1)  # verified
        data.append(100)  # share
        data.append(0)  # primary_sale_happened
        data.append(1 if mutable else 0)  # is_mutable
    else:
        data[321] = 0
        data[322] = 0  # primary_sale_happened
        data[323] = 1 if mutable else 0  # is_mutable
    return bytes(data)


def build_mint_account(
    mint: str,
    *,
    supply: int,
    decimals: int = 9,
    mint_authority: str | None = None,
    freeze_authority: str | None = None,
    token_2022: bool = False,
    extensions: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a jsonParsed mint account."""
    program_id = TOKEN_2022_PROGRAM_ID if token_2022 else TOKEN_PROGRAM_ID
    info: dict[str, Any] = {
        "mintAuthority": mint_authority,
        "supply": str(supply),
        "decimals": decimals,
        "isInitialized": True,
        "freezeAuthority": freeze_authority,
    }
    if extensions:
        info["extensions"] = extensions
    return {
        "owner": program_id,
        "executable": False,
        "lamports": 1_000_000,
        "data": {
            "program": "spl-token-2022" if token_2022 else "spl-token",
            "parsed": {"type": "mint", "info": info},
            "space": 82,
        },
    }


def metadata_account(
    mint: str,
    *,
    creator: str | None,
    update_authority: str | None,
    mutable: bool,
    name: str = "Test Token",
    symbol: str = "TEST",
) -> tuple[str, dict[str, Any]]:
    """Return the metadata PDA and a base64 account response."""
    address = metadata_address(mint)
    data = build_metadata_data(
        mint=mint,
        creator=creator,
        update_authority=update_authority,
        mutable=mutable,
        name=name,
        symbol=symbol,
    )
    return address, {
        "owner": METAPLEX_PROGRAM_ID,
        "executable": False,
        "lamports": 1_000_000,
        "data": [base64.b64encode(data).decode(), "base64"],
    }


def token_account_info(owner: str, amount: int, decimals: int = 9) -> dict[str, Any]:
    """Build a jsonParsed token account."""
    return {
        "owner": TOKEN_PROGRAM_ID,
        "executable": False,
        "lamports": 2_000_000,
        "data": {
            "program": "spl-token",
            "parsed": {
                "type": "account",
                "info": {
                    "owner": owner,
                    "tokenAmount": {
                        "amount": str(amount),
                        "decimals": decimals,
                        "uiAmount": amount / 10**decimals,
                        "uiAmountString": str(amount / 10**decimals),
                    },
                    "state": "initialized",
                },
            },
            "space": 165,
        },
    }


def wallet_account() -> dict[str, Any]:
    """System-owned wallet account metadata."""
    return {
        "owner": SYSTEM_PROGRAM_ID,
        "executable": False,
        "lamports": 1_000_000_000,
        "data": ["", "base64"],
    }


@dataclass
class FakeSolanaChain:
    """Scriptable Solana JSON-RPC adapter for the native engine tests."""

    slot: int = 1_000
    mint_address: str = ""
    mint_account: dict[str, Any] | None = None
    metadata_accounts: dict[str, dict[str, Any]] = field(default_factory=dict)
    largest_accounts: list[dict[str, Any]] = field(default_factory=list)
    token_account_infos: dict[str, dict[str, Any]] = field(default_factory=dict)
    owner_infos: dict[str, dict[str, Any] | None] = field(default_factory=dict)
    signatures: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    transactions: dict[str, dict[str, Any] | None] = field(default_factory=dict)
    accounts_by_owner: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    funding_error: bool = False
    rpc_calls_count: int = 0
    closed: bool = False
    supply_value: dict[str, Any] = field(default_factory=dict)

    @property
    def rpc_calls(self) -> int:
        return self.rpc_calls_count

    async def get_slot(self) -> int:
        self.rpc_calls_count += 1
        return self.slot

    async def get_account_info(
        self,
        address: str,
        *,
        encoding: str = "jsonParsed",
    ) -> dict[str, Any] | None:
        self.rpc_calls_count += 1
        if address == self.mint_address:
            return self.mint_account
        if address in self.metadata_accounts:
            return self.metadata_accounts[address]
        if address in self.token_account_infos:
            return self.token_account_infos[address]
        if address in self.owner_infos:
            return self.owner_infos[address]
        return None

    async def get_multiple_accounts(
        self,
        addresses: list[str],
        *,
        encoding: str = "jsonParsed",
    ) -> list[dict[str, Any] | None]:
        self.rpc_calls_count += 1
        values: list[dict[str, Any] | None] = []
        for address in addresses:
            values.append(
                self.metadata_accounts.get(address)
                or self.token_account_infos.get(address)
                or self.owner_infos.get(address)
            )
        return values

    async def get_token_largest_accounts(self, mint: str) -> list[dict[str, Any]]:
        self.rpc_calls_count += 1
        return self.largest_accounts

    async def get_token_supply(self, mint: str) -> dict[str, Any]:
        self.rpc_calls_count += 1
        return self.supply_value

    async def get_signatures_for_address(
        self,
        address: str,
        *,
        limit: int,
        before: str | None = None,
    ) -> list[dict[str, Any]]:
        self.rpc_calls_count += 1
        if self.funding_error:
            raise RpcError("funding history unavailable")
        return self.signatures.get(address, [])

    async def get_transaction(self, signature: str) -> dict[str, Any] | None:
        self.rpc_calls_count += 1
        return self.transactions.get(signature)

    async def get_token_accounts_by_owner(
        self,
        owner: str,
        mint: str,
    ) -> list[dict[str, Any]]:
        self.rpc_calls_count += 1
        return self.accounts_by_owner.get(owner, [])

    async def close(self) -> None:
        self.closed = True


class FakeSolanaRpcFactory:
    """Returns one fake Solana chain."""

    def __init__(self, chain: FakeSolanaChain) -> None:
        self.chain = chain
        self.closed = False

    def get_client(self, rpc_urls=None) -> FakeSolanaChain:
        return self.chain

    async def close(self) -> None:
        self.closed = True


@dataclass(frozen=True, slots=True)
class SolanaScenario:
    """A fully wired Solana test scenario."""

    chain: FakeSolanaChain
    mint: str
    creator: str
    wallets: tuple[str, ...]
    metadata_pda: str


def _funding_transaction(funder: str, wallet: str, amount: int = 1_000_000_000) -> dict[str, Any]:
    return {
        "meta": {
            "preBalances": [10 * amount, 0],
            "postBalances": [9 * amount, amount],
            "fee": 5000,
            "err": None,
        },
        "transaction": {
            "signatures": [f"funding-{wallet}"],
            "message": {
                "accountKeys": [
                    {"pubkey": funder, "signer": True, "writable": True},
                    {"pubkey": wallet, "signer": False, "writable": True},
                ],
                "instructions": [],
            },
        },
    }


def build_scenario(
    name: str,
    *,
    supply: int = 1_000_000_000,
    mint_authority: str | None = None,
    freeze_authority: str | None = None,
    token_2022: bool = False,
    extensions: list[dict[str, Any]] | None = None,
    creator_amount: int = 2_000_000,
    retail_amounts: list[int] | None = None,
    pool_amount: int = 300_000_000,
    burn_amount: int = 100_000_000,
    metadata_mutable: bool = False,
    shared_funder_wallets: int = 0,
    funding_error: bool = False,
) -> SolanaScenario:
    """Build a deterministic Solana token scenario.

    ``retail_amounts`` are token-account amounts for distinct on-curve wallets.
    A pool token account owned by an off-curve PDA is included when pool_amount > 0.
    """
    mint = on_curve_address(f"{name}:mint")
    creator = on_curve_address(f"{name}:creator")
    wallets = tuple(on_curve_address(f"{name}:wallet:{index}") for index in range(10))
    amounts = retail_amounts or [10_000_000] * 10
    if len(amounts) != len(wallets):
        raise ValueError("retail_amounts must match the ten test wallets")

    metadata_pda, metadata = metadata_account(
        mint,
        creator=creator,
        update_authority=creator if metadata_mutable else None,
        mutable=metadata_mutable,
        name=f"{name.title()} Token",
        symbol=name[:8].upper(),
    )
    chain = FakeSolanaChain(
        slot=1_234_567,
        mint_address=mint,
        mint_account=build_mint_account(
            mint,
            supply=supply,
            mint_authority=mint_authority,
            freeze_authority=freeze_authority,
            token_2022=token_2022,
            extensions=extensions,
        ),
        metadata_accounts={metadata_pda: metadata},
        funding_error=funding_error,
        supply_value={"amount": str(supply), "decimals": 9, "uiAmountString": str(supply / 1e9)},
    )
    if creator_amount > 0:
        chain.accounts_by_owner[creator] = [token_account_info(creator, creator_amount)]

    top_items: list[tuple[str, str, int]] = []
    for index, (wallet, amount) in enumerate(zip(wallets, amounts, strict=True)):
        account = token_account_address(f"{name}:wallet-account:{index}")
        chain.token_account_infos[account] = token_account_info(wallet, amount)
        chain.owner_infos[wallet] = wallet_account()
        top_items.append((account, wallet, amount))
    if pool_amount > 0:
        pool_owner = off_curve_address(f"{name}:pool")
        account = token_account_address(f"{name}:pool-account")
        chain.token_account_infos[account] = token_account_info(pool_owner, pool_amount)
        top_items.append((account, pool_owner, pool_amount))
    if burn_amount > 0:
        burn_owner = BURN_ADDRESSES[0]
        account = token_account_address(f"{name}:burn-account")
        chain.token_account_infos[account] = token_account_info(burn_owner, burn_amount)
        top_items.append((account, burn_owner, burn_amount))
    top_items.sort(key=lambda item: -item[2])
    chain.largest_accounts = [
        {
            "address": account,
            "amount": str(amount),
            "decimals": 9,
            "uiAmount": amount / 1e9,
            "uiAmountString": str(amount / 1e9),
        }
        for account, _, amount in top_items
    ]

    if shared_funder_wallets:
        funder = on_curve_address(f"{name}:shared-funder")
        chain.owner_infos[funder] = wallet_account()
        for wallet in wallets[:shared_funder_wallets]:
            signature = f"sig-{wallet}"
            chain.signatures[wallet] = [{"signature": signature}]
            chain.transactions[signature] = _funding_transaction(funder, wallet)

    return SolanaScenario(
        chain=chain,
        mint=mint,
        creator=creator,
        wallets=wallets,
        metadata_pda=metadata_pda,
    )


def clean_scenario() -> SolanaScenario:
    return build_scenario("clean")


def rug_scenario() -> SolanaScenario:
    extension = [
        {
            "extension": "transferFeeConfig",
            "state": {
                "newerTransferFee": {
                    "transferFeeBasisPoints": 6000,
                    "maximumFee": "1000000000",
                }
            },
        }
    ]
    scenario = build_scenario(
        "rug",
        mint_authority=on_curve_address("rug:mint-authority"),
        freeze_authority=on_curve_address("rug:freeze-authority"),
        token_2022=True,
        extensions=extension,
        creator_amount=250_000_000,
        retail_amounts=[150_000_000, 150_000_000, 150_000_000, *([20_000_000] * 7)],
        pool_amount=0,
        burn_amount=0,
        metadata_mutable=True,
        shared_funder_wallets=3,
    )
    return scenario


def moderate_scenario() -> SolanaScenario:
    return build_scenario(
        "moderate",
        creator_amount=100_000_000,
        retail_amounts=[30_000_000, 30_000_000, 30_000_000, *([20_000_000] * 7)],
        pool_amount=300_000_000,
        burn_amount=50_000_000,
        shared_funder_wallets=3,
    )


def unknown_cluster_scenario() -> SolanaScenario:
    return build_scenario("unknown-cluster", funding_error=True)


__all__ = [
    "FakeSolanaChain",
    "FakeSolanaRpcFactory",
    "SolanaScenario",
    "build_metadata_data",
    "build_mint_account",
    "build_scenario",
    "clean_scenario",
    "metadata_account",
    "moderate_scenario",
    "off_curve_address",
    "on_curve_address",
    "rug_scenario",
    "token_account_address",
    "token_account_info",
    "unknown_cluster_scenario",
    "wallet_account",
]
