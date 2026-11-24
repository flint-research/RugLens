"""Base58, PDA, account-parser, and funding-trace tests for Solana."""

from __future__ import annotations

from tests.solana_helpers import (
    build_metadata_data,
    build_mint_account,
    on_curve_address,
    token_account_info,
    wallet_account,
)

from ruglens.chains.solana.base58 import (
    base58_decode,
    base58_encode,
    decode_pubkey,
    is_valid_pubkey,
)
from ruglens.chains.solana.parsers import (
    metadata_address,
    parse_funding_source,
    parse_metaplex_metadata,
    parse_mint_account,
    parse_token_account,
)
from ruglens.chains.solana.pda import find_program_address, is_on_curve, is_pda
from ruglens.chains.solana.registry import (
    METAPLEX_PROGRAM_ID,
    SYSTEM_PROGRAM_ID,
    TOKEN_PROGRAM_ID,
    normalize_solana_address,
)
from ruglens.core.exceptions import InvalidTokenError

USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"


def test_base58_known_vectors_and_round_trip() -> None:
    assert base58_encode(b"\x00" * 32) == SYSTEM_PROGRAM_ID
    assert base58_decode(SYSTEM_PROGRAM_ID) == b"\x00" * 32
    assert base58_decode("1") == b"\x00"
    assert base58_encode(b"") == ""
    for address in (USDC, TOKEN_PROGRAM_ID, METAPLEX_PROGRAM_ID):
        raw = decode_pubkey(address)
        assert len(raw) == 32
        assert base58_encode(raw) == address
        assert is_valid_pubkey(address)
    assert not is_valid_pubkey("not-a-pubkey")
    assert not is_valid_pubkey("0x" + "11" * 20)


def test_normalize_solana_address() -> None:
    assert normalize_solana_address(USDC) == USDC
    try:
        normalize_solana_address("0x" + "11" * 20)
    except ValueError:
        pass
    else:  # pragma: no cover
        raise AssertionError("EVM address should not be a valid Solana public key")


def test_ed25519_curve_and_pda_derivation() -> None:
    wallet = on_curve_address("curve-test")
    assert is_on_curve(decode_pubkey(wallet))
    pda, bump = find_program_address([b"ruglens-test"], decode_pubkey(TOKEN_PROGRAM_ID))
    assert is_pda(pda)
    assert not is_on_curve(decode_pubkey(pda))
    again, again_bump = find_program_address([b"ruglens-test"], decode_pubkey(TOKEN_PROGRAM_ID))
    assert (pda, bump) == (again, again_bump)
    assert 0 <= bump <= 255
    metadata_pda = metadata_address(USDC)
    assert is_pda(metadata_pda)


def test_mint_parser_json_and_raw() -> None:
    mint = on_curve_address("mint-parser")
    authority = on_curve_address("mint-parser-authority")
    freeze = on_curve_address("mint-parser-freeze")
    account = build_mint_account(
        mint,
        supply=1_000_000,
        decimals=6,
        mint_authority=authority,
        freeze_authority=freeze,
        token_2022=True,
        extensions=[{"extension": "permanentDelegate", "state": {"delegate": authority}}],
    )
    state = parse_mint_account(mint, account)
    assert state.mint_authority == authority
    assert state.freeze_authority == freeze
    assert state.supply == 1_000_000
    assert state.decimals == 6
    assert state.program_name == "Token-2022"
    assert state.extension_names == ("permanentDelegate",)

    raw = bytearray(82)
    raw[0:4] = (1).to_bytes(4, "little")
    raw[4:36] = decode_pubkey(authority)
    raw[36:44] = (1234).to_bytes(8, "little")
    raw[44] = 9
    raw[45] = 1
    raw[46:50] = (0).to_bytes(4, "little")
    raw_account = {
        "owner": TOKEN_PROGRAM_ID,
        "data": [base58_encode(bytes(raw)), "base64"],
    }
    # Use a valid base64 encoding instead of base58 for the raw path.
    import base64

    raw_account["data"] = [base64.b64encode(bytes(raw)).decode(), "base64"]
    raw_state = parse_mint_account(mint, raw_account)
    assert raw_state.supply == 1234
    assert raw_state.decimals == 9
    assert raw_state.mint_authority == authority
    assert raw_state.freeze_authority is None


def test_mint_parser_rejects_non_mint() -> None:
    try:
        parse_mint_account("x", {"owner": SYSTEM_PROGRAM_ID, "data": {}})
    except InvalidTokenError:
        pass
    else:  # pragma: no cover
        raise AssertionError("non-mint should be rejected")


def test_metadata_parser() -> None:
    mint = on_curve_address("metadata-mint")
    creator = on_curve_address("metadata-creator")
    update_authority = on_curve_address("metadata-update")
    data = build_metadata_data(
        mint=mint,
        creator=creator,
        update_authority=update_authority,
        mutable=True,
        name="RugLens Test",
        symbol="RUG",
    )
    import base64

    metadata = parse_metaplex_metadata(
        "meta",
        {"owner": METAPLEX_PROGRAM_ID, "data": [base64.b64encode(data).decode(), "base64"]},
    )
    assert metadata.name == "RugLens Test"
    assert metadata.symbol == "RUG"
    assert metadata.update_authority == update_authority
    assert metadata.is_mutable is True
    assert metadata.creators[0].address == creator
    assert metadata.creators[0].verified is True


def test_token_account_parser() -> None:
    owner = on_curve_address("token-owner")
    parsed = parse_token_account(token_account_info(owner, 42, 9))
    assert parsed == (owner, 42, "initialized")


def test_funding_source_parser() -> None:
    funder = on_curve_address("funder")
    wallet = on_curve_address("funded-wallet")
    tx = {
        "meta": {
            "preBalances": [10_000_000_000, 0],
            "postBalances": [8_999_995_000, 1_000_000_000],
        },
        "transaction": {
            "message": {
                "accountKeys": [
                    {"pubkey": funder, "signer": True},
                    {"pubkey": wallet, "signer": False},
                ]
            }
        },
    }
    assert parse_funding_source(tx, wallet) == funder
    assert parse_funding_source(tx, funder) is None


def test_wallet_owner_metadata_shape() -> None:
    assert wallet_account()["owner"] == SYSTEM_PROGRAM_ID
