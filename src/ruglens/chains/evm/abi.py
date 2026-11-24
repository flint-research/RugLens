"""ABI constants and small, defensive decoders for on-chain reads."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from eth_abi.abi import decode, encode
from eth_utils.address import to_checksum_address
from eth_utils.crypto import keccak

from ruglens.core.sanitization import sanitize_reason


def selector(signature: str) -> bytes:
    """Return the 4-byte selector for an ABI signature."""
    return keccak(text=signature)[:4]


class Selectors:
    """Selectors used across the engine."""

    NAME = selector("name()")
    SYMBOL = selector("symbol()")
    DECIMALS = selector("decimals()")
    TOTAL_SUPPLY = selector("totalSupply()")
    BALANCE_OF = selector("balanceOf(address)")
    ALLOWANCE = selector("allowance(address,address)")
    APPROVE = selector("approve(address,uint256)")
    TRANSFER = selector("transfer(address,uint256)")
    OWNER = selector("owner()")
    GET_OWNER = selector("getOwner()")
    GET_PAIR = selector("getPair(address,address)")
    TOKEN0 = selector("token0()")
    TOKEN1 = selector("token1()")
    GET_RESERVES = selector("getReserves()")
    FACTORY = selector("factory()")
    GET_AMOUNTS_OUT = selector("getAmountsOut(uint256,address[])")
    SWAP_EXACT_ETH_FOR_TOKENS = selector(
        "swapExactETHForTokensSupportingFeeOnTransferTokens(uint256,address[],address,uint256)"
    )
    SWAP_EXACT_TOKENS_FOR_ETH = selector(
        "swapExactTokensForETHSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)"
    )
    WETH_DEPOSIT = selector("deposit()")
    GET_THRESHOLD = selector("getThreshold()")
    GET_OWNERS = selector("getOwners()")
    GET_MIN_DELAY = selector("getMinDelay()")
    DELAY = selector("delay()")
    QUEUE_TRANSACTION = selector("queueTransaction(address,uint256,string,bytes,uint256)")
    EXECUTE_TRANSACTION = selector("executeTransaction(address,uint256,string,bytes,uint256)")


TRANSFER_EVENT_TOPIC = "0x" + keccak(text="Transfer(address,address,uint256)").hex()

# EIP-1967 standard storage slots.
EIP1967_IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
EIP1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
EIP1967_BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
DEAD_ADDRESS = "0x000000000000000000000000000000000000dEaD"
BURN_ADDRESSES: tuple[str, ...] = (ZERO_ADDRESS, DEAD_ADDRESS)


def encode_call(signature: str, arg_types: Sequence[str], args: Sequence[Any]) -> bytes:
    """Encode a function call selector and ABI arguments."""
    return selector(signature) + encode(list(arg_types), list(args))


def encode_balance_of(owner: str) -> bytes:
    """Encode ``balanceOf(owner)``."""
    return Selectors.BALANCE_OF + encode(["address"], [to_checksum_address(owner)])


def decode_uint(data: bytes, *, bits: int = 256) -> int:
    """Decode a single unsigned integer, rejecting malformed payloads."""
    if len(data) < 32:
        raise ValueError("ABI uint payload is shorter than 32 bytes")
    value: int = decode([f"uint{bits}"], data[:32])[0]
    return value


def decode_address(data: bytes) -> str:
    """Decode an ABI-encoded address into checksum form."""
    if len(data) < 32:
        raise ValueError("ABI address payload is shorter than 32 bytes")
    raw: str = decode(["address"], data[:32])[0]
    return to_checksum_address(raw)


def decode_uint_array(data: bytes) -> list[int]:
    """Decode a dynamic ``uint256[]`` return value."""
    if not data:
        raise ValueError("Empty uint256[] payload")
    values = decode(["uint256[]"], data)[0]
    return [int(value) for value in values]


def decode_reserves(data: bytes) -> tuple[int, int, int]:
    """Decode ``getReserves()`` into ``(reserve0, reserve1, timestamp)``."""
    if len(data) < 96:
        raise ValueError("Malformed getReserves payload")
    reserve0, reserve1, timestamp = decode(["uint112", "uint112", "uint32"], data[:96])
    return int(reserve0), int(reserve1), int(timestamp)


def decode_bool(data: bytes) -> bool:
    """Decode an ABI boolean."""
    return bool(decode_uint(data))


def decode_string_or_bytes32(data: bytes) -> str | None:
    """Decode token name/symbol, tolerating non-standard bytes32 returns."""
    if not data:
        return None
    if len(data) >= 64:
        try:
            value: str = decode(["string"], data)[0]
            return value
        except Exception:
            pass
    try:
        raw = data[:32]
        value_bytes = raw.split(b"\x00", 1)[0]
        return value_bytes.decode("utf-8", errors="replace")
    except Exception:
        return None


def decode_revert_reason(data: bytes | None) -> str:
    """Decode an Error(string), Panic(uint256), or unknown revert payload."""
    if not data:
        return ""
    try:
        if data[:4] == selector("Error(string)"):
            reason: str = decode(["string"], data[4:])[0]
            return sanitize_reason(reason)
        if data[:4] == selector("Panic(uint256)"):
            code = decode_uint(data[4:])
            return sanitize_reason(f"Panic(0x{code:02x})")
    except Exception:
        pass
    return sanitize_reason("0x" + data[:196].hex())


def topic_to_address(topic: str) -> str:
    """Extract a checksummed address from a 32-byte log topic."""
    raw = topic[2:] if topic.startswith("0x") else topic
    if len(raw) != 64:
        raise ValueError("Log topic is not 32 bytes")
    return to_checksum_address("0x" + raw[-40:])


def hex_data_to_bytes(data: str | bytes | None) -> bytes:
    """Decode 0x-prefixed hex, accepting bytes and empty values."""
    if data is None:
        return b""
    if isinstance(data, bytes):
        return data
    if not data:
        return b""
    raw = data[2:] if data.startswith("0x") else data
    if len(raw) % 2:
        raise ValueError("Odd-length hex payload")
    return bytes.fromhex(raw)
