"""Multicall3 encoding and decoding.

Multicall3 is deployed at the same address on Ethereum, BSC, and Base. Batching
metadata, pair, ownership, and holder reads reduces RPC volume by 80-90%.
"""

from __future__ import annotations

from collections.abc import Sequence

from eth_abi.abi import decode, encode
from eth_utils.address import to_checksum_address

from ruglens.core.models import RpcCall, RpcCallResult

MULTICALL3_ADDRESS = "0xcA11bde05977b3631167028862bE2a173976CA11"
AGGREGATE3_SIGNATURE = "aggregate3((address,bool,bytes)[])"
AGGREGATE3_SELECTOR = bytes.fromhex("82ad56cb")


def encode_aggregate3(calls: Sequence[RpcCall]) -> bytes:
    """Encode ``aggregate3((address,bool,bytes)[])`` with allowFailure=True."""
    if not calls:
        raise ValueError("Multicall3 requires at least one call")
    tuples = [(to_checksum_address(call.to), True, call.data) for call in calls]
    encoded: bytes = encode(["(address,bool,bytes)[]"], [tuples])
    return AGGREGATE3_SELECTOR + encoded


def decode_aggregate3(data: bytes) -> list[RpcCallResult]:
    """Decode aggregate3 return data into per-call results."""
    if not data:
        raise ValueError("Empty Multicall3 response")
    decoded = decode(["(bool,bytes)[]"], data)[0]
    return [
        RpcCallResult(success=bool(success), return_data=bytes(payload))
        for success, payload in decoded
    ]
