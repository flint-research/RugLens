"""Solana program-derived address derivation and Ed25519 on-curve checks.

This avoids pulling a Rust/Solana SDK into the engine. The curve check follows
the standard Ed25519 compressed-point decompression test used by Solana's
``Pubkey::is_on_curve``.
"""

from __future__ import annotations

import hashlib

from ruglens.chains.solana.base58 import decode_pubkey, encode_pubkey

_P = 2**255 - 19
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)
_MAX_SEED_LENGTH = 32


def is_on_curve(pubkey: bytes) -> bool:
    """Return True when 32 bytes decompress to a valid Ed25519 point."""
    if len(pubkey) != 32:
        raise ValueError("Ed25519 public keys are 32 bytes")
    y = int.from_bytes(pubkey, "little") & ((1 << 255) - 1)
    if y >= _P:
        return False
    y_squared = (y * y) % _P
    numerator = (y_squared - 1) % _P
    denominator = (_D * y_squared + 1) % _P
    x_squared = (numerator * pow(denominator, _P - 2, _P)) % _P
    x = pow(x_squared, (_P + 3) // 8, _P)
    if (x * x - x_squared) % _P != 0:
        x = (x * _SQRT_M1) % _P
    return (x * x - x_squared) % _P == 0


def create_program_address(seeds: list[bytes], program_id: bytes) -> bytes:
    """Derive one program address for a specific seed set (no bump loop)."""
    if len(seeds) > 16:
        raise ValueError("Solana allows at most 16 PDA seeds")
    for seed in seeds:
        if len(seed) > _MAX_SEED_LENGTH:
            raise ValueError("Solana PDA seeds may be at most 32 bytes")
    digest = hashlib.sha256(b"".join(seeds) + program_id + b"ProgramDerivedAddress").digest()
    if is_on_curve(digest):
        raise ValueError("derived address is on the Ed25519 curve")
    return digest


def find_program_address(seeds: list[bytes], program_id: bytes) -> tuple[str, int]:
    """Find the canonical Solana PDA and bump seed."""
    for bump in range(255, -1, -1):
        try:
            address = create_program_address([*seeds, bytes([bump])], program_id)
        except ValueError:
            continue
        return encode_pubkey(address), bump
    raise ValueError("could not find a viable program address")


def find_program_address_bytes(seeds: list[bytes], program_id: bytes) -> tuple[bytes, int]:
    """Bytes variant of :func:`find_program_address`."""
    for bump in range(255, -1, -1):
        try:
            address = create_program_address([*seeds, bytes([bump])], program_id)
        except ValueError:
            continue
        return address, bump
    raise ValueError("could not find a viable program address")


def is_pda(address: str) -> bool:
    """Whether an address lies off the Ed25519 curve (PDA-like)."""
    return not is_on_curve(decode_pubkey(address))
