"""Minimal, dependency-free Base58 codec for Solana public keys and signatures."""

from __future__ import annotations

_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_INDEX = {char: index for index, char in enumerate(_ALPHABET)}


def base58_encode(data: bytes) -> str:
    """Encode bytes using Bitcoin/Solana Base58."""
    if not data:
        return ""
    zeroes = len(data) - len(data.lstrip(b"\x00"))
    number = int.from_bytes(data, "big")
    encoded: list[str] = []
    while number > 0:
        number, remainder = divmod(number, 58)
        encoded.append(_ALPHABET[remainder])
    return "1" * zeroes + "".join(reversed(encoded))


def base58_decode(text: str) -> bytes:
    """Decode Base58 text, rejecting invalid characters."""
    if not text:
        return b""
    value = 0
    for char in text:
        try:
            digit = _INDEX[char]
        except KeyError as exc:
            raise ValueError(f"invalid Base58 character: {char!r}") from exc
        value = value * 58 + digit
    zeroes = len(text) - len(text.lstrip("1"))
    payload = b"" if value == 0 else value.to_bytes((value.bit_length() + 7) // 8, "big")
    return b"\x00" * zeroes + payload


def decode_pubkey(address: str) -> bytes:
    """Decode a Solana public key and require exactly 32 bytes."""
    if not isinstance(address, str) or not address:
        raise ValueError("public key must be a non-empty string")
    payload = base58_decode(address)
    if len(payload) != 32:
        raise ValueError(f"Solana public key must decode to 32 bytes, got {len(payload)}")
    return payload


def encode_pubkey(payload: bytes) -> str:
    """Encode 32 raw bytes as a Solana address."""
    if len(payload) != 32:
        raise ValueError("Solana public keys are 32 bytes")
    return base58_encode(payload)


def is_valid_pubkey(address: str) -> bool:
    """Whether a string is a syntactically valid Solana public key."""
    try:
        decode_pubkey(address)
    except ValueError:
        return False
    return True
