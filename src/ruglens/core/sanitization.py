"""Sanitization helpers for untrusted metadata and trace strings.

Token contracts are adversarial. Metadata may contain ANSI escape sequences,
terminal control codes, HTML, or arbitrarily long strings. Every string that
leaves the chain layer passes through this module.
"""

from __future__ import annotations

import re
from typing import Any

_ANSI_ESCAPE = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_PRINTABLE_ASCII = re.compile(r"[^\x20-\x7e]")
_WHITESPACE = re.compile(r"\s+")


def sanitize_text(value: Any, *, max_length: int = 128, fallback: str = "") -> str:
    """Return a short, printable, terminal-safe representation of ``value``.

    The function strips ANSI escapes and control characters, removes angle
    brackets to neutralize HTML injection, collapses whitespace, and truncates
    to ``max_length`` characters.
    """
    if value is None:
        return fallback
    text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)
    text = _ANSI_ESCAPE.sub("", text)
    text = _CONTROL_CHARS.sub("", text)
    text = _PRINTABLE_ASCII.sub("", text)
    text = text.replace("<", "").replace(">", "")
    text = _WHITESPACE.sub(" ", text).strip()
    if not text:
        return fallback
    return text[:max_length]


def sanitize_token_name(value: Any) -> str:
    """Sanitize an ERC-20 name (max 128 printable characters)."""
    return sanitize_text(value, max_length=128, fallback="Unknown Token")


def sanitize_token_symbol(value: Any) -> str:
    """Sanitize an ERC-20 symbol (max 32 printable characters)."""
    return sanitize_text(value, max_length=32, fallback="UNKNOWN")


def sanitize_reason(value: Any, *, max_length: int = 256) -> str:
    """Sanitize an RPC revert reason or error message."""
    return sanitize_text(value, max_length=max_length, fallback="")
