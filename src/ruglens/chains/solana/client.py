"""Async Solana JSON-RPC client with failover, rate limiting, and response caps."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from collections.abc import Sequence
from itertools import count
from typing import Any
from urllib.parse import urlparse

import httpx

from ruglens.core.config import RugLensSettings
from ruglens.core.exceptions import (
    ConfigurationError,
    RateLimitError,
    RpcError,
    RpcResponseTooLargeError,
    RpcTimeoutError,
)

logger = logging.getLogger(__name__)

_RETRYABLE_MARKERS = (
    "429",
    "500",
    "502",
    "503",
    "504",
    "rate limit",
    "too many",
    "timeout",
    "temporarily unavailable",
    "connection",
    "connect",
    "network",
    "unreachable",
)


class _TokenBucket:
    def __init__(self, rate_per_second: float) -> None:
        self._rate = rate_per_second
        self._capacity = max(1.0, rate_per_second)
        self._tokens = self._capacity
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            self._tokens = min(
                self._capacity,
                self._tokens + max(0.0, now - self._last) * self._rate,
            )
            self._last = now
            if self._tokens < 1.0:
                await asyncio.sleep((1.0 - self._tokens) / self._rate)
                self._tokens = 0.0
                self._last = time.monotonic()
            else:
                self._tokens -= 1.0


def _validate_endpoint(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ConfigurationError(f"Invalid Solana RPC URL: {url!r}")
    return url


def _is_retryable(error: Exception) -> bool:
    if isinstance(error, RateLimitError):
        return True
    text = str(error).lower()
    return any(marker in text for marker in _RETRYABLE_MARKERS)


class SolanaRpcClient:
    """Read-only Solana JSON-RPC access for one assessment."""

    def __init__(
        self,
        settings: RugLensSettings,
        rpc_urls: Sequence[str],
    ) -> None:
        urls = list(dict.fromkeys(_validate_endpoint(url) for url in rpc_urls))
        if not urls:
            raise ConfigurationError("No Solana RPC URLs configured")
        self._settings = settings
        self._urls = urls
        self._http = httpx.AsyncClient(
            timeout=httpx.Timeout(
                settings.rpc_timeout,
                connect=settings.rpc_connect_timeout,
            ),
            follow_redirects=False,
        )
        self._limit = _TokenBucket(settings.rpc_rate_limit_per_second)
        self._semaphore = asyncio.Semaphore(settings.rpc_max_concurrency)
        self._ids = count(1)
        self._rotation = count()
        self._calls = 0
        self._closed = False

    @property
    def rpc_calls(self) -> int:
        """Number of HTTP RPC attempts made."""
        return self._calls

    async def _single_call(self, url: str, method: str, params: list[Any]) -> Any:
        request_id = next(self._ids)
        payload = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        async with self._http.stream("POST", url, json=payload) as response:
            if response.status_code == 429:
                raise RateLimitError(f"{method} rate limited")
            if response.status_code >= 300:
                raise RpcError(
                    f"{method} returned HTTP {response.status_code}",
                    method=method,
                )
            declared = response.headers.get("content-length")
            if declared is not None:
                try:
                    if int(declared) > self._settings.rpc_max_response_bytes:
                        raise RpcResponseTooLargeError(
                            f"{method} response exceeded {self._settings.rpc_max_response_bytes} bytes"
                        )
                except ValueError:
                    pass
            chunks: list[bytes] = []
            total = 0
            async for chunk in response.aiter_bytes():
                total += len(chunk)
                if total > self._settings.rpc_max_response_bytes:
                    raise RpcResponseTooLargeError(
                        f"{method} response exceeded {self._settings.rpc_max_response_bytes} bytes"
                    )
                chunks.append(chunk)
        try:
            decoded = json.loads(b"".join(chunks))
        except json.JSONDecodeError as exc:
            raise RpcError(f"{method} returned invalid JSON", method=method) from exc
        if not isinstance(decoded, dict):
            raise RpcError(f"{method} returned a non-object response", method=method)
        if "error" in decoded:
            error = decoded["error"]
            if isinstance(error, dict):
                message = str(error.get("message", "RPC error"))
                code = error.get("code")
            else:
                message = str(error)
                code = None
            lowered = message.lower()
            if code in {-32429, -32005} or "rate limit" in lowered or "too many" in lowered:
                raise RateLimitError(f"{method}: {message}", method=method)
            raise RpcError(f"{method} failed: {message}", method=method)
        return decoded.get("result")

    async def _call(self, method: str, params: list[Any]) -> Any:
        if self._closed:
            raise RpcError("Solana RPC client is closed", method=method)
        attempts = self._settings.rpc_max_retries + 1
        start = next(self._rotation) % len(self._urls)
        last_error: Exception | None = None
        for attempt in range(attempts):
            url = self._urls[(start + attempt) % len(self._urls)]
            try:
                await self._limit.acquire()
                async with self._semaphore:
                    self._calls += 1
                    return await asyncio.wait_for(
                        self._single_call(url, method, params),
                        timeout=self._settings.rpc_timeout,
                    )
            except RpcResponseTooLargeError:
                raise
            except (TimeoutError, httpx.TimeoutException) as exc:
                last_error = RpcTimeoutError(f"{method} timed out", method=method)
                logger.warning(
                    "Solana RPC timeout for %s (attempt %d): %s", method, attempt + 1, exc
                )
            except (httpx.HTTPError, OSError) as exc:
                last_error = RpcError(f"{method} transport error: {exc}", method=method)
                logger.warning("Solana RPC transport error for %s: %s", method, exc)
            except RpcError as exc:
                last_error = exc
            if last_error is not None and not _is_retryable(last_error):
                raise last_error
            if attempt < attempts - 1:
                await asyncio.sleep(min(self._settings.rpc_backoff_base * (2**attempt), 5.0))
        if last_error is None:  # pragma: no cover
            last_error = RpcError(f"{method} failed", method=method)
        raise last_error

    async def get_slot(self) -> int:
        """Return the current confirmed slot."""
        result = await self._call("getSlot", [{"commitment": "confirmed"}])
        if not isinstance(result, int):
            raise RpcError("Malformed getSlot result")
        return result

    async def get_account_info(
        self,
        address: str,
        *,
        encoding: str = "jsonParsed",
    ) -> dict[str, Any] | None:
        """Fetch one account at the current confirmed bank."""
        result = await self._call(
            "getAccountInfo",
            [address, {"encoding": encoding, "commitment": "confirmed"}],
        )
        if not isinstance(result, dict):
            raise RpcError("Malformed getAccountInfo result")
        value = result.get("value")
        if value is None:
            return None
        if not isinstance(value, dict):
            raise RpcError("Malformed getAccountInfo account")
        return value

    async def get_multiple_accounts(
        self,
        addresses: Sequence[str],
        *,
        encoding: str = "jsonParsed",
    ) -> list[dict[str, Any] | None]:
        """Fetch up to 100 accounts in one JSON-RPC call."""
        if len(addresses) > 100:
            raise RpcError("getMultipleAccounts supports at most 100 addresses")
        result = await self._call(
            "getMultipleAccounts",
            [list(addresses), {"encoding": encoding, "commitment": "confirmed"}],
        )
        if not isinstance(result, dict) or not isinstance(result.get("value"), list):
            raise RpcError("Malformed getMultipleAccounts result")
        values: list[dict[str, Any] | None] = []
        for value in result["value"]:
            if value is not None and not isinstance(value, dict):
                raise RpcError("Malformed account in getMultipleAccounts result")
            values.append(value)
        return values

    async def get_token_largest_accounts(self, mint: str) -> list[dict[str, Any]]:
        """Fetch the 20 largest token accounts for a mint."""
        result = await self._call(
            "getTokenLargestAccounts",
            [mint, {"commitment": "confirmed"}],
        )
        if not isinstance(result, dict) or not isinstance(result.get("value"), list):
            raise RpcError("Malformed getTokenLargestAccounts result")
        accounts = [item for item in result["value"] if isinstance(item, dict)]
        return accounts

    async def get_token_supply(self, mint: str) -> dict[str, Any]:
        """Fetch mint supply."""
        result = await self._call("getTokenSupply", [mint, {"commitment": "confirmed"}])
        if not isinstance(result, dict) or not isinstance(result.get("value"), dict):
            raise RpcError("Malformed getTokenSupply result")
        return result["value"]

    async def get_signatures_for_address(
        self,
        address: str,
        *,
        limit: int,
        before: str | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch recent signatures, newest first."""
        options: dict[str, Any] = {"limit": min(max(limit, 1), 1_000), "commitment": "confirmed"}
        if before:
            options["before"] = before
        result = await self._call("getSignaturesForAddress", [address, options])
        if not isinstance(result, list):
            raise RpcError("Malformed getSignaturesForAddress result")
        return [item for item in result if isinstance(item, dict)]

    async def get_transaction(self, signature: str) -> dict[str, Any] | None:
        """Fetch a parsed transaction, preferring version 1 with a v0 fallback."""
        try:
            result = await self._call(
                "getTransaction",
                [
                    signature,
                    {
                        "encoding": "jsonParsed",
                        "maxSupportedTransactionVersion": 1,
                        "commitment": "confirmed",
                    },
                ],
            )
        except RpcError as exc:
            if "maxsupportedtransactionversion" not in str(exc).lower():
                raise
            result = await self._call(
                "getTransaction",
                [
                    signature,
                    {
                        "encoding": "jsonParsed",
                        "maxSupportedTransactionVersion": 0,
                        "commitment": "confirmed",
                    },
                ],
            )
        if result is None:
            return None
        if not isinstance(result, dict):
            raise RpcError("Malformed getTransaction result")
        return result

    async def get_token_accounts_by_owner(
        self,
        owner: str,
        mint: str,
    ) -> list[dict[str, Any]]:
        """Fetch all token accounts for an owner and mint."""
        result = await self._call(
            "getTokenAccountsByOwner",
            [
                owner,
                {"mint": mint},
                {"encoding": "jsonParsed", "commitment": "confirmed"},
            ],
        )
        if not isinstance(result, dict) or not isinstance(result.get("value"), list):
            raise RpcError("Malformed getTokenAccountsByOwner result")
        return [item for item in result["value"] if isinstance(item, dict)]

    async def close(self) -> None:
        """Close the HTTP session."""
        if self._closed:
            return
        self._closed = True
        with contextlib.suppress(Exception):
            await self._http.aclose()
