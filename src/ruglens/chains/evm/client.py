"""Resilient asynchronous EVM client.

Features: ordered RPC failover, token-bucket rate limiting, exponential
backoff, response-size ceilings, Multicall3 batching, and a block-aware
bytecode cache. All calls are pinned to an explicit block number.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from itertools import count
from typing import Any, cast
from urllib.parse import urlparse

import aiohttp
from eth_utils.address import is_address, to_checksum_address
from web3 import AsyncWeb3

from ruglens.chains.cache import BytecodeCache
from ruglens.chains.evm.abi import hex_data_to_bytes
from ruglens.chains.evm.multicall import MULTICALL3_ADDRESS, decode_aggregate3, encode_aggregate3
from ruglens.chains.evm.provider import CappedAsyncHTTPProvider
from ruglens.chains.evm.registry import normalize_chain
from ruglens.core.config import RugLensSettings
from ruglens.core.exceptions import (
    CacheError,
    ConfigurationError,
    InvalidAddressError,
    RateLimitError,
    RpcError,
    RpcResponseTooLargeError,
    RpcTimeoutError,
)
from ruglens.core.models import RpcCall, RpcCallResult

logger = logging.getLogger(__name__)


class _TokenBucket:
    """Async token-bucket rate limiter."""

    def __init__(self, rate_per_second: float, capacity: float | None = None) -> None:
        if rate_per_second <= 0:
            raise ValueError("rate must be positive")
        self._rate = rate_per_second
        self._capacity = capacity if capacity is not None else max(1.0, rate_per_second)
        self._tokens = self._capacity
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0) -> None:
        if tokens > self._capacity:
            raise ValueError("requested tokens exceed bucket capacity")
        async with self._lock:
            now = time.monotonic()
            elapsed = max(0.0, now - self._last)
            self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
            self._last = now
            if self._tokens < tokens:
                wait_seconds = (tokens - self._tokens) / self._rate
                await asyncio.sleep(wait_seconds)
                self._tokens = 0.0
                self._last = time.monotonic()
            else:
                self._tokens -= tokens


@dataclass
class _Endpoint:
    url: str
    web3: AsyncWeb3[Any]
    failures: int = 0
    cooldown_until: float = 0.0
    last_error: str = field(default="")


_RETRYABLE_MARKERS = (
    "rate limit",
    "too many requests",
    "timeout",
    "timed out",
    "temporarily unavailable",
    "service unavailable",
    "header not found",
    "connection",
    "502",
    "503",
    "504",
    "429",
)


def _validate_rpc_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ConfigurationError(f"RPC URL must use http or https: {url!r}")
    if not parsed.hostname:
        raise ConfigurationError(f"RPC URL has no host: {url!r}")
    return url


def _normalize_address(address: str) -> str:
    if not is_address(address):
        raise InvalidAddressError(f"Invalid EVM address: {address!r}")
    return to_checksum_address(address)


class EvmClient:
    """One chain, one or more RPC endpoints, one shared bytecode cache."""

    def __init__(
        self,
        chain_id: int,
        rpc_urls: Sequence[str],
        settings: RugLensSettings,
        *,
        cache: BytecodeCache | None = None,
    ) -> None:
        self._chain = normalize_chain(chain_id)
        self._settings = settings
        self._cache = cache
        unique_urls = list(dict.fromkeys(_validate_rpc_url(url) for url in rpc_urls))
        if not unique_urls:
            raise ConfigurationError(f"No RPC URLs configured for chain {chain_id}")
        self._endpoints = [
            _Endpoint(
                url=url,
                web3=AsyncWeb3(
                    CappedAsyncHTTPProvider(
                        url,
                        timeout=settings.rpc_timeout,
                        connect_timeout=settings.rpc_connect_timeout,
                        max_response_bytes=settings.rpc_max_response_bytes,
                    )
                ),
            )
            for url in unique_urls
        ]
        self._rate_limiter = _TokenBucket(settings.rpc_rate_limit_per_second)
        self._semaphore = asyncio.Semaphore(settings.rpc_max_concurrency)
        self._rotation = count()
        self._calls = 0
        self._multicall_disabled = False
        self._closed = False

    @property
    def chain_id(self) -> int:
        """Numeric chain id."""
        return int(self._chain.chain_id)

    @property
    def rpc_calls(self) -> int:
        """Number of network RPC attempts made by this client."""
        return self._calls

    @property
    def cache(self) -> BytecodeCache | None:
        """Shared bytecode cache, when configured."""
        return self._cache

    def _ordered_endpoints(self) -> list[_Endpoint]:
        count_now = next(self._rotation)
        start = count_now % len(self._endpoints)
        return self._endpoints[start:] + self._endpoints[:start]

    @staticmethod
    def _extract_error(response: dict[str, Any]) -> tuple[int | None, str]:
        error = response.get("error")
        if isinstance(error, dict):
            raw_code = error.get("code")
            code = int(raw_code) if isinstance(raw_code, int) else None
            message = str(error.get("message", "RPC error"))
            return code, message
        return None, str(error or "Unknown RPC error")

    @staticmethod
    def _is_retryable(error: Exception) -> bool:
        if isinstance(error, RateLimitError):
            return True
        text = str(error).lower()
        return any(marker in text for marker in _RETRYABLE_MARKERS)

    def _check_size(self, result: Any) -> None:
        try:
            encoded = json.dumps(result, separators=(",", ":"), default=str)
        except (TypeError, ValueError):
            encoded = str(result)
        if len(encoded.encode("utf-8", errors="ignore")) > self._settings.rpc_max_response_bytes:
            raise RpcResponseTooLargeError(
                f"RPC response exceeded {self._settings.rpc_max_response_bytes} bytes"
            )

    async def _request(self, method: str, params: Sequence[Any]) -> Any:
        if self._closed:
            raise RpcError("RPC client is closed", method=method)
        attempts = self._settings.rpc_max_retries + 1
        last_error: Exception | None = None
        ordered = self._ordered_endpoints()
        for attempt in range(attempts):
            endpoint = ordered[attempt % len(ordered)]
            if endpoint.cooldown_until > time.monotonic():
                endpoint = ordered[(attempt + 1) % len(ordered)]
            try:
                await self._rate_limiter.acquire()
                async with self._semaphore:
                    self._calls += 1
                    response = await asyncio.wait_for(
                        endpoint.web3.provider.make_request(method, params),
                        timeout=self._settings.rpc_timeout,
                    )
            except RpcResponseTooLargeError:
                raise
            except TimeoutError as exc:
                last_error = RpcTimeoutError(f"{method} timed out", method=method)
                endpoint.failures += 1
                endpoint.last_error = str(exc)
                logger.warning(
                    "RPC timeout on %s via %s (attempt %d)", method, endpoint.url, attempt + 1
                )
            except (aiohttp.ClientError, OSError) as exc:
                last_error = RpcError(f"{method} transport error: {exc}", method=method)
                endpoint.failures += 1
                endpoint.last_error = str(exc)
                logger.warning("RPC transport error on %s via %s: %s", method, endpoint.url, exc)
            except Exception as exc:
                last_error = RpcError(f"{method} provider error: {exc}", method=method)
                endpoint.failures += 1
                endpoint.last_error = str(exc)
                logger.warning("RPC provider error on %s via %s: %s", method, endpoint.url, exc)
            else:
                if not isinstance(response, dict):
                    last_error = RpcError(f"{method} returned a non-object response", method=method)
                elif "error" in response:
                    code, message = self._extract_error(cast(dict[str, Any], response))
                    normalized = message.lower()
                    if (
                        code in {-32005, -32029}
                        or "rate limit" in normalized
                        or "too many" in normalized
                    ):
                        last_error = RateLimitError(f"{method}: {message}", method=method)
                        endpoint.cooldown_until = time.monotonic() + 5.0
                    else:
                        last_error = RpcError(f"{method} failed: {message}", method=method)
                else:
                    result = response.get("result")
                    self._check_size(result)
                    endpoint.failures = 0
                    return result

            if last_error is not None and not self._is_retryable(last_error):
                raise last_error
            if attempt < attempts - 1:
                delay = min(
                    self._settings.rpc_backoff_base * (2**attempt),
                    5.0,
                )
                await asyncio.sleep(delay)

        if last_error is None:  # pragma: no cover - defensive
            last_error = RpcError(f"{method} failed without an error", method=method)
        raise last_error

    async def get_block_number(self) -> int:
        """Fetch the current head block number."""
        result = await self._request("eth_blockNumber", [])
        try:
            return int(str(result), 16)
        except (TypeError, ValueError) as exc:
            raise RpcError(f"Malformed eth_blockNumber result: {result!r}") from exc

    async def get_code(self, address: str, block_number: int) -> bytes:
        """Fetch runtime bytecode at an exact block, consulting the cache first."""
        checksum = _normalize_address(address)
        if self._cache is not None:
            try:
                cached = await self._cache.get(self.chain_id, checksum, block_number)
                if cached is not None:
                    return cached
            except CacheError as exc:
                logger.warning("Bytecode cache read failed, falling back to RPC: %s", exc)

        result = await self._request("eth_getCode", [checksum, hex(block_number)])
        if not isinstance(result, str):
            raise RpcError("eth_getCode returned a non-string result")
        try:
            code = hex_data_to_bytes(result)
        except ValueError as exc:
            raise RpcError(f"Malformed bytecode returned for {checksum}") from exc
        if len(code) > self._settings.max_bytecode_bytes:
            raise RpcResponseTooLargeError(
                f"Bytecode for {checksum} is {len(code)} bytes (max {self._settings.max_bytecode_bytes})"
            )
        if self._cache is not None:
            try:
                await self._cache.put(self.chain_id, checksum, block_number, code)
            except CacheError as exc:
                logger.warning("Bytecode cache write failed: %s", exc)
        return code

    async def get_balance(self, address: str, block_number: int) -> int:
        """Fetch native balance at a block."""
        checksum = _normalize_address(address)
        result = await self._request("eth_getBalance", [checksum, hex(block_number)])
        try:
            return int(str(result), 16)
        except (TypeError, ValueError) as exc:
            raise RpcError("Malformed eth_getBalance result") from exc

    async def get_storage_at(self, address: str, slot: str, block_number: int) -> str:
        """Fetch one 32-byte storage word at a block."""
        checksum = _normalize_address(address)
        normalized_slot = slot[2:] if slot.startswith("0x") else slot
        try:
            raw_slot = bytes.fromhex(normalized_slot)
        except ValueError as exc:
            raise RpcError(f"Invalid storage slot: {slot!r}") from exc
        if len(raw_slot) > 32:
            raise RpcError("Storage slot exceeds 32 bytes")
        raw_slot = raw_slot.rjust(32, b"\x00")
        result = await self._request(
            "eth_getStorageAt",
            [checksum, "0x" + raw_slot.hex(), hex(block_number)],
        )
        if not isinstance(result, str) or not result.startswith("0x"):
            raise RpcError("Malformed eth_getStorageAt result")
        return result

    async def eth_call(self, to: str, data: bytes, block_number: int) -> bytes:
        """Execute a read-only call pinned to a block."""
        checksum = _normalize_address(to)
        result = await self._request(
            "eth_call",
            [{"to": checksum, "data": "0x" + data.hex()}, hex(block_number)],
        )
        if not isinstance(result, str):
            raise RpcError("eth_call returned a non-string result")
        try:
            return hex_data_to_bytes(result)
        except ValueError as exc:
            raise RpcError("Malformed eth_call return data") from exc

    async def multicall(
        self,
        calls: Sequence[RpcCall],
        block_number: int,
        *,
        allow_failure: bool = True,
    ) -> list[RpcCallResult]:
        """Batch calls through Multicall3.aggregate3, falling back per-call."""
        if not calls:
            return []
        if not self._multicall_disabled:
            encoded = encode_aggregate3(calls)
            try:
                result = await self.eth_call(MULTICALL3_ADDRESS, encoded, block_number)
                decoded = decode_aggregate3(result)
                if len(decoded) != len(calls):
                    raise RpcError("Multicall3 returned a mismatched result count")
                return decoded
            except (RpcError, ValueError) as exc:
                logger.warning(
                    "Multicall3 unavailable on chain %s (%s); falling back to individual calls",
                    self.chain_id,
                    exc,
                )
                self._multicall_disabled = True

        results: list[RpcCallResult] = []
        for call in calls:
            try:
                data = await self.eth_call(call.to, call.data, block_number)
                results.append(RpcCallResult(success=True, return_data=data))
            except RpcError as exc:
                if not allow_failure:
                    raise
                logger.debug("Individual fallback call failed for %s: %s", call.to, exc)
                results.append(RpcCallResult(success=False))
        return results

    async def get_logs(
        self,
        address: str,
        topics: Sequence[str | None],
        from_block: int,
        to_block: int,
    ) -> list[dict[str, Any]]:
        """Fetch logs for one address and topic list, bounded by block range."""
        if to_block < from_block:
            raise RpcError("Invalid log range: to_block precedes from_block")
        checksum = _normalize_address(address)
        result = await self._request(
            "eth_getLogs",
            [
                {
                    "address": checksum,
                    "topics": list(topics),
                    "fromBlock": hex(from_block),
                    "toBlock": hex(to_block),
                }
            ],
        )
        if not isinstance(result, list):
            raise RpcError("eth_getLogs returned a non-array result")
        normalized: list[dict[str, Any]] = []
        for entry in result:
            if not isinstance(entry, dict):
                raise RpcError("Malformed log entry returned by RPC")
            item = dict(entry)
            for key in ("blockNumber", "transactionIndex", "logIndex"):
                raw = item.get(key)
                if isinstance(raw, str):
                    with contextlib.suppress(ValueError):
                        item[key] = int(raw, 16)
            normalized.append(item)
        return normalized

    async def close(self) -> None:
        """Disconnect all provider HTTP sessions."""
        if self._closed:
            return
        self._closed = True
        for endpoint in self._endpoints:
            try:
                await endpoint.web3.provider.disconnect()
            except Exception as exc:
                logger.debug("Error disconnecting RPC endpoint %s: %s", endpoint.url, exc)
