"""Chain registry, multicall, cache, and RPC client tests."""

from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from eth_abi.abi import encode
from tests.helpers import WETH

from ruglens.chains.cache import BytecodeCache
from ruglens.chains.evm.client import EvmClient
from ruglens.chains.evm.multicall import decode_aggregate3, encode_aggregate3
from ruglens.chains.evm.registry import normalize_chain, resolve_rpc_urls
from ruglens.core.exceptions import (
    ConfigurationError,
    RpcError,
    RpcResponseTooLargeError,
    UnsupportedChainError,
)
from ruglens.core.models import RpcCall


def test_chain_aliases() -> None:
    assert normalize_chain("eth").chain_id == 1
    assert normalize_chain("ethereum").chain_id == 1
    assert normalize_chain("56").chain_id == 56
    assert normalize_chain("base").slug == "base"
    assert normalize_chain(8453).weth.startswith("0x4200")
    with pytest.raises(UnsupportedChainError):
        normalize_chain("solana")


def test_rpc_url_resolution_env(monkeypatch: pytest.MonkeyPatch) -> None:
    chain = normalize_chain("eth")
    monkeypatch.setenv("RUGLENS_ETH_RPC_URL", "https://one.example,https://two.example")
    assert resolve_rpc_urls(chain) == ("https://one.example", "https://two.example")
    assert resolve_rpc_urls(chain, "https://explicit.example") == ("https://explicit.example",)
    with pytest.raises(ConfigurationError):
        resolve_rpc_urls(chain, "")


def test_multicall_roundtrip() -> None:
    calls = [
        RpcCall(to=WETH, data=b"\x01\x02"),
        RpcCall(to="0x2222222222222222222222222222222222222222", data=b"\x03"),
    ]
    encoded = encode_aggregate3(calls)
    assert encoded[:4].hex() == "82ad56cb"
    response = encode(
        ["(bool,bytes)[]"],
        [[(True, b"\xaa\xbb"), (False, b"")]],
    )
    decoded = decode_aggregate3(response)
    assert decoded[0].success is True
    assert decoded[0].return_data == b"\xaa\xbb"
    assert decoded[1].success is False


@pytest.mark.asyncio
async def test_bytecode_cache_persists_and_prunes(tmp_path: Path) -> None:
    path = tmp_path / "cache.sqlite3"
    cache = BytecodeCache(path, max_bytes=100)
    await cache.initialize()
    await cache.put(1, WETH, 10, b"\xaa" * 60)
    await cache.put(1, WETH, 11, b"\xbb" * 60)
    stats = await cache.stats()
    assert stats["entries"] == 1
    assert stats["bytes"] <= 100
    assert await cache.get(1, WETH, 10) is None  # oldest entry evicted
    assert await cache.get(1, WETH, 11) == b"\xbb" * 60
    await cache.close()

    reopened = BytecodeCache(path, max_bytes=100)
    await reopened.initialize()
    assert await reopened.get(1, WETH, 11) == b"\xbb" * 60
    await reopened.clear()
    assert await reopened.get(1, WETH, 11) is None
    await reopened.close()


class _RpcServer:
    def __init__(self, responder) -> None:
        self.responder = responder
        self.requests: list[dict[str, Any]] = []
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def _handler(self):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(length) or b"{}")
                outer.requests.append(payload)
                status, response = outer.responder(payload)
                body = json.dumps(response).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: Any) -> None:
                return

        return Handler

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args: Any) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.httpd.server_port}"


def _ok(result: Any) -> tuple[int, dict[str, Any]]:
    return 200, {"jsonrpc": "2.0", "id": 1, "result": result}


@pytest.mark.asyncio
async def test_client_retries_then_succeeds(settings) -> None:
    attempts = {"count": 0}

    def responder(payload: dict[str, Any]):
        if payload["method"] == "eth_blockNumber":
            attempts["count"] += 1
            if attempts["count"] == 1:
                return 503, {"error": "unavailable"}
            return _ok("0x2a")
        return _ok(None)

    with _RpcServer(responder) as server:
        client = EvmClient(1, [server.url], settings)
        try:
            assert await client.get_block_number() == 42
            assert attempts["count"] == 2
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_client_failover_to_second_endpoint(settings) -> None:
    def responder(payload: dict[str, Any]):
        return _ok("0x2a")

    with _RpcServer(responder) as live:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            dead_port = probe.getsockname()[1]
        client = EvmClient(1, [f"http://127.0.0.1:{dead_port}", live.url], settings)
        try:
            assert await client.get_block_number() == 42
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_bytecode_cache_avoids_second_network_call(settings, tmp_path: Path) -> None:
    count = {"code": 0}

    def responder(payload: dict[str, Any]):
        if payload["method"] == "eth_getCode":
            count["code"] += 1
            return _ok("0x60006000")
        return _ok(None)

    cache = BytecodeCache(tmp_path / "code.sqlite3")
    with _RpcServer(responder) as server:
        client = EvmClient(1, [server.url], settings, cache=cache)
        try:
            first = await client.get_code(WETH, 100)
            second = await client.get_code(WETH, 100)
            assert first == second == b"\x60\x00\x60\x00"
            assert count["code"] == 1
        finally:
            await client.close()
            await cache.close()


@pytest.mark.asyncio
async def test_rate_limit_error_is_classified(settings) -> None:
    attempts = {"count": 0}

    def responder(payload: dict[str, Any]):
        if payload["method"] == "eth_blockNumber":
            attempts["count"] += 1
            if attempts["count"] == 1:
                return 429, {"error": "too many requests"}
            return _ok("0x1")
        return _ok(None)

    with _RpcServer(responder) as server:
        client = EvmClient(1, [server.url], settings)
        try:
            assert await client.get_block_number() == 1
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_rpc_redirects_are_not_followed(settings) -> None:
    def responder(payload: dict[str, Any]):
        return 302, {"error": "redirect"}

    with _RpcServer(responder) as server:
        client = EvmClient(1, [server.url], settings)
        try:
            with pytest.raises(RpcError, match="302"):
                await client.get_block_number()
            assert len(server.requests) == 1
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_oversized_bytecode_is_rejected(settings, tmp_path: Path) -> None:
    def responder(payload: dict[str, Any]):
        if payload["method"] == "eth_getCode":
            return _ok("0x" + "60" * 100_000)
        return _ok(None)

    with _RpcServer(responder) as server:
        client = EvmClient(1, [server.url], settings)
        try:
            with pytest.raises(RpcResponseTooLargeError):
                await client.get_code(WETH, 100)
        finally:
            await client.close()
