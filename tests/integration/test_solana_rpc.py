"""Solana JSON-RPC client tests against a local HTTP server."""

from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from ruglens.chains.registry import (
    chain_display_name,
    is_solana_chain,
    resolve_chain_selector,
)
from ruglens.chains.solana.client import SolanaRpcClient
from ruglens.chains.solana.factory import SolanaRpcFactory
from ruglens.chains.solana.registry import resolve_solana_rpc_urls
from ruglens.core.exceptions import (
    ConfigurationError,
    RpcError,
    RpcResponseTooLargeError,
)


class _SolanaServer:
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


def test_chain_selector_supports_solana() -> None:
    assert resolve_chain_selector("solana") == 101
    assert resolve_chain_selector("sol") == 101
    assert resolve_chain_selector(101) == 101
    assert is_solana_chain(101) is True
    assert chain_display_name(101) == "Solana Mainnet"
    assert resolve_chain_selector("eth") == 1


def test_rpc_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RUGLENS_SOLANA_RPC_URL", "https://one.example,https://two.example")
    assert resolve_solana_rpc_urls() == ("https://one.example", "https://two.example")
    assert resolve_solana_rpc_urls("https://explicit.example") == ("https://explicit.example",)
    with pytest.raises(ConfigurationError):
        resolve_solana_rpc_urls("")


@pytest.mark.asyncio
async def test_client_methods_and_retry(settings) -> None:
    attempts = {"slot": 0}

    def responder(payload: dict[str, Any]):
        method = payload["method"]
        if method == "getSlot":
            attempts["slot"] += 1
            if attempts["slot"] == 1:
                return 503, {"error": "unavailable"}
            return _ok(12345)
        if method == "getAccountInfo":
            return _ok({"context": {"slot": 1}, "value": {"owner": "x"}})
        if method == "getMultipleAccounts":
            return _ok({"context": {"slot": 1}, "value": [{"owner": "x"}, None]})
        if method == "getTokenLargestAccounts":
            return _ok({"context": {"slot": 1}, "value": [{"address": "a", "amount": "10"}]})
        if method == "getTokenSupply":
            return _ok({"context": {"slot": 1}, "value": {"amount": "100"}})
        if method == "getSignaturesForAddress":
            return _ok([{"signature": "sig"}])
        if method == "getTransaction":
            return _ok({"transaction": {}, "meta": {}})
        if method == "getTokenAccountsByOwner":
            return _ok({"context": {"slot": 1}, "value": [{}]})
        return _ok(None)

    with _SolanaServer(responder) as server:
        client = SolanaRpcClient(settings, [server.url])
        try:
            assert await client.get_slot() == 12345
            assert await client.get_account_info("mint") == {"owner": "x"}
            assert (await client.get_multiple_accounts(["a", "b"]))[1] is None
            assert await client.get_token_largest_accounts("mint") == [
                {"address": "a", "amount": "10"}
            ]
            assert await client.get_token_supply("mint") == {"amount": "100"}
            assert await client.get_signatures_for_address("a", limit=10) == [{"signature": "sig"}]
            assert await client.get_transaction("sig") == {"transaction": {}, "meta": {}}
            transaction_request = next(
                request for request in server.requests if request["method"] == "getTransaction"
            )
            assert transaction_request["params"][1]["maxSupportedTransactionVersion"] == 1
            assert await client.get_token_accounts_by_owner("owner", "mint") == [{}]
            assert attempts["slot"] == 2
            assert client.rpc_calls >= 8
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_client_failover_and_redirect_and_size(settings) -> None:
    def responder(payload: dict[str, Any]):
        if payload["method"] == "getSlot":
            return _ok(1)
        return _ok(None)

    with _SolanaServer(responder) as live:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            dead_port = probe.getsockname()[1]
        client = SolanaRpcClient(settings, [f"http://127.0.0.1:{dead_port}", live.url])
        try:
            assert await client.get_slot() == 1
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_client_rejects_oversized_responses(settings) -> None:
    small = settings.model_copy(update={"rpc_max_response_bytes": 100})

    def responder(payload: dict[str, Any]):
        return _ok("x" * 1_000)

    with _SolanaServer(responder) as server:
        client = SolanaRpcClient(small, [server.url])
        try:
            with pytest.raises(RpcResponseTooLargeError):
                await client.get_slot()
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_client_does_not_follow_redirects(settings) -> None:
    def responder(payload: dict[str, Any]):
        return 302, {"error": "redirect"}

    with _SolanaServer(responder) as server:
        client = SolanaRpcClient(settings, [server.url])
        try:
            with pytest.raises(RpcError, match="302"):
                await client.get_slot()
            assert len(server.requests) == 1
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_factory_caches_clients(settings) -> None:
    factory = SolanaRpcFactory(settings)
    first = factory.get_client(["https://example.invalid"])
    second = factory.get_client(["https://example.invalid"])
    assert first is second
    await factory.close()
