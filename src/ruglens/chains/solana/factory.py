"""Factory for cached Solana RPC clients."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence

from ruglens.chains.solana.client import SolanaRpcClient
from ruglens.chains.solana.registry import resolve_solana_rpc_urls
from ruglens.core.config import RugLensSettings


class SolanaRpcFactory:
    """Create one client per (resolved) Solana RPC URL set."""

    def __init__(self, settings: RugLensSettings) -> None:
        self._settings = settings
        self._clients: dict[tuple[str, ...], SolanaRpcClient] = {}
        self._lock = asyncio.Lock()
        self._closed = False

    def get_client(self, rpc_urls: Sequence[str] | None = None) -> SolanaRpcClient:
        """Return a cached client for the resolved URL list."""
        if self._closed:
            raise RuntimeError("Solana RPC factory is closed")
        urls = resolve_solana_rpc_urls(rpc_urls)
        key = tuple(urls)
        existing = self._clients.get(key)
        if existing is not None:
            return existing
        client = SolanaRpcClient(self._settings, urls)
        self._clients[key] = client
        return client

    async def close(self) -> None:
        """Close all RPC clients."""
        if self._closed:
            return
        self._closed = True
        async with self._lock:
            clients = list(self._clients.values())
            self._clients.clear()
        await asyncio.gather(*(client.close() for client in clients), return_exceptions=True)
