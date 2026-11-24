"""Chain-adapter factory with shared bytecode caching."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence

from ruglens.chains.cache import BytecodeCache
from ruglens.chains.evm.client import EvmClient
from ruglens.chains.evm.registry import ChainConfig, normalize_chain, resolve_rpc_urls
from ruglens.core.config import RugLensSettings


class EvmChainFactory:
    """Creates and caches :class:`EvmClient` instances per chain and URL set."""

    def __init__(
        self,
        settings: RugLensSettings,
        *,
        rpc_overrides: Mapping[int, Sequence[str]] | None = None,
        cache: BytecodeCache | None = None,
    ) -> None:
        self._settings = settings
        self._rpc_overrides = dict(rpc_overrides or {})
        self._cache = cache or BytecodeCache(
            settings.resolved_cache_path(),
            max_bytes=settings.cache_max_bytes,
        )
        self._owns_cache = cache is None
        self._clients: dict[tuple[int, tuple[str, ...]], EvmClient] = {}
        self._lock = asyncio.Lock()
        self._closed = False

    async def get_adapter(
        self,
        chain_id: int,
        rpc_urls: Sequence[str] | None = None,
    ) -> EvmClient:
        """Return a cached adapter for the chain and resolved RPC URLs."""
        if self._closed:
            raise RuntimeError("Chain factory is closed")
        chain: ChainConfig = normalize_chain(chain_id)
        urls = resolve_rpc_urls(
            chain,
            rpc_urls if rpc_urls is not None else self._rpc_overrides.get(int(chain.chain_id)),
        )
        key = (int(chain.chain_id), tuple(urls))
        async with self._lock:
            existing = self._clients.get(key)
            if existing is not None:
                return existing
            await self._cache.initialize()
            client = EvmClient(
                int(chain.chain_id),
                urls,
                self._settings,
                cache=self._cache,
            )
            self._clients[key] = client
            return client

    @property
    def cache(self) -> BytecodeCache:
        """The shared bytecode cache."""
        return self._cache

    async def close(self) -> None:
        """Close all clients and the shared cache."""
        if self._closed:
            return
        self._closed = True
        async with self._lock:
            clients = list(self._clients.values())
            self._clients.clear()
        await asyncio.gather(*(client.close() for client in clients), return_exceptions=True)
        if self._owns_cache:
            await self._cache.close()
