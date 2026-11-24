"""AsyncWeb3 HTTP provider with a hard response-size ceiling.

Web3's stock provider buffers an entire HTTP response before parsing. RugLens
inspects adversarial RPC endpoints, so responses are streamed and rejected as
soon as they exceed the configured byte cap.
"""

from __future__ import annotations

import asyncio

import aiohttp
from web3.providers.rpc import AsyncHTTPProvider

from ruglens.core.exceptions import RpcResponseTooLargeError


class CappedAsyncHTTPProvider(AsyncHTTPProvider):
    """AsyncWeb3 JSON-RPC provider that streams with a maximum body size."""

    def __init__(
        self,
        endpoint_uri: str,
        *,
        timeout: float,
        connect_timeout: float,
        max_response_bytes: int,
    ) -> None:
        super().__init__(endpoint_uri, request_kwargs={"timeout": timeout})
        self._timeout = timeout
        self._connect_timeout = connect_timeout
        self._max_response_bytes = max_response_bytes
        self._session: aiohttp.ClientSession | None = None
        self._session_lock = asyncio.Lock()

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is not None:
            return self._session
        async with self._session_lock:
            if self._session is None:
                self._session = aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(
                        total=self._timeout,
                        connect=self._connect_timeout,
                    )
                )
            return self._session

    async def _make_request(self, method: str, request_data: bytes) -> bytes:
        session = await self._get_session()
        async with session.post(
            str(self.endpoint_uri),
            data=request_data,
            headers=self.get_request_headers(),
            allow_redirects=False,
        ) as response:
            if response.status >= 300:
                raise aiohttp.ClientResponseError(
                    request_info=response.request_info,
                    history=response.history,
                    status=response.status,
                    message=f"RPC returned HTTP {response.status} (redirects are not followed)",
                    headers=response.headers,
                )
            declared = response.headers.get("Content-Length")
            if declared is not None:
                try:
                    if int(declared) > self._max_response_bytes:
                        raise RpcResponseTooLargeError(
                            f"RPC Content-Length {declared} exceeds {self._max_response_bytes} bytes"
                        )
                except ValueError:
                    pass
            chunks: list[bytes] = []
            total = 0
            async for chunk in response.content.iter_chunked(65_536):
                total += len(chunk)
                if total > self._max_response_bytes:
                    raise RpcResponseTooLargeError(
                        f"RPC response exceeded {self._max_response_bytes} bytes"
                    )
                chunks.append(chunk)
            return b"".join(chunks)

    async def disconnect(self) -> None:
        """Close the streaming HTTP session."""
        if self._session is not None:
            await self._session.close()
            self._session = None
