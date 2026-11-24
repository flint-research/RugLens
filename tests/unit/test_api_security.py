"""API SSRF policy tests."""

from __future__ import annotations

import pytest

from ruglens.core.exceptions import UnsafeUrlError
from ruglens.interfaces.api.security import validate_public_rpc_url


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8545",
        "http://localhost:8545",
        "http://169.254.169.254/latest/meta-data",
        "http://10.0.0.5/rpc",
        "http://192.168.1.10/",
        "http://0.0.0.0/",
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://100.64.0.1/",
        "http://metadata.google.internal/",
        "file:///etc/passwd",
        "http://user:pass@1.1.1.1/",
        "http://1.1.1.1/#fragment",
        "http://1.1.1.1:0/",
    ],
)
async def test_blocked_urls(url: str) -> None:
    with pytest.raises(UnsafeUrlError):
        await validate_public_rpc_url(url)


@pytest.mark.asyncio
async def test_public_ip_literal_passes() -> None:
    assert await validate_public_rpc_url("https://93.184.216.34/rpc") == "https://93.184.216.34/rpc"


@pytest.mark.asyncio
async def test_allow_private_escape_hatch() -> None:
    assert (
        await validate_public_rpc_url("http://127.0.0.1:8545", allow_private=True)
        == "http://127.0.0.1:8545"
    )
