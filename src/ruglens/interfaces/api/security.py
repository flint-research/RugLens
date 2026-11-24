"""SSRF protection for caller-supplied RPC endpoints."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from urllib.parse import urlsplit

from ruglens.core.exceptions import UnsafeUrlError

_BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "metadata",
}
_BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".home.arpa")
_EXTRA_BLOCKED_NETWORKS = (
    ipaddress.ip_network("100.64.0.0/10"),  # carrier-grade NAT
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),  # benchmarking
    ipaddress.ip_network("240.0.0.0/4"),
)


def _is_blocked_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        return True
    return any(address in network for network in _EXTRA_BLOCKED_NETWORKS)


async def validate_public_rpc_url(url: str, *, allow_private: bool = False) -> str:
    """Validate an HTTP(S) RPC URL against private/loopback/link-local targets.

    DNS is resolved and every returned address is checked. Custom RPC endpoints
    are disabled by default in the API; enabling them still requires this check.
    """
    if not isinstance(url, str) or not url.strip():
        raise UnsafeUrlError("RPC URL must be a non-empty string")
    if len(url) > 2_048:
        raise UnsafeUrlError("RPC URL is too long")
    parsed = urlsplit(url.strip())
    if parsed.scheme not in {"http", "https"}:
        raise UnsafeUrlError("RPC URL scheme must be http or https")
    if parsed.username or parsed.password:
        raise UnsafeUrlError("RPC URLs may not contain credentials")
    if parsed.fragment:
        raise UnsafeUrlError("RPC URLs may not contain fragments")
    hostname = parsed.hostname
    if not hostname:
        raise UnsafeUrlError("RPC URL must include a hostname")
    normalized_host = hostname.rstrip(".").lower()
    if normalized_host in _BLOCKED_HOSTNAMES or normalized_host.endswith(_BLOCKED_SUFFIXES):
        raise UnsafeUrlError("RPC URL resolves to a blocked local hostname")
    try:
        port = parsed.port
    except ValueError as exc:
        raise UnsafeUrlError("RPC URL has an invalid port") from exc
    if port == 0:
        raise UnsafeUrlError("RPC URL has an invalid port")
    if allow_private:
        return url.strip()

    try:
        literal = ipaddress.ip_address(normalized_host.split("%", 1)[0])
    except ValueError:
        literal = None
    if literal is not None:
        if _is_blocked_address(literal):
            raise UnsafeUrlError("RPC URL points to a blocked IP address")
        return url.strip()

    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(
                normalized_host,
                port or (443 if parsed.scheme == "https" else 80),
                type=socket.SOCK_STREAM,
            ),
            timeout=3.0,
        )
    except TimeoutError as exc:
        raise UnsafeUrlError(f"RPC hostname resolution timed out: {hostname}") from exc
    except socket.gaierror as exc:
        raise UnsafeUrlError(f"RPC hostname could not be resolved: {hostname}") from exc
    if not infos:
        raise UnsafeUrlError(f"RPC hostname resolved to no addresses: {hostname}")
    for info in infos:
        raw_address = info[4][0]
        try:
            address = ipaddress.ip_address(str(raw_address).split("%", 1)[0])
        except ValueError as exc:
            raise UnsafeUrlError("RPC hostname resolved to an invalid address") from exc
        if _is_blocked_address(address):
            raise UnsafeUrlError(
                f"RPC hostname resolves to a blocked private/internal address: {raw_address}"
            )
    return url.strip()
