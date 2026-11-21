"""DNS-over-HTTPS resolver helpers.

The module keeps the legacy ``DoHResolver`` class for existing callers and adds
``resolve_hostname()``, used by the Windows app to resolve a VPN server
hostname with the configured resolver-DNS policy before tunnel establishment.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import struct
import time
from typing import Iterable, List, Optional

import httpx

logger = logging.getLogger("perchvpn.doh_resolver")

DOH_TIMEOUT = 5.0


class ResolverError(Exception):
    """Raised when a non-system resolver policy cannot produce an address."""


class DoHResolver:
    """Compatibility wrapper retained for existing control-plane experiments."""

    def __init__(self, timeout: float = DOH_TIMEOUT) -> None:
        self.timeout = timeout

    async def resolve(self, host: str, family: int = socket.AF_INET) -> List[str]:
        provider = "cloudflare" if family == socket.AF_INET else "cloudflare"
        try:
            addresses = await resolve_hostname(host, provider, timeout=self.timeout)
        except ResolverError:
            return []
        if family == socket.AF_INET6:
            return [ip for ip in addresses if ":" in ip]
        return [ip for ip in addresses if ":" not in ip]

    async def _system_resolve(self, host: str, family: int) -> List[str]:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, None, family=family, type=socket.SOCK_STREAM)
        return list({info[4][0] for info in infos})


# In-memory DoH result cache. Country switches resolve the same edge
# hostnames repeatedly; without this every switch pays the full DoH RTT
# (2.8-3.4 s on the reference connection). Entries live for the DNS TTL,
# clamped to a 15 minute floor so short TTLs cannot cause a stampede.
_DNS_CACHE_MIN_TTL = 900.0
_DNS_CACHE_MAX_ENTRIES = 512
_DNS_CACHE: "dict[tuple[str, str, str, str], tuple[float, tuple[str, ...]]]" = {}
_DNS_STATS = {"hits": 0, "misses": 0, "expired": 0, "stores": 0}


def clear_dns_cache() -> None:
    _DNS_CACHE.clear()


def dns_cache_stats() -> dict:
    now = time.monotonic()
    live = sum(1 for expires, _ in _DNS_CACHE.values() if expires > now)
    return {
        "entries": len(_DNS_CACHE),
        "live": live,
        **_DNS_STATS,
        "min_ttl": _DNS_CACHE_MIN_TTL,
    }


def _cache_key(host: str, provider: str, custom_ip: str, local_address: Optional[str]) -> tuple[str, str, str, str]:
    return (
        host.strip().lower().rstrip("."),
        provider,
        (custom_ip or "").strip(),
        (local_address or "").strip(),
    )


def _cache_lookup(key: tuple[str, str, str, str]) -> Optional[list[str]]:
    entry = _DNS_CACHE.get(key)
    if entry is None:
        return None
    expires, addresses = entry
    if expires <= time.monotonic():
        _DNS_CACHE.pop(key, None)
        _DNS_STATS["expired"] += 1
        return None
    _DNS_STATS["hits"] += 1
    return list(addresses)


def _cache_store(key: tuple[str, str, str, str], addresses: list[str], ttl: float) -> None:
    if not addresses:
        return
    lifetime = max(float(ttl or 0.0), _DNS_CACHE_MIN_TTL)
    if len(_DNS_CACHE) >= _DNS_CACHE_MAX_ENTRIES:
        # Evict the entry closest to expiry; bounded and deterministic.
        oldest = min(_DNS_CACHE, key=lambda k: _DNS_CACHE[k][0])
        _DNS_CACHE.pop(oldest, None)
    _DNS_CACHE[key] = (time.monotonic() + lifetime, tuple(addresses))
    _DNS_STATS["stores"] += 1


_PROVIDER_ENDPOINTS = {
    "cloudflare": ("1.1.1.1", "1.0.0.1"),
    "google": ("8.8.8.8", "8.8.4.4"),
    "quad9": ("9.9.9.9", "149.112.112.112"),
}


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _build_query(name: str, qtype: int) -> bytes:
    transaction_id = 0x4F50
    flags = 0x0100
    header = struct.pack("!HHHHHH", transaction_id, flags, 1, 0, 0, 0)
    question = b""
    for label in name.strip(".").split("."):
        encoded = label.encode("ascii")
        if not encoded or len(encoded) > 63:
            raise ResolverError(f"invalid DNS name: {name!r}")
        question += bytes([len(encoded)]) + encoded
    question += b"\x00"
    question += struct.pack("!HH", qtype, 1)
    return header + question


def _parse_name(data: bytes, offset: int) -> tuple[int, str]:
    labels: list[str] = []
    jumped = False
    original_offset = offset
    visited: set[int] = set()
    while True:
        if offset >= len(data):
            raise ResolverError("truncated DNS name")
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if offset + 2 > len(data):
                raise ResolverError("truncated DNS pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                original_offset = offset + 2
            if pointer in visited:
                raise ResolverError("DNS compression loop")
            visited.add(pointer)
            offset = pointer
            jumped = True
            continue
        if offset + 1 + length > len(data):
            raise ResolverError("truncated DNS label")
        labels.append(data[offset + 1 : offset + 1 + length].decode("ascii", errors="replace"))
        offset += 1 + length
    return (original_offset if jumped else offset), ".".join(labels)


def _parse_answers(data: bytes, qtype: int) -> list[str]:
    return _parse_answers_with_ttl(data, qtype)[0]


def _parse_answers_with_ttl(data: bytes, qtype: int) -> tuple[list[str], float]:
    if len(data) < 12:
        raise ResolverError("truncated DNS response")
    qdcount = int.from_bytes(data[4:6], "big")
    ancount = int.from_bytes(data[6:8], "big")
    offset = 12
    for _ in range(qdcount):
        offset, _ = _parse_name(data, offset)
        offset += 4
        if offset > len(data):
            raise ResolverError("truncated DNS question")
    addresses: list[str] = []
    min_ttl: Optional[float] = None
    for _ in range(ancount):
        offset, _ = _parse_name(data, offset)
        if offset + 10 > len(data):
            raise ResolverError("truncated DNS answer")
        rtype, rclass, _ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        if offset + rdlength > len(data):
            raise ResolverError("truncated DNS rdata")
        rdata = data[offset : offset + rdlength]
        offset += rdlength
        if rclass != 1:
            continue
        if rtype == 1 and qtype in (1, 255) and rdlength == 4:
            addresses.append(socket.inet_ntoa(rdata))
            min_ttl = float(_ttl) if min_ttl is None else min(min_ttl, float(_ttl))
        elif rtype == 28 and qtype in (28, 255) and rdlength == 16:
            addresses.append(socket.inet_ntop(socket.AF_INET6, rdata))
            min_ttl = float(_ttl) if min_ttl is None else min(min_ttl, float(_ttl))
    return addresses, (min_ttl if min_ttl is not None else 0.0)


def _local_addr_kwargs(local_address: Optional[str]) -> dict:
    if local_address:
        return {"local_address": local_address}
    return {}


async def _query_endpoint(
    host: str,
    endpoint: str,
    timeout: float,
    local_address: Optional[str] = None,
) -> tuple[list[str], float]:
    url = f"https://{endpoint}/dns-query"
    query_a = _build_query(host, 1)
    query_aaaa = _build_query(host, 28)
    results: list[str] = []
    min_ttl: Optional[float] = None

    async with httpx.AsyncClient(
        timeout=timeout,
        verify=True,
        transport=httpx.AsyncHTTPTransport(**_local_addr_kwargs(local_address)),
    ) as client:
        responses = await asyncio.gather(
            client.post(url, content=query_a, headers={"content-type": "application/dns-message", "accept": "application/dns-message"}),
            client.post(url, content=query_aaaa, headers={"content-type": "application/dns-message", "accept": "application/dns-message"}),
            return_exceptions=True,
        )
    for response in responses:
        if isinstance(response, BaseException):
            logger.debug("DoH query to %s failed: %s", endpoint, response)
            continue
        try:
            response.raise_for_status()
            addresses, ttl = _parse_answers_with_ttl(
                response.content, 1 if response is responses[0] else 28
            )
            results.extend(addresses)
            if addresses:
                min_ttl = ttl if min_ttl is None else min(min_ttl, ttl)
        except Exception as exc:  # noqa: BLE001
            logger.debug("DoH response from %s unusable: %s", endpoint, exc)
    # De-duplicate while preserving order.
    seen: set[str] = set()
    unique: list[str] = []
    for address in results:
        if address not in seen:
            seen.add(address)
            unique.append(address)
    if not unique:
        raise ResolverError(f"no DNS answers from {endpoint}")
    return unique, (min_ttl if min_ttl is not None else 0.0)


async def _race_endpoints(
    host: str,
    endpoints: Iterable[str],
    timeout: float,
    local_address: Optional[str] = None,
) -> tuple[list[str], float]:
    tasks = [
        asyncio.create_task(_query_endpoint(host, endpoint, timeout, local_address))
        for endpoint in endpoints
    ]
    pending = set(tasks)
    while pending:
        done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            if task.exception() is None:
                result = task.result()
                for other in pending:
                    other.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
                return result
    raise ResolverError("all DoH endpoints failed")


async def resolve_hostname(
    host: str,
    provider: str,
    custom_ip: str = "",
    timeout: float = 5.0,
    local_address: Optional[str] = None,
) -> Optional[List[str]]:
    """Resolve ``host`` according to the configured resolver policy.

    ``None`` means "use the system resolver / no override". Explicit provider
    failures raise ``ResolverError`` rather than silently falling back to
    system DNS.
    """
    provider = (provider or "system").strip().lower()
    if _is_ip(host):
        return None
    if provider == "system":
        return None
    if provider != "automatic" and provider != "custom" and provider not in _PROVIDER_ENDPOINTS:
        raise ResolverError(f"unknown resolver provider: {provider!r}")
    if provider == "custom" and not _is_ip(custom_ip):
        raise ResolverError("custom resolver must be an IP address")

    key = _cache_key(host, provider, custom_ip, local_address)
    cached = _cache_lookup(key)
    if cached is not None:
        logger.debug("DoH cache hit for %s (%s)", host, provider)
        return cached
    _DNS_STATS["misses"] += 1

    if provider == "automatic":
        endpoints = [ip for pair in _PROVIDER_ENDPOINTS.values() for ip in pair]
        try:
            addresses, ttl = await _race_endpoints(host, endpoints, timeout, local_address)
        except ResolverError as exc:
            raise ResolverError(f"automatic DoH resolution failed: {exc}") from exc
    else:
        endpoints = (custom_ip,) if provider == "custom" else _PROVIDER_ENDPOINTS[provider]
        addresses, ttl = await _race_endpoints(host, endpoints, timeout, local_address)
    _cache_store(key, addresses, ttl)
    return addresses


class DoHTransport(httpx.AsyncBaseTransport):
    """Compatibility transport retained for ``http_client``.

    It intentionally does not rewrite the connection target because httpx
    connection pooling/SNI handling is not safely replaceable here. Resolver
    policy for VPN-server hostnames is applied separately by
    ``resolve_hostname()`` before tunnel establishment.
    """

    def __init__(
        self,
        fallback_transport: Optional[httpx.AsyncBaseTransport] = None,
        doh_resolver: Optional["DoHResolver"] = None,
    ) -> None:
        self._fallback = fallback_transport or httpx.AsyncHTTPTransport()
        self._doh_resolver = doh_resolver or DoHResolver()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return await self._fallback.handle_async_request(request)
