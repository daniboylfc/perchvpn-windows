"""Focused tests for resolver-DNS policy selection."""

from __future__ import annotations

import asyncio
import socket
import struct

import pytest

from perchvpn import doh_resolver


def _dns_response(ip: str) -> bytes:
    header = struct.pack("!HHHHHH", 0x4F50, 0x8180, 1, 1, 0, 0)
    question = b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
    rdata = socket.inet_aton(ip)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + rdata
    return header + question + answer


class FakeResponse:
    def __init__(self, content: bytes):
        self.content = content
        self.status_code = 200

    def raise_for_status(self):
        return None


class FakeClient:
    def __init__(self, content: bytes):
        self.content = content

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    async def post(self, url, content=None, headers=None):
        return FakeResponse(self.content)


@pytest.mark.asyncio
async def test_system_resolver_returns_none(monkeypatch):
    assert await doh_resolver.resolve_hostname("example.com", "system") is None


@pytest.mark.asyncio
async def test_named_resolver_returns_doh_address(monkeypatch):
    monkeypatch.setattr(doh_resolver.httpx, "AsyncClient", lambda **kwargs: FakeClient(_dns_response("9.3.3.3")))
    assert await doh_resolver.resolve_hostname("example.com", "quad9") == ["9.3.3.3"]


@pytest.mark.asyncio
async def test_http_client_uses_certificate_verification(monkeypatch):
    captured = {}

    class CapturingClient(FakeClient):
        def __init__(self, **kwargs):
            captured.update(kwargs)
            super().__init__(_dns_response("9.3.3.3"))

    monkeypatch.setattr(doh_resolver.httpx, "AsyncClient", CapturingClient)
    await doh_resolver.resolve_hostname("example.com", "quad9")
    assert captured.get("verify") is True


@pytest.mark.asyncio
async def test_custom_resolver_requires_ip(monkeypatch):
    with pytest.raises(doh_resolver.ResolverError):
        await doh_resolver.resolve_hostname("example.com", "custom", custom_ip="not-an-ip")


@pytest.mark.asyncio
async def test_named_resolver_does_not_fallback_on_failure(monkeypatch):
    class FailingClient(FakeClient):
        async def post(self, url, content=None, headers=None):
            raise RuntimeError("boom")

    monkeypatch.setattr(doh_resolver.httpx, "AsyncClient", lambda **kwargs: FailingClient(b""))
    with pytest.raises(doh_resolver.ResolverError):
        await doh_resolver.resolve_hostname("example.com", "cloudflare")


@pytest.mark.asyncio
async def test_automatic_fails_closed_on_total_failure(monkeypatch):
    class FailingClient(FakeClient):
        async def post(self, url, content=None, headers=None):
            raise RuntimeError("boom")

    monkeypatch.setattr(doh_resolver.httpx, "AsyncClient", lambda **kwargs: FailingClient(b""))
    with pytest.raises(doh_resolver.ResolverError):
        await doh_resolver.resolve_hostname("example.com", "automatic")


@pytest.mark.asyncio
async def test_quad9_endpoints_negotiate_http2(monkeypatch):
    """Quad9 answers HTTP/1.1 with "505 HTTP Version Not Supported".

    Its endpoints must be dialled with HTTP/2 negotiated via ALPN, otherwise
    every Quad9 query fails while still being raced by "automatic".
    """
    captured: dict = {}

    def transport_factory(**kwargs):
        captured.update(kwargs)
        return object()

    monkeypatch.setattr(doh_resolver.httpx, "AsyncHTTPTransport", transport_factory)
    monkeypatch.setattr(
        doh_resolver.httpx, "AsyncClient", lambda **kwargs: FakeClient(_dns_response("9.3.3.3"))
    )
    assert await doh_resolver.resolve_hostname("example.com", "quad9") == ["9.3.3.3"]
    assert captured.get("http2") is True


@pytest.mark.asyncio
async def test_http1_endpoints_keep_http1(monkeypatch):
    captured: dict = {}

    def transport_factory(**kwargs):
        captured.update(kwargs)
        return object()

    monkeypatch.setattr(doh_resolver.httpx, "AsyncHTTPTransport", transport_factory)
    monkeypatch.setattr(
        doh_resolver.httpx, "AsyncClient", lambda **kwargs: FakeClient(_dns_response("9.3.3.3"))
    )
    await doh_resolver.resolve_hostname("example.com", "cloudflare")
    assert captured.get("http2") is False


@pytest.mark.asyncio
async def test_losing_race_tasks_never_leak_exceptions(monkeypatch):
    """A loser that fails after the winner returned must be awaited.

    Otherwise asyncio logs "Task exception was never retrieved" for a query
    the caller never saw.
    """
    handled: list = []

    async def fake_query(host, endpoint, timeout, local_address=None):
        if endpoint == "1.1.1.1":
            return ["9.3.3.3"], 60.0
        await asyncio.sleep(0.05)
        raise doh_resolver.ResolverError("late failure from %s" % endpoint)

    monkeypatch.setattr(doh_resolver, "_query_endpoint", fake_query)
    loop = asyncio.get_running_loop()
    loop.set_exception_handler(lambda _loop, ctx: handled.append(ctx))
    try:
        result = await doh_resolver._race_endpoints(
            "example.com", ["1.1.1.1", "8.8.8.8"], 1.0
        )
        await asyncio.sleep(0.1)
    finally:
        loop.set_exception_handler(None)
    assert result[0] == ["9.3.3.3"]
    assert handled == []


@pytest.mark.asyncio
async def test_cancelled_race_cancels_every_query(monkeypatch):
    started: list = []
    cancelled: list = []

    async def fake_query(host, endpoint, timeout, local_address=None):
        started.append(endpoint)
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            cancelled.append(endpoint)
            raise
        return ["9.3.3.3"], 60.0

    monkeypatch.setattr(doh_resolver, "_query_endpoint", fake_query)
    task = asyncio.create_task(
        doh_resolver._race_endpoints("example.com", ["1.1.1.1", "8.8.8.8"], 1.0)
    )
    for _ in range(50):
        if len(started) == 2:
            break
        await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.sleep(0.05)
    assert sorted(cancelled) == ["1.1.1.1", "8.8.8.8"]
