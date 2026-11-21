"""Focused tests for resolver-DNS policy selection."""

from __future__ import annotations

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
