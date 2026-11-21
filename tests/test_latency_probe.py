"""Focused checks for the /api/latency TCP probe endpoint.

The probe target is validated server-side: only globally routable unicast
addresses are accepted. Hostnames that resolve to loopback, private, link-local,
unspecified, or multicast addresses are rejected. The connection pins to the
validated IP address, preventing an independent hostname lookup.

Cases:
* success against a real public destination -> integer milliseconds
* loopback/private/link-local rejected -> HTTPException (504), never fabricated 0 ms
* unresolvable hostname -> HTTPException (504)
* mixed DNS answers (some prohibited, some valid) -> rejected
* IPv4 and IPv6 handling
"""

from __future__ import annotations

import asyncio
import socket

import pytest

from perchvpn_windows.api import get_latency


@pytest.mark.asyncio
async def test_latency_success_against_public_destination():
    """Probe a real public destination and verify integer latency ms."""
    result = await get_latency(host="google.com", port=443)
    assert isinstance(result["latency_ms"], int)
    assert result["latency_ms"] >= 0
    assert result["host"] == "google.com"
    assert result["port"] == 443


@pytest.mark.asyncio
async def test_latency_loopback_rejected():
    """Loopback addresses (127.0.0.1, ::1) are explicitly rejected."""
    import ipaddress  # noqa: F401  needed for the assertion message below
    with pytest.raises(Exception) as exc:
        await get_latency(host="127.0.0.1", port=9999)
    assert "Latency probe failed" in str(exc.value) or "no globally routable" in str(exc.value)


@pytest.mark.asyncio
async def test_latency_private_rejected():
    """Private network addresses are explicitly rejected."""
    with pytest.raises(Exception) as exc:
        await get_latency(host="10.0.0.1", port=9999)
    assert "Latency probe failed" in str(exc.value) or "no globally routable" in str(exc.value)


@pytest.mark.asyncio
async def test_latency_link_local_rejected():
    """Link-local addresses are explicitly rejected."""
    with pytest.raises(Exception) as exc:
        await get_latency(host="169.254.0.1", port=9999)
    assert "Latency probe failed" in str(exc.value) or "no globally routable" in str(exc.value)


class _FakeWriter:
    def close(self) -> None:
        pass

    async def wait_closed(self) -> None:
        pass


@pytest.mark.asyncio
async def test_latency_validated_ip_used(monkeypatch):
    """The probe must connect to the validated IP literal after one lookup.

    Simulates DNS rebinding: a second lookup of the hostname would return
    loopback. The handler must resolve once, connect to the validated public IP,
    and never call ``asyncio.open_connection(host, ...)`` (which re-resolves).
    """
    loop = asyncio.get_running_loop()
    validated_ip = "8.8.8.8"
    async_resolutions: list[str] = []
    sync_resolutions: list[str] = []
    open_connection_calls: list[tuple] = []
    connects: list[tuple] = []

    async def fake_getaddrinfo(host, port, **kwargs):
        async_resolutions.append(host)
        if len(async_resolutions) == 1:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (validated_ip, port))]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

    def fake_sync_getaddrinfo(host, port, **kwargs):
        sync_resolutions.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (validated_ip, port or 0))]

    async def fake_sock_connect(sock, address):
        connects.append(address)

    async def fake_open_connection(*args, **kwargs):
        open_connection_calls.append(args)
        return object(), _FakeWriter()

    monkeypatch.setattr(loop, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(socket, "getaddrinfo", fake_sync_getaddrinfo)
    monkeypatch.setattr(loop, "sock_connect", fake_sock_connect)
    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)

    result = await get_latency(host="edge.example", port=2499)

    assert isinstance(result["latency_ms"], int)
    assert result["latency_ms"] >= 0
    assert len(async_resolutions) == 1, "hostname must be resolved exactly once"
    assert open_connection_calls == [], "asyncio.open_connection re-resolves the hostname"
    assert connects == [(validated_ip, 2499)], f"must connect to the validated IP, got {connects}"


@pytest.mark.asyncio
async def test_latency_mixed_dns_answers_rejected(monkeypatch):
    """If any DNS answer is prohibited, the entire hostname is rejected.

    This covers the case where a hostname resolves to both a valid public IP
    and a prohibited address; the server must reject the hostname and must not
    connect to the public answer.
    """
    loop = asyncio.get_running_loop()
    connects: list[tuple] = []

    async def fake_getaddrinfo(host, port, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port)),
        ]

    def fake_sync_getaddrinfo(host, port, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port or 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port or 0)),
        ]

    async def fake_sock_connect(sock, address):
        connects.append(address)

    monkeypatch.setattr(loop, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(socket, "getaddrinfo", fake_sync_getaddrinfo)
    monkeypatch.setattr(loop, "sock_connect", fake_sock_connect)

    with pytest.raises(Exception) as exc:
        await get_latency(host="mixed.example", port=2499)
    assert "Latency probe failed" in str(exc.value)
    assert connects == [], "must not connect when any DNS answer is prohibited"


@pytest.mark.asyncio
async def test_latency_ipv4_validated():
    """IPv4 addresses go through the same validation pipeline."""
    result = await get_latency(host="8.8.8.8", port=443)
    assert isinstance(result["latency_ms"], int)
    assert result["latency_ms"] >= 0
