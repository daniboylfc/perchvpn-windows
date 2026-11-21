"""Focused tests for the local HTTP proxy frontend."""

from __future__ import annotations

import asyncio

import pytest

from src.perchvpn_windows.http_proxy import HttpProxyServer


@pytest.mark.asyncio
async def test_http_proxy_binds_and_rejects_without_session():
    server = HttpProxyServer("127.0.0.1", 0, lambda: None, proxy_only_mode=True)
    await server.start()
    try:
        sock = server._server.sockets[0]
        host, port = sock.getsockname()[:2]
        assert host == "127.0.0.1"
        assert port > 0

        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=2)
        writer.write(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        await writer.drain()
        response = await asyncio.wait_for(reader.read(256), timeout=2)
        writer.close()
        await writer.wait_closed()

        assert response.startswith(b"HTTP/1.1 502")
    finally:
        await server.stop()

    with pytest.raises((ConnectionRefusedError, OSError)):
        await asyncio.wait_for(asyncio.open_connection(host, port), timeout=1)


@pytest.mark.asyncio
async def test_loopback_bind_accepted():
    for host in ("127.0.0.1", "::1"):
        server = HttpProxyServer(host, 0, lambda: None, proxy_only_mode=True)
        await server.start()
        try:
            assert server._server is not None
            assert server._server.sockets
        finally:
            await server.stop()


@pytest.mark.asyncio
async def test_wildcard_bind_rejected():
    for host in ("0.0.0.0", "::"):
        server = HttpProxyServer(host, 0, lambda: None, proxy_only_mode=True)
        with pytest.raises(ValueError, match="loopback"):
            await server.start()


@pytest.mark.asyncio
async def test_wildcard_bind_accepted_with_local_proxy_auth():
    server = HttpProxyServer(
        "0.0.0.0", 0, lambda: None, proxy_only_mode=True,
        local_proxy_users={"alice": "secret"},
    )
    await server.start()
    try:
        assert server._server is not None
    finally:
        await server.stop()


def test_config_wildcard_http_proxy_bind_requires_auth():
    from src.perchvpn_windows.config import WindowsConfig

    with pytest.raises(ValueError, match="loopback"):
        WindowsConfig(listen_host="0.0.0.0", http_proxy_enabled=True)
    WindowsConfig(
        listen_host="0.0.0.0",
        http_proxy_enabled=True,
        local_proxy_auth_enabled=True,
        local_proxy_username="alice",
        local_proxy_password="secret",
    )


@pytest.mark.asyncio
async def test_nonloopback_bind_rejected():
    server = HttpProxyServer("192.0.2.10", 0, lambda: None, proxy_only_mode=True)
    with pytest.raises(ValueError, match="loopback"):
        await server.start()


def test_config_rejects_nonloopback_http_proxy_bind():
    from src.perchvpn_windows.config import WindowsConfig

    with pytest.raises(ValueError, match="loopback"):
        WindowsConfig(listen_host="0.0.0.0", http_proxy_enabled=True)
    with pytest.raises(ValueError, match="loopback"):
        WindowsConfig(listen_host="192.0.2.10", http_proxy_enabled=True)
    WindowsConfig(listen_host="127.0.0.1", http_proxy_enabled=True)
    WindowsConfig(listen_host="::1", http_proxy_enabled=True)


def test_api_rejects_nonloopback_http_proxy_bind():
    from pydantic import ValidationError
    from src.perchvpn_windows.api import NetworkConfig

    with pytest.raises(ValidationError):
        NetworkConfig(http_proxy_enabled=True, socks_bind_address="0.0.0.0")
    with pytest.raises(ValidationError):
        NetworkConfig(http_proxy_enabled=True, socks_bind_address="192.0.2.10")
    NetworkConfig(http_proxy_enabled=True, socks_bind_address="127.0.0.1")
    NetworkConfig(http_proxy_enabled=True, socks_bind_address="::1")


@pytest.mark.asyncio
async def test_http_proxy_stop_terminates_active_connect_tunnel():
    class FakeUpstream:
        def __init__(self) -> None:
            self.closed = asyncio.Event()
            self.read_started = asyncio.Event()

        async def read(self):
            self.read_started.set()
            await asyncio.Event().wait()

        async def write(self, data: bytes) -> None:
            return None

        async def close(self) -> None:
            self.closed.set()

    upstream = FakeUpstream()

    class FakePool:
        async def open_stream(self, host, port):
            return upstream

    server = HttpProxyServer("127.0.0.1", 0, lambda: FakePool(), proxy_only_mode=False)
    await server.start()
    try:
        host, port = server._server.sockets[0].getsockname()[:2]
        client_reader, client_writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=2
        )
        client_writer.write(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        await client_writer.drain()
        response = await asyncio.wait_for(client_reader.readuntil(b"\r\n\r\n"), timeout=2)
        assert response.startswith(b"HTTP/1.1 200")

        await asyncio.wait_for(upstream.read_started.wait(), timeout=2)

        await asyncio.wait_for(server.stop(), timeout=2)

        assert upstream.closed.is_set()
        client_writer.close()
        try:
            await asyncio.wait_for(client_writer.wait_closed(), timeout=2)
        except (ConnectionError, OSError):
            pass
    finally:
        try:
            await server.stop()
        except Exception:
            pass
