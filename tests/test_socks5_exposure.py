"""Focused tests for SOCKS5 loopback-only binding."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from src.perchvpn.proxy.socks import Socks5Server
from src.perchvpn_windows.api import NetworkConfig
from src.perchvpn_windows.config import WindowsConfig


def test_config_accepts_loopback_socks_bind():
    WindowsConfig(listen_host="127.0.0.1")
    WindowsConfig(listen_host="::1")


def test_config_wildcard_socks_bind_requires_local_proxy_auth():
    with pytest.raises(ValueError, match="loopback"):
        WindowsConfig(listen_host="0.0.0.0")
    with pytest.raises(ValueError, match="loopback"):
        WindowsConfig(listen_host="0.0.0.0", local_proxy_auth_enabled=True)
    WindowsConfig(
        listen_host="0.0.0.0",
        local_proxy_auth_enabled=True,
        local_proxy_username="alice",
        local_proxy_password="secret",
    )
    with pytest.raises(ValueError, match="loopback"):
        WindowsConfig(listen_host="192.0.2.10")


def test_api_wildcard_socks_bind_requires_local_proxy_auth():
    with pytest.raises(ValidationError):
        NetworkConfig(socks_bind_address="0.0.0.0")
    with pytest.raises(ValidationError):
        NetworkConfig(
            socks_bind_address="0.0.0.0",
            local_proxy_auth_enabled=True,
            local_proxy_username="alice",
            local_proxy_password="",
        )
    NetworkConfig(
        socks_bind_address="0.0.0.0",
        local_proxy_auth_enabled=True,
        local_proxy_username="alice",
        local_proxy_password="secret",
    )
    with pytest.raises(ValidationError):
        NetworkConfig(socks_bind_address="192.0.2.10")
    NetworkConfig(socks_bind_address="127.0.0.1")
    NetworkConfig(socks_bind_address="::1")


@pytest.mark.asyncio
async def test_socks_server_rejects_nonloopback_bind():
    pool = MagicMock()
    for host in ("192.0.2.10",):
        server = Socks5Server(host, 0, pool)
        with pytest.raises(ValueError, match="loopback"):
            await server.start()


@pytest.mark.asyncio
async def test_socks_server_wildcard_bind_requires_auth():
    pool = MagicMock()
    server = Socks5Server("0.0.0.0", 0, pool)
    with pytest.raises(ValueError, match="loopback"):
        await server.start()
    server = Socks5Server(
        "0.0.0.0", 0, pool, local_proxy_users={"alice": "secret"}
    )
    await server.start()
    try:
        assert server._server is not None
    finally:
        await server.close()


@pytest.mark.asyncio
async def test_socks_server_accepts_loopback_bind():
    pool = MagicMock()
    for host in ("127.0.0.1", "::1"):
        server = Socks5Server(host, 0, pool)
        await server.start()
        try:
            assert server._server is not None
        finally:
            await server.close()
