"""Tests for SOCKS5 frontend lifecycle and binding."""

from __future__ import annotations

import asyncio
import logging
import socket
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.perchvpn_windows.frontend import Socks5Frontend
from perchvpn.proxy.pool import SessionPool
from perchvpn.proxy.session import H2ProxySession, H2Stream


class TestSocks5Frontend:
    @pytest.fixture
    def mock_pool(self):
        pool = MagicMock(spec=SessionPool)
        pool.open_stream = AsyncMock()
        return pool

    @pytest.fixture
    def mock_stream(self):
        stream = MagicMock(spec=H2Stream)
        stream.read = AsyncMock(return_value=None)
        stream.write = AsyncMock()
        stream.close = AsyncMock()
        stream.wait_established = AsyncMock()
        stream.established = asyncio.Event()
        stream.established.set()
        return stream

    @pytest.mark.asyncio
    async def test_frontend_start_binds_to_address(self, mock_pool):
        frontend = Socks5Frontend(mock_pool, "127.0.0.1", 1080, max_connections=10, idle_timeout=0.0)
        await frontend.start()
        assert frontend.host == "127.0.0.1"
        assert frontend.port == 1080
        await frontend.stop()

    @pytest.mark.asyncio
    async def test_frontend_start_with_zero_max_connections(self, mock_pool):
        frontend = Socks5Frontend(mock_pool, "127.0.0.1", 1080, max_connections=0, idle_timeout=0.0)
        await frontend.start()
        await frontend.stop()

    @pytest.mark.asyncio
    async def test_frontend_start_with_idle_timeout(self, mock_pool):
        frontend = Socks5Frontend(mock_pool, "127.0.0.1", 1080, max_connections=10, idle_timeout=30.0)
        await frontend.start()
        await frontend.stop()

    @pytest.mark.asyncio
    async def test_frontend_stop_closes_server(self, mock_pool):
        frontend = Socks5Frontend(mock_pool, "127.0.0.1", 1080)
        await frontend.start()
        await frontend.stop()

    @pytest.mark.asyncio
    async def test_frontend_bind_failure_logs_exact_error(self, mock_pool, caplog):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as blocker:
            blocker.bind(("127.0.0.1", 0))
            blocker.listen(1)
            port = blocker.getsockname()[1]
            frontend = Socks5Frontend(mock_pool, "127.0.0.1", port)
            with caplog.at_level(logging.ERROR, logger="perchvpn_windows.frontend"):
                with pytest.raises(OSError):
                    await frontend.start()

        assert "SOCKS5 proxy failed to bind" in caplog.text
        assert "127.0.0.1:%d" % port in caplog.text
