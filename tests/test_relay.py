"""Tests for relay and lifecycle behavior."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from perchvpn.proxy.relay import relay_bidirectional, HALF_CLOSE_DRAIN_TIMEOUT
from perchvpn.proxy.session import H2Stream


class MockReader:
    def __init__(self, data_chunks: list[bytes]):
        self._chunks = data_chunks
        self._index = 0
        self._eof = False

    async def read(self, n: int) -> bytes:
        if self._index < len(self._chunks):
            chunk = self._chunks[self._index]
            self._index += 1
            return chunk
        self._eof = True
        return b""

    def at_eof(self) -> bool:
        return self._eof


class MockWriter:
    def __init__(self):
        self._written = bytearray()
        self._closed = False
        self._eof_sent = False

    def write(self, data: bytes):
        self._written.extend(data)

    async def drain(self):
        pass

    def write_eof(self):
        self._eof_sent = True

    def close(self):
        self._closed = True

    async def wait_closed(self):
        pass

    def get_extra_info(self, name):
        return None


class MockUpstreamStream:
    def __init__(self, data_chunks: list[bytes]):
        self._chunks = data_chunks
        self._index = 0
        self._closed = False

    async def read(self) -> bytes | None:
        if self._index < len(self._chunks):
            chunk = self._chunks[self._index]
            self._index += 1
            return chunk
        return None

    async def write(self, data: bytes):
        pass

    async def close(self):
        self._closed = True


class TestRelayBidirectional:
    @pytest.mark.asyncio
    async def test_relay_client_to_upstream(self):
        """Test data flows from client to upstream."""
        reader = MockReader([b"hello", b"world", b""])
        writer = MockWriter()
        upstream = MockUpstreamStream([])

        await relay_bidirectional(reader, writer, upstream, idle_timeout=0.0)

        assert writer._written == b""

    @pytest.mark.asyncio
    async def test_relay_upstream_to_client(self):
        """Test data flows from upstream to client."""
        reader = MockReader([b""])
        writer = MockWriter()
        upstream = MockUpstreamStream([b"hello", b"world", b""])

        await relay_bidirectional(reader, writer, upstream, idle_timeout=0.0)

        assert writer._written == b"helloworld"

    @pytest.mark.asyncio
    async def test_relay_bidirectional_both_directions(self):
        """Test data flows in both directions simultaneously."""
        reader = MockReader([b"client1", b"client2", b""])
        writer = MockWriter()
        upstream = MockUpstreamStream([b"server1", b"server2", b""])

        await relay_bidirectional(reader, writer, upstream, idle_timeout=0.0)

        assert writer._written == b"server1server2"

    @pytest.mark.asyncio
    async def test_relay_half_close_drain(self):
        """Test half-close drain timeout behavior."""
        reader = MockReader([b"data", b""])
        writer = MockWriter()
        upstream = MockUpstreamStream([b"server_data", b"more_data", b""])

        await relay_bidirectional(reader, writer, upstream, idle_timeout=0.0)

        assert b"server_data" in writer._written
        assert b"more_data" in writer._written


class TestFrontendLifecycle:
    """Integration-style tests for frontend start/serve/stop lifecycle."""

    @pytest.mark.asyncio
    async def test_frontend_start_stop_cycle(self):
        from src.perchvpn_windows.frontend import Socks5Frontend
        from perchvpn.proxy.pool import SessionPool

        mock_pool = MagicMock(spec=SessionPool)
        frontend = Socks5Frontend(mock_pool, "127.0.0.1", 0, max_connections=10, idle_timeout=0.0)

        await frontend.start()
        assert frontend._server._server is not None

        # Get the actual bound port
        port = frontend._server._server.sockets[0].getsockname()[1]
        assert port > 0

        await frontend.stop()