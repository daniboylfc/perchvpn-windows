"""SOCKS5 protocol tests: no-auth CONNECT for IPv4, domain, IPv6."""

from __future__ import annotations

import asyncio
import struct
import ipaddress
from unittest.mock import AsyncMock, MagicMock

import pytest

from perchvpn.proxy.socks import Socks5Server, SOCKS_VERSION, _CMD_CONNECT, _REP_COMMAND_NOT_SUPPORTED, _REP_ADDRESS_TYPE_NOT_SUPPORTED, _REP_SUCCEEDED
from perchvpn.proxy.pool import SessionPool
from perchvpn.proxy.session import H2Stream


class MockReader:
    def __init__(self, data: bytes = b""):
        self._buffer = bytearray(data)
        self._read_event = asyncio.Event()
        self._eof = False

    def feed(self, data: bytes):
        self._buffer.extend(data)
        self._read_event.set()

    def set_eof(self):
        self._eof = True
        self._read_event.set()

    async def readexactly(self, n: int) -> bytes:
        while len(self._buffer) < n:
            if self._eof:
                raise asyncio.IncompleteReadError(bytes(self._buffer), n)
            await self._read_event.wait()
            self._read_event.clear()
        data = bytes(self._buffer[:n])
        del self._buffer[:n]
        return data


class MockWriter:
    def __init__(self):
        self._written = bytearray()
        self._closed = False

    def write(self, data: bytes):
        self._written.extend(data)

    async def drain(self):
        pass

    def get_extra_info(self, name):
        if name == "peername":
            return ("127.0.0.1", 12345)
        if name == "sockname":
            return ("127.0.0.1", 1080)
        return None

    def close(self):
        self._closed = True

    async def wait_closed(self):
        pass


@pytest.fixture
def mock_pool():
    pool = MagicMock(spec=SessionPool)
    mock_stream = MagicMock(spec=H2Stream)
    mock_stream.read = AsyncMock(return_value=None)
    mock_stream.write = AsyncMock()
    mock_stream.close = AsyncMock()
    mock_stream.wait_established = AsyncMock()
    mock_stream.established = asyncio.Event()
    mock_stream.established.set()
    pool.open_stream = AsyncMock(return_value=mock_stream)
    return pool


@pytest.fixture
def server(mock_pool):
    return Socks5Server("127.0.0.1", 1080, mock_pool, max_connections=10, idle_timeout=0.0)


class TestSocks5NoAuthConnect:
    @pytest.mark.asyncio
    async def test_ipv4_connect(self, server, mock_pool):
        """Test SOCKS5 CONNECT to IPv4 address."""
        reader = MockReader()
        writer = MockWriter()
        server_task = asyncio.create_task(server._negotiate_and_serve(reader, writer, "127.0.0.1"))

        await asyncio.sleep(0.01)

        # Send SOCKS5 handshake: version=5, nmethods=1, method=0 (no auth)
        reader.feed(struct.pack("!BB", SOCKS_VERSION, 1) + bytes([0x00]))

        # Send CONNECT request: version=5, cmd=1 (CONNECT), rsv=0, atyp=1 (IPv4), addr=1.2.3.4, port=80
        reader.feed(struct.pack("!BBBB", SOCKS_VERSION, _CMD_CONNECT, 0x00, 0x01) + ipaddress.IPv4Address("1.2.3.4").packed + struct.pack("!H", 80))

        await asyncio.wait_for(server_task, timeout=1.0)

        # Verify upstream was called with correct target
        mock_pool.open_stream.assert_called_once()
        args, kwargs = mock_pool.open_stream.call_args
        assert args[0] == "1.2.3.4"
        assert args[1] == 80
        assert kwargs.get("affinity_key") == "127.0.0.1"

        # Verify success reply sent
        assert len(writer._written) > 0

    @pytest.mark.asyncio
    async def test_domain_connect(self, server, mock_pool):
        """Test SOCKS5 CONNECT to domain name."""
        reader = MockReader()
        writer = MockWriter()
        server_task = asyncio.create_task(server._negotiate_and_serve(reader, writer, "127.0.0.1"))

        await asyncio.sleep(0.01)

        reader.feed(struct.pack("!BB", SOCKS_VERSION, 1) + bytes([0x00]))

        # Domain: length=9, "example.com", port=443
        domain = b"example.com"
        reader.feed(struct.pack("!BBBB", SOCKS_VERSION, _CMD_CONNECT, 0x00, 0x03) + bytes([len(domain)]) + domain + struct.pack("!H", 443))

        await asyncio.wait_for(server_task, timeout=1.0)

        mock_pool.open_stream.assert_called_once()
        args, kwargs = mock_pool.open_stream.call_args
        assert args[0] == "example.com"
        assert args[1] == 443

    @pytest.mark.asyncio
    async def test_ipv6_connect(self, server, mock_pool):
        """Test SOCKS5 CONNECT to IPv6 address."""
        reader = MockReader()
        writer = MockWriter()
        server_task = asyncio.create_task(server._negotiate_and_serve(reader, writer, "127.0.0.1"))

        await asyncio.sleep(0.01)

        reader.feed(struct.pack("!BB", SOCKS_VERSION, 1) + bytes([0x00]))

        # IPv6: atyp=4, addr=::1, port=443 (MASQUE-gated ports reach upstream)
        ipv6_addr = ipaddress.IPv6Address("::1").packed
        reader.feed(struct.pack("!BBBB", SOCKS_VERSION, _CMD_CONNECT, 0x00, 0x04) + ipv6_addr + struct.pack("!H", 443))

        await asyncio.wait_for(server_task, timeout=1.0)

        mock_pool.open_stream.assert_called_once()
        args, kwargs = mock_pool.open_stream.call_args
        assert args[0] == "::1"
        assert args[1] == 443

    @pytest.mark.asyncio
    async def test_unsupported_version_rejected(self, server, mock_pool):
        """Test that non-SOCKS5 version is rejected."""
        reader = MockReader()
        writer = MockWriter()
        server_task = asyncio.create_task(server._negotiate_and_serve(reader, writer, "127.0.0.1"))

        await asyncio.sleep(0.01)

        # Send version 4 (SOCKS4)
        reader.feed(struct.pack("!BB", 4, 1) + bytes([0x00]))

        with pytest.raises(ConnectionError, match="unsupported SOCKS version 4"):
            await asyncio.wait_for(server_task, timeout=1.0)

    @pytest.mark.asyncio
    async def test_unsupported_command_rejected(self, server, mock_pool):
        """Test that non-CONNECT command is rejected."""
        reader = MockReader()
        writer = MockWriter()
        server_task = asyncio.create_task(server._negotiate_and_serve(reader, writer, "127.0.0.1"))

        await asyncio.sleep(0.01)

        reader.feed(struct.pack("!BB", SOCKS_VERSION, 1) + bytes([0x00]))

        # BIND command (0x02)
        reader.feed(struct.pack("!BBBB", SOCKS_VERSION, 0x02, 0x00, 0x01) + ipaddress.IPv4Address("1.2.3.4").packed + struct.pack("!H", 80))

        await asyncio.wait_for(server_task, timeout=1.0)

        # Should have sent command not supported reply (after 2-byte handshake reply)
        assert len(writer._written) >= 12
        reply = writer._written[2:12]  # Skip 2-byte handshake reply
        assert reply[1] == _REP_COMMAND_NOT_SUPPORTED

    @pytest.mark.asyncio
    async def test_unsupported_address_type_rejected(self, server, mock_pool):
        """Test that unsupported address type is rejected."""
        reader = MockReader()
        writer = MockWriter()
        server_task = asyncio.create_task(server._negotiate_and_serve(reader, writer, "127.0.0.1"))

        await asyncio.sleep(0.01)

        reader.feed(struct.pack("!BB", SOCKS_VERSION, 1) + bytes([0x00]))

        # Invalid atyp = 0x02 (not defined in RFC 1928)
        reader.feed(struct.pack("!BBBB", SOCKS_VERSION, _CMD_CONNECT, 0x00, 0x02) + b"\x00\x00\x00\x00" + struct.pack("!H", 80))

        await asyncio.wait_for(server_task, timeout=1.0)

        assert len(writer._written) >= 12
        reply = writer._written[2:12]  # Skip 2-byte handshake reply
        assert reply[1] == _REP_ADDRESS_TYPE_NOT_SUPPORTED

    @pytest.mark.asyncio
    async def test_no_auth_method_offered_rejected(self, server, mock_pool):
        """Test that client not offering no-auth is rejected."""
        reader = MockReader()
        writer = MockWriter()
        server_task = asyncio.create_task(server._negotiate_and_serve(reader, writer, "127.0.0.1"))

        await asyncio.sleep(0.01)

        # Offer only GSSAPI (0x01), not no-auth (0x00)
        reader.feed(struct.pack("!BB", SOCKS_VERSION, 1) + bytes([0x01]))

        with pytest.raises(ConnectionError, match="client did not offer a supported SOCKS auth method"):
            await asyncio.wait_for(server_task, timeout=1.0)


class TestSocks5ReplyFormat:
    @pytest.mark.asyncio
    async def test_reply_contains_correct_format(self, server, mock_pool):
        """Verify SOCKS5 reply format for successful connection."""
        reader = MockReader()
        writer = MockWriter()
        server_task = asyncio.create_task(server._negotiate_and_serve(reader, writer, "127.0.0.1"))

        await asyncio.sleep(0.01)

        reader.feed(struct.pack("!BB", SOCKS_VERSION, 1) + bytes([0x00]))
        reader.feed(struct.pack("!BBBB", SOCKS_VERSION, _CMD_CONNECT, 0x00, 0x01) + ipaddress.IPv4Address("1.2.3.4").packed + struct.pack("!H", 80))

        await asyncio.wait_for(server_task, timeout=1.0)

        # Parse reply (skip 2-byte handshake reply)
        reply = writer._written[2:12]
        ver, rep, rsv, atyp = struct.unpack("!BBBB", reply[:4])
        assert ver == SOCKS_VERSION
        assert rep == _REP_SUCCEEDED
        assert rsv == 0x00
        assert atyp == 0x01  # IPv4
        assert reply[4:8] == ipaddress.IPv4Address("127.0.0.1").packed
        assert struct.unpack("!H", reply[8:10])[0] == 1080

class TestSocks5UserPassAuth:
    """RFC 1929 user/pass negotiation when local proxy auth is configured."""

    @staticmethod
    def _authed_server(mock_pool):
        return Socks5Server(
            "127.0.0.1", 1080, mock_pool, local_proxy_users={"alice": "s3cret"}
        )

    @pytest.mark.asyncio
    async def test_correct_credentials_connect(self, mock_pool):
        server = self._authed_server(mock_pool)
        reader = MockReader()
        writer = MockWriter()
        task = asyncio.create_task(server._negotiate_and_serve(reader, writer, "127.0.0.1"))
        await asyncio.sleep(0.01)

        reader.feed(struct.pack("!BB", SOCKS_VERSION, 1) + bytes([0x02]))
        await asyncio.sleep(0.01)
        version, method = struct.unpack("!BB", bytes(writer._written[0:2]))
        assert method == 0x02

        user = b"alice"
        password = b"s3cret"
        reader.feed(
            struct.pack("!BB", 0x01, len(user)) + user
            + struct.pack("!B", len(password)) + password
        )
        await asyncio.sleep(0.01)
        aver, astatus = struct.unpack("!BB", bytes(writer._written[-2:]))
        assert (aver, astatus) == (0x01, 0x00)

        reader.feed(
            struct.pack("!BBBB", SOCKS_VERSION, _CMD_CONNECT, 0x00, 0x01)
            + ipaddress.IPv4Address("1.2.3.4").packed + struct.pack("!H", 443)
        )
        await asyncio.wait_for(task, timeout=1.0)
        assert mock_pool.open_stream.await_count == 1

    @pytest.mark.asyncio
    async def test_wrong_credentials_rejected(self, mock_pool):
        server = self._authed_server(mock_pool)
        reader = MockReader()
        writer = MockWriter()
        task = asyncio.create_task(server._negotiate_and_serve(reader, writer, "127.0.0.1"))
        await asyncio.sleep(0.01)

        reader.feed(struct.pack("!BB", SOCKS_VERSION, 1) + bytes([0x02]))
        await asyncio.sleep(0.01)
        user = b"alice"
        password = b"wrong"
        reader.feed(
            struct.pack("!BB", 0x01, len(user)) + user
            + struct.pack("!B", len(password)) + password
        )
        with pytest.raises(ConnectionError):
            await asyncio.wait_for(task, timeout=1.0)
        aver, astatus = struct.unpack("!BB", bytes(writer._written[-2:]))
        assert astatus == 0x01
        mock_pool.open_stream.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_auth_only_client_rejected_when_auth_configured(self, mock_pool):
        server = self._authed_server(mock_pool)
        reader = MockReader()
        writer = MockWriter()
        task = asyncio.create_task(server._negotiate_and_serve(reader, writer, "127.0.0.1"))
        await asyncio.sleep(0.01)

        reader.feed(struct.pack("!BB", SOCKS_VERSION, 1) + bytes([0x00]))
        with pytest.raises(ConnectionError):
            await asyncio.wait_for(task, timeout=1.0)
        version, method = struct.unpack("!BB", bytes(writer._written[0:2]))
        assert method == 0xFF
        mock_pool.open_stream.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_auth_connect_when_auth_not_configured(self, server, mock_pool):
        reader = MockReader()
        writer = MockWriter()
        task = asyncio.create_task(server._negotiate_and_serve(reader, writer, "127.0.0.1"))
        await asyncio.sleep(0.01)
        reader.feed(struct.pack("!BB", SOCKS_VERSION, 2) + bytes([0x00, 0x02]))
        await asyncio.sleep(0.01)
        version, method = struct.unpack("!BB", bytes(writer._written[0:2]))
        assert method == 0x00
        reader.feed(
            struct.pack("!BBBB", SOCKS_VERSION, _CMD_CONNECT, 0x00, 0x01)
            + ipaddress.IPv4Address("1.2.3.4").packed + struct.pack("!H", 443)
        )
        await asyncio.wait_for(task, timeout=1.0)
        assert mock_pool.open_stream.await_count == 1
