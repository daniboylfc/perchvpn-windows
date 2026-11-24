"""Regression: a multi-MB outbound upload must flow through HTTP/2 CONNECT.

The relay hands ``H2Stream.write`` whatever a socket read produced (up to
64 KiB).  hyper-h2 refuses any frame larger than the remaining stream window
(65 535 bytes initially) or the peer's maximum frame size (16 KiB by default),
and it does not buffer, so a single ``send_data`` call for such a chunk raised
``FlowControlError``/``FrameTooLargeError`` and the tunnel was torn down
mid-upload.  ``H2ProxySession._send_data`` now splits the payload into
admissible frames and waits for the peer's WINDOW_UPDATE when the window runs
dry.

These tests wire two real hyper-h2 connections together in memory (no sockets,
no TLS): the peer mirrors the behaviour that matters - it consumes DATA and
acknowledges it, which is what makes the window grow again.
"""

from __future__ import annotations

import asyncio

import pytest
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, StreamEnded

import perchvpn.proxy.session as session_module
from perchvpn.exceptions import ProxyError
from perchvpn.proxy.session import H2ProxySession, H2Stream


class _Wire:
    """Minimal stand-in for the asyncio TLS writer (bytes in, bytes out)."""

    def __init__(self) -> None:
        self._buffer = bytearray()

    def write(self, data: bytes) -> None:
        self._buffer.extend(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        return None

    async def wait_closed(self) -> None:
        return None

    def take(self) -> bytes:
        data = bytes(self._buffer)
        self._buffer.clear()
        return data


class _Peer:
    """A real server-side h2 connection that consumes upload data."""

    def __init__(self) -> None:
        self.conn = H2Connection(
            config=H2Configuration(client_side=False, header_encoding="utf-8")
        )
        self.received = bytearray()
        self.ended = False

    def feed(self, data: bytes) -> None:
        for event in self.conn.receive_data(data):
            if isinstance(event, DataReceived):
                if event.data:
                    self.received.extend(event.data)
                self.conn.acknowledge_received_data(
                    event.flow_controlled_length, event.stream_id
                )
            elif isinstance(event, StreamEnded):
                self.ended = True


def _connect_pair():
    session = H2ProxySession("upstream.example", 443, "token")
    client = H2Connection(
        config=H2Configuration(client_side=True, header_encoding="utf-8")
    )
    client_wire = _Wire()
    session._conn = client
    session._writer = client_wire
    client.initiate_connection()
    client_wire.write(client.data_to_send())

    peer = _Peer()
    peer.feed(client_wire.take())
    peer.conn.initiate_connection()

    for event in client.receive_data(peer.conn.data_to_send()):
        session._handle_event(event)

    stream = H2Stream(session, 1)
    session._streams[1] = stream
    client.send_headers(
        1,
        [
            (":method", "CONNECT"),
            (":authority", "target.example:443"),
            ("proxy-authorization", "Bearer token"),
        ],
    )
    client_wire.write(client.data_to_send())
    peer.feed(client_wire.take())
    peer.conn.send_headers(1, [(":status", "200")])
    for event in client.receive_data(peer.conn.data_to_send()):
        session._handle_event(event)
    assert stream.established.is_set()
    return session, client, client_wire, peer


async def _pump(
    session: H2ProxySession,
    client: H2Connection,
    client_wire: _Wire,
    peer: _Peer,
    stop: asyncio.Event,
) -> None:
    """Carry bytes both ways until the transfer is done."""
    while not stop.is_set():
        data = client_wire.take()
        if data:
            peer.feed(data)
        outbound = peer.conn.data_to_send()
        if outbound:
            for event in client.receive_data(outbound):
                session._handle_event(event)
        reply = client.data_to_send()
        if reply:
            peer.feed(reply)
        await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_multi_megabyte_upload_flows_through_flow_control():
    session, client, client_wire, peer = _connect_pair()

    payload = bytes(range(256)) * (4 * 1024 * 1024 // 256)
    assert len(payload) == 4 * 1024 * 1024

    stop = asyncio.Event()
    pump = asyncio.create_task(_pump(session, client, client_wire, peer, stop))
    try:
        # Two relay-sized writes (64 KiB each) plus the rest in one call: the
        # sizes that used to raise FrameTooLargeError/FlowControlError.
        await session._send_data(1, payload[:65536])
        await session._send_data(1, payload[65536:131072])
        await session._send_data(1, payload[131072:])

        for _ in range(200):
            if len(peer.received) >= len(payload):
                break
            await asyncio.sleep(0.01)
    finally:
        stop.set()
        pump.cancel()
        await asyncio.gather(pump, return_exceptions=True)

    assert len(peer.received) == len(payload)
    assert bytes(peer.received) == payload
    assert session.is_closed is False


@pytest.mark.asyncio
async def test_upload_waiting_for_a_window_fails_as_proxy_error(monkeypatch):
    """A peer that never opens the window must not hang the relay forever."""
    monkeypatch.setattr(session_module, "WRITE_TIMEOUT", 0.2)
    session = H2ProxySession("upstream.example", 443, "token")

    class StalledConn:
        max_outbound_frame_size = 16384

        def local_flow_control_window(self, stream_id: int) -> int:
            return 0

    session._conn = StalledConn()
    session._streams[1] = H2Stream(session, 1)

    with pytest.raises(ProxyError) as excinfo:
        await asyncio.wait_for(session._send_data(1, b"x" * 4096), timeout=5.0)
    assert "stalled" in str(excinfo.value)
    assert session.is_closed


@pytest.mark.asyncio
async def test_upload_to_closed_stream_is_proxy_error():
    session = H2ProxySession("upstream.example", 443, "token")

    class FakeConn:
        max_outbound_frame_size = 16384

        def local_flow_control_window(self, stream_id: int) -> int:
            return 65535

    session._conn = FakeConn()
    with pytest.raises(ProxyError):
        await session._send_data(7, b"data")
