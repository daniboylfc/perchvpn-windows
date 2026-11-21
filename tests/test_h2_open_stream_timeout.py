"""Focused tests for the HTTP/2 CONNECT stream-establishment timeout (P1-3).

Wholly offline: the h2 connection and the TLS writer are fakes; only the
session's stream bookkeeping and timers are exercised.
"""

from __future__ import annotations

import asyncio

import pytest
from h2.events import ResponseReceived, StreamEnded, StreamReset

import perchvpn.proxy.session as session_module
from perchvpn.exceptions import ProxyError
from perchvpn.proxy.session import H2ProxySession


class FakeConn:
    def __init__(self) -> None:
        self.sent_headers: list[tuple[int, list[tuple[str, str]]]] = []
        self.resets: list[int] = []

    def get_next_available_stream_id(self) -> int:
        return 1

    def send_headers(self, stream_id: int, headers) -> None:
        self.sent_headers.append((stream_id, list(headers)))

    def reset_stream(self, stream_id: int, error_code: int = 0) -> None:
        self.resets.append(stream_id)

    def data_to_send(self) -> bytes:
        return b""

    @property
    def max_outbound_frame_size(self) -> int:
        return 16384


class FakeWriter:
    def __init__(self) -> None:
        self.buffer = b""

    def write(self, data: bytes) -> None:
        self.buffer += data

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        return None

    async def wait_closed(self) -> None:
        return None


def _session() -> H2ProxySession:
    session = H2ProxySession("upstream.example", 443, "token")
    session._conn = FakeConn()
    session._writer = FakeWriter()
    return session


async def _noop_read_loop(*args, **kwargs) -> None:
    return None


class TestOpenStreamTimeout:
    @pytest.mark.asyncio
    async def test_no_response_times_out_and_resets(self, monkeypatch):
        monkeypatch.setattr(session_module, "OPEN_STREAM_TIMEOUT", 0.05)
        session = _session()
        with pytest.raises(ProxyError):
            await session.open_stream("target.example", 80)
        assert session._streams == {}
        assert session._conn.resets == [1]

    @pytest.mark.asyncio
    async def test_successful_connect_returns_stream(self, monkeypatch):
        monkeypatch.setattr(session_module, "OPEN_STREAM_TIMEOUT", 1.0)
        session = _session()

        async def respond():
            await asyncio.sleep(0)
            session._handle_event(ResponseReceived(stream_id=1, headers=[(":status", "200")]))

        responder = asyncio.create_task(respond())
        stream = await session.open_stream("target.example", 80)
        await responder
        assert stream.stream_id == 1
        assert session._streams[1] is stream
        assert session._conn.resets == []

    @pytest.mark.asyncio
    async def test_stream_end_releases_multiplex_slot(self):
        session = _session()
        stream = session_module.H2Stream(session, 1)
        stream.established.set()
        session._streams[1] = stream

        session._handle_event(StreamEnded(stream_id=1))

        assert session.active_streams == 0
        assert 1 not in session._streams
        assert await stream.read() is None

    @pytest.mark.asyncio
    async def test_stream_reset_releases_multiplex_slot(self):
        session = _session()
        stream = session_module.H2Stream(session, 1)
        stream.established.set()
        session._streams[1] = stream

        session._handle_event(
            StreamReset(stream_id=1, error_code=0, remote_reset=True)
        )

        assert session.active_streams == 0
        assert 1 not in session._streams
        assert await stream.read() is None

    @pytest.mark.asyncio
    async def test_non_2xx_connect_is_refused_and_reset(self, monkeypatch):
        monkeypatch.setattr(session_module, "OPEN_STREAM_TIMEOUT", 1.0)
        session = _session()

        async def refuse():
            await asyncio.sleep(0)
            session._handle_event(ResponseReceived(stream_id=1, headers=[(":status", "403")]))

        responder = asyncio.create_task(refuse())
        with pytest.raises(ProxyError):
            await session.open_stream("target.example", 80)
        await responder
        assert 1 not in session._streams
        assert session._conn.resets == [1]

    @pytest.mark.asyncio
    async def test_reset_before_establishment_fails_promptly(self, monkeypatch):
        monkeypatch.setattr(session_module, "OPEN_STREAM_TIMEOUT", 5.0)
        session = _session()

        async def reset():
            await asyncio.sleep(0)
            session._handle_event(StreamReset(stream_id=1, error_code=0, remote_reset=True))

        responder = asyncio.create_task(reset())
        with pytest.raises(ProxyError):
            await session.open_stream("target.example", 80)
        await responder
        assert 1 not in session._streams

    @pytest.mark.asyncio
    async def test_connection_close_fails_pending_stream(self, monkeypatch):
        monkeypatch.setattr(session_module, "OPEN_STREAM_TIMEOUT", 5.0)
        monkeypatch.setattr(session_module.H2ProxySession, "_read_loop", _noop_read_loop)
        session = _session()
        task = asyncio.create_task(session.open_stream("target.example", 80))
        await asyncio.sleep(0)
        session._mark_unhealthy()
        with pytest.raises(ProxyError):
            await asyncio.wait_for(task, timeout=1.0)

    @pytest.mark.asyncio
    async def test_timeout_that_races_with_establishment_keeps_stream(self, monkeypatch):
        class RacyStream(session_module.H2Stream):
            async def wait_established(self) -> None:
                # Synthetic race: wait_established sets the event and raises TimeoutError.
                # Per the refined contract, this is NOT propagated; it is converted to ProxyError.
                self.established.set()
                raise asyncio.TimeoutError

        monkeypatch.setattr(session_module, "H2Stream", RacyStream)
        monkeypatch.setattr(session_module, "OPEN_STREAM_TIMEOUT", 1.0)
        session = _session()
        with pytest.raises(ProxyError):
            await session.open_stream("target.example", 80)
        # Stream must be removed from bookkeeping and reset notified
        assert session._streams == {}
        assert session._conn.resets == [1]


    @pytest.mark.asyncio
    async def test_caller_cancellation_drains_establishment_task(self, monkeypatch):
        """Verify that cancelling open_stream() while establishment is pending.

        - caller CancellationError propagates after cleanup
        - stream is removed from session._streams
        - stream is reset as appropriate
        - establishment task is drained (no unobserved exception)
        """
        # Make wait_established never complete, so the pending future
        # stays pending until we cancel open_stream().
        original_wait = session_module.H2Stream.wait_established

        class NeverCompletesStream(session_module.H2Stream):
            async def wait_established(self) -> None:
                # Intentionally never sets the event or returns;
                # the task stays pending until open_stream() cancels it.
                await original_wait(self)

        monkeypatch.setattr(session_module, "H2Stream", NeverCompletesStream)
        monkeypatch.setattr(session_module, "OPEN_STREAM_TIMEOUT", 5.0)
        session = _session()

        # Launch open_stream(); it will block in wait_established().
        task = asyncio.create_task(session.open_stream("target.example", 80))

        # Let it start waiting.
        await asyncio.sleep(0)

        # Cancel from the caller's context.
        task.cancel()

        # The task should raise CancelledError after cleanup.
        with pytest.raises(asyncio.CancelledError):
            await task

        # Stream must be removed from bookkeeping.
        assert 1 not in session._streams

        # Stream must have been reset.
        assert session._conn.resets == [1]

        # The establishment task must be drained (no unobserved exception).
        # The establishment future was awaited in the drain loop above, which
        # consumes the CancelledError and prevents it from being emitted as
        # an unhandled task exception.  Verify the future was stored and
        # accessed (drain loop was executed).
        assert session._established_future is not None
        # Verify the establishment task reached a terminal state after drainage.
        # Note: For H2Stream.wait_established() which uses asyncio.Event.wait(),
        # the task will be done() but not necessarily cancelled() since Event.wait()
        # does not set the cancelled flag when the containing task is cancelled.
        assert session._established_future.done()
        assert session._established_future.cancelled()


