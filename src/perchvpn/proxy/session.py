"""A single HTTP/2 session to an upstream Mozilla VPN proxy node.

Each outbound TCP connection requested by a SOCKS5 client is tunneled as an
HTTP/2 stream on this session using the standard HTTP/2 CONNECT method
(RFC 7540 section 8.3), authenticated with the Guardian proxy-pass bearer
token.
"""

from __future__ import annotations

import asyncio
import logging
import os
import ssl
import time
from typing import Dict, Optional

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.settings import SettingCodes
from h2.events import (
    ConnectionTerminated,
    DataReceived,
    PingAckReceived,
    ResponseReceived,
    StreamEnded,
    StreamReset,
)
from h2.exceptions import ProtocolError, StreamClosedError, TooManyStreamsError

from ..exceptions import ProxyError
from ..tls_trust import load_certifi_roots
from .http1_session import SessionAtCapacity
from .transport_options import TransportOptions, configure_client_hello
from .upstream_proxy import connect_through_upstream_proxy

logger = logging.getLogger(__name__)


DEFAULT_HANDSHAKE_TIMEOUT = 10.0

READ_IDLE_TIMEOUT = 30.0
PING_TIMEOUT = 15.0
WRITE_TIMEOUT = 30.0
_KEEPALIVE_POLL_INTERVAL = 1.0

OPEN_STREAM_TIMEOUT = 20.0

STREAM_SLOT_WAIT_TIMEOUT = 15.0
_STREAM_SLOT_POLL_INTERVAL = 0.05


def _format_authority(host: str, port: int) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]:{port}"
    return f"{host}:{port}"


class H2Stream:
    """One tunneled TCP connection multiplexed over a parent HTTP/2 session."""

    def __init__(
        self,
        session: "H2ProxySession",
        stream_id: int,
        metrics: Optional["TrafficMetrics"] = None,
    ):
        self._session = session
        self.stream_id = stream_id
        self._incoming: "asyncio.Queue[Optional[bytes]]" = asyncio.Queue()
        self._ended = False
        self.established = asyncio.Event()
        self.failed: Optional[Exception] = None
        self._metrics = metrics

    async def wait_established(self) -> None:
        await self.established.wait()
        if self.failed:
            raise self.failed

    async def read(self) -> Optional[bytes]:
        """Return the next chunk of data, or ``None`` at end-of-stream."""
        chunk = await self._incoming.get()
        if chunk and self._metrics:
            self._metrics.add_downloaded(len(chunk))
        return chunk

    def _feed(self, chunk: Optional[bytes]) -> None:
        if chunk is None:
            if self._ended:
                return
            self._ended = True
        self._incoming.put_nowait(chunk)

    async def write(self, data: bytes) -> None:
        if data and self._metrics:
            self._metrics.add_uploaded(len(data))
        await self._session._send_data(self.stream_id, data)

    async def close(self) -> None:
        session = self._session
        conn = session._conn
        if conn is None or session._closed:
            return
        try:
            await session._end_stream(self.stream_id)
        except (AssertionError, ProtocolError, StreamClosedError, ProxyError):
            return


class H2ProxySession:
    def __init__(
        self,
        host: str,
        port: int,
        token: str,
        upstream_proxy: Optional[UpstreamProxyConfig] = None,
        edge_host: Optional[str] = None,
        edge_port: Optional[int] = None,
        source_bind_ip: Optional[str] = None,
        upstream_proxy_host: Optional[str] = None,
        physical_interface: Optional[int] = None,
        options: Optional[TransportOptions] = None,
    ):
        self.host = host
        self.port = port
        self.token = token
        self.upstream_proxy = upstream_proxy
        self.edge_host = edge_host
        self.edge_port = edge_port
        self.source_bind_ip = source_bind_ip
        self.upstream_proxy_host = upstream_proxy_host
        self.physical_interface = physical_interface
        self.options = options or TransportOptions()
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._conn: Optional[H2Connection] = None
        self._streams: Dict[int, H2Stream] = {}
        self._write_lock = asyncio.Lock()
        self._reader_task: Optional[asyncio.Task] = None
        self._keepalive_task: Optional[asyncio.Task] = None
        self._closed = False
        self._last_activity = time.monotonic()
        self._pending_ping: Optional[bytes] = None
        self._pending_ping_sent_at: float = 0.0

    async def connect(self, timeout: float = DEFAULT_HANDSHAKE_TIMEOUT) -> None:
        ssl_context = ssl.create_default_context()
        ssl_context.set_alpn_protocols(["h2"])
        # ClientHello parity knobs (cipher/curve preference).  Record-level
        # fragmentation is not applied here: the asyncio SSL transport owns
        # the record stream for HTTP/2 (see transport_options.py).
        # Platform roots plus certifi's bundle (see tls_trust.py).
        load_certifi_roots(ssl_context)
        configure_client_hello(ssl_context, self.options.utls_fingerprint)

        connect_host = self.edge_host or self.host
        connect_port = self.edge_port or self.port
        if self.upstream_proxy is not None:
            # Transport-level upstream proxy chaining for H2.
            # 1. Establish TCP connection to the upstream proxy.
            # 2. Authenticate (SOCKS5 or HTTP CONNECT) with optional credentials.
            # 3. Send CONNECT through the upstream proxy to reach the remote edge.
            # 4. Then perform the existing TLS handshake and H2 ALPN negotiation
            #    through the proxied connection.
            proxy_sock, _ = connect_through_upstream_proxy(
                self.upstream_proxy, connect_host, connect_port,
                source_bind_ip=self.source_bind_ip,
                dial_host=self.upstream_proxy_host,
                interface_index=self.physical_interface,
            )
            try:
                self._reader, self._writer = await asyncio.wait_for(
                    asyncio.open_connection(sock=proxy_sock, ssl=ssl_context, server_hostname=self.host),
                    timeout=timeout,
                )
                negotiated = self._writer.get_extra_info("ssl_object")
                if negotiated is not None and negotiated.selected_alpn_protocol() != "h2":
                    proxy_sock.close()
                    raise ProxyError(f"upstream {self.host}:{self.port} did not negotiate HTTP/2")
            except BaseException:
                proxy_sock.close()
                raise
        else:
            # Source-address pinning for TUN egress control (None = OS default).
            connect_kwargs = {}
            if self.source_bind_ip:
                connect_kwargs["local_addr"] = (self.source_bind_ip, 0)
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(
                    connect_host, connect_port,
                    ssl=ssl_context, server_hostname=self.host,
                    **connect_kwargs,
                ),
                timeout=timeout,
            )
            negotiated = self._writer.get_extra_info("ssl_object")
            if negotiated is not None and negotiated.selected_alpn_protocol() not in (None, "h2"):
                raise ProxyError(f"upstream {self.host}:{self.port} did not negotiate HTTP/2")

        config = H2Configuration(
            client_side=True,
            header_encoding="utf-8",
            validate_outbound_headers=False,
        )
        self._conn = H2Connection(config=config)
        self._conn.initiate_connection()
        await self._flush()
        self._last_activity = time.monotonic()
        self._reader_task = asyncio.create_task(self._read_loop())
        self._keepalive_task = asyncio.create_task(self._keepalive_loop())

    @property
    def is_closed(self) -> bool:
        """Whether the upstream session has ended."""
        return self._closed

    @property
    def active_streams(self) -> int:
        """Number of open tunnels (pool scaling input)."""
        return len(self._streams)

    async def close(self) -> None:
        if self._keepalive_task is not None:
            self._keepalive_task.cancel()
            try:
                await self._keepalive_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        if self._reader_task is not None:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        if self._writer is not None:
            self._writer.close()
            # A TUN teardown can black-hole the upstream route before the
            # FIN lands; wait_closed then hangs on retransmits for seconds.
            # Cap the graceful wait — an abortive close is fine on shutdown.
            try:
                await asyncio.wait_for(self._writer.wait_closed(), timeout=0.5)
            except asyncio.TimeoutError:
                pass
            except Exception:  # noqa: BLE001 - dead peer/route variants
                pass
        self._closed = True

    def update_token(self, token: str) -> None:
        """Update the bearer token used for streams opened from now on."""
        self.token = token

    def _handle_event(self, event: object) -> None:
        """Handle an HTTP/2 event from the upstream connection.

        ResponseReceived drives CONNECT establishment. DataReceived and
        StreamEnded deliver tunnel bytes and EOF. StreamReset fails a pending
        establishment or terminates an established stream.
        """
        from h2.events import DataReceived, ResponseReceived, StreamEnded, StreamReset

        if isinstance(event, ResponseReceived):
            code = None
            for name, value in event.headers:
                if name.lower() == ":status":
                    code = int(value)
                    break
            stream = self._streams.get(event.stream_id)
            if stream is None:
                return
            if code is not None and 200 <= code <= 299:
                stream.established.set()
            elif code is not None:
                stream.failed = ProxyError(
                    f"upstream {self.host}:{self.port} refused CONNECT with status {code}"
                )
                stream.established.set()
            return

        if isinstance(event, DataReceived):
            stream = self._streams.get(event.stream_id)
            if stream is None:
                return
            if event.data:
                stream._feed(event.data)
            if self._conn is not None:
                self._conn.acknowledge_received_data(
                    event.flow_controlled_length, event.stream_id
                )
            return

        if isinstance(event, StreamEnded):
            stream = self._streams.pop(event.stream_id, None)
            if stream is not None:
                stream._feed(None)
            return

        if isinstance(event, StreamReset):
            stream = self._streams.pop(event.stream_id, None)
            if stream is None:
                return
            if not stream.established.is_set():
                stream.failed = ProxyError(
                    f"upstream {self.host}:{self.port} reset CONNECT stream"
                )
                stream.established.set()
            else:
                stream._feed(None)

    async def _flush(self) -> None:
        assert self._conn is not None and self._writer is not None
        data = self._conn.data_to_send()
        if data:
            self._writer.write(data)
            try:
                await asyncio.wait_for(self._writer.drain(), timeout=WRITE_TIMEOUT)
            except asyncio.TimeoutError:
                self._mark_unhealthy()
                raise ProxyError(f"write to upstream {self.host}:{self.port} timed out after {WRITE_TIMEOUT}s")

    async def _read_loop(self) -> None:
        assert self._reader is not None and self._conn is not None
        try:
            while True:
                chunk = await self._reader.read(65536)
                if not chunk:
                    break
                self._last_activity = time.monotonic()
                events = self._conn.receive_data(chunk)
                for event in events:
                    self._handle_event(event)
                async with self._write_lock:
                    await self._flush()
        except Exception as exc:  # noqa: BLE001
            logger.debug("upstream session read loop ended: %s", exc)
        finally:
            self._closed = True
            for stream in list(self._streams.values()):
                if not stream.established.is_set():
                    stream.failed = ProxyError("upstream connection closed before the stream was established")
                    stream.established.set()
                stream._feed(None)
            self._streams.clear()

    async def _keepalive_loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(_KEEPALIVE_POLL_INTERVAL)
                if self._closed:
                    return
                now = time.monotonic()
                if self._pending_ping is not None:
                    if now - self._pending_ping_sent_at >= PING_TIMEOUT:
                        logger.warning(
                            "upstream %s:%s did not ack keepalive ping within %ss; marking session unhealthy",
                            self.host, self.port, PING_TIMEOUT,
                        )
                        self._mark_unhealthy()
                        return
                    continue
                if now - self._last_activity >= READ_IDLE_TIMEOUT:
                    await self._send_ping()
        except asyncio.CancelledError:
            pass
        except Exception as exc:  # noqa: BLE001
            logger.debug("upstream session keepalive loop ended: %s", exc)

    async def _send_ping(self) -> None:
        assert self._conn is not None
        payload = os.urandom(8)
        try:
            self._conn.ping(payload)
            await self._flush()
        except Exception as exc:  # noqa: BLE001
            logger.debug("keepalive ping failed: %s", exc)
            self._mark_unhealthy()

    def _mark_unhealthy(self) -> None:
        self._closed = True

    async def _send_data(self, stream_id: int, data: bytes) -> None:
        assert self._conn is not None
        self._conn.send_data(stream_id, data, end_stream=False)
        await self._flush()

    async def _end_stream(self, stream_id: int) -> None:
        assert self._conn is not None
        self._conn.send_data(stream_id, b"", end_stream=True)
        try:
            await self._flush()
        except Exception as exc:  # noqa: BLE001
            logger.debug("ending upstream stream %s failed: %s", stream_id, exc)

    async def open_stream(
        self, target_host: str, target_port: int, metrics: Optional["TrafficMetrics"] = None
    ) -> H2Stream:
        if self._closed:
            raise ProxyError(f"upstream {self.host}:{self.port} is closed")
        await self._await_stream_slot()
        stream = None
        try:
            async with self._write_lock:
                get_stream_id = getattr(self._conn, "get_next_available_stream_id", None)
                stream_id = get_stream_id() if callable(get_stream_id) else stream_id_for_stream(target_host, target_port)
                headers = [
                    (":method", "CONNECT"),
                    (":authority", _format_authority(target_host, target_port)),
                    ("proxy-authorization", f"Bearer {self.token}"),
                ]
                send_headers = getattr(self._conn, "send_headers", None)
                if callable(send_headers):
                    send_headers(stream_id, headers)
                stream = H2Stream(self, stream_id, metrics)
                self._streams[stream_id] = stream
                await self._flush()
            # Race the stream establishment against the timeout.
            # Use asyncio.wait with FIRST_COMPLETED to detect if establishment
            # completed (possibly with an exception) or if timeout occurred.
            self._established_future = asyncio.ensure_future(stream.wait_established())
            established_future = self._established_future
            done, pending = await asyncio.wait(
                [established_future],
                timeout=OPEN_STREAM_TIMEOUT,
                return_when=asyncio.FIRST_COMPLETED,
            )
            # Cancel the pending future (wait_established if it didn't complete)
            for f in pending:
                f.cancel()
            # Check if the establishment future completed
            if established_future in done:
                # The wait_established coroutine completed
                exc = established_future.exception()
                if exc is not None:
                    # An exception occurred during establishment.
                    # Production wait_established() never raises TimeoutError; it raises
                    # the failure reason (ProxyError). Convert any exception to ProxyError.
                    if stream is not None:
                        self._streams.pop(stream.stream_id, None)
                        if self._conn is not None:
                            try:
                                self._conn.reset_stream(stream.stream_id)
                            except (ProtocolError, StreamClosedError):
                                pass
                    raise ProxyError(f"upstream {self.host}:{self.port} stream establishment failed: {exc}")
                # No exception - establishment completed successfully
                if self._closed:
                    raise ProxyError(f"upstream {self.host}:{self.port} is closed")
                return stream
            # The establishment future did not complete within the timeout
            # (or was cancelled). Convert to ProxyError.
            if stream is not None:
                self._streams.pop(stream.stream_id, None)
                if self._conn is not None:
                    try:
                        self._conn.reset_stream(stream.stream_id)
                    except (ProtocolError, StreamClosedError):
                        pass
            raise ProxyError(f"upstream {self.host}:{self.port} stream establishment timed out after {OPEN_STREAM_TIMEOUT}s")
        except ProxyError:
            raise
        except BaseException:
            if stream is not None:
                self._streams.pop(stream.stream_id, None)
                if self._conn is not None:
                    try:
                        self._conn.reset_stream(stream.stream_id)
                    except (ProtocolError, StreamClosedError):
                        pass
            # Cancel the establishment future if it's still pending
            # (happens when open_stream is cancelled during asyncio.wait)
            if self._established_future is not None and not self._established_future.done():
                self._established_future.cancel()
            # If the session was marked unhealthy while waiting, raise ProxyError
            if self._closed:
                raise ProxyError(f"upstream {self.host}:{self.port} is closed")
            raise
    async def _await_stream_slot(self) -> None:
        """Wait for an available HTTP/2 stream slot.

        Returns immediately if a slot is available (under the concurrent stream limit).
        If at the limit, waits up to ``STREAM_SLOT_WAIT_TIMEOUT`` for a slot to open.
        Raises ``ProxyError`` if the session is closed or the wait times out.

        The stream limit is read from the remote H2 connection's
        ``MAX_CONCURRENT_STREAMS`` setting. If no connection is configured,
        there is no effective limit and this method returns immediately.
        """
        if self._closed:
            raise ProxyError(f"upstream {self.host}:{self.port} is closed")

        # Soft per-session cap from the multiplex concurrency setting.  The
        # pool scales out on SessionAtCapacity instead of waiting.
        soft_limit = self.options.multiplex_streams

        # Determine the concurrent stream limit from the remote connection.
        limit = float("inf")
        if self._conn is not None and hasattr(self._conn, "remote_settings"):
            # Read the concurrent stream limit from the remote connection.
            # Compatible with h2 Settings .get(), test SimpleNamespace, and
            # test doubles that don't have remote_settings.
            try:
                limit = self._conn.remote_settings.get(
                    SettingCodes.MAX_CONCURRENT_STREAMS, float("inf")
                )
            except AttributeError:
                limit = float(getattr(self._conn.remote_settings, "max_concurrent_streams", float("inf")))

        effective = min(limit, soft_limit)

        # If already under the limit, return immediately.
        if len(self._streams) < effective:
            return

        # At or over the configured multiplex soft cap: let the pool scale
        # out with a fresh session immediately.
        if len(self._streams) >= soft_limit:
            raise SessionAtCapacity(
                f"upstream {self.host}:{self.port} is at its configured "
                f"multiplex concurrency of {soft_limit} streams"
            )

        # Remote-limited (not by our soft cap): poll for a slot to open.
        import asyncio

        deadline = asyncio.get_event_loop().time() + STREAM_SLOT_WAIT_TIMEOUT
        while asyncio.get_event_loop().time() < deadline:
            if self._closed:
                raise ProxyError(f"upstream {self.host}:{self.port} is closed")
            if len(self._streams) < limit:
                return
            await asyncio.sleep(_STREAM_SLOT_POLL_INTERVAL)

        # Timeout expired still at the limit.
        raise ProxyError(
            f"upstream {self.host}:{self.port} stream slot wait timed out after "
            f"{STREAM_SLOT_WAIT_TIMEOUT}s"
        )


def stream_id_for_stream(target_host: str, target_port: int) -> int:
    """Allocate a unique stream ID (simplified, real impl would use h2 internals)."""
    return 1
