"""HTTP/1.1 CONNECT transport to the upstream edge (upstream v2.0.3 parity).

Classic HTTP/1.1 ``CONNECT`` over TLS, one tunnel per session.  This is the
transport where this codebase owns the TLS record stream end-to-end (memory
BIOs), so the uTLS ClientHello knobs and TLS record/packet fragmentation are
applied here.  The pool treats each HTTP/1.1 session as a single-slot tunnel
and dials more sessions on demand.
"""

from __future__ import annotations

import asyncio
import logging
import socket as socket_module
import ssl
import time
from typing import Dict, Optional

from ..exceptions import ProxyError
from ..tls_trust import load_certifi_roots
from .transport_options import TransportOptions, configure_client_hello, fragment_bytes
from .upstream_proxy import connect_through_upstream_proxy

logger = logging.getLogger(__name__)

DEFAULT_HANDSHAKE_TIMEOUT = 10.0
_CONNECT_RESPONSE_TIMEOUT = 15.0
_MAX_TUNNELS_PER_SESSION = 1


class SessionAtCapacity(ProxyError):
    """The session carries its maximum number of concurrent tunnels."""


def _tls_context(options: Optional[TransportOptions]) -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.set_alpn_protocols(["http/1.1"])
    # Platform roots (Windows cert store) plus certifi's bundle, so 2025-era
    # roots (e.g. GlobalSign Root E46 on MASQUE edges) verify on lean or
    # stale Windows stores.  Verification mode is untouched (strict).
    load_certifi_roots(context)
    if options is not None:
        configure_client_hello(context, options.utls_fingerprint)
    return context


def _handshake_sync(
    sock: socket_module.socket,
    host: str,
    context: ssl.SSLContext,
    rbio: ssl.MemoryBIO,
    wbio: ssl.MemoryBIO,
    options: Optional[TransportOptions],
    timeout: float,
) -> ssl.SSLObject:
    """Drive a memory-BIO TLS handshake over a blocking socket.

    ``wrap_bio`` yields the raw handshake records through the outgoing BIO,
    which lets us split and pace the ClientHello exactly as configured.
    The same BIOs are returned with the object so post-handshake writes can
    be flushed too.
    """
    obj = context.wrap_bio(rbio, wbio, server_hostname=host)
    deadline = time.monotonic() + max(timeout, 0.1)
    sock.settimeout(max(timeout, 0.1))
    while True:
        try:
            obj.do_handshake()
            break
        except ssl.SSLWantReadError:
            _flush_outgoing(wbio, sock, options, deadline)
            chunk = sock.recv(65536)
            if not chunk:
                raise ProxyError(f"connection to {host} closed during TLS handshake")
            rbio.write(chunk)
        except ssl.SSLWantWriteError:
            _flush_outgoing(wbio, sock, options, deadline)
        if time.monotonic() > deadline:
            raise ProxyError(f"TLS handshake to {host} timed out")
    return obj


def _flush_outgoing(
    wbio: ssl.MemoryBIO,
    sock: socket_module.socket,
    options: Optional[TransportOptions],
    deadline: float,
) -> None:
    while True:
        try:
            data = wbio.read()
        except ssl.SSLWantReadError:
            return
        if not data:
            return
        fragmenting = options is not None and options.fragmenting
        chunks = fragment_bytes(data, options) if fragmenting else [(data, 0.0)]
        for chunk, pause in chunks:
            if pause:
                time.sleep(pause)
            sock.sendall(chunk)
            if fragmenting and time.monotonic() > deadline:
                return


def _dial_direct(
    connect_host: str, connect_port: int, source_bind_ip: Optional[str], timeout: float
) -> socket_module.socket:
    sock = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_STREAM)
    try:
        if source_bind_ip:
            sock.bind((source_bind_ip, 0))
        sock.settimeout(max(timeout, 0.1))
        sock.connect((connect_host, connect_port))
        return sock
    except BaseException:
        sock.close()
        raise


class H1Stream:
    """One tunneled TCP connection carried by an HTTP/1.1 CONNECT tunnel."""

    def __init__(self, session: "H1ProxySession", metrics=None):
        self._session = session
        self.established = asyncio.Event()
        self.failed: Optional[Exception] = None
        self._ended = False
        self._metrics = metrics

    async def wait_established(self) -> None:
        await self.established.wait()
        if self.failed:
            raise self.failed

    async def read(self) -> Optional[bytes]:
        if self._ended:
            return None
        loop = asyncio.get_running_loop()
        chunk = await self._session._tunnel_read()
        if self._metrics and chunk:
            self._metrics.add_downloaded(len(chunk))
        if chunk == b"":
            self._ended = True
            return None
        return chunk

    async def write(self, data: bytes) -> None:
        if self._metrics and data:
            self._metrics.add_uploaded(len(data))
        await self._session._tunnel_write(data)

    async def close(self) -> None:
        await self._session.close()


class H1ProxySession:
    def __init__(
        self,
        host: str,
        port: int,
        token: str,
        upstream_proxy=None,
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
        self._sock: Optional[socket_module.socket] = None
        self._ssl: Optional[ssl.SSLObject] = None
        self._rbio: Optional[ssl.MemoryBIO] = None
        self._wbio: Optional[ssl.MemoryBIO] = None
        self._tunnels: Dict[int, H1Stream] = {}
        self._next_tunnel = 0
        self._closed = False
        self._alpn: Optional[str] = None

    # -- lifecycle ---------------------------------------------------

    async def connect(self, timeout: float = DEFAULT_HANDSHAKE_TIMEOUT) -> None:
        loop = asyncio.get_running_loop()
        connect_host = self.edge_host or self.host
        connect_port = self.edge_port or self.port
        try:
            if self.upstream_proxy is not None:
                proxy_sock, _ = await loop.run_in_executor(
                    None,
                    lambda: connect_through_upstream_proxy(
                        self.upstream_proxy,
                        connect_host,
                        connect_port,
                        source_bind_ip=self.source_bind_ip,
                        dial_host=self.upstream_proxy_host,
                        interface_index=self.physical_interface,
                    ),
                )
                sock = proxy_sock
            else:
                sock = await loop.run_in_executor(
                    None, _dial_direct, connect_host, connect_port, self.source_bind_ip, timeout
                )
            context = _tls_context(self.options)
            self._rbio = ssl.MemoryBIO()
            self._wbio = ssl.MemoryBIO()
            handshake = await loop.run_in_executor(
                None,
                lambda: _handshake_sync(
                    sock, self.host, context, self._rbio, self._wbio, self.options, timeout
                ),
            )
            self._ssl = handshake
            self._sock = sock
            self._alpn = self._ssl.selected_alpn_protocol()
            if self._alpn not in (None, "http/1.1"):
                raise ProxyError(
                    f"upstream {self.host}:{self.port} did not negotiate HTTP/1.1"
                )
        except ProxyError:
            self._safe_close_sock()
            raise
        except BaseException as exc:  # noqa: BLE001
            self._safe_close_sock()
            raise ProxyError(f"HTTP/1.1 transport to {self.host}:{self.port} failed: {exc}") from exc

    def _safe_close_sock(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def _mark_connection_lost(self) -> None:
        """The edge dropped the transport (mid-CONNECT EOF, SSL death, or a
        CONNECT that timed out on a dead path).  Mark the session dead so
        the pool replaces it and retries the client on a fresh dial — and
        so SessionPool's close-storm detector observes the churn.  Mirrors
        how the H2/H3 sessions report connection loss through their read
        loops; without this the pool would keep dialing replacement
        sessions while treating the corpse as live."""
        self._closed = True
        for stream in list(self._tunnels.values()):
            stream._ended = True
        self._tunnels.clear()
        self._safe_close_sock()

    @property
    def is_closed(self) -> bool:
        return self._closed

    @property
    def active_streams(self) -> int:
        return len(self._tunnels)

    def update_token(self, token: str) -> None:
        self.token = token

    async def close(self) -> None:
        self._closed = True
        for stream in list(self._tunnels.values()):
            stream._ended = True
        self._tunnels.clear()
        if self._ssl is not None:
            try:
                self._ssl.unwrap()
            except (ssl.SSLError, OSError, ValueError):
                pass
        self._safe_close_sock()

    # -- tunnel establishment ---------------------------------------

    async def open_stream(
        self, target_host: str, target_port: int, metrics=None
    ) -> H1Stream:
        if self._closed:
            raise ProxyError(f"upstream {self.host}:{self.port} is closed")
        if self.active_streams >= _MAX_TUNNELS_PER_SESSION:
            raise SessionAtCapacity(
                f"upstream {self.host}:{self.port} HTTP/1.1 session already "
                "carries its single CONNECT tunnel"
            )
        stream = H1Stream(self, metrics)
        tunnel_id = self._next_tunnel
        self._next_tunnel += 1
        self._tunnels[tunnel_id] = stream
        try:
            request = (
                f"CONNECT {_format_authority(target_host, target_port)} HTTP/1.1\r\n"
                f"Host: {_format_authority(target_host, target_port)}\r\n"
                f"Proxy-Authorization: Bearer {self.token}\r\n"
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) PerchVPN\r\n"
                "\r\n"
            ).encode("ascii")
            await self._tunnel_write(request)
            status_line, headers = await self._read_connect_response()
            if not status_line.startswith("HTTP/1.1 200") and not status_line.startswith("HTTP/1.0 200"):
                self._tunnels.pop(tunnel_id, None)
                raise ProxyError(
                    f"upstream {self.host}:{self.port} refused CONNECT: {status_line.strip()}"
                )
        except ProxyError as exc:
            self._tunnels.pop(tunnel_id, None)
            # A refusal ("refused CONNECT: <status>") is a live session
            # answering; transport death and silent timeouts are not.
            message = str(exc)
            if (
                "connection closed before CONNECT response" in message
                or "CONNECT response timed out" in message
                or "session is not connected" in message
            ):
                self._mark_connection_lost()
            raise
        except BaseException as exc:  # noqa: BLE001
            self._tunnels.pop(tunnel_id, None)
            # SSL/OSError failures during establishment are transport death.
            self._mark_connection_lost()
            raise ProxyError(
                f"upstream {self.host}:{self.port} CONNECT establishment failed: {exc}"
            ) from exc
        stream.established.set()
        return stream

    async def _tunnel_write(self, data: bytes) -> None:
        if self._ssl is None or self._wbio is None or self._sock is None:
            raise ProxyError("HTTP/1.1 session is not connected")
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._ssl.write, data)
        await loop.run_in_executor(None, _flush_outgoing, self._wbio, self._sock, None, 0.0)

    async def _tunnel_read(self) -> bytes:
        """Blocking SSLObject read lifted to a worker thread.

        Incoming ciphertext is consumed through the session's incoming BIO;
        if the BIO runs dry the socket is read and the loop continues.
        """
        if self._ssl is None or self._rbio is None or self._sock is None:
            raise ProxyError("HTTP/1.1 session is not connected")
        while True:
            try:
                return self._ssl.read(65536)
            except ssl.SSLWantReadError:
                chunk = self._sock.recv(65536)
                if not chunk:
                    raise ssl.SSLEOFError("connection closed") from None
                self._rbio.write(chunk)
            except ssl.SSLWantWriteError:
                _flush_outgoing(self._wbio, self._sock, None, 0.0)

    async def _read_connect_response(self) -> tuple[str, Dict[str, str]]:
        loop = asyncio.get_running_loop()
        deadline = time.monotonic() + _CONNECT_RESPONSE_TIMEOUT
        buffered = b""
        while b"\r\n\r\n" not in buffered:
            if time.monotonic() > deadline:
                raise ProxyError("CONNECT response timed out")
            try:
                chunk = await self._tunnel_read()
            except ssl.SSLEOFError as exc:
                raise ProxyError("connection closed before CONNECT response") from exc
            if not chunk:
                raise ProxyError("connection closed before CONNECT response")
            buffered += chunk
        head, _, _rest = buffered.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        headers: Dict[str, str] = {}
        for line in lines[1:]:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        return lines[0], headers


def _format_authority(host: str, port: int) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]:{port}"
    return f"{host}:{port}"
