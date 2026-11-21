"""Local SOCKS5 proxy server."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import struct
from typing import Optional, Tuple

from .pool import SessionPool
from .relay import relay_bidirectional
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from perchvpn_windows.metrics import TrafficMetrics

logger = logging.getLogger("perchvpn.proxy.socks")

SOCKS_VERSION = 0x05
_CMD_CONNECT = 0x01
_ATYP_IPV4 = 0x01
_ATYP_DOMAIN = 0x03
_ATYP_IPV6 = 0x04
_AUTH_NO_AUTH = 0x00
_AUTH_USERPASS = 0x02
_AUTH_NO_ACCEPTABLE = 0xFF
_REP_SUCCEEDED = 0x00
_REP_GENERAL_FAILURE = 0x01
_REP_CONNECTION_NOT_ALLOWED = 0x02
_REP_COMMAND_NOT_SUPPORTED = 0x07
_REP_ADDRESS_TYPE_NOT_SUPPORTED = 0x08

# Fastly MASQUE upstream edges only accept CONNECT streams to ports 80/443
# and answer every other port with HTTP 502 (which also poisons live :443
# streams). Reject those ports locally with the SOCKS5 ruleset error before
# an upstream stream is ever opened, and trip a short breaker when a 502
# slips through so retrying background apps cannot storm the session.  A 502
# is a *target* verdict (the edge could not reach that host), not a port one:
# keying the breaker by port blacked out every :443 flow for 15 s after a
# single policy refusal and starved the exit/egress verification probes.
_TARGET_BREAKER_COOLDOWN_SECONDS = 15.0
_PORT_BREAKER_COOLDOWN_SECONDS = _TARGET_BREAKER_COOLDOWN_SECONDS
_MAX_TARGET_BREAKERS = 512
_MASQUE_ALLOWED_PORTS = (80, 443)
_MASQUE_REFUSAL_MARKER = "refused CONNECT with status 502"


class Socks5Server:
    def __init__(
        self,
        host: str,
        port: int,
        pool: SessionPool,
        *,
        max_connections: int = 256,
        idle_timeout: float = 0.0,
        metrics: Optional["TrafficMetrics"] = None,
        upstream_proxy: Optional[object] = None,
        proxy_only_mode: bool = False,
        local_proxy_users: Optional[dict[str, str]] = None,
    ):
        self.host = host
        self.port = port
        self.pool = pool
        self.idle_timeout = idle_timeout
        self._metrics: Optional["TrafficMetrics"] = metrics
        self.upstream_proxy = upstream_proxy
        self.proxy_only_mode = proxy_only_mode
        self.local_proxy_users = dict(local_proxy_users) if local_proxy_users else {}
        # (target_host, target_port) -> monotonic deadline while the MASQUE
        # 502 breaker is tripped for that destination.
        self._target_breakers: dict[tuple[str, int], float] = {}
        self._semaphore = asyncio.Semaphore(max_connections) if max_connections > 0 else None
        self._server: Optional[asyncio.AbstractServer] = None
        self._client_tasks: set[asyncio.Task] = set()

    def set_pool(self, pool: Optional[SessionPool], metrics: Optional["TrafficMetrics"] = None) -> None:
        """Atomically point new client connections at a new session pool.

        In-flight connections keep the pool they already opened a stream on;
        only subsequent requests use the new upstream. This is the hot-swap
        seam that avoids restarting the listener (and the TUN forwarding to
        it) on a country change.
        """
        self.pool = pool
        if metrics is not None:
            self._metrics = metrics

    async def start(self) -> None:
        import ipaddress

        try:
            address = ipaddress.ip_address(self.host)
            if not (address.is_loopback or address.is_unspecified):
                raise ValueError(
                    "SOCKS5 bind address must be a loopback IP address "
                    "(or 0.0.0.0 with local proxy authentication)"
                )
            if address.is_unspecified and not self.local_proxy_users:
                raise ValueError(
                    "SOCKS5 bind address must be a loopback IP address "
                    "(0.0.0.0 requires local proxy authentication)"
                )
        except ValueError as exc:
            raise ValueError("SOCKS5 bind address must be a loopback IP address") from exc
        self._server = await asyncio.start_server(self._accept_client, self.host, self.port)

    async def serve_forever(self) -> None:
        assert self._server is not None
        await self._server.serve_forever()

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            for task in list(self._client_tasks):
                task.cancel()
            if self._client_tasks:
                await asyncio.gather(*self._client_tasks, return_exceptions=True)
            await self._server.wait_closed()

    def _accept_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.create_task(self._handle_client(reader, writer))
        self._client_tasks.add(task)
        task.add_done_callback(self._client_tasks.discard)

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        client_ip = peer[0] if peer else None
        if self._semaphore is not None:
            await self._semaphore.acquire()
        if self._metrics:
            self._metrics.connection_opened()
        try:
            await self._negotiate_and_serve(reader, writer, client_ip)
        except (ConnectionError, asyncio.IncompleteReadError) as exc:
            logger.debug("socks client %s disconnected: %s", peer, exc)
        except Exception as exc:  # noqa: BLE001
            logger.warning("socks client %s error: %s", peer, exc)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            if self._semaphore is not None:
                self._semaphore.release()
            if self._metrics:
                self._metrics.connection_closed()

    async def _negotiate_userpass(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """RFC 1929 username/password subnegotiation.

        Raises ConnectionError after replying with a failure status when the
        credentials do not match (the connection is closed by the caller).
        """
        ver, ulen = struct.unpack("!BB", await reader.readexactly(2))
        if ver != 0x01:
            raise ConnectionError(f"unsupported auth subnegotiation version {ver}")
        username = (await reader.readexactly(ulen)).decode("utf-8", errors="replace")
        (plen,) = struct.unpack("!B", await reader.readexactly(1))
        password = (await reader.readexactly(plen)).decode("utf-8", errors="replace")
        ok = self.local_proxy_users.get(username) == password
        status = 0x00 if ok else 0x01
        writer.write(struct.pack("!BB", 0x01, status))
        await writer.drain()
        if not ok:
            raise ConnectionError("local proxy authentication failed")

    async def _negotiate_and_serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, client_ip: Optional[str]) -> None:
        version, nmethods = struct.unpack("!BB", await reader.readexactly(2))
        if version != SOCKS_VERSION:
            raise ConnectionError(f"unsupported SOCKS version {version}")
        offered_methods = await reader.readexactly(nmethods)
        if self.local_proxy_users:
            if _AUTH_USERPASS in offered_methods:
                method = _AUTH_USERPASS
            elif _AUTH_NO_AUTH in offered_methods:
                # Credentials are mandatory on this listener; a no-auth client
                # must not reach the pool.
                writer.write(struct.pack("!BB", SOCKS_VERSION, _AUTH_NO_ACCEPTABLE))
                await writer.drain()
                raise ConnectionError("local proxy requires username/password auth")
            else:
                method = _AUTH_NO_ACCEPTABLE
        else:
            method = _AUTH_NO_AUTH if _AUTH_NO_AUTH in offered_methods else _AUTH_NO_ACCEPTABLE
        writer.write(struct.pack("!BB", SOCKS_VERSION, method))
        await writer.drain()
        if method == _AUTH_NO_ACCEPTABLE:
            raise ConnectionError("client did not offer a supported SOCKS auth method")
        if method == _AUTH_USERPASS:
            await self._negotiate_userpass(reader, writer)

        header = await reader.readexactly(4)
        version, cmd, _rsv, atyp = struct.unpack("!BBBB", header)
        if version != SOCKS_VERSION:
            await self._reply(writer, _REP_GENERAL_FAILURE)
            raise ConnectionError(f"unsupported SOCKS version {version}")

        # Proxy-only mode: reject all CONNECT requests with failure response.
        # Never report a successful connection with a no-op stream.
        if self.proxy_only_mode:
            logger.info("proxy-only mode: rejecting CONNECT request")
            await self._reply(writer, _REP_GENERAL_FAILURE)
            return

        if cmd != _CMD_CONNECT:
            await self._reply(writer, _REP_COMMAND_NOT_SUPPORTED)
            return

        if atyp == _ATYP_IPV4:
            addr_bytes = await reader.readexactly(4)
            target_host = str(ipaddress.IPv4Address(addr_bytes))
        elif atyp == _ATYP_DOMAIN:
            (length,) = struct.unpack("!B", await reader.readexactly(1))
            target_host = (await reader.readexactly(length)).decode("utf-8", errors="replace")
        elif atyp == _ATYP_IPV6:
            addr_bytes = await reader.readexactly(16)
            target_host = str(ipaddress.IPv6Address(addr_bytes))
        else:
            await self._reply(writer, _REP_ADDRESS_TYPE_NOT_SUPPORTED)
            return

        (target_port,) = struct.unpack("!H", await reader.readexactly(2))

        # The built-in MASQUE upstream cannot serve ports outside 80/443;
        # answer immediately with the ruleset error instead of burning an
        # upstream stream (and possibly the live session) on a guaranteed 502.
        # A custom upstream proxy keeps its own port policy, so gating is off.
        if (
            self.upstream_proxy is None
            and target_port not in _MASQUE_ALLOWED_PORTS
        ):
            await self._reply(writer, _REP_CONNECTION_NOT_ALLOWED)
            return
        target_key = (target_host, target_port)
        now = asyncio.get_running_loop().time()
        breaker_until = self._target_breakers.get(target_key)
        if breaker_until is not None:
            if now < breaker_until:
                await self._reply(writer, _REP_CONNECTION_NOT_ALLOWED)
                return
            self._target_breakers.pop(target_key, None)

        try:
            upstream = await self.pool.open_stream(target_host, target_port, affinity_key=client_ip)
        except Exception as exc:  # noqa: BLE001
            logger.warning("failed to open upstream tunnel to %s:%s: %s", target_host, target_port, exc)
            if _MASQUE_REFUSAL_MARKER in str(exc):
                self._trip_target_breaker(target_key)
            await self._reply(writer, _REP_GENERAL_FAILURE)
            return

        await self._reply(writer, _REP_SUCCEEDED, writer.get_extra_info("sockname"))
        await relay_bidirectional(reader, writer, upstream, self.idle_timeout)

    def _trip_target_breaker(self, key: tuple[str, int]) -> None:
        """Block one refused destination briefly, never the whole port.

        The breaker exists so background apps retrying the same edge-refused
        host cannot storm the session, but a 502 says nothing about other
        destinations on that port.  Entries are bounded: expired deadlines are
        pruned first, then the oldest key.
        """
        now = asyncio.get_running_loop().time()
        self._target_breakers[key] = now + _TARGET_BREAKER_COOLDOWN_SECONDS
        if len(self._target_breakers) <= _MAX_TARGET_BREAKERS:
            return
        for stale in [item for item, until in self._target_breakers.items() if until <= now]:
            self._target_breakers.pop(stale, None)
        while len(self._target_breakers) > _MAX_TARGET_BREAKERS:
            self._target_breakers.pop(next(iter(self._target_breakers)), None)

    @staticmethod
    async def _reply(writer: asyncio.StreamWriter, rep: int, local_addr: Optional[Tuple] = None) -> None:
        host = "0.0.0.0"
        port = 0
        if local_addr:
            host, port = local_addr[0], local_addr[1]

        atyp = _ATYP_IPV4
        addr_bytes = bytes(4)
        try:
            ip_obj = ipaddress.ip_address(host)
        except ValueError:
            ip_obj = None
        if isinstance(ip_obj, ipaddress.IPv6Address):
            atyp = _ATYP_IPV6
            addr_bytes = ip_obj.packed
        elif isinstance(ip_obj, ipaddress.IPv4Address):
            atyp = _ATYP_IPV4
            addr_bytes = ip_obj.packed

        writer.write(struct.pack("!BBBB", SOCKS_VERSION, rep, 0x00, atyp) + addr_bytes + struct.pack("!H", port))
        await writer.drain()
