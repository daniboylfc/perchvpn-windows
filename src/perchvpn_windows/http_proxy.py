"""Optional local HTTP proxy frontend.

The server speaks enough HTTP to support CONNECT tunneling and ordinary
request forwarding. Every tunneled byte goes through the same upstream
session pool as the SOCKS5 frontend, so proxy-only mode and SOCKS clients
cannot silently bypass the VPN/upstream transport.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Callable, Optional
from urllib.parse import urlsplit

from perchvpn.proxy.relay import relay_bidirectional
from perchvpn.proxy.session import H2Stream

logger = logging.getLogger("perchvpn_windows.http_proxy")

MAX_HEADER_BYTES = 65536
OPEN_STREAM_TIMEOUT = 20.0


def _is_local_network(host: str) -> bool:
    import ipaddress

    if host.lower() in ("localhost",):
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (
        addr.is_loopback
        or addr.is_private
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
        or addr.is_reserved
    )


class HttpProxyServer:
    def __init__(
        self,
        host: str,
        port: int,
        session_provider: Callable[[], Optional[object]],
        *,
        max_connections: int = 256,
        proxy_only_mode: bool = False,
        local_proxy_users: Optional[dict[str, str]] = None,
    ):
        self.host = host
        self.port = port
        self._session_provider = session_provider
        self._max_connections = max_connections
        self.proxy_only_mode = proxy_only_mode
        self.local_proxy_users = dict(local_proxy_users) if local_proxy_users else {}
        self._semaphore = asyncio.Semaphore(max_connections) if max_connections > 0 else None
        self._server: Optional[asyncio.AbstractServer] = None
        self._client_tasks: set[asyncio.Task] = set()
        self._accepting = False

    async def start(self) -> None:
        import ipaddress

        try:
            address = ipaddress.ip_address(self.host)
            if not (address.is_loopback or address.is_unspecified):
                raise ValueError(
                    "HTTP proxy bind address must be a loopback IP address "
                    "(or 0.0.0.0 with local proxy authentication)"
                )
            if address.is_unspecified and not self.local_proxy_users:
                raise ValueError(
                    "HTTP proxy bind address must be a loopback IP address "
                    "(0.0.0.0 requires local proxy authentication)"
                )
        except ValueError as exc:
            raise ValueError("HTTP proxy bind address must be a loopback IP address") from exc
        self._accepting = True
        self._client_tasks = set()
        self._server = await asyncio.start_server(self._accept_client, self.host, self.port)

    async def stop(self) -> None:
        self._accepting = False
        server = self._server
        if server is not None:
            server.close()
        for task in list(self._client_tasks):
            task.cancel()
        if self._client_tasks:
            await asyncio.gather(*self._client_tasks, return_exceptions=True)
        if server is not None:
            await server.wait_closed()
            self._server = None
        self._client_tasks.clear()

    async def _accept_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if not self._accepting:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            return
        task = asyncio.current_task()
        if task is not None:
            self._client_tasks.add(task)
        try:
            if not self._accepting:
                return
            await self._handle_client(reader, writer)
        finally:
            if task is not None:
                self._client_tasks.discard(task)

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self._semaphore is not None:
            await self._semaphore.acquire()
        try:
            await self._handle_client_or_raise(reader, writer)
        except (ConnectionError, asyncio.IncompleteReadError, EOFError):
            pass
        except Exception as exc:  # noqa: BLE001
            logger.debug("http proxy client error: %s", exc)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            if self._semaphore is not None:
                self._semaphore.release()

    async def _handle_client_or_raise(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        request_line = await reader.readline()
        if not request_line:
            return
        parts = request_line.decode("iso-8859-1").strip().split()
        if len(parts) < 2:
            await self._send_error(writer, 400, "Bad Request")
            return
        method = parts[0].upper()
        target = parts[1]
        version = parts[2] if len(parts) > 2 else "HTTP/1.1"

        headers: list[tuple[str, str]] = []
        host_header = ""
        while True:
            line = await reader.readline()
            if not line or line in (b"\r\n", b"\n"):
                break
            if len(headers) > 100:
                await self._send_error(writer, 431, "Request Header Fields Too Large")
                return
            text = line.decode("iso-8859-1").rstrip("\r\n")
            if ":" in text:
                name, value = text.split(":", 1)
                headers.append((name.strip(), value.strip()))
                if name.lower() == "host":
                    host_header = value.strip()

        if method == "CONNECT":
            if self.local_proxy_users and not self._check_basic_auth(headers):
                await self._send_error(writer, 407, "Proxy Authentication Required")
                return
            await self._handle_connect(reader, writer, target)
            return

        if self.local_proxy_users and not self._check_basic_auth(headers):
            await self._send_error(writer, 407, "Proxy Authentication Required")
            return

        await self._handle_forward(reader, writer, method, target, version, headers, host_header)

    def _check_basic_auth(self, headers: list[tuple[str, str]]) -> bool:
        import base64

        for name, value in headers:
            if name.lower() != "proxy-authorization":
                continue
            scheme, _, token = value.partition(" ")
            if scheme.lower() != "basic":
                continue
            try:
                decoded = base64.b64decode(token.strip(), validate=True).decode(
                    "utf-8", errors="replace"
                )
            except Exception:
                return False
            username, sep, password = decoded.partition(":")
            if not sep:
                return False
            return self.local_proxy_users.get(username) == password
        return False

    async def _handle_connect(self, reader, writer, target: str) -> None:
        host, _, port_text = target.rpartition(":")
        if not host:
            host = target
            port_text = "443"
        try:
            port = int(port_text)
        except ValueError:
            await self._send_error(writer, 400, "Bad Request")
            return
        if not (1 <= port <= 65535):
            await self._send_error(writer, 400, "Bad Request")
            return
        if _is_local_network(host):
            await self._send_error(writer, 403, "Forbidden", "Local network destinations are not carried by the tunnel")
            return
        if self.proxy_only_mode:
            await self._send_error(writer, 502, "Bad Gateway", "No VPN session available in proxy-only mode")
            return

        pool = self._session_provider()
        if pool is None:
            await self._send_error(writer, 502, "Bad Gateway", "No VPN session available")
            return

        upstream = None
        try:
            try:
                upstream = await asyncio.wait_for(pool.open_stream(host, port), timeout=OPEN_STREAM_TIMEOUT)
            except Exception as exc:  # noqa: BLE001
                await self._send_error(writer, 502, "Bad Gateway", f"Failed to connect to {host}:{port}: {exc}")
                return

            writer.write(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: Perch VPN\r\n\r\n")
            await writer.drain()
            await relay_bidirectional(reader, writer, upstream, idle_timeout=0.0)
        finally:
            if upstream is not None:
                try:
                    await upstream.close()
                except Exception:  # noqa: BLE001
                    pass

    async def _handle_forward(self, reader, writer, method, target, version, headers, host_header) -> None:
        parsed = urlsplit(target)
        if parsed.hostname:
            host = parsed.hostname
            port = parsed.port or 80
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
        else:
            host = host_header.split(":", 1)[0] if host_header else ""
            port = int(host_header.split(":", 1)[1]) if ":" in host_header else 80
            path = target

        if not host:
            await self._send_error(writer, 400, "Bad Request", "Missing destination host")
            return
        if _is_local_network(host):
            await self._send_error(writer, 403, "Forbidden", "Local network destinations are not carried by the tunnel")
            return
        if self.proxy_only_mode:
            await self._send_error(writer, 502, "Bad Gateway", "No VPN session available in proxy-only mode")
            return

        pool = self._session_provider()
        if pool is None:
            await self._send_error(writer, 502, "Bad Gateway", "No VPN session available")
            return

        upstream = None
        try:
            try:
                upstream = await asyncio.wait_for(pool.open_stream(host, port), timeout=OPEN_STREAM_TIMEOUT)
            except Exception as exc:  # noqa: BLE001
                await self._send_error(writer, 502, "Bad Gateway", f"Failed to connect to {host}:{port}: {exc}")
                return

            request_line = f"{method} {path} {version}\\r\\n".encode("iso-8859-1")
            upstream_write = upstream.write
            await upstream_write(request_line)
            for name, value in headers:
                if name.lower() != "proxy-connection":
                    await upstream_write(f"{name}: {value}\r\n".encode("iso-8859-1"))
            await upstream_write(b"\r\n")

            # Forward request body if Content-Length is present.
            content_length = 0
            for name, value in headers:
                if name.lower() == "content-length":
                    try:
                        content_length = int(value)
                    except ValueError:
                        content_length = 0
            if content_length > 0:
                body = await reader.readexactly(content_length)
                await upstream_write(body)

            # Relay response.
            # The upstream is an H2 stream; read chunks until EOF.
            while True:
                chunk = await upstream.read()
                if not chunk:
                    break
                writer.write(chunk)
                await writer.drain()
            writer.close()
        finally:
            if upstream is not None:
                try:
                    await upstream.close()
                except Exception:  # noqa: BLE001
                    pass

    async def _send_error(self, writer: asyncio.StreamWriter, status: int, reason: str, body: str = "") -> None:
        payload = body.encode("utf-8")
        response = (
            f"HTTP/1.1 {status} {reason}\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(payload)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("iso-8859-1")
        writer.write(response + payload)
        await writer.drain()
