"""Upstream proxy configuration and protocol handling for Windows H2 chaining."""

from __future__ import annotations

import base64
import socket
import struct
import sys
from typing import Optional

IP_UNICAST_IF = 31


class UpstreamProxyConfig:
    """Upstream proxy configuration for H2 transport-level chaining."""

    def __init__(
        self,
        host: str,
        port: int,
        type: str = "socks5",
        username: str = "",
        password: str = "",
    ):
        self.host = host
        self.port = port
        if type not in ("socks5", "http"):
            raise ValueError(f"upstream_proxy.type must be 'socks5' or 'http', got {type!r}")
        self.type = type
        self.username = username
        self.password = password


class UpstreamProxyError(Exception):
    """Raised when the upstream proxy cannot be reached or authenticated."""


def _apply_source_bind(sock: socket.socket, source_bind_ip: Optional[str]) -> None:
    """Bind the socket's source address before connect() (physical egress pin)."""
    if source_bind_ip:
        sock.bind((source_bind_ip, 0))


def _apply_physical_interface(sock: socket.socket, interface_index: Optional[int]) -> None:
    """Pin IPv4 egress to one interface (Windows IP_UNICAST_IF) before connect()."""
    if not interface_index or sys.platform != "win32":
        return
    try:
        sock.setsockopt(
            socket.IPPROTO_IP, IP_UNICAST_IF, struct.pack("!I", int(interface_index))
        )
    except (OSError, ValueError) as exc:
        raise UpstreamProxyError(
            f"failed to pin upstream proxy egress to interface {interface_index}: {exc}"
        ) from exc


def _proxy_connection_target(proxy: UpstreamProxyConfig, dial_host: Optional[str]) -> str:
    """The address actually connected to; never a name resolved by the OS."""
    return dial_host or proxy.host


def _connect_socks5(
    proxy: UpstreamProxyConfig,
    target_host: str,
    target_port: int,
    source_bind_ip: Optional[str] = None,
    dial_host: Optional[str] = None,
    interface_index: Optional[int] = None,
) -> socket.socket:
    """Establish a TCP connection to the upstream proxy, authenticate with
    SOCKS5 (optional username/password), and request CONNECT to the target."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30.0)
    try:
        _apply_source_bind(sock, source_bind_ip)
        _apply_physical_interface(sock, interface_index)
        sock.connect((_proxy_connection_target(proxy, dial_host), proxy.port))
        # SOCKS5 greeting: no authentication plus username/password.
        sock.sendall(b"\x05\x02\x00\x02")
        resp = _recv_exact(sock, 2)
        if resp[0] != 0x05 or resp[1] not in (0x00, 0x02):
            raise UpstreamProxyError(f"SOCKS5 greeting failed: {resp[1]:#x}")
        if resp[1] == 0x02:
            if not (proxy.username and proxy.password):
                raise UpstreamProxyError("SOCKS5 proxy requires authentication")
            auth = (
                b"\x01"
                + bytes([len(proxy.username)]) + proxy.username.encode("utf-8")
                + bytes([len(proxy.password)]) + proxy.password.encode("utf-8")
            )
            sock.sendall(auth)
            auth_resp = _recv_exact(sock, 2)
            if auth_resp[0] != 0x01 or auth_resp[1] != 0x00:
                raise UpstreamProxyError("SOCKS5 authentication failed")
        # CONNECT request with a domain-name address.
        request = b"\x05\x01\x00\x03" + bytes([len(target_host)]) + target_host.encode("utf-8") + struct.pack(">H", target_port)
        sock.sendall(request)
        resp = _recv_exact(sock, 10)
        if resp[1] != 0x00:
            raise UpstreamProxyError(f"SOCKS5 CONNECT failed: {resp[1]:#x}")
        return sock
    except (OSError, UpstreamProxyError) as exc:
        sock.close()
        raise UpstreamProxyError(f"SOCKS5 upstream proxy failed: {exc}") from exc


def _connect_http(
    proxy: UpstreamProxyConfig,
    target_host: str,
    target_port: int,
    source_bind_ip: Optional[str] = None,
    dial_host: Optional[str] = None,
    interface_index: Optional[int] = None,
) -> socket.socket:
    """Establish a TCP connection to the upstream proxy, authenticate with
    optional Basic auth, and request HTTP CONNECT to the target."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30.0)
    try:
        _apply_source_bind(sock, source_bind_ip)
        _apply_physical_interface(sock, interface_index)
        sock.connect((_proxy_connection_target(proxy, dial_host), proxy.port))
    except (OSError, UpstreamProxyError):
        sock.close()
        raise
    if proxy.username and proxy.password:
        cred = base64.b64encode(f"{proxy.username}:{proxy.password}".encode()).decode()
        sock.sendall(f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n".encode())
        sock.sendall(f"Proxy-Authorization: Basic {cred}\r\n\r\n".encode())
    else:
        sock.sendall(f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n\r\n".encode())
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            raise UpstreamProxyError("HTTP CONNECT response closed")
        response += chunk
    status_line = response.split(b"\r\n", 1)[0].decode(errors="replace")
    parts = status_line.split()
    if len(parts) < 2 or not parts[1].startswith("2"):
        raise UpstreamProxyError(f"HTTP CONNECT failed: {status_line}")
    return sock


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise UpstreamProxyError("upstream proxy closed the connection")
        data += chunk
    return data


def connect_through_upstream_proxy(
    proxy: UpstreamProxyConfig,
    target_host: str,
    target_port: int,
    source_bind_ip: Optional[str] = None,
    dial_host: Optional[str] = None,
    interface_index: Optional[int] = None,
) -> tuple[socket.socket, socket.socket]:
    """Establish a connection to the upstream proxy and request CONNECT to
    the target. Returns (reader, writer) tuple of socket objects."""
    if proxy.type == "socks5":
        sock = _connect_socks5(
            proxy, target_host, target_port, source_bind_ip, dial_host, interface_index
        )
    elif proxy.type == "http":
        sock = _connect_http(
            proxy, target_host, target_port, source_bind_ip, dial_host, interface_index
        )
    else:
        raise UpstreamProxyError(f"Unknown upstream proxy type: {proxy.type!r}")
    return sock, sock
