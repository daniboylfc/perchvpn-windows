"""Focused tests for upstream proxy connection handling."""

from __future__ import annotations

import socket
import threading
import time

import pytest

from perchvpn.proxy.upstream_proxy import (
    UpstreamProxyConfig,
    UpstreamProxyError,
    connect_through_upstream_proxy,
)


def _serve(handler, port_holder):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(8)
    port_holder.append(sock.getsockname()[1])
    while True:
        try:
            conn, _ = sock.accept()
        except OSError:
            break
        threading.Thread(target=handler, args=(conn,), daemon=True).start()


def test_socks5_no_auth_connect():
    port_holder = []
    def handler(conn):
        data = conn.recv(2)
        assert data == b"\x05\x02"
        assert conn.recv(2) == b"\x00\x02"
        conn.sendall(b"\x05\x00")
        req = conn.recv(256)
        assert req[:4] == b"\x05\x01\x00\x03"
        domain_len = req[4]
        host = req[5:5 + domain_len].decode()
        port = int.from_bytes(req[5 + domain_len:7 + domain_len], "big")
        assert (host, port) == ("example.com", 443)
        conn.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
        conn.close()

    server = threading.Thread(target=_serve, args=(handler, port_holder), daemon=True)
    server.start()
    time.sleep(0.1)
    port = port_holder[0]
    proxy = UpstreamProxyConfig(host="127.0.0.1", port=port, type="socks5")
    sock, _ = connect_through_upstream_proxy(proxy, "example.com", 443)
    sock.close()


def test_socks5_userpass_connect():
    port_holder = []
    def handler(conn):
        assert conn.recv(2) == b"\x05\x02"
        assert conn.recv(2) == b"\x00\x02"
        conn.sendall(b"\x05\x02")
        auth = conn.recv(256)
        assert auth[0:2] == b"\x01\x05"
        assert auth[2:7] == b"alice"
        assert auth[7:8] == b"\x06"
        assert auth[8:14] == b"secret"
        conn.sendall(b"\x01\x00")
        req = conn.recv(256)
        assert req[:4] == b"\x05\x01\x00\x03"
        conn.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
        conn.close()

    server = threading.Thread(target=_serve, args=(handler, port_holder), daemon=True)
    server.start()
    time.sleep(0.1)
    proxy = UpstreamProxyConfig(host="127.0.0.1", port=port_holder[0], type="socks5", username="alice", password="secret")
    sock, _ = connect_through_upstream_proxy(proxy, "example.com", 443)
    sock.close()


def test_http_proxy_connect():
    port_holder = []
    def handler(conn):
        data = b""
        while b"\r\n\r\n" not in data:
            data += conn.recv(4096)
        assert data.startswith(b"CONNECT example.com:443 HTTP/1.1")
        conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        conn.close()

    server = threading.Thread(target=_serve, args=(handler, port_holder), daemon=True)
    server.start()
    time.sleep(0.1)
    proxy = UpstreamProxyConfig(host="127.0.0.1", port=port_holder[0], type="http")
    sock, _ = connect_through_upstream_proxy(proxy, "example.com", 443)
    sock.close()


def test_http_proxy_rejects_non_2xx():
    port_holder = []
    def handler(conn):
        data = b""
        while b"\r\n\r\n" not in data:
            data += conn.recv(4096)
        conn.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
        conn.close()

    server = threading.Thread(target=_serve, args=(handler, port_holder), daemon=True)
    server.start()
    time.sleep(0.1)
    proxy = UpstreamProxyConfig(host="127.0.0.1", port=port_holder[0], type="http")
    with pytest.raises(UpstreamProxyError):
        connect_through_upstream_proxy(proxy, "example.com", 443)
