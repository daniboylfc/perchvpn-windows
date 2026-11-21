"""Tests for upstream v2.0.3 transport parity options."""

from __future__ import annotations

import asyncio
import ssl
import socket
import shutil
import subprocess
import threading
from pathlib import Path

import pytest

from src.perchvpn.proxy import transport_options as to
from src.perchvpn.proxy.http1_session import (
    H1ProxySession,
    SessionAtCapacity,
    _handshake_sync,
)


def _unverified_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["http/1.1"])
    return context
from src.perchvpn.proxy.transport_options import TransportOptions


class TestClientHelloKnobs:
    def test_disabled_applies_nothing(self):
        ctx = ssl.create_default_context()
        assert to.configure_client_hello(ctx, "disabled") == []

    @pytest.mark.parametrize("fp", ["chrome", "firefox", "edge", "safari", "ios"])
    def test_browser_fingerprints_apply_cipher_and_curve(self, fp):
        ctx = ssl.create_default_context()
        applied = to.configure_client_hello(ctx, fp)
        assert any(k.startswith("ciphers=") for k in applied)
        assert any(k.startswith("curve=") for k in applied)

    def test_randomized_applies_random_cipher_bucket(self):
        ctx = ssl.create_default_context()
        applied = to.configure_client_hello(ctx, "randomized")
        assert "ciphers=randomized" in applied

    def test_unknown_fingerprint_is_inert(self):
        ctx = ssl.create_default_context()
        assert to.configure_client_hello(ctx, "wget") == []


class TestTlsRecordSplitting:
    def test_handshake_record_split_into_capped_records(self):
        payload = b"x" * 600
        record = b"\x16\x03\x01" + len(payload).to_bytes(2, "big") + payload
        parts = to.split_tls_records(record, max_len=256)
        assert len(parts) >= 3
        for part in parts:
            assert part[0] == 22
            assert int.from_bytes(part[3:5], "big") == len(part) - 5
        # The payload survives the header rebuild.
        payloads = b"".join(part[5:] for part in parts)
        assert payloads == payload

    def test_app_data_passes_through(self):
        appdata = b"\x17\x03\x03" + (600).to_bytes(2, "big") + b"y" * 600
        assert to.split_tls_records(appdata) == [appdata]

    def test_malformed_prefix_passthrough(self):
        garbage = b"not-tls"
        assert to.split_tls_records(garbage) == [garbage]


class TestFragmentBytes:
    def test_disabled_passes_through(self):
        opts = TransportOptions(tls_fragment_mode="disabled")
        chunks = to.fragment_bytes(b"hello", opts)
        assert chunks == [(b"hello", 0.0)]

    def test_record_mode_no_pacing(self):
        payload = b"z" * 300
        record = b"\x16\x03\x01" + len(payload).to_bytes(2, "big") + payload
        opts = TransportOptions(tls_fragment_mode="record")
        chunks = to.fragment_bytes(record, opts)
        assert len(chunks) >= 2
        assert all(pause == 0.0 for _, pause in chunks)
        payloads = b"".join(c[5:] for c, _ in chunks)
        assert payloads == payload

    def test_packet_mode_paces_and_falls_back(self):
        opts = TransportOptions(
            tls_fragment_mode="packet",
            tls_fragment_fallback_delay_ms=10,
        )
        data = bytes(range(256)) * 4  # 1024 bytes -> 16 segments of 64
        fake_time = iter([0.0] + [0.001] * 10 + [1.0] * 100)
        monkey_clock = lambda: next(fake_time)  # noqa: E731
        chunks = to.fragment_bytes(data, opts, clock=monkey_clock)
        assert b"".join(c for c, _ in chunks) == data
        assert chunks[0] == (data[:64], 0.0)
        # Fallback: the remainder arrives as one unfragmented chunk.
        assert len(chunks[-1][0]) > to.PACKET_SEGMENT_SIZE
        assert chunks[-1][1] == to._SEGMENT_PAUSE_SECONDS

    def test_combined_splits_records_then_segments(self):
        opts = TransportOptions(tls_fragment_mode="combined")
        payload = b"w" * 700
        record = b"\x16\x03\x01" + len(payload).to_bytes(2, "big") + payload
        chunks = to.fragment_bytes(record, opts)
        sizes = [len(c) for c, _ in chunks]
        assert max(sizes) <= to.PACKET_SEGMENT_SIZE


@pytest.fixture(scope="module")
def tls_cert(tmp_path_factory) -> Path:
    if not shutil.which("openssl"):
        pytest.skip("openssl is required to mint a test certificate")
    d = tmp_path_factory.mktemp("tls")
    key = d / "key.pem"
    crt = d / "crt.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(crt),
            "-subj", "/CN=edge.test", "-days", "1",
        ],
        check=True, capture_output=True,
    )
    return d


class _ScriptedServer(threading.Thread):
    """Blocking TLS server over a socketpair; drives CONNECT responses."""

    def __init__(self, sock, certdir, responses):
        super().__init__(daemon=True)
        self.responses = list(responses)
        self.received = []
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(certdir / "crt.pem", certdir / "key.pem")
        self.sock = sock
        self.ctx = ctx
        self.tls = None
        self.error = None

    def run(self):
        try:
            self.tls = self.ctx.wrap_socket(self.sock, server_side=True)
            for response in self.responses:
                data = self.tls.recv(65536)
                if not data:
                    break
                self.received.append(data)
                if response is None:
                    continue
                self.tls.sendall(response)
                if response == b"":
                    break
        except Exception as exc:  # noqa: BLE001
            self.error = exc


class TestH1HandshakeAndTunnel:
    @pytest.mark.asyncio
    async def test_handshake_connect_tunnel_and_capacity(self, tls_cert):
        server_sock, client_sock = socket.socketpair()
        server = _ScriptedServer(server_sock, tls_cert, [b"HTTP/1.1 200 OK\r\n\r\n"])
        server.start()

        options = TransportOptions(
            utls_fingerprint="firefox",
            tls_fragment_mode="record",
        )
        session = H1ProxySession("edge.test", 443, "tok", options=options)
        context = _unverified_context()
        rbio, wbio = ssl.MemoryBIO(), ssl.MemoryBIO()
        loop = asyncio.get_running_loop()
        obj = await loop.run_in_executor(
            None,
            lambda: _handshake_sync(client_sock, "edge.test", context, rbio, wbio, options, 5.0),
        )
        session._sock = client_sock
        session._ssl = obj
        session._rbio = rbio
        session._wbio = wbio
        session._alpn = obj.selected_alpn_protocol()

        stream = await session.open_stream("target.example.com", 80)
        await stream.wait_established()
        assert server.received and b"CONNECT target.example.com:80" in server.received[0]
        assert b"Proxy-Authorization: Bearer tok" in server.received[0]

        # HTTP/1.1 sessions carry exactly one tunnel.
        with pytest.raises(SessionAtCapacity):
            await session.open_stream("other.example.com", 80)

        server.join(timeout=5)
        assert server.error is None
        await session.close()

    @pytest.mark.asyncio
    async def test_connect_refusal_raises_proxy_error(self, tls_cert):
        server_sock, client_sock = socket.socketpair()
        server = _ScriptedServer(server_sock, tls_cert, [b"HTTP/1.1 403 Forbidden\r\n\r\n"])
        server.start()

        options = TransportOptions()
        session = H1ProxySession("edge.test", 443, "tok", options=options)
        context = _unverified_context()
        rbio, wbio = ssl.MemoryBIO(), ssl.MemoryBIO()
        loop = asyncio.get_running_loop()
        obj = await loop.run_in_executor(
            None,
            lambda: _handshake_sync(client_sock, "edge.test", context, rbio, wbio, options, 5.0),
        )
        session._sock = client_sock
        session._ssl = obj
        session._rbio = rbio
        session._wbio = wbio

        from src.perchvpn.exceptions import ProxyError

        with pytest.raises(ProxyError, match="refused CONNECT"):
            await session.open_stream("target.example.com", 80)
        server.join(timeout=5)
        assert server.error is None
        await session.close()


class TestH1ConnectionLoss:
    @pytest.mark.asyncio
    async def test_edge_close_mid_connect_marks_session_dead(self, tls_cert):
        """The edge dropping the transport mid-CONNECT must mark the session
        dead (is_closed), so SessionPool replaces it, retries the client on
        a fresh dial, and its close-storm detector observes the churn."""
        from src.perchvpn.exceptions import ProxyError

        server_sock, client_sock = socket.socketpair()
        server = _ScriptedServer(server_sock, tls_cert, [])  # never answers
        server.start()

        options = TransportOptions()
        session = H1ProxySession("edge.test", 443, "tok", options=options)
        context = _unverified_context()
        rbio, wbio = ssl.MemoryBIO(), ssl.MemoryBIO()
        loop = asyncio.get_running_loop()
        obj = await loop.run_in_executor(
            None,
            lambda: _handshake_sync(client_sock, "edge.test", context, rbio, wbio, options, 5.0),
        )
        session._ssl = obj
        session._rbio = rbio
        session._wbio = wbio
        # Deterministic edge drop: any read on the transport returns EOF.
        class _DeadSock:
            def __init__(self):
                self.sent = b""

            def send(self, data):
                self.sent += data
                return len(data)

            def sendall(self, data):
                return self.send(data)

            def recv(self, n):
                return b""

            def close(self):
                pass

        dead = _DeadSock()
        session._sock = dead
        assert session.is_closed is False

        with pytest.raises(ProxyError, match="connection closed before CONNECT response"):
            await session.open_stream("t.example.com", 80)

        assert session.is_closed is True
        assert session._tunnels == {}
        assert dead.sent  # the CONNECT request left through the transport
        server_sock.close()
        server.join(timeout=5)
        await session.close()
