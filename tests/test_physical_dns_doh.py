"""Unit tests for the source-bound DoH fallback in physical_dns."""

from __future__ import annotations

import socket
import ssl
import struct
import types

import pytest

from perchvpn_windows import physical_dns
from perchvpn_windows.physical_dns import (
    DOH_IPV4_ENDPOINTS,
    PhysicalDnsError,
    build_query,
    parse_response,
    query_doh_ipv4,
    resolve_ipv4,
)


def _name(value: str) -> bytes:
    out = bytearray()
    for label in value.rstrip(".").split("."):
        out.append(len(label))
        out.extend(label.encode())
    out.append(0)
    return bytes(out)


def _response(
    query_id: int,
    qname: str = "api.example.com",
    address: str = "203.0.113.9",
    *,
    rcode: int = 0,
) -> bytes:
    flags = 0x8000 | 0x0100 | rcode
    header = struct.pack(">HHHHHH", query_id, flags, 1, 1, 0, 0)
    answer = (
        b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(address)
    )
    return header + _name(qname) + struct.pack(">HH", 1, 1) + answer


def _http(body: bytes, *, status: str = "HTTP/1.1 200 OK") -> bytes:
    head = (
        "%s\r\nHost: 1.1.1.1\r\nContent-Type: application/dns-message\r\n"
        "Content-Length: %d\r\nConnection: close\r\n\r\n" % (status, len(body))
    )
    return head.encode("ascii") + body


def _http_with(body: bytes, extra_header: bytes) -> bytes:
    response = _http(body)
    head, separator, rest = response.partition(b"\r\n\r\n")
    return head + b"\r\n" + extra_header + separator + rest


class _FakeTLS:
    def __init__(self, response: bytes):
        self.response = response
        self.sent = b""

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def recv(self, size: int) -> bytes:
        chunk, self.response = self.response[:size], self.response[size:]
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeContext:
    def __init__(self, tls: _FakeTLS | None, error: BaseException | None, log: dict):
        self.tls = tls
        self.error = error
        self.log = log

    def wrap_socket(self, sock, server_hostname=None):
        self.log.setdefault("sni", []).append(server_hostname)
        self.log["tls"] = self.tls
        if self.error is not None:
            raise self.error
        return self.tls


class _FakeSocket:
    def __init__(self, log: dict, connect_error: BaseException | None):
        self.log = log
        self.connect_error = connect_error

    def bind(self, addr) -> None:
        self.log.setdefault("bind", []).append(addr)

    def setsockopt(self, level, option, value) -> None:
        self.log.setdefault("setsockopt", []).append((level, option, value))

    def settimeout(self, value) -> None:
        self.log["timeout"] = value

    def connect(self, addr) -> None:
        self.log.setdefault("connect", []).append(addr)
        if self.connect_error is not None:
            raise self.connect_error

    def close(self) -> None:
        self.log["closed"] = self.log.get("closed", 0) + 1


def _fake_network(
    monkeypatch,
    responses,
    *,
    wrap_error: BaseException | None = None,
    connect_error: BaseException | None = None,
):
    """Patch physical_dns.socket/ssl with per-endpoint scripted responses."""
    log: dict = {}
    queue = list(responses)

    def factory(*_args):
        return _FakeSocket(log, connect_error)

    def context():
        tls = _FakeTLS(queue.pop(0)) if queue else None
        return _FakeContext(tls, wrap_error, log)

    fake_socket = types.SimpleNamespace(
        AF_INET=socket.AF_INET,
        SOCK_STREAM=socket.SOCK_STREAM,
        SOCK_DGRAM=socket.SOCK_DGRAM,
        IPPROTO_IP=socket.IPPROTO_IP,
        inet_ntoa=socket.inet_ntoa,
        inet_aton=socket.inet_aton,
        timeout=socket.timeout,
        socket=factory,
    )
    fake_ssl = types.SimpleNamespace(
        create_default_context=context, SSLError=ssl.SSLError
    )
    monkeypatch.setattr(physical_dns, "socket", fake_socket)
    monkeypatch.setattr(physical_dns, "ssl", fake_ssl)
    return log


def _set_platform(monkeypatch, value: str) -> None:
    monkeypatch.setattr(
        physical_dns, "sys", types.SimpleNamespace(platform=value)
    )


def test_parse_zero_id_rejected_by_default_but_allowed_for_doh() -> None:
    packet = _response(0)
    with pytest.raises(PhysicalDnsError, match="id mismatch"):
        parse_response(packet, "api.example.com", 0x1234)
    assert parse_response(packet, "api.example.com", 0x1234, allow_zero_id=True) == [
        "203.0.113.9"
    ]


def test_zero_id_still_validates_everything_else() -> None:
    with pytest.raises(PhysicalDnsError, match="rcode"):
        parse_response(_response(0, rcode=3), "api.example.com", 1, allow_zero_id=True)
    with pytest.raises(PhysicalDnsError, match="wrong name"):
        parse_response(
            _response(0, qname="other.example.com"),
            "api.example.com",
            1,
            allow_zero_id=True,
        )
    with pytest.raises(PhysicalDnsError, match="truncated"):
        parse_response(b"\x00\x00", "api.example.com", 1, allow_zero_id=True)


def test_doh_request_shape_and_binding(monkeypatch) -> None:
    _set_platform(monkeypatch, "win32")
    log = _fake_network(monkeypatch, [_http(_response(0x1234))])
    assert query_doh_ipv4(
        "api.example.com",
        source_ip="192.168.1.2",
        interface_index=10,
        query_id=0x1234,
    ) == ["203.0.113.9"]

    assert log["bind"] == [("192.168.1.2", 0)]
    assert log["setsockopt"] == [
        (socket.IPPROTO_IP, 31, struct.pack("!I", 10))
    ]
    assert log["connect"] == [("1.1.1.1", 443)]
    assert log["sni"] == ["cloudflare-dns.com"]
    sent = log["tls"].sent
    head, _, body = sent.partition(b"\r\n\r\n")
    assert head.startswith(b"POST /dns-query HTTP/1.1\r\n")
    assert b"\r\nHost: cloudflare-dns.com\r\n" in head
    assert b"\r\nContent-Type: application/dns-message\r\n" in head
    assert b"\r\nContent-Length: %d\r\n" % len(body) in head
    assert body == build_query("api.example.com", 0x1234)


@pytest.mark.parametrize(
    ("endpoint", "hostname"),
    [
        ("1.1.1.1", "cloudflare-dns.com"),
        ("1.0.0.1", "cloudflare-dns.com"),
        ("8.8.8.8", "dns.google"),
        ("9.9.9.9", "dns.quad9.net"),
    ],
)
def test_doh_endpoint_uses_canonical_sni_and_host(
    monkeypatch, endpoint, hostname
) -> None:
    _set_platform(monkeypatch, "win32")
    log = _fake_network(monkeypatch, [_http(_response(0x1234))])
    assert query_doh_ipv4(
        "api.example.com",
        endpoints=(endpoint,),
        query_id=0x1234,
    ) == ["203.0.113.9"]

    assert log["connect"] == [(endpoint, 443)]
    assert log["sni"] == [hostname]
    head, _, _ = log["tls"].sent.partition(b"\r\n\r\n")
    assert ("\r\nHost: %s\r\n" % hostname).encode("ascii") in head


def test_query_rejects_non_literal_endpoint_before_socket(monkeypatch) -> None:
    log = _fake_network(monkeypatch, [])
    with pytest.raises(ValueError, match="IPv4 literal"):
        query_doh_ipv4("api.example.com", endpoints=("cloudflare-dns.com",))
    assert log == {}


def test_resolve_rejects_non_literal_endpoint_before_udp_query() -> None:
    calls: list = []

    def query(*_args, **_kwargs):
        calls.append(1)
        return ["203.0.113.9"]

    with pytest.raises(ValueError, match="IPv4 literal"):
        resolve_ipv4(
            "api.example.com",
            ["192.168.1.1"],
            query=query,
            doh_endpoints=("cloudflare-dns.com",),
        )
    assert calls == []


def test_doh_rejects_missing_or_invalid_content_type(monkeypatch) -> None:
    body = _response(1)
    missing = _http(body).replace(
        b"Content-Type: application/dns-message\r\n", b""
    )
    _fake_network(monkeypatch, [missing])
    with pytest.raises(PhysicalDnsError, match="Content-Type"):
        query_doh_ipv4("api.example.com", endpoints=("1.1.1.1",))

    wrong = _http(body).replace(b"application/dns-message", b"text/html", 1)
    _fake_network(monkeypatch, [wrong])
    with pytest.raises(PhysicalDnsError, match="Content-Type"):
        query_doh_ipv4("api.example.com", endpoints=("1.1.1.1",))


def test_doh_rejects_transfer_and_content_encoding(monkeypatch) -> None:
    body = _response(1)
    _fake_network(
        monkeypatch, [_http_with(body, b"Transfer-Encoding: chunked")]
    )
    with pytest.raises(PhysicalDnsError, match="transfer-encoding"):
        query_doh_ipv4("api.example.com", endpoints=("1.1.1.1",))

    _fake_network(monkeypatch, [_http_with(body, b"Content-Encoding: gzip")])
    with pytest.raises(PhysicalDnsError, match="content-encoding"):
        query_doh_ipv4("api.example.com", endpoints=("1.1.1.1",))


def test_doh_rejects_duplicate_content_length(monkeypatch) -> None:
    body = _response(1)
    duplicate = _http_with(body, b"Content-Length: %d" % (len(body) + 1))
    _fake_network(monkeypatch, [duplicate])
    with pytest.raises(PhysicalDnsError, match="duplicate"):
        query_doh_ipv4("api.example.com", endpoints=("1.1.1.1",))


def test_doh_rejects_malformed_response_header(monkeypatch) -> None:
    _fake_network(monkeypatch, [_http_with(_response(1), b"Not-A-Header")])
    with pytest.raises(PhysicalDnsError, match="malformed"):
        query_doh_ipv4("api.example.com", endpoints=("1.1.1.1",))


def test_nonzero_id_and_interface_skipped_off_windows(monkeypatch) -> None:
    _set_platform(monkeypatch, "linux")
    log = _fake_network(monkeypatch, [_http(_response(0x4242))])
    assert query_doh_ipv4(
        "api.example.com", interface_index=10, query_id=0x4242
    ) == ["203.0.113.9"]
    assert "setsockopt" not in log


def test_doh_rejects_http_error(monkeypatch) -> None:
    _fake_network(monkeypatch, [_http(_response(1), status="HTTP/1.1 500 Oops")])
    with pytest.raises(PhysicalDnsError, match="HTTP error"):
        query_doh_ipv4("api.example.com", endpoints=("1.1.1.1",))


def test_doh_rejects_missing_or_bogus_content_length(monkeypatch) -> None:
    _fake_network(
        monkeypatch,
        [
            b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n"
            b"Connection: close\r\n\r\n"
        ],
    )
    with pytest.raises(PhysicalDnsError, match="missing Content-Length"):
        query_doh_ipv4("api.example.com", endpoints=("1.1.1.1",))
    _fake_network(monkeypatch, [_http(b"")])
    with pytest.raises(PhysicalDnsError, match="length"):
        query_doh_ipv4("api.example.com", endpoints=("1.1.1.1",))


def test_doh_rejects_truncated_and_malformed_bodies(monkeypatch) -> None:
    short = _http(_response(1))
    _fake_network(monkeypatch, [short[:-2]])
    with pytest.raises(PhysicalDnsError, match="truncated"):
        query_doh_ipv4("api.example.com", endpoints=("1.1.1.1",))
    _fake_network(monkeypatch, [_http(b"\x00\x01")])
    with pytest.raises(PhysicalDnsError, match="truncated DNS header"):
        query_doh_ipv4("api.example.com", endpoints=("1.1.1.1",))


def test_doh_rejects_dns_rcode(monkeypatch) -> None:
    _fake_network(monkeypatch, [_http(_response(1, rcode=2))])
    with pytest.raises(PhysicalDnsError, match="rcode"):
        query_doh_ipv4("api.example.com", endpoints=("1.1.1.1",), query_id=1)


def test_doh_fails_closed_on_certificate_error(monkeypatch) -> None:
    error = ssl.SSLCertVerificationError(
        "certificate verify failed: hostname mismatch"
    )
    log = _fake_network(monkeypatch, [_http(_response(1))], wrap_error=error)
    with pytest.raises(PhysicalDnsError, match="certificate"):
        query_doh_ipv4("api.example.com", endpoints=("1.1.1.1",))
    assert log["sni"] == ["cloudflare-dns.com"]


def test_doh_reports_timeout(monkeypatch) -> None:
    _fake_network(monkeypatch, [], connect_error=TimeoutError("timed out"))
    with pytest.raises(PhysicalDnsError, match="timed out"):
        query_doh_ipv4("api.example.com", timeout=0.5)


def test_doh_fails_over_to_second_endpoint(monkeypatch) -> None:
    _set_platform(monkeypatch, "win32")
    log = _fake_network(monkeypatch, [_http(_response(7))], connect_error=None)
    calls: list = []

    real_factory = physical_dns.socket.socket

    def factory(*args):
        calls.append(1)
        if len(calls) == 1:
            return _FakeSocket(log, OSError("reset"))
        return real_factory(*args)

    monkeypatch.setattr(physical_dns.socket, "socket", factory)
    assert query_doh_ipv4(
        "api.example.com",
        source_ip="192.168.1.2",
        interface_index=10,
        query_id=7,
    ) == ["203.0.113.9"]
    assert log["bind"] == [("192.168.1.2", 0), ("192.168.1.2", 0)]
    assert log["setsockopt"] == [
        (socket.IPPROTO_IP, 31, struct.pack("!I", 10)),
        (socket.IPPROTO_IP, 31, struct.pack("!I", 10)),
    ]
    assert log["connect"] == [("1.1.1.1", 443), ("1.0.0.1", 443)]
    assert log["sni"] == ["cloudflare-dns.com"]
    assert tuple(DOH_IPV4_ENDPOINTS) == ("1.1.1.1", "1.0.0.1", "8.8.8.8")


def test_doh_fails_closed_when_all_endpoints_fail(monkeypatch) -> None:
    _fake_network(monkeypatch, [], connect_error=OSError("unreachable"))
    with pytest.raises(PhysicalDnsError, match="1.1.1.1.*1.0.0.1"):
        query_doh_ipv4("api.example.com")


def _udp_failure(exc):
    def query(*_args, **_kwargs):
        raise exc

    return query


def _doh_result(addresses, calls):
    def query(name, **kwargs):
        calls.append((name, kwargs))
        return addresses

    return query


def test_resolve_falls_back_to_doh_on_udp_timeout() -> None:
    calls: list = []
    result = resolve_ipv4(
        "api.example.com",
        ["192.168.1.1"],
        source_ip="192.168.1.2",
        interface_index=10,
        query=_udp_failure(TimeoutError("timed out")),
        doh_query=_doh_result(["203.0.113.9"], calls),
    )
    assert result == ["203.0.113.9"]
    assert calls[0][0] == "api.example.com"
    assert calls[0][1]["source_ip"] == "192.168.1.2"
    assert calls[0][1]["interface_index"] == 10


def test_resolve_falls_back_on_udp_permission_error() -> None:
    calls: list = []
    blocked = PermissionError(13, "denied")
    blocked.winerror = 10013  # type: ignore[attr-defined]
    assert resolve_ipv4(
        "api.example.com",
        ["192.168.1.1"],
        query=_udp_failure(blocked),
        doh_query=_doh_result(["203.0.113.9"], calls),
    ) == ["203.0.113.9"]


def test_resolve_does_not_fall_back_after_later_authoritative_error() -> None:
    calls: list = []

    def query(server, *_args, **_kwargs):
        if server == "192.168.1.1":
            raise TimeoutError("timed out")
        raise PhysicalDnsError("DNS error rcode 3")

    def doh(*_args, **_kwargs):
        calls.append(1)
        return ["203.0.113.9"]

    with pytest.raises(PhysicalDnsError, match="rcode"):
        resolve_ipv4(
            "api.example.com",
            ["192.168.1.1", "192.168.1.53"],
            query=query,
            doh_query=doh,
        )
    assert calls == []


def test_resolve_does_not_fall_back_on_dns_errors() -> None:
    calls: list = []

    def doh(*_args, **_kwargs):
        calls.append(1)
        return ["203.0.113.9"]

    with pytest.raises(PhysicalDnsError, match="wrong name"):
        resolve_ipv4(
            "api.example.com",
            ["192.168.1.1"],
            query=_udp_failure(PhysicalDnsError("DNS answer for the wrong name")),
            doh_query=doh,
        )
    assert calls == []


def test_resolve_prefers_udp_answer_and_skips_doh() -> None:
    calls: list = []
    result = resolve_ipv4(
        "api.example.com",
        ["192.168.1.1"],
        query=lambda *_a, **_k: ["198.51.100.4"],
        doh_query=_doh_result(["203.0.113.9"], calls),
    )
    assert result == ["198.51.100.4"]
    assert calls == []


def test_resolve_fails_closed_when_doh_also_fails() -> None:
    def doh(*_args, **_kwargs):
        raise PhysicalDnsError("DoH HTTP error: HTTP/1.1 503")

    with pytest.raises(PhysicalDnsError, match="DoH HTTP error"):
        resolve_ipv4(
            "api.example.com",
            ["192.168.1.1"],
            query=_udp_failure(TimeoutError("timed out")),
            doh_query=doh,
        )


def test_doh_tls_context_loads_current_root_bundle(monkeypatch) -> None:
    import certifi

    loaded: dict = {}

    class _Context:
        def load_verify_locations(self, cafile=None) -> None:
            loaded["cafile"] = cafile

    fake_ssl = types.SimpleNamespace(
        create_default_context=_Context, SSLError=ssl.SSLError
    )
    monkeypatch.setattr(physical_dns, "ssl", fake_ssl)

    physical_dns._verifying_tls_context()
    assert loaded["cafile"] == certifi.where()


def test_doh_tls_context_falls_back_to_platform_store(monkeypatch) -> None:
    class _Context:
        pass

    fake_ssl = types.SimpleNamespace(
        create_default_context=_Context, SSLError=ssl.SSLError
    )
    monkeypatch.setattr(physical_dns, "ssl", fake_ssl)

    assert isinstance(physical_dns._verifying_tls_context(), _Context)
