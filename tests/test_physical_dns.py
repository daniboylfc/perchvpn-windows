"""Unit tests for the physical-path DNS client."""

from __future__ import annotations

import socket
import struct
import threading

import pytest

from perchvpn_windows import physical_dns
from perchvpn_windows.physical_dns import (
    PhysicalDnsError,
    build_query,
    parse_response,
    query_a,
    resolve_ipv4,
)


def _name(value: str) -> bytes:
    out = bytearray()
    for label in value.rstrip(".").split("."):
        out.append(len(label))
        out.extend(label.encode())
    out.append(0)
    return bytes(out)


def _a(address: str) -> bytes:
    return socket.inet_aton(address)


def _rr(owner: bytes, rtype: int, rdata: bytes) -> bytes:
    return owner + struct.pack(">HHIH", rtype, 1, 60, len(rdata)) + rdata


def _response(
    query_id: int,
    qname: str,
    answers: bytes = b"",
    *,
    qtype: int = 1,
    rcode: int = 0,
    truncated: bool = False,
    ancount: int | None = None,
) -> bytes:
    flags = 0x8000 | 0x0100 | rcode
    if truncated:
        flags |= 0x0200
    count = ancount if ancount is not None else (1 if answers else 0)
    header = struct.pack(">HHHHHH", query_id, flags, 1, count, 0, 0)
    return header + _name(qname) + struct.pack(">HH", qtype, 1) + answers


def test_build_query_encodes_recursive_a_record() -> None:
    packet = build_query("api.example.com", query_id=0x1234)
    assert packet[:2] == b"\x12\x34"
    flags, qdcount = struct.unpack(">HH", packet[2:6])
    assert flags == 0x0100
    assert qdcount == 1
    assert packet.endswith(struct.pack(">HH", 1, 1))
    assert _name("api.example.com") in packet


def test_parse_returns_a_records_and_ignores_unrelated() -> None:
    answers = _rr(b"\xc0\x0c", 1, _a("203.0.113.9")) + _rr(
        b"\x05other\x07example\x00", 1, _a("198.51.100.7")
    )
    packet = _response(7, "api.example.com", answers, ancount=2)
    assert parse_response(packet, "api.example.com", 7) == ["203.0.113.9"]


def test_parse_follows_in_response_cname_chain() -> None:
    cname = _rr(b"\xc0\x0c", 5, _name("edge.cdn.example.net"))
    record = _rr(b"\xc0\x0c", 1, _a("203.0.113.5"))
    packet = _response(9, "api.example.com", cname + record, ancount=2)
    assert parse_response(packet, "api.example.com", 9) == ["203.0.113.5"]


def test_parse_rejects_id_mismatch() -> None:
    packet = _response(1, "api.example.com", _rr(b"\xc0\x0c", 1, _a("203.0.113.5")))
    with pytest.raises(PhysicalDnsError, match="id mismatch"):
        parse_response(packet, "api.example.com", 2)


def test_parse_rejects_answer_for_another_name() -> None:
    packet = _response(3, "api.example.com", _rr(b"\xc0\x0c", 1, _a("203.0.113.5")))
    with pytest.raises(PhysicalDnsError, match="wrong name"):
        parse_response(packet, "evil.example.com", 3)


def test_parse_rejects_error_rcode_and_truncation() -> None:
    answers = _rr(b"\xc0\x0c", 1, _a("203.0.113.5"))
    with pytest.raises(PhysicalDnsError, match="rcode"):
        parse_response(_response(5, "api.example.com", answers, rcode=3), "api.example.com", 5)
    with pytest.raises(PhysicalDnsError, match="truncated"):
        parse_response(
            _response(5, "api.example.com", answers, truncated=True),
            "api.example.com",
            5,
        )


def test_parse_rejects_response_without_a_records() -> None:
    packet = _response(11, "api.example.com", b"")
    with pytest.raises(PhysicalDnsError, match="no A records"):
        parse_response(packet, "api.example.com", 11)


def test_resolve_uses_next_server_and_dedupes() -> None:
    calls: list[str] = []

    def fake_query(server, host, **kwargs):
        calls.append(server)
        if server == "192.168.1.1":
            raise PhysicalDnsError("timeout")
        return ["203.0.113.9", "203.0.113.9", "198.51.100.4"]

    assert resolve_ipv4(
        "api.example.com", ["192.168.1.1", "192.168.1.53"], query=fake_query
    ) == ["203.0.113.9", "203.0.113.9", "198.51.100.4"]
    assert calls == ["192.168.1.1", "192.168.1.53"]


def test_resolve_fails_closed_without_a_server() -> None:
    with pytest.raises(PhysicalDnsError, match="no physical DNS server"):
        resolve_ipv4("api.example.com", [])
    with pytest.raises(PhysicalDnsError, match="empty hostname"):
        resolve_ipv4("", ["192.168.1.1"])


def test_query_a_binds_source_and_sends_to_server_port_53(monkeypatch) -> None:
    fake = _FakeSocket()
    monkeypatch.setattr(physical_dns.socket, "socket", lambda *a, **k: fake)

    assert query_a(
        "192.168.1.1", "api.example.com", source_ip="192.168.1.2", query_id=0x4321
    ) == ["203.0.113.5"]
    assert fake.bound == ("192.168.1.2", 0)
    assert fake.sent_to == ("192.168.1.1", 53)
    assert fake.closed
    assert struct.unpack(">H", fake.sent_packet[:2])[0] == 0x4321


def test_query_a_rejects_a_reply_from_another_sender(monkeypatch) -> None:
    fake = _FakeSocket(from_addr=("203.0.113.66", 53))
    monkeypatch.setattr(physical_dns.socket, "socket", lambda *a, **k: fake)

    with pytest.raises(PhysicalDnsError, match="instead of"):
        query_a("192.168.1.1", "api.example.com", query_id=0x4321)


class _FakeSocket:
    def __init__(self, from_addr: tuple = ("192.168.1.1", 53)) -> None:
        self.from_addr = from_addr
        self.bound = None
        self.sent_to = None
        self.sent_packet = b""
        self.closed = False

    def bind(self, address) -> None:
        self.bound = address

    def settimeout(self, timeout) -> None:
        self.timeout = timeout

    def sendto(self, packet, address) -> None:
        self.sent_packet = packet
        self.sent_to = address
        query_id = struct.unpack(">H", packet[:2])[0]
        self._reply = _response(
            query_id,
            "api.example.com",
            _rr(_name("api.example.com"), 1, _a("203.0.113.5")),
        )

    def recvfrom(self, size):
        return self._reply, self.from_addr

    def close(self) -> None:
        self.closed = True
