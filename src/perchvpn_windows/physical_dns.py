"""Minimal plain-DNS client for the physical adapter.

The OS resolver (``socket.getaddrinfo``) selects a DNS server per interface
metric and honours NRPT/split-DNS rules.  While another tunnel (e.g. PattN)
owns a lower-metric default route, that stack can resolve through the tunnel,
so it cannot prove that a PerchVPN control-plane hostname was resolved over
the physical Wi-Fi path.

This module queries the physical adapter's own DNS servers directly, with the
socket bound to the physical address.  Callers must only pass servers whose
route was verified to leave through the physical interface (see
``tun_helper.find_route_interface``); with that filter the DNS query is on the
physical link exactly like the pinned upstream connections.

Plain UDP is tried first.  When local filters block port 53 (PATTN/sing-box
installs a WFP rule: UDP times out, TCP gets WSAEACCES), ``resolve_ipv4``
falls back to a source-bound HTTPS DoH POST to an IP-literal endpoint
(Cloudflare 1.1.1.1, then 1.0.0.1).  Endpoints are validated as IPv4 literals
so no endpoint hostname is ever resolved through another tunnel.  TLS still
uses the resolver's canonical hostname for SNI and certificate verification
because some resolvers reject or mis-certify a bare IP literal; the TCP
connection itself remains pinned to the validated IP literal.

Only A/IN records are needed for IPv4 endpoint pinning.
"""

from __future__ import annotations

import errno
import ipaddress
import secrets
import socket
import ssl
import struct
import sys
from typing import Callable, Iterable, List, Optional, Sequence, Set, Tuple

__all__ = [
    "DOH_IPV4_ENDPOINTS",
    "PhysicalDnsError",
    "build_query",
    "parse_response",
    "query_a",
    "query_doh_ipv4",
    "resolve_ipv4",
]


class PhysicalDnsError(RuntimeError):
    """A physical-path DNS query failed or returned an unusable answer."""


QTYPE_A = 1
QCLASS_IN = 1
_RCODE_NOERROR = 0
_FLAG_QR = 0x8000
_FLAG_TC = 0x0200
_FLAG_RD = 0x0100
IP_UNICAST_IF = 31
DOH_PATH = "/dns-query"
DOH_IPV4_ENDPOINTS: Tuple[str, ...] = ("1.1.1.1", "1.0.0.1", "8.8.8.8")
# Canonical TLS/Host names for the pinned resolver IPs.  The request still
# connects to the literal IP, so DNS for these names is never consulted.
DOH_ENDPOINT_HOSTNAMES = {
    "1.1.1.1": "cloudflare-dns.com",
    "1.0.0.1": "cloudflare-dns.com",
    "8.8.8.8": "dns.google",
    "9.9.9.9": "dns.quad9.net",
}
_DOH_MAX_BYTES = 65535


def _validated_ipv4_endpoints(endpoints: Iterable[str]) -> Tuple[str, ...]:
    """Return only endpoints that are proven IPv4 literals, before any socket."""
    validated: List[str] = []
    for endpoint in endpoints:
        try:
            address = ipaddress.IPv4Address(endpoint)
        except (ipaddress.AddressValueError, TypeError) as exc:
            raise ValueError(
                "DoH endpoint is not an IPv4 literal: %r" % (endpoint,)
            ) from exc
        text = str(address)
        if text not in validated:
            validated.append(text)
    return tuple(validated)


def _encode_name(name: str) -> bytes:
    labels = [part for part in name.rstrip(".").split(".") if part]
    if not labels:
        raise PhysicalDnsError("empty DNS name")
    encoded = bytearray()
    for label in labels:
        raw = label.encode("idna")
        if len(raw) > 63:
            raise PhysicalDnsError("DNS label too long: %r" % label)
        encoded.append(len(raw))
        encoded.extend(raw)
    encoded.append(0)
    if len(encoded) > 255:
        raise PhysicalDnsError("DNS name too long: %r" % name)
    return bytes(encoded)


def build_query(name: str, query_id: Optional[int] = None) -> bytes:
    """Build a recursive A/IN query packet."""
    ident = secrets.randbits(16) if query_id is None else int(query_id) & 0xFFFF
    header = struct.pack(">HHHHHH", ident, _FLAG_RD, 1, 0, 0, 0)
    return header + _encode_name(name) + struct.pack(">HH", QTYPE_A, QCLASS_IN)


def _decode_name(data: bytes, offset: int) -> Tuple[str, int]:
    labels: List[str] = []
    seen: Set[int] = set()
    next_offset = offset
    cursor = offset
    while True:
        if cursor >= len(data):
            raise PhysicalDnsError("truncated DNS name")
        length = data[cursor]
        if length == 0:
            cursor += 1
            if next_offset == offset:
                next_offset = cursor
            break
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(data):
                raise PhysicalDnsError("truncated DNS pointer")
            pointer = ((length & 0x3F) << 8) | data[cursor + 1]
            if next_offset == offset:
                next_offset = cursor + 2
            if pointer in seen:
                raise PhysicalDnsError("DNS compression loop")
            seen.add(pointer)
            cursor = pointer
            continue
        if length & 0xC0:
            raise PhysicalDnsError("invalid DNS label length")
        cursor += 1
        end = cursor + length
        if end > len(data):
            raise PhysicalDnsError("truncated DNS label")
        labels.append(data[cursor:end].decode("ascii", "replace"))
        cursor = end
    return ".".join(labels).lower(), next_offset


def parse_response(
    data: bytes,
    name: str,
    query_id: int,
    *,
    allow_zero_id: bool = False,
) -> List[str]:
    """Parse a response for ``name`` and return its A records.

    Follows an in-response CNAME chain (common for CDN endpoints) and ignores
    unrelated records.  Anything malformed, truncated, mismatched or carrying
    an error RCODE is rejected so a bad answer can never be pinned.

    ``allow_zero_id`` exists only for DoH: RFC 8484 lets a server answer with
    ID 0 regardless of the query ID.  UDP callers keep the strict echo check.
    """
    if len(data) < 12:
        raise PhysicalDnsError("truncated DNS header")
    ident, flags, qdcount, ancount = struct.unpack(">HHHH", data[:8])
    if ident != (int(query_id) & 0xFFFF) and not (allow_zero_id and ident == 0):
        raise PhysicalDnsError("DNS response id mismatch")
    if not flags & _FLAG_QR:
        raise PhysicalDnsError("DNS packet is not a response")
    if flags & _FLAG_TC:
        raise PhysicalDnsError("truncated DNS response")
    rcode = flags & 0x000F
    if rcode != _RCODE_NOERROR:
        raise PhysicalDnsError("DNS error rcode %d" % rcode)
    if qdcount != 1:
        raise PhysicalDnsError("unexpected DNS question count")

    offset = 12
    qname, offset = _decode_name(data, offset)
    if offset + 4 > len(data):
        raise PhysicalDnsError("truncated DNS question")
    qtype, qclass = struct.unpack(">HH", data[offset : offset + 4])
    offset += 4
    if qtype != QTYPE_A or qclass != QCLASS_IN:
        raise PhysicalDnsError("unexpected DNS question type")
    expected = name.rstrip(".").lower()
    if qname != expected:
        raise PhysicalDnsError("DNS answer for the wrong name")

    a_records: dict = {}
    cnames: dict = {}
    for _ in range(ancount):
        owner, offset = _decode_name(data, offset)
        if offset + 10 > len(data):
            raise PhysicalDnsError("truncated DNS record")
        rtype, rclass, _ttl, rdlength = struct.unpack(
            ">HHIH", data[offset : offset + 10]
        )
        offset += 10
        rdata_offset = offset
        offset += rdlength
        if offset > len(data):
            raise PhysicalDnsError("truncated DNS record data")
        if rclass != QCLASS_IN:
            continue
        if rtype == QTYPE_A:
            if rdlength != 4:
                raise PhysicalDnsError("invalid A record length")
            a_records.setdefault(owner, []).append(
                socket.inet_ntoa(data[rdata_offset:offset])
            )
        elif rtype == 5:
            target, _ = _decode_name(data, rdata_offset)
            cnames.setdefault(owner, target)

    chain: List[str] = [expected]
    cursor = expected
    while cursor in cnames and cnames[cursor] not in chain:
        cursor = cnames[cursor]
        chain.append(cursor)

    addresses: List[str] = []
    for owner in chain:
        for address in a_records.get(owner, []):
            if address not in addresses:
                addresses.append(address)
    if not addresses:
        raise PhysicalDnsError("no A records for %s" % name)
    return addresses


def _bind_physical_interface(
    sock: socket.socket, interface_index: Optional[int]
) -> None:
    """Pin IPv4 egress to the physical interface (Windows IP_UNICAST_IF)."""
    if not interface_index or sys.platform != "win32":
        return
    try:
        sock.setsockopt(
            socket.IPPROTO_IP, IP_UNICAST_IF, struct.pack("!I", int(interface_index))
        )
    except (OSError, ValueError) as exc:
        raise PhysicalDnsError(
            "failed to bind physical DNS to interface %s: %s"
            % (interface_index, exc)
        ) from exc


def _read_doh_body(tls: ssl.SSLSocket, limit: int = _DOH_MAX_BYTES) -> bytes:
    """Read one HTTP/1.1 response and return its (bounded) DNS body."""
    buffered = b""
    while b"\r\n\r\n" not in buffered:
        chunk = tls.recv(4096)
        if not chunk:
            raise PhysicalDnsError("DoH response closed before headers")
        buffered += chunk
        if len(buffered) > limit:
            raise PhysicalDnsError("DoH response headers too large")
    head, _, rest = buffered.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    parts = status_line.split()
    if len(parts) < 2 or parts[1] != "200":
        raise PhysicalDnsError("DoH HTTP error: %s" % status_line)
    content_type: Optional[bytes] = None
    content_lengths: List[bytes] = []
    for line in head.split(b"\r\n")[1:]:
        if not line:
            continue
        key, separator, value = line.partition(b":")
        header = key.strip().lower()
        if not separator or not header:
            raise PhysicalDnsError("malformed DoH response header")
        value = value.strip()
        if header == b"content-type":
            content_type = value
        elif header in (b"transfer-encoding", b"content-encoding"):
            raise PhysicalDnsError(
                "DoH unsupported response header: %s" % header.decode("latin-1")
            )
        elif header == b"content-length":
            content_lengths.append(value)
    if content_type is None:
        raise PhysicalDnsError("DoH response missing Content-Type")
    if not content_type.lower().startswith(b"application/dns-message"):
        raise PhysicalDnsError(
            "DoH unexpected Content-Type: %s"
            % content_type.decode("latin-1", "replace")
        )
    if len(content_lengths) != 1:
        raise PhysicalDnsError("DoH duplicate or missing Content-Length")
    raw_length = content_lengths[0]
    if b"," in raw_length:
        raise PhysicalDnsError("DoH ambiguous Content-Length")
    try:
        length = int(raw_length)
    except ValueError as exc:
        raise PhysicalDnsError("DoH invalid Content-Length") from exc
    if length <= 0 or length > limit:
        raise PhysicalDnsError("DoH response length %d is unusable" % length)
    body = rest
    while len(body) < length:
        chunk = tls.recv(length - len(body))
        if not chunk:
            raise PhysicalDnsError("truncated DoH response body")
        body += chunk
    return body[:length]


def _verifying_tls_context() -> ssl.SSLContext:
    """Build a certificate-verifying TLS context with a current root set.

    Windows LTSC images ship a machine root store frozen at image build time,
    so a resolver certificate anchored in a root added later (for example the
    2022 SSL.com roots used by ``1.0.0.1``/``one.one.one.one``) reports
    ``unable to get local issuer certificate``.  ``certifi`` carries a current
    public root set; load it on top of the platform defaults.  Verification is
    never disabled, and a missing bundle falls back to the platform store.
    """
    context = ssl.create_default_context()
    try:
        import certifi
    except ImportError:  # pragma: no cover - certifi is a hard dependency
        return context
    loader = getattr(context, "load_verify_locations", None)
    if loader is None:  # pragma: no cover - test doubles
        return context
    try:
        loader(cafile=certifi.where())
    except (OSError, ssl.SSLError):
        return context
    return context


def _query_doh_endpoint(
    endpoint: str,
    name: str,
    packet: bytes,
    query_id: int,
    *,
    source_ip: str,
    interface_index: Optional[int],
    timeout: float,
) -> List[str]:
    """One HTTPS POST to an IP-literal resolver; never disables verification."""
    server_name = DOH_ENDPOINT_HOSTNAMES.get(endpoint, endpoint)
    request = (
        "POST %s HTTP/1.1\r\nHost: %s\r\n"
        "Content-Type: application/dns-message\r\n"
        "Accept: application/dns-message\r\n"
        "Content-Length: %d\r\nConnection: close\r\n\r\n"
        % (DOH_PATH, server_name, len(packet))
    ).encode("ascii") + packet
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if source_ip:
            sock.bind((source_ip, 0))
        _bind_physical_interface(sock, interface_index)
        sock.settimeout(timeout)
        sock.connect((endpoint, 443))
        context = _verifying_tls_context()
        with context.wrap_socket(sock, server_hostname=server_name) as tls:
            tls.sendall(request)
            body = _read_doh_body(tls)
    finally:
        sock.close()
    return parse_response(body, name, query_id, allow_zero_id=True)


def query_doh_ipv4(
    name: str,
    *,
    source_ip: str = "",
    interface_index: Optional[int] = None,
    timeout: float = 3.0,
    endpoints: Sequence[str] = DOH_IPV4_ENDPOINTS,
    query_id: Optional[int] = None,
) -> List[str]:
    """Resolve ``name`` over source-bound DoH, trying IP-literal endpoints.

    Every endpoint is validated as an IPv4 literal before any socket is
    created, so no DoH hostname is ever resolved through the system/PATTN
    resolver.  The TCP connection stays pinned to that literal while TLS SNI,
    certificate verification and the HTTP Host header use the resolver's
    canonical hostname.  Fails closed when no configured endpoint produces a
    valid answer.
    """
    validated_endpoints = _validated_ipv4_endpoints(endpoints)
    host = (name or "").strip().rstrip(".")
    if not host:
        raise PhysicalDnsError("empty hostname")
    ident = secrets.randbits(16) if query_id is None else int(query_id) & 0xFFFF
    packet = build_query(host, ident)
    errors: List[str] = []
    for endpoint in validated_endpoints:
        try:
            return _query_doh_endpoint(
                endpoint,
                host,
                packet,
                ident,
                source_ip=source_ip,
                interface_index=interface_index,
                timeout=timeout,
            )
        except (PhysicalDnsError, OSError) as exc:
            errors.append("%s: %s" % (endpoint, exc))
    raise PhysicalDnsError(
        "physical DoH resolution failed for %s (%s)"
        % (host, "; ".join(errors) or "no DoH endpoint configured")
    )


def query_a(
    server: str,
    name: str,
    *,
    source_ip: str = "",
    timeout: float = 2.0,
    query_id: Optional[int] = None,
) -> List[str]:
    """Send one A query to ``server`` from ``source_ip`` over UDP."""
    ident = secrets.randbits(16) if query_id is None else int(query_id) & 0xFFFF
    packet = build_query(name, ident)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        if source_ip:
            sock.bind((source_ip, 0))
        sock.settimeout(timeout)
        sock.sendto(packet, (server, 53))
        data, addr = sock.recvfrom(4096)
    finally:
        sock.close()
    if addr[0] != server:
        raise PhysicalDnsError(
            "DNS reply came from %s instead of %s" % (addr[0], server)
        )
    return parse_response(data, name, ident)


def _doh_fallback_reason(exc: BaseException) -> bool:
    """Only a blocked/timeout UDP path justifies the DoH fallback.

    A DNS-level error (wrong name, RCODE, malformed answer) is authoritative
    and must never be retried through a different transport.
    """
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return True
    if isinstance(exc, PermissionError):
        return True
    if isinstance(exc, OSError):
        if getattr(exc, "winerror", None) == 10013:
            return True
        if exc.errno in (errno.EACCES, errno.EPERM):
            return True
    return False


def resolve_ipv4(
    name: str,
    servers: Sequence[str],
    *,
    source_ip: str = "",
    interface_index: Optional[int] = None,
    timeout: float = 2.0,
    query: Callable[..., List[str]] = query_a,
    doh_query: Optional[Callable[..., List[str]]] = None,
    doh_endpoints: Sequence[str] = DOH_IPV4_ENDPOINTS,
    deadline: Optional[float] = None,
) -> List[str]:
    """Resolve ``name`` against the physical adapter, then DoH if port 53 is
    blocked (timeout / WSAEACCES).  Any DoH failure fails closed.

    ``deadline`` bounds the total wall time (seconds, monotonic) so a
    competing tunnel route cannot stack per-server timeouts plus the DoH
    fallback into a multi-second stall; when unset it derives from
    ``timeout`` (four attempts' worth).
    """
    import time as _time

    validated_endpoints = _validated_ipv4_endpoints(doh_endpoints)
    host = (name or "").strip().rstrip(".")
    if not host:
        raise PhysicalDnsError("empty hostname")
    if deadline is None:
        deadline = max(4.0, float(timeout) * 4.0)
    started = _time.monotonic()

    def _budget_left() -> bool:
        return _time.monotonic() - started < deadline

    errors: List[str] = []
    fallback_allowed = True
    queried = 0
    for server in servers:
        if not server:
            continue
        if queried and not _budget_left():
            errors.append("deadline reached after %d server(s)" % queried)
            break
        queried += 1
        try:
            addresses = query(server, host, source_ip=source_ip, timeout=timeout)
        except (PhysicalDnsError, OSError) as exc:
            errors.append("%s: %s" % (server, exc))
            if not _doh_fallback_reason(exc):
                fallback_allowed = False
            continue
        if addresses:
            return addresses
        errors.append("%s: empty answer" % server)
        fallback_allowed = False
    if fallback_allowed and queried and _budget_left():
        resolve_doh = doh_query or query_doh_ipv4
        try:
            addresses = resolve_doh(
                host,
                source_ip=source_ip,
                interface_index=interface_index,
                timeout=timeout,
                endpoints=validated_endpoints,
            )
        except (PhysicalDnsError, OSError) as exc:
            errors.append("doh: %s" % exc)
        else:
            if addresses:
                return addresses
            errors.append("doh: empty answer")
    raise PhysicalDnsError(
        "physical DNS resolution failed for %s (%s)"
        % (host, "; ".join(errors) or "no physical DNS server")
    )
