"""Live, read-only proof that PerchVPN's physical path leaves via Wi-Fi.

Run on the Windows host:

    python tests\\test_live_physical_preflight.py

It never elevates, never changes routes/adapters/DNS, and never touches the
PATTN/sing-box tunnel.  It only reads route/adapter statistics and opens one
source-bound TCP connection to the guardian's physically resolved address,
which is the same egress mechanism the app uses.

Exit code 0 = PASS, 1 = FAIL.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import struct
import subprocess
import sys
import time
import types
from pathlib import Path

WIFI_INDEX = None  # discovered dynamically at runtime
WIFI_IP = ""  # discovered from active Wi-Fi adapter before any socket is opened
WIFI_DNS = "192.168.1.1"
IP_UNICAST_IF = getattr(socket, "IP_UNICAST_IF", 31)
WIFI_ADAPTER = "Wi-Fi"
TUN_ADAPTER = None  # discovered dynamically at runtime
GUARDIAN_HOST = "vpn.mozilla.org"
SEND_BYTES = 32 * 65536

_RESULTS: list[tuple[str, bool, str]] = []


def _record(name: str, ok: bool, detail: str) -> None:
    _RESULTS.append((name, ok, detail))
    print(json.dumps({"check": name, "ok": bool(ok), "detail": detail}))


def _powershell(script: str) -> str:
    completed = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "powershell failed")
    return completed.stdout.strip()


def _discover_wifi_index() -> int:
    """Dynamically resolve the active Wi-Fi adapter's interface index."""
    output = _powershell(
        "Get-NetAdapter -Name 'Wi-Fi' -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty InterfaceIndex"
    )
    lines = [l.strip() for l in output.splitlines() if l.strip()]
    if not lines:
        raise RuntimeError("no active Wi-Fi adapter found")
    return int(lines[0])


def _discover_tunnel_adapter() -> str:
    """Dynamically resolve the active foreign tunnel adapter name."""
    for name in ("tun0", "singbox_tun"):
        output = _powershell(
            "Get-NetAdapter -Name '%s' -ErrorAction SilentlyContinue | "
            "Select-Object -ExpandProperty Name" % name
        )
        lines = [l.strip() for l in output.splitlines() if l.strip()]
        if lines:
            return lines[0]
    raise RuntimeError("no active tunnel adapter found (tun0/singbox_tun)")


def _discover_wifi_ipv4() -> str:
    """Return the single usable IPv4 literal assigned to the Wi-Fi ifIndex."""
    if WIFI_INDEX is None:
        raise RuntimeError("WIFI_INDEX not discovered yet")
    output = _powershell(
        "Get-NetIPAddress -InterfaceIndex %d -AddressFamily IPv4 | "
        "Select-Object -ExpandProperty IPAddress" % WIFI_INDEX
    )
    candidates: list[str] = []
    for line in output.splitlines():
        text = line.strip()
        if not text:
            continue
        address = ipaddress.IPv4Address(text)
        if (
            address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_unspecified
        ):
            continue
        if text not in candidates:
            candidates.append(text)
    if len(candidates) != 1:
        raise RuntimeError(
            "expected exactly one usable IPv4 on Wi-Fi ifIndex %d, got %r"
            % (WIFI_INDEX, candidates)
        )
    return candidates[0]


def _adapter_bytes(name: str) -> tuple[int, int]:
    out = _powershell(
        "$s=Get-NetAdapterStatistics -Name '%s'; "
        "'{0},{1}' -f $s.SentBytes,$s.ReceivedBytes" % name
    )
    sent, received = out.split(",")
    return int(sent), int(received)


def _snapshot() -> tuple[int, int]:
    return _adapter_bytes(WIFI_ADAPTER)[0], _adapter_bytes(TUN_ADAPTER)[0]


def _snapshot_recv() -> tuple[int, int]:
    return _adapter_bytes(WIFI_ADAPTER)[1], _adapter_bytes(TUN_ADAPTER)[1]


def _decode_unicast_if(value: object) -> int:
    """Decode the Windows IP_UNICAST_IF DWORD returned by getsockopt().

    Winsock setsockopt() takes the interface index as a network-order DWORD,
    but getsockopt() returns it as a host-order DWORD.  The live Windows probe
    confirmed this asymmetry: setsockopt("!I", 10) reads back as b"\\x0a\\x00\\x00\\x00".
    """
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise ValueError(
            "IP_UNICAST_IF read-back has unsupported type %s"
            % type(value).__name__
        )
    raw = bytes(value)
    if len(raw) != 4:
        raise ValueError(
            "IP_UNICAST_IF read-back has %d bytes, expected 4" % len(raw)
        )
    return int.from_bytes(raw, sys.byteorder)


def _set_and_readback_unicast_if(
    sock: socket.socket, interface_index: int
) -> int:
    """Set IP_UNICAST_IF and require the kernel read-back to match."""
    try:
        index = int(interface_index)
        if index <= 0 or index > 0xFFFFFFFF:
            raise ValueError("invalid interface index: %r" % interface_index)
        sock.setsockopt(
            socket.IPPROTO_IP, IP_UNICAST_IF, struct.pack("!I", index)
        )
        raw = sock.getsockopt(socket.IPPROTO_IP, IP_UNICAST_IF, 4)
        decoded = _decode_unicast_if(raw)
    except (OSError, TypeError, ValueError, struct.error) as exc:
        raise RuntimeError(
            "IP_UNICAST_IF set/read-back failed for ifIndex %r: %s"
            % (interface_index, exc)
        ) from exc
    if decoded != index:
        raise RuntimeError(
            "IP_UNICAST_IF read-back mismatch: set %d, read %d"
            % (index, decoded)
        )
    return decoded


def _bind_physical(sock: socket.socket) -> int | None:
    sock.bind((WIFI_IP, 0))
    if sys.platform != "win32":
        return None
    return _set_and_readback_unicast_if(sock, WIFI_INDEX)


def test_unicast_if_readback_offline() -> None:
    """Offline checks for IP_UNICAST_IF set/read-back and source binding."""
    class FakeSocket:
        def __init__(self, readback):
            self.readback = readback
            self.bind_address = None
            self.set_calls = []
            self.get_calls = []

        def bind(self, address):
            self.bind_address = address

        def setsockopt(self, level, option, value):
            self.set_calls.append((level, option, value))

        def getsockopt(self, level, option, size):
            self.get_calls.append((level, option, size))
            return self.readback

    checks = 0
    wifi_index = 10 if WIFI_INDEX is None else WIFI_INDEX
    expected_ip = WIFI_IP or "192.168.1.2"
    fake = FakeSocket(struct.pack("<I", wifi_index))
    assert _set_and_readback_unicast_if(fake, wifi_index) == wifi_index
    assert fake.set_calls == [
        (socket.IPPROTO_IP, IP_UNICAST_IF, struct.pack("!I", wifi_index))
    ]
    assert fake.get_calls == [(socket.IPPROTO_IP, IP_UNICAST_IF, 4)]
    checks += 1

    for readback in (
        struct.pack("<I", wifi_index + 1),
        struct.pack("!I", wifi_index),
        b"\x00\x00\x00",
        "10",
        None,
    ):
        fake = FakeSocket(readback)
        try:
            _set_and_readback_unicast_if(fake, wifi_index)
        except RuntimeError:
            checks += 1
        else:
            raise AssertionError("accepted invalid read-back %r" % (readback,))

    fake = FakeSocket(struct.pack("<I", wifi_index))
    original_platform = sys.platform
    original_ip = globals()["WIFI_IP"]
    original_idx = globals()["WIFI_INDEX"]
    try:
        sys.platform = "win32"
        globals()["WIFI_IP"] = expected_ip
        globals()["WIFI_INDEX"] = wifi_index
        assert _bind_physical(fake) == wifi_index
        assert fake.bind_address == (expected_ip, 0)
    finally:
        sys.platform = original_platform
        globals()["WIFI_IP"] = original_ip
        globals()["WIFI_INDEX"] = original_idx
    checks += 1

    print("offline IP_UNICAST_IF checks passed: %d" % checks)


def _bulk_download(host: str, path: str, expected: int) -> dict:
    """One source-bound TLS download: proves bytes arrived on Wi-Fi."""
    import ssl

    ip = socket.getaddrinfo(host, 443, socket.AF_INET)[0][4][0]
    context = ssl.create_default_context()
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(15.0)
    local = ""
    try:
        unicast_if = _bind_physical(raw)
        raw.connect((ip, 443))
        local = "%s:%d" % raw.getsockname()
        with context.wrap_socket(raw, server_hostname=host) as tls:
            tls.sendall(
                ("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n"
                 % (path, host)).encode()
            )
            received = 0
            while received < expected:
                chunk = tls.recv(65536)
                if not chunk:
                    break
                received += len(chunk)
        return {
            "ip": ip,
            "received": received,
            "local": local,
            "ip_unicast_if": unicast_if,
        }
    finally:
        raw.close()


def _burst(remote_ip: str) -> dict:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    try:
        unicast_if = _bind_physical(sock)
        started = time.monotonic()
        sock.connect((remote_ip, 443))
        elapsed_ms = int((time.monotonic() - started) * 1000)
        payload = b"\x00" * 65536
        sent = 0
        for _ in range(SEND_BYTES // len(payload)):
            try:
                sent += sock.send(payload)
            except OSError:
                break
        return {
            "local": "%s:%d" % sock.getsockname(),
            "connect_ms": elapsed_ms,
            "sent": sent,
            "ip_unicast_if": unicast_if,
        }
    finally:
        sock.close()


def _step_egress() -> bool:
    from perchvpn_windows.tun_state_capture import detect_physical_egress

    egress = detect_physical_egress()
    ok = egress is not None and int(egress[1]) == WIFI_INDEX and egress[0] == WIFI_IP
    _record("detect_physical_egress", ok, repr(egress))

    gateway = _powershell(
        "(Get-NetRoute -InterfaceIndex %d -DestinationPrefix '0.0.0.0/0' | "
        "Select-Object -First 1).NextHop" % WIFI_INDEX
    )
    _record(
        "physical_gateway",
        gateway == WIFI_DNS,
        "ifIndex=%d gateway=%s" % (WIFI_INDEX, gateway),
    )
    return ok and gateway == WIFI_DNS


def _resolve_with_evidence(
    host: str, source_ip: str, interface_index: int, timeout: float
) -> tuple[list[str], float, list[dict], bytes]:
    """Run resolve_ipv4 while recording socket binding and DoH HTTP evidence."""
    from perchvpn_windows import physical_dns

    real_socket = physical_dns.socket
    real_read_doh_body = physical_dns._read_doh_body
    records: list[dict] = []
    response = {"bytes": b""}

    class RecordingSocket(real_socket.socket):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._audit = {
                "kind": "tcp" if self.type == real_socket.SOCK_STREAM else "udp",
                "created": time.monotonic(),
                "bound": None,
                "bound_local": None,
                "connect": None,
                "local": None,
                "ip_unicast_if": None,
                "ip_unicast_if_readback": None,
                "ip_unicast_if_readback_error": None,
                "closed": None,
            }
            records.append(self._audit)

        def bind(self, address):
            self._audit["bound"] = address
            result = super().bind(address)
            try:
                self._audit["bound_local"] = self.getsockname()
            except OSError:
                pass
            return result

        def setsockopt(self, level, option, value):
            result = super().setsockopt(level, option, value)
            if (
                level == real_socket.IPPROTO_IP
                and option == physical_dns.IP_UNICAST_IF
                and isinstance(value, (bytes, bytearray))
                and len(value) == 4
            ):
                self._audit["ip_unicast_if"] = struct.unpack("!I", value)[0]
                try:
                    raw = super().getsockopt(
                        real_socket.IPPROTO_IP,
                        physical_dns.IP_UNICAST_IF,
                        4,
                    )
                    self._audit["ip_unicast_if_readback"] = _decode_unicast_if(raw)
                except (OSError, ValueError) as exc:
                    self._audit["ip_unicast_if_readback_error"] = str(exc)
            return result

        def connect(self, address):
            self._audit["connect"] = address
            result = super().connect(address)
            try:
                self._audit["local"] = self.getsockname()
            except OSError as exc:
                self._audit["local_error"] = str(exc)
            return result

        def close(self):
            if self._audit["closed"] is None:
                self._audit["closed"] = time.monotonic()
            return super().close()

    def factory(*args, **kwargs):
        return RecordingSocket(*args, **kwargs)

    proxy = types.SimpleNamespace(
        AF_INET=real_socket.AF_INET,
        SOCK_STREAM=real_socket.SOCK_STREAM,
        SOCK_DGRAM=real_socket.SOCK_DGRAM,
        IPPROTO_IP=real_socket.IPPROTO_IP,
        inet_ntoa=real_socket.inet_ntoa,
        inet_aton=real_socket.inet_aton,
        timeout=real_socket.timeout,
        socket=factory,
    )

    class Tee:
        def __init__(self, wrapped):
            self._wrapped = wrapped

        def recv(self, size):
            chunk = self._wrapped.recv(size)
            if len(response["bytes"]) < 8192:
                response["bytes"] += chunk[: 8192 - len(response["bytes"])]
            return chunk

    def read_doh_body(tls, limit=physical_dns._DOH_MAX_BYTES):
        return real_read_doh_body(Tee(tls), limit)

    started = time.monotonic()
    physical_dns.socket = proxy
    physical_dns._read_doh_body = read_doh_body
    try:
        addresses = physical_dns.resolve_ipv4(
            host,
            [WIFI_DNS],
            source_ip=source_ip,
            interface_index=interface_index,
            timeout=timeout,
        )
    finally:
        elapsed = time.monotonic() - started
        physical_dns._read_doh_body = real_read_doh_body
        physical_dns.socket = real_socket
    return addresses, elapsed, records, response["bytes"]


def _step_dns() -> tuple[bool, str]:
    from perchvpn_windows import tun_helper
    from perchvpn_windows.physical_dns import PhysicalDnsError

    route = tun_helper.find_route_interface(WIFI_DNS)
    _record(
        "dns_server_route",
        route == WIFI_INDEX,
        "%s -> if%s" % (WIFI_DNS, route),
    )
    addresses: list[str] = []
    records: list[dict] = []
    response = b""
    elapsed = 0.0
    doh_binding_ok = True
    try:
        addresses, elapsed, records, response = _resolve_with_evidence(
            GUARDIAN_HOST, WIFI_IP, WIFI_INDEX, 3.0
        )
        detail = "%s -> %s via %s" % (
            GUARDIAN_HOST, ",".join(addresses), WIFI_DNS
        )
        ok = bool(addresses)
    except (PhysicalDnsError, OSError) as exc:
        detail = "%s via %s failed: %s" % (GUARDIAN_HOST, WIFI_DNS, exc)
        ok = False
    _record("physical_dns", ok, detail)

    tcp_records = [
        record for record in records
        if record["kind"] == "tcp" and record.get("connect")
    ]
    endpoints = [record["connect"][0] for record in tcp_records]
    status_line = ""
    if response:
        status_line = response.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    _record(
        "doh_endpoint",
        bool(endpoints),
        "endpoint=%s attempts=%s" % (endpoints[-1] if endpoints else "-", endpoints),
    )
    _record(
        "doh_http_status",
        status_line.startswith("HTTP/1.1 200")
        or status_line.startswith("HTTP/1.0 200"),
        status_line or "no DoH response captured",
    )
    if tcp_records:
        record = tcp_records[-1]
        binding = "bind=%s local=%s IP_UNICAST_IF=%s readback=%s" % (
            record.get("bound"),
            record.get("local"),
            record.get("ip_unicast_if"),
            record.get("ip_unicast_if_readback")
            or record.get("ip_unicast_if_readback_error"),
        )
        binding_ok = (
            record.get("local") is not None
            and record["local"][0] == WIFI_IP
            and record.get("ip_unicast_if") == WIFI_INDEX
            and record.get("ip_unicast_if_readback") == WIFI_INDEX
        )
        doh_binding_ok = binding_ok
    else:
        binding = "no DoH TCP socket"
        binding_ok = False
    _record("doh_source_binding", binding_ok, binding)
    _record("doh_elapsed_ms", ok, "%.0f" % (elapsed * 1000.0))

    try:
        socket.create_connection((WIFI_DNS, 53), timeout=3.0).close()
        _record("direct_dns_tcp53", True, "%s:53 connect allowed" % WIFI_DNS)
    except OSError as exc:
        _record("direct_dns_tcp53", False, "%s:53 connect refused: %s" % (WIFI_DNS, exc))

    fallback = ""
    try:
        fallback = socket.getaddrinfo(GUARDIAN_HOST, 443, socket.AF_INET)[0][4][0]
    except OSError as exc:
        _record("system_resolver", False, str(exc))
    else:
        _record(
            "system_resolver",
            True,
            "%s -> %s (system/PATTN DNS, used only for the handshake target)"
            % (GUARDIAN_HOST, fallback),
        )
    return ok and doh_binding_ok, (addresses[0] if addresses else fallback)


def _step_handshake(remote_ip: str) -> bool:
    wifi0, tun0 = _snapshot()
    time.sleep(0.5)
    wifi1, tun1 = _snapshot()
    noise_wifi, noise_tun = wifi1 - wifi0, tun1 - tun0
    _record("idle_noise", True, "wifi=%d tun=%d" % (noise_wifi, noise_tun))

    wifi0, tun0 = _snapshot()
    try:
        result = _burst(remote_ip)
    except (OSError, RuntimeError) as exc:
        result = None
        _record(
            "source_bound_handshake",
            False,
            "remote=%s connect failed: %s" % (remote_ip, exc),
        )
    else:
        _record(
            "source_bound_handshake",
            result["local"].startswith(WIFI_IP + ":") and result["sent"] > 0,
            "local=%s IP_UNICAST_IF=%s connect_ms=%d sent=%d" % (
                result["local"], result["ip_unicast_if"],
                result["connect_ms"], result["sent"],
            ),
        )
    time.sleep(0.5)
    wifi1, tun1 = _snapshot()
    wifi_delta, tun_delta = wifi1 - wifi0, tun1 - tun0
    _record(
        "send_counters",
        True,
        "wifi_delta=%d tun_delta=%d (idle noise wifi=%d tun=%d)"
        % (wifi_delta, tun_delta, noise_wifi, noise_tun),
    )

    # Decisive receive-side proof: one source-bound 1 MiB TLS download must
    # arrive on the Wi-Fi NIC, while the tunnel stays at background noise.
    wifi0, tun0 = _snapshot_recv()
    time.sleep(1.0)
    wifi_idle, tun_idle = _snapshot_recv()
    time.sleep(0.0)
    try:
        bulk = _bulk_download(
            "speed.cloudflare.com", "/__down?bytes=1048576", 1048576
        )
    except (OSError, RuntimeError) as exc:
        _record("bulk_recv_counters", False, "source-bound download failed: %s" % exc)
        return False
    time.sleep(0.5)
    wifi1, tun1 = _snapshot_recv()
    wifi_recv = wifi1 - wifi0
    tun_recv = tun1 - tun0
    # Attribution: the payload can only arrive on the NIC that carried it.
    # The TUN's own deltas are other applications' traffic and need not be 0.
    payload = bulk["received"]
    bulk_ok = (
        payload >= 800000
        and wifi_recv >= int(payload * 0.8)
        and tun_recv < int(payload * 0.5)
    )
    _record(
        "bulk_recv_counters",
        bulk_ok,
        "remote=%s local=%s IP_UNICAST_IF=%s recv=%d wifi_recv=%d tun_recv=%d "
        "(1s idle wifi=%d tun=%d)"
        % (
            bulk["ip"], bulk["local"], bulk["ip_unicast_if"],
            bulk["received"], wifi_recv, tun_recv,
            wifi_idle - wifi0, tun_idle - tun0,
        ),
    )
    return bulk_ok


def _live_unicast_if_probe() -> int:
    """Set and read back IP_UNICAST_IF on a real socket; no connect/send."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError as exc:
        print(
            json.dumps(
                {
                    "check": "ip_unicast_if_live",
                    "ok": False,
                    "detail": "socket creation failed: %s" % exc,
                    "ip_unicast_if_readback": None,
                }
            )
        )
        return 1
    try:
        readback = _set_and_readback_unicast_if(sock, WIFI_INDEX)
    except (OSError, RuntimeError) as exc:
        print(
            json.dumps(
                {
                    "check": "ip_unicast_if_live",
                    "ok": False,
                    "detail": str(exc),
                    "ip_unicast_if_readback": None,
                }
            )
        )
        return 1
    finally:
        sock.close()
    ok = readback == WIFI_INDEX
    print(
        json.dumps(
            {
                "check": "ip_unicast_if_live",
                "ok": ok,
                "detail": "setsockopt/getsockopt ifIndex=%d" % WIFI_INDEX,
                "ip_unicast_if_readback": readback,
            }
        )
    )
    return 0 if ok else 1


def main() -> int:
    global WIFI_IP, WIFI_INDEX, TUN_ADAPTER
    if sys.platform != "win32":
        print(json.dumps({"error": "live preflight requires Windows"}))
        return 1
    repo_src = Path(__file__).resolve().parents[1] / "src"
    if str(repo_src) not in sys.path:
        sys.path.insert(0, str(repo_src))

    try:
        WIFI_INDEX = _discover_wifi_index()
        TUN_ADAPTER = _discover_tunnel_adapter()
        _record("adapter_discovery", True, "wifi_ifIndex=%d tun_adapter=%s" % (WIFI_INDEX, TUN_ADAPTER))
    except (OSError, RuntimeError, ValueError) as exc:
        _record("adapter_discovery", False, str(exc))
        return 1

    try:
        WIFI_IP = _discover_wifi_ipv4()
    except (OSError, RuntimeError, ValueError) as exc:
        _record("wifi_ipv4", False, str(exc))
        return 1
    _record("wifi_ipv4", True, "ifIndex=%d ip=%s" % (WIFI_INDEX, WIFI_IP))

    egress_ok = _step_egress()
    dns_ok, remote_ip = _step_dns() if egress_ok else (False, "")
    counters_ok = _step_handshake(remote_ip) if remote_ip else False
    passed = egress_ok and dns_ok and counters_ok
    print(
        json.dumps(
            {
                "tcp_egress": "PASS" if (counters_ok and egress_ok) else "FAIL",
                "physical_dns": "PASS" if dns_ok else "BLOCKED",
                "result": "PASS" if passed else "FAIL",
            }
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    if "--unicast-if-only" in sys.argv:
        try:
            WIFI_INDEX = _discover_wifi_index()
            _record("adapter_discovery", True, "wifi_ifIndex=%d" % WIFI_INDEX)
        except (OSError, RuntimeError, ValueError) as exc:
            print(json.dumps({"check": "adapter_discovery", "ok": False, "detail": str(exc)}))
            sys.exit(1)
        sys.exit(_live_unicast_if_probe())
    sys.exit(main())
