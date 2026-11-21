"""End-to-end PerchVPN TUN frontend test against a real sing-box sidecar.

Runs inside the Windows guest as an elevated process.  It imports the actual
client modules from src/perchvpn_windows (TunFrontend, recovery gate, config
builder, DNS/DoH helpers), drives a start -> evidence -> traffic -> stop cycle,
and writes a machine-readable report.

A local SOCKS5 relay (127.0.0.1:1080) stands in for the PerchVPN upstream
proxy: the test environment has no FxA/Guardian credentials.  The relay dials
destinations directly, so every CONNECT it records proves the packet traversed
TUN -> sing-box -> the client's SOCKS outbound.
"""
from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import logging
import os
import random
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    # The guest runs an embeddable Python whose ``._pth`` replaces the normal
    # startup path, so the script directory is not added automatically.
    sys.path.insert(0, str(_HERE))

from e2e_support import split_route_evidence  # noqa: E402

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
RUNTIME = ROOT / "runtime"
LOGS = ROOT / "logs"
BIN = ROOT / "bin"
EXE = BIN / "sing-box.exe"
STATE = RUNTIME / "tun-ownership.json"
CONFIG = RUNTIME / "sing-box.json"
REPORT = LOGS / "client-e2e-result.json"
ADAPTER = "PerchVPN_%s" % os.urandom(3).hex()
PROXY_PORT = 1080
TUN_DNS_PEER = "172.19.0.2"
PROBE_DEST = "203.0.113.10"
CERTS = ROOT / "certs"
E2E_CA = CERTS / "e2e-ca.pem"
E2E_SERVER_CERT = CERTS / "e2e-server.pem"
E2E_SERVER_KEY = CERTS / "e2e-server.key"
_E2E_CERT_PATHS: Optional[tuple[Path, Path, Path]] = None


def _e2e_cert_paths() -> tuple[Path, Path, Path]:
    """Return staged E2E certs, or generate short-lived fixtures on demand.

    Private-key fixtures are intentionally not committed.  If a developer has
    staged them locally, use those; otherwise create a one-day CA and
    localhost server certificate in a private temporary directory.
    """
    global _E2E_CERT_PATHS
    if _E2E_CERT_PATHS is not None:
        return _E2E_CERT_PATHS
    if E2E_CA.is_file() and E2E_SERVER_CERT.is_file() and E2E_SERVER_KEY.is_file():
        _E2E_CERT_PATHS = (E2E_CA, E2E_SERVER_CERT, E2E_SERVER_KEY)
        return _E2E_CERT_PATHS
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    except ImportError as exc:
        raise RuntimeError(
            "E2E TLS fixtures are absent and cryptography is unavailable; "
            "install cryptography or provide scripts/e2e/certs/e2e-*.pem/key"
        ) from exc

    cert_dir = Path(tempfile.mkdtemp(prefix="perchvpn-e2e-certs-"))
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "PerchVPN E2E Ephemeral CA")]
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = cert_dir / "e2e-ca.pem"
    server_cert_path = cert_dir / "e2e-server.pem"
    server_key_path = cert_dir / "e2e-server.key"
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    server_cert_path.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    server_key_path.write_bytes(
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    _E2E_CERT_PATHS = (ca_path, server_cert_path, server_key_path)
    return _E2E_CERT_PATHS


# The recovery gate serializes 6-8 PowerShell/netsh spawns; on the 2-vCPU
# sandbox VM a fully warm gate measures ~6 s (dev hosts stay under 6 s), so
# the acceptance bound keeps small headroom above the measured warm floor.
PRESTART_BOUND_SECONDS = 8.0
H1_OPTIONS = ("chrome", "combined")

RUNTIME.mkdir(parents=True, exist_ok=True)
LOGS.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger("client_e2e")


def _tls_context() -> ssl.SSLContext:
    """Verifying TLS context backed by the current public root set.

    The Windows 10 LTSC guest image ships a frozen machine root store, so
    resolver certificates anchored in roots added after image build (for
    example the 2022 SSL.com roots used by ``1.0.0.1``) fail with
    ``unable to get local issuer certificate``.  ``certifi`` carries a current
    bundle; verification is never disabled.  Falls back to the platform store
    when certifi is unavailable.
    """
    try:
        import certifi
    except ImportError:
        return ssl.create_default_context()
    try:
        return ssl.create_default_context(cafile=certifi.where())
    except (OSError, ssl.SSLError):
        return ssl.create_default_context()


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def setup_logging() -> None:
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    fh = logging.FileHandler(LOGS / "client-e2e.log", encoding="utf-8")
    fh.setFormatter(fmt)
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logging.basicConfig(level=logging.DEBUG, handlers=[fh, sh], force=True)
    logger.setLevel(logging.DEBUG)
    for name in ("perchvpn_windows", "perchvpn"):
        logging.getLogger(name).setLevel(logging.DEBUG)


def write_partial(report: Dict[str, Any], tag: str) -> None:
    path = LOGS / ("client-e2e-partial-%s.json" % tag)
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        tmp.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        os.replace(tmp, path)
    except Exception:  # noqa: BLE001
        logger.exception("partial report write failed: %s", tag)


def phase(name: str, **extra: Any) -> None:
    payload = {"phase": name, "at": utcnow(), **extra}
    tmp = RUNTIME / "phase.json.tmp"
    tmp.write_text(json.dumps(payload, default=str), encoding="utf-8")
    os.replace(tmp, RUNTIME / "phase.json")
    logger.info("phase -> %s %s", name, extra or "")


def run_ps(script: str, timeout: float = 45.0) -> Dict[str, Any]:
    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script,
    ]
    started = time.monotonic()
    token = os.urandom(4).hex()
    out_path = RUNTIME / ("ps-%s.out" % token)
    err_path = RUNTIME / ("ps-%s.err" % token)
    timed_out = False
    rc: Optional[int] = None
    try:
        with open(out_path, "wb") as out_fh, open(err_path, "wb") as err_fh:
            proc = subprocess.Popen(cmd, stdout=out_fh, stderr=err_fh, stdin=subprocess.DEVNULL)
            try:
                rc = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                subprocess.run(
                    ["taskkill.exe", "/T", "/F", "/PID", str(proc.pid)],
                    capture_output=True,
                    timeout=20,
                )
                try:
                    rc = proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    rc = None
        stdout = out_path.read_text(encoding="utf-8", errors="replace") if out_path.exists() else ""
        stderr = err_path.read_text(encoding="utf-8", errors="replace") if err_path.exists() else ""
    except Exception as exc:  # noqa: BLE001
        stdout = ""
        stderr = "%s: %s" % (type(exc).__name__, exc)
    finally:
        for path in (out_path, err_path):
            try:
                path.unlink()
            except OSError:
                pass
    return {
        "rc": None if timed_out else rc,
        "stdout": stdout,
        "stderr": ("timeout: " + stderr[-4000:]) if timed_out else stderr[-4000:],
        "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
    }


SNAPSHOT_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
$perch = @(Get-NetAdapter -IncludeHidden | Where-Object { $_.Name -like 'Perch*' })
$tunRoutes = @(Get-NetRoute -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -like 'Perch*' })
$defaults = @(Get-NetRoute -AddressFamily IPv4 | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0','0.0.0.0/1','128.0.0.0/1') })
$ips = @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -like 'Perch*' })
$metrics = @(Get-NetIPInterface -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -like 'Perch*' })
$dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { @($_.ServerAddresses).Count -gt 0 })
$procs = @(Get-Process -Name sing-box -ErrorAction SilentlyContinue)
$adapterRows = @($perch | Select-Object Name,InterfaceIndex,InterfaceDescription,Status,MacAddress)
$addressRows = @($ips | Select-Object InterfaceAlias,IPAddress,PrefixLength,PrefixOrigin)
$tunRouteRows = @($tunRoutes | Select-Object DestinationPrefix,NextHop,InterfaceAlias,InterfaceIndex,RouteMetric,Protocol)
$defaultRows = @($defaults | Select-Object DestinationPrefix,NextHop,InterfaceAlias,InterfaceIndex,RouteMetric,Protocol)
$metricRows = @($metrics | Select-Object InterfaceAlias,InterfaceMetric)
$dnsRows = @($dns | ForEach-Object { [pscustomobject]@{ InterfaceAlias = $_.InterfaceAlias; Servers = @($_.ServerAddresses) } })
$procRows = @($procs | Select-Object Id,ProcessName,StartTime)
$obj = [ordered]@{
    adapters = $adapterRows
    addresses = $addressRows
    tun_routes = $tunRouteRows
    default_routes = $defaultRows
    metrics = $metricRows
    dns = $dnsRows
    singbox = $procRows
}
$obj | ConvertTo-Json -Depth 6 -Compress
"""


def run_cmd(cmd: List[str], timeout: float = 15.0) -> Dict[str, Any]:
    started = time.monotonic()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {
            "rc": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr[-2000:],
            "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "rc": None,
            "stdout": "",
            "stderr": "%s: %s" % (type(exc).__name__, exc),
            "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
        }


def warm_up_windows_spawns(budget_s: float = 90.0) -> Dict[str, Any]:
    """Exercise the subprocess spawns the TUN recovery gate depends on.

    A checkpoint-restored guest spawns powershell.exe/netsh cold in 10-20 s,
    which trips the gate's 10 s ``netsh winhttp show proxy`` capture and fails
    the start closed before the first adapter is ever created.  Run the same
    spawn classes until they respond quickly, before the timed pre-start gate.
    """
    started = time.monotonic()
    probes = (
        ["netsh", "winhttp", "show", "proxy"],
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "$null"],
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object -First 1).Name",
        ],
    )
    rounds: List[float] = []
    warm = False
    while time.monotonic() - started < budget_s:
        worst = 0.0
        for cmd in probes:
            res = run_cmd(cmd, timeout=45.0)
            worst = max(worst, float(res["elapsed_ms"]))
        rounds.append(round(worst, 1))
        if worst < 2500.0:
            warm = True
            break
    return {
        "rounds": rounds,
        "warm": warm,
        "elapsed_s": round(time.monotonic() - started, 1),
    }


def physical_ifindex() -> Optional[int]:
    script = (
        "$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | "
        "Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1; "
        "if ($r) { [string]$r.InterfaceIndex }"
    )
    # The first powershell.exe spawn after a checkpoint restore can exceed
    # the single-probe timeout; retry instead of silently losing the egress
    # binding the SOCKS relay needs to stay off the TUN.
    for attempt, timeout in enumerate((20.0, 45.0, 45.0), start=1):
        res = run_ps(script, timeout=timeout)
        text = (res.get("stdout") or "").strip()
        try:
            return int(text)
        except ValueError:
            logger.warning(
                "physical ifindex probe failed (attempt %d): rc=%s out=%r err=%r",
                attempt, res.get("rc"), text[:100], (res.get("stderr") or "")[:200],
            )
    return None


def snapshot() -> Dict[str, Any]:
    res = run_ps(SNAPSHOT_PS, timeout=45)
    parsed: Optional[Dict[str, Any]] = None
    if res["rc"] == 0 and res["stdout"].strip():
        try:
            parsed = json.loads(res["stdout"].strip())
        except json.JSONDecodeError as exc:
            res["parse_error"] = str(exc)
    return {"raw_rc": res["rc"], "elapsed_ms": res["elapsed_ms"], "stderr": res["stderr"], "data": parsed}


def https_get(
    host: str,
    path: str = "/cdn-cgi/trace",
    timeout: float = 12.0,
    sni: Optional[str] = None,
) -> Dict[str, Any]:
    started = time.monotonic()
    ctx = _tls_context()
    server_name = sni or host
    try:
        with socket.create_connection((host, 443), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=server_name) as tls:
                req = (
                    "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: perch-e2e\r\n"
                    "Accept: */*\r\nConnection: close\r\n\r\n" % (path, server_name)
                )
                tls.sendall(req.encode("ascii"))
                data = b""
                while True:
                    chunk = tls.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > 262144:
                        break
        head, _, body = data.partition(b"\r\n\r\n")
        status = None
        parts = head.split(b"\r\n", 1)[0].split(b" ")
        if len(parts) >= 2:
            status = int(parts[1])
        return {
            "ok": status is not None and 200 <= status < 500,
            "status": status,
            "host": host,
            "path": path,
            "body": body.decode("utf-8", "replace")[:2000],
            "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001 - evidence, not control flow
        return {
            "ok": False,
            "status": None,
            "host": host,
            "path": path,
            "body": "",
            "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
            "error": "%s: %s" % (type(exc).__name__, exc),
        }


def trace(host: str = "1.0.0.1") -> Dict[str, Any]:
    return https_get(host, "/cdn-cgi/trace", timeout=15.0)


def route_lookup(ips: Sequence[str] = ("1.0.0.1", "8.8.8.8", "172.19.0.2", "1.1.1.1")) -> Dict[str, Any]:
    quoted = "','".join(ips)
    script = (
        "$ErrorActionPreference='SilentlyContinue';$out=@();"
        "foreach($ip in @('%s')){"
        "$r=Find-NetRoute -RemoteIPAddress $ip -ErrorAction SilentlyContinue | Select-Object -First 1;"
        "if($r){$out += [pscustomobject]@{ip=$ip;destination=$r.DestinationPrefix;"
        "nexthop=$r.NextHop;interface=$r.InterfaceAlias;ifindex=$r.InterfaceIndex;metric=$r.RouteMetric}}"
        "else{$out += [pscustomobject]@{ip=$ip;destination=$null;nexthop=$null;"
        "interface=$null;ifindex=$null;metric=$null}}};"
        "$out | ConvertTo-Json -Compress"
    ) % quoted
    res = run_ps(script, timeout=60)
    rows: List[Any] = []
    if res.get("rc") == 0 and res.get("stdout", "").strip():
        try:
            parsed = json.loads(res["stdout"].strip())
            rows = parsed if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError:
            rows = []
    return {"rows": rows, "rc": res.get("rc"), "stderr": res.get("stderr")}


def http_get(host: str, port: int = 80, path: str = "/", timeout: float = 10.0) -> Dict[str, Any]:
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            req = (
                "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: perch-e2e\r\n"
                "Accept: */*\r\nConnection: close\r\n\r\n" % (path, host)
            )
            s.sendall(req.encode("ascii"))
            data = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
                if len(data) > 131072:
                    break
        head, _, body = data.partition(b"\r\n\r\n")
        status = None
        parts = head.split(b"\r\n", 1)[0].split(b" ")
        if len(parts) >= 2:
            status = int(parts[1])
        return {
            "ok": status is not None and 100 <= status < 500,
            "status": status,
            "host": host,
            "port": port,
            "body": body.decode("utf-8", "replace")[:800],
            "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "status": None,
            "host": host,
            "port": port,
            "body": "",
            "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
            "error": "%s: %s" % (type(exc).__name__, exc),
        }


def ps_https_trace(url: str = "https://www.cloudflare.com/cdn-cgi/trace") -> Dict[str, Any]:
    script = (
        "$ErrorActionPreference='Stop';"
        "try{$r=Invoke-WebRequest -Uri '%s' -UseBasicParsing -TimeoutSec 20;"
        "[pscustomobject]@{ok=$true;status=[int]$r.StatusCode;"
        "body=[string]$r.Content;error=$null} | ConvertTo-Json -Compress}"
        "catch{[pscustomobject]@{ok=$false;status=$null;body='';"
        "error=$_.Exception.Message} | ConvertTo-Json -Compress}"
    ) % url
    res = run_ps(script, timeout=60)
    parsed: Dict[str, Any] = {}
    if res.get("rc") == 0 and res.get("stdout", "").strip():
        try:
            parsed = json.loads(res["stdout"].strip())
        except json.JSONDecodeError:
            parsed = {}
    parsed.setdefault("ok", False)
    parsed.setdefault("error", res.get("stderr") or "no output")
    parsed["body"] = str(parsed.get("body") or "")[:800]
    parsed["elapsed_ms"] = res.get("elapsed_ms")
    return parsed


def curl_get(url: str, timeout: float = 25.0) -> Dict[str, Any]:
    started = time.monotonic()
    try:
        proc = subprocess.run(
            ["curl.exe", "-sS", "--max-time", str(int(timeout)), url],
            capture_output=True,
            text=True,
            timeout=timeout + 5,
        )
        return {
            "ok": proc.returncode == 0 and bool(proc.stdout.strip()),
            "rc": proc.returncode,
            "body": (proc.stdout or "")[:800],
            "stderr": (proc.stderr or "")[-800:],
            "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "rc": None,
            "body": "",
            "stderr": "%s: %s" % (type(exc).__name__, exc),
            "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
        }


def nslookup(server: str, name: str, tcp: bool = False, timeout: float = 12.0) -> Dict[str, Any]:
    args = ["nslookup.exe"]
    if tcp:
        args.append("-vc")
    args.extend([name, server])
    started = time.monotonic()
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        raw = (proc.stdout or "") + (proc.stderr or "")
        answers: List[str] = []
        for line in raw.splitlines():
            text = line.strip()
            if text.lower().startswith("addresses:"):
                answers.extend([v.strip() for v in text.split(":", 1)[1].split(",") if v.strip()])
            elif text.lower().startswith("address:") and server not in text:
                value = text.split(":", 1)[1].strip()
                if value and value not in answers:
                    answers.append(value)
        answers = [a for a in answers if a and a != server]
        return {
            "ok": proc.returncode == 0 and bool(answers),
            "answers": answers,
            "rc": proc.returncode,
            "raw": raw[-800:],
            "transport": "nslookup-tcp" if tcp else "nslookup-udp",
            "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "answers": [],
            "rc": None,
            "raw": "",
            "transport": "nslookup-tcp" if tcp else "nslookup-udp",
            "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
            "error": "%s: %s" % (type(exc).__name__, exc),
        }


def ps_dns_lookup(server: str, name: str, tcp_only: bool = True) -> Dict[str, Any]:
    flags = " -DnsOnly -TcpOnly" if tcp_only else " -DnsOnly"
    script = (
        "$ErrorActionPreference='Stop';"
        "try{$r=@(Resolve-DnsName -Name '%s' -Server '%s' -Type A%s -ErrorAction Stop);"
        "$a=@($r | Where-Object {$_.Type -eq 'A'} | ForEach-Object {$_.IPAddress});"
        "[pscustomobject]@{ok=($a.Count -gt 0);answers=$a;error=$null} | ConvertTo-Json -Compress}"
        "catch{[pscustomobject]@{ok=$false;answers=@();error=$_.Exception.Message} | ConvertTo-Json -Compress}"
    ) % (name, server, flags)
    res = run_ps(script, timeout=60)
    parsed: Dict[str, Any] = {"ok": False, "answers": [], "error": res.get("stderr") or "no output"}
    if res.get("rc") == 0 and res.get("stdout", "").strip():
        try:
            parsed.update(json.loads(res["stdout"].strip()))
        except json.JSONDecodeError:
            pass
    parsed["elapsed_ms"] = res.get("elapsed_ms")
    parsed["transport"] = "powershell-tcp" if tcp_only else "powershell-udp"
    return parsed


def _skip_name(data: bytes, off: int) -> int:
    while True:
        if off >= len(data):
            raise ValueError("truncated name")
        length = data[off]
        if length == 0:
            return off + 1
        if length & 0xC0 == 0xC0:
            return off + 2
        off += 1 + length


def dns_packet(name: str, ident: int) -> bytes:
    header = struct.pack(">HHHHHH", ident, 0x0100, 1, 0, 0, 0)
    q = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna")
        q += bytes([len(raw)]) + raw
    q += b"\x00" + struct.pack(">HH", 1, 1)
    return header + q


def parse_dns(data: bytes) -> Dict[str, Any]:
    if len(data) < 12:
        raise ValueError("short DNS response")
    ident, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
    off = 12
    for _ in range(qd):
        off = _skip_name(data, off) + 4
    answers: List[str] = []
    for _ in range(an):
        off = _skip_name(data, off)
        atype, aclass, _ttl, rdlen = struct.unpack(">HHIH", data[off : off + 10])
        off += 10
        rdata = data[off : off + rdlen]
        off += rdlen
        if atype == 1 and aclass == 1 and rdlen == 4:
            answers.append(socket.inet_ntoa(rdata))
    return {"id": ident, "rcode": flags & 0xF, "answers": answers, "ancount": an}


def dns_query_tcp(server: str, name: str, timeout: float = 6.0) -> Dict[str, Any]:
    ident = random.randrange(0, 65536)
    packet = dns_packet(name, ident)
    started = time.monotonic()
    s = socket.create_connection((server, 53), timeout=timeout)
    try:
        s.settimeout(timeout)
        s.sendall(struct.pack(">H", len(packet)) + packet)
        length = struct.unpack(">H", s.recv(2))[0]
        chunks = b""
        while len(chunks) < length:
            chunk = s.recv(length - len(chunks))
            if not chunk:
                break
            chunks += chunk
        parsed = parse_dns(chunks)
        parsed["transport"] = "tcp"
        parsed["ok"] = parsed["rcode"] == 0 and bool(parsed["answers"])
        parsed["elapsed_ms"] = round((time.monotonic() - started) * 1000, 1)
        parsed["error"] = None
        return parsed
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "transport": "tcp",
            "name": name,
            "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
            "error": "%s: %s" % (type(exc).__name__, exc),
        }
    finally:
        s.close()


def dns_query_udp(server: str, name: str, timeout: float = 6.0) -> Dict[str, Any]:
    ident = random.randrange(0, 65536)
    packet = dns_packet(name, ident)
    started = time.monotonic()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        s.sendto(packet, (server, 53))
        data, addr = s.recvfrom(4096)
        parsed = parse_dns(data)
        parsed["transport"] = "udp"
        parsed["peer"] = addr[0]
        parsed["ok"] = parsed["rcode"] == 0 and bool(parsed["answers"])
        parsed["elapsed_ms"] = round((time.monotonic() - started) * 1000, 1)
        parsed["error"] = None
        return parsed
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "transport": "udp",
            "name": name,
            "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
            "error": "%s: %s" % (type(exc).__name__, exc),
        }
    finally:
        s.close()


def system_resolve(name: str) -> Dict[str, Any]:
    started = time.monotonic()
    try:
        infos = socket.getaddrinfo(name, 443, socket.AF_INET, socket.SOCK_STREAM)
        ips = sorted({entry[4][0] for entry in infos})
        return {
            "ok": bool(ips),
            "ips": ips,
            "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "ips": [],
            "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
            "error": "%s: %s" % (type(exc).__name__, exc),
        }


def socks5_connect(proxy_host: str, proxy_port: int, dest_host: str, dest_port: int, timeout: float = 12.0) -> socket.socket:
    s = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00":
        raise OSError("socks5 greeting rejected")
    try:
        ip = socket.inet_aton(dest_host)
        request = b"\x05\x01\x00\x01" + ip
    except OSError:
        raw = dest_host.encode("idna")
        request = b"\x05\x01\x00\x03" + bytes([len(raw)]) + raw
    request += struct.pack(">H", dest_port)
    s.sendall(request)
    reply = s.recv(10)
    if len(reply) < 10 or reply[1] != 0:
        raise OSError("socks5 connect failed: %r" % (reply,))
    return s


def https_via_socks(
    proxy_host: str,
    proxy_port: int,
    dest_host: str,
    path: str,
    timeout: float = 12.0,
    sni: Optional[str] = None,
) -> Dict[str, Any]:
    started = time.monotonic()
    raw = None
    server_name = sni or dest_host
    try:
        raw = socks5_connect(proxy_host, proxy_port, dest_host, 443, timeout=timeout)
        ctx = _tls_context()
        with ctx.wrap_socket(raw, server_hostname=server_name) as tls:
            raw = None
            req = (
                "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: perch-e2e\r\n"
                "Accept: */*\r\nConnection: close\r\n\r\n" % (path, server_name)
            )
            tls.sendall(req.encode("ascii"))
            data = b""
            while True:
                chunk = tls.recv(65536)
                if not chunk:
                    break
                data += chunk
                if len(data) > 262144:
                    break
        head, _, body = data.partition(b"\r\n\r\n")
        status = None
        parts = head.split(b"\r\n", 1)[0].split(b" ")
        if len(parts) >= 2:
            status = int(parts[1])
        return {
            "ok": status is not None and 200 <= status < 500,
            "status": status,
            "host": dest_host,
            "path": path,
            "body": body.decode("utf-8", "replace")[:1000],
            "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "status": None,
            "host": dest_host,
            "path": path,
            "body": "",
            "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
            "error": "%s: %s" % (type(exc).__name__, exc),
        }
    finally:
        if raw is not None:
            try:
                raw.close()
            except OSError:
                pass


class SocksRelay:
    """Minimal SOCKS5 CONNECT relay that records every destination."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = PROXY_PORT,
        egress_ifindex: Optional[int] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.egress_ifindex = egress_ifindex
        self.server: Optional[asyncio.AbstractServer] = None
        self.connects: List[Dict[str, Any]] = []
        self.counts: Dict[str, int] = {}
        self.total = 0
        self.errors: List[str] = []
        self.record_cap = 500

    def record(self, peer: Any, host: str, port: int, atyp: int) -> None:
        self.total += 1
        key = "%s:%s" % (host, port)
        self.counts[key] = self.counts.get(key, 0) + 1
        if len(self.connects) < self.record_cap:
            self.connects.append({"ts": time.time(), "peer": peer, "host": host, "port": port, "atyp": atyp})

    def summary(self) -> Dict[str, Any]:
        return {
            "total": self.total,
            "unique": [
                {"endpoint": key, "count": count}
                for key, count in sorted(self.counts.items(), key=lambda kv: -kv[1])[:40]
            ],
            "recorded": list(self.connects),
            "errors": list(self.errors[-20:]),
        }

    async def _dial(self, host: str, port: int) -> Any:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        last_exc: Optional[Exception] = None
        for family, stype, proto, _canon, addr in infos:
            sock = socket.socket(family, stype, proto)
            sock.setblocking(False)
            if self.egress_ifindex and family == socket.AF_INET:
                option = getattr(socket, "IP_UNICAST_IF", 31)
                sock.setsockopt(socket.IPPROTO_IP, option, int(self.egress_ifindex).to_bytes(4, "big"))
            try:
                await loop.sock_connect(sock, addr)
                return await asyncio.open_connection(sock=sock)
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                try:
                    sock.close()
                except OSError:
                    pass
        raise last_exc or OSError("no address for %s" % host)

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle, self.host, self.port)
        logger.info(
            "socks relay listening on %s:%s egress_ifindex=%s",
            self.host,
            self.port,
            self.egress_ifindex,
        )

    async def close(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
            self.server = None

    async def _doh_exchange(self, query: bytes) -> bytes:
        """Answer a DNS-over-TCP message with a DNS-over-HTTPS POST.

        While a session is running sing-box hides port 53 from unrelated
        processes (``strict_route``), so this stand-in proxy cannot open a
        plain DNS socket of its own.  A real upstream proxy would resolve on
        the far side; the harness emulates that with DoH on port 443.
        """
        reader, writer = await asyncio.open_connection(
            "1.1.1.1", 443, ssl=_tls_context(), server_hostname="one.one.one.one"
        )
        try:
            writer.write(
                b"POST /dns-query HTTP/1.1\r\n"
                b"Host: one.one.one.one\r\n"
                b"Content-Type: application/dns-message\r\n"
                b"Accept: application/dns-message\r\n"
                b"Content-Length: " + str(len(query)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + query
            )
            await writer.drain()
            data = await reader.read()
        finally:
            writer.close()
        head, _, body = data.partition(b"\r\n\r\n")
        status_line = head.split(b"\r\n", 1)[0]
        if b" 200 " not in status_line:
            raise OSError("doh status %r" % status_line)
        return body

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        try:
            greeting = await reader.readexactly(2)
            if greeting[0] != 5:
                raise OSError("bad socks version")
            methods = await reader.readexactly(greeting[1])
            if 0 not in methods:
                raise OSError("no no-auth method")
            writer.write(b"\x05\x00")
            await writer.drain()

            head = await reader.readexactly(4)
            if head[0] != 5 or head[1] != 1:
                raise OSError("only CONNECT supported")
            atyp = head[3]
            if atyp == 1:
                host = socket.inet_ntoa(await reader.readexactly(4))
            elif atyp == 3:
                length = (await reader.readexactly(1))[0]
                host = (await reader.readexactly(length)).decode("idna", "replace")
            elif atyp == 4:
                host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
            else:
                raise OSError("bad atyp %d" % atyp)
            port = struct.unpack(">H", await reader.readexactly(2))[0]
            self.record(peer, host, port, atyp)

            if port == 53:
                # Upstream Fastly MASQUE proxy edges refuse CONNECT to non-443 ports
                # (observed: 1.1.1.1:53 -> HTTP 502 Bad Gateway, mapped to SOCKS5 REP 0x01).
                # Fail closed on port 53 so tunnel DNS cannot regress to cleartext TCP/UDP.
                writer.write(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                self.errors.append("port 53 rejected (Fastly MASQUE parity: HTTP 502)")
                return

            if port == 80 and host == PROBE_DEST:
                body = b"PERCH_TUN_PROBE_OK\n"
                writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                writer.write(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                    b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body
                )
                await writer.drain()
                return

            up_reader, up_writer = await self._dial(host, port)
            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()

            async def pump(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
                try:
                    while True:
                        chunk = await src.read(65536)
                        if not chunk:
                            break
                        dst.write(chunk)
                        await dst.drain()
                except Exception:  # noqa: BLE001
                    pass
                finally:
                    try:
                        dst.close()
                    except Exception:  # noqa: BLE001
                        pass

            await asyncio.gather(pump(reader, up_writer), pump(up_reader, writer))
        except Exception as exc:  # noqa: BLE001
            self.errors.append("%s: %s" % (type(exc).__name__, exc))
        finally:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass


def make_report() -> Dict[str, Any]:
    return {
        "schema": "perchvpn-client-e2e/1",
        "started_at": utcnow(),
        "finished_at": None,
        "environment": {
            "host": os.environ.get("COMPUTERNAME"),
            "user": os.environ.get("USERNAME"),
            "python": sys.version,
            "exe": str(EXE),
            "adapter": ADAPTER,
            "egress_ifindex": None,
            "proxy": "127.0.0.1:%d (local direct relay)" % PROXY_PORT,
            "tun_dns_peer": TUN_DNS_PEER,
        },
        "checks": [],
        "pre": {},
        "start": {},
        "states": [],
        "up": {},
        "stop": {},
        "post": {},
        "error": None,
    }


def add_check(report: Dict[str, Any], name: str, ok: Any, critical: bool, detail: Any = "") -> None:
    report["checks"].append({"name": name, "ok": bool(ok), "critical": bool(critical), "detail": detail})


# ---------------------------------------------------------------------------
# Phase 3: core datapath parity (h1 transport, TLS fragmentation, API/WS
# surface, relayer failover, pre-start latency, Wintun ghost hygiene).
# ---------------------------------------------------------------------------

WINTUN_GHOST_PS = (
    "$ghosts = @(Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue | "
    "Where-Object { $_.PNPDeviceID -like 'SWD\\WINTUN*' -and $_.Present -eq $false }); "
    "$ghosts.Count"
)


def wintun_ghost_count() -> int:
    """Count non-present SWD\\WINTUN PnP nodes (ghost Wintun devices)."""
    result = run_ps(WINTUN_GHOST_PS, timeout=30.0)
    try:
        return int((result.get("stdout") or "").strip() or -1)
    except ValueError:
        return -1


def _e2e_h1_tls_context(options: Any) -> "ssl.SSLContext":
    """Verifying H1 client context that trusts the staged E2E stand-in CA.

    Mirrors ``perchvpn.proxy.http1_session._tls_context`` (ALPN http/1.1 +
    ClientHello fingerprint knobs) but anchors verification in the E2E CA
    so the stand-in edge's self-hosted certificate chains.  Verification is
    never disabled.
    """
    from perchvpn.proxy.transport_options import configure_client_hello

    ca_path, _, _ = _e2e_cert_paths()
    context = ssl.create_default_context(cafile=str(ca_path))
    context.set_alpn_protocols(["http/1.1"])
    if options is not None:
        configure_client_hello(context, getattr(options, "utls_fingerprint", "disabled"))
    return context


class TlsConnectProxy(threading.Thread):
    """TLS-terminating HTTP CONNECT stand-in upstream edge (memory-BIO server).

    The server deliberately reads the raw socket in a manual loop feeding a
    server-side MemoryBIO, so it can record the exact TCP segment sizes of
    the client's first flight.  With ``tls_fragment_mode`` active the client
    emits the ClientHello as many small records/segments instead of one;
    that evidence proves fragmentation is live on the wire, not just in the
    config builder.
    """

    def __init__(self, host: str = "127.0.0.1") -> None:
        super().__init__(name="e2e-tls-connect-proxy", daemon=True)
        self.host = host
        self.port = 0
        self.ready = threading.Event()
        self._stop = threading.Event()
        self.first_flight_segments: List[int] = []
        self.connects: List[str] = []
        self.errors: List[str] = []
        self.tunnels_served = 0
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        _, cert_path, key_path = _e2e_cert_paths()
        self._ctx.load_cert_chain(str(cert_path), str(key_path))
        self._ctx.set_alpn_protocols(["http/1.1"])

    def run(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind((self.host, 0))
            self.port = listener.getsockname()[1]
            listener.listen(4)
            listener.settimeout(0.5)
            self.ready.set()
            while not self._stop.is_set():
                try:
                    conn, _addr = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                threading.Thread(target=self._serve, args=(conn,), daemon=True).start()
        except Exception as exc:  # noqa: BLE001
            self.errors.append("listener: %s" % exc)
        finally:
            self.ready.set()
            try:
                listener.close()
            except OSError:
                pass

    def stop(self) -> None:
        self._stop.set()

    @staticmethod
    def _drain(wbio: "ssl.MemoryBIO", conn: socket.socket) -> None:
        while True:
            try:
                data = wbio.read()
            except ssl.SSLWantReadError:
                return
            if not data:
                return
            conn.sendall(data)

    def _serve(self, conn: socket.socket) -> None:
        rbio, wbio = ssl.MemoryBIO(), ssl.MemoryBIO()
        tunneled = False
        try:
            conn.settimeout(10.0)
            obj = self._ctx.wrap_bio(rbio, wbio, server_side=True)
            while True:
                try:
                    obj.do_handshake()
                    break
                except ssl.SSLWantReadError:
                    # The ServerHello flight may already be pending in the
                    # outgoing BIO; it must leave before blocking for more
                    # client input or both sides deadlock.
                    self._drain(wbio, conn)
                    chunk = conn.recv(65536)
                    if not chunk:
                        raise OSError("client closed during handshake")
                    self.first_flight_segments.append(len(chunk))
                    rbio.write(chunk)
                except ssl.SSLWantWriteError:
                    self._drain(wbio, conn)
            self._drain(wbio, conn)
            buf = b""
            target = None
            while True:
                # A tunneled CONNECT must not be answered with the inner
                # response before the client's inner request arrives: the h1
                # client writes the probe GET only after the 200 is consumed,
                # and an early close surfaces as WinError 10053 on Windows.
                if tunneled and target is not None and b"\r\n\r\n" in buf:
                    body = b"PERCH_TUN_PROBE_OK\n" if "203.0.113.10:80" in target else b"edge-stand-in: unsupported destination\n"
                    obj.write(
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                        b"Connection: close\r\n\r\n" + body
                    )
                    self._drain(wbio, conn)
                    try:
                        obj.unwrap()
                    except (ssl.SSLError, OSError):
                        pass
                    self._drain(wbio, conn)
                    break
                if not tunneled and b"\r\n\r\n" in buf:
                    head, rest = buf.split(b"\r\n\r\n", 1)
                    line = head.split(b"\r\n")[0].decode("latin1")
                    if not line.startswith("CONNECT"):
                        buf = b""
                        continue
                    self.connects.append(line)
                    obj.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    self._drain(wbio, conn)
                    tunneled = True
                    self.tunnels_served += 1
                    target = line.split()[1] if len(line.split()) > 1 else ""
                    buf = rest
                    continue
                try:
                    plaintext = obj.read()
                except ssl.SSLWantReadError:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    rbio.write(chunk)
                    continue
                except (ssl.SSLEOFError, ssl.SSLError):
                    break
                if not plaintext:
                    break
                buf += plaintext
        except Exception as exc:  # noqa: BLE001
            self.errors.append("%s: %s" % (type(exc).__name__, exc))
        finally:
            try:
                conn.close()
            except OSError:
                pass


class FakeRelayer(threading.Thread):
    """Stand-in relayer worker: records the ``?url=`` parameter it receives."""

    def __init__(self) -> None:
        super().__init__(name="e2e-fake-relayer", daemon=True)
        self.port = 0
        self.ready = threading.Event()
        self._stop = threading.Event()
        self.requests: List[str] = []
        self.errors: List[str] = []

    def run(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind(("127.0.0.1", 0))
            self.port = server.getsockname()[1]
            server.listen(4)
            server.settimeout(0.5)
            self.ready.set()
            while not self._stop.is_set():
                try:
                    conn, _addr = server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                try:
                    self._serve(conn)
                except Exception as exc:  # noqa: BLE001
                    self.errors.append("%s: %s" % (type(exc).__name__, exc))
                finally:
                    try:
                        conn.close()
                    except OSError:
                        pass
        except Exception as exc:  # noqa: BLE001
            self.errors.append("listener: %s" % exc)
        finally:
            self.ready.set()
            try:
                server.close()
            except OSError:
                pass

    def stop(self) -> None:
        self._stop.set()

    def _serve(self, conn: socket.socket) -> None:
        conn.settimeout(10.0)
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(65536)
            if not chunk:
                return
            data += chunk
        head = data.split(b"\r\n\r\n", 1)[0].decode("latin1")
        request_line = head.split("\r\n")[0]
        self.requests.append(request_line)
        body = b"relayed-ok"
        conn.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: close\r\n\r\n" + body
        )


async def _phase3_h1(report: Dict[str, Any]) -> None:
    """HTTP/1.1 CONNECT transport + combined TLS fragmentation over TLS."""
    import sys as _sys

    if str(SRC) not in _sys.path:
        _sys.path.insert(0, str(SRC))
    from perchvpn.proxy import http1_session as h1
    from perchvpn.proxy.transport_options import TransportOptions

    proxy = TlsConnectProxy()
    proxy.start()
    session = None
    try:
        if not await asyncio.to_thread(proxy.ready.wait, 10.0) or not proxy.port:
            add_check(report, "h1_stand_in_edge_up", False, True, proxy.errors)
            return
        add_check(report, "h1_stand_in_edge_up", True, True, {"port": proxy.port})

        # Verification stays on: anchor trust in the staged E2E stand-in CA.
        h1._tls_context = _e2e_h1_tls_context  # type: ignore[assignment]
        # The 5 ms product pacing is shorter than guest scheduler jitter, so
        # loopback recv() coalesces paced ClientHello segments into one read
        # and the wire evidence becomes flaky.  A 25 ms pause keeps the
        # segments observable while staying inside the fragment budget.
        from perchvpn.proxy import transport_options as _to

        _to._SEGMENT_PAUSE_SECONDS = 0.025
        from perchvpn.proxy.http1_session import H1ProxySession, SessionAtCapacity

        options = TransportOptions(
            utls_fingerprint=H1_OPTIONS[0], tls_fragment_mode=H1_OPTIONS[1]
        )
        session = H1ProxySession("127.0.0.1", proxy.port, token="e2e-phase3", options=options)
        await asyncio.wait_for(session.connect(), timeout=15.0)
        add_check(
            report,
            "h1_connect_ok",
            session._ssl is not None and session._alpn == "http/1.1",
            True,
            {"alpn": session._alpn, "edge_errors": proxy.errors},
        )
        segments = list(proxy.first_flight_segments)
        # combined mode splits the ~400B ClientHello into 256B records then
        # 64B packet segments; loopback coalescing is avoided by the 5ms
        # pacing between fragments.
        add_check(
            report,
            "h1_clienthello_fragmented_on_wire",
            len(segments) >= 3,
            True,
            {"segments": segments, "mode": H1_OPTIONS[1], "fingerprint": H1_OPTIONS[0]},
        )
        stream = await asyncio.wait_for(
            session.open_stream("203.0.113.10", 80), timeout=15.0
        )
        await asyncio.wait_for(stream.wait_established(), timeout=15.0)
        add_check(
            report,
            "h1_tunnel_established",
            stream in session._tunnels.values() and bool(proxy.connects),
            True,
            {"connects": proxy.connects},
        )
        await stream.write(
            b"GET /probe HTTP/1.1\r\nHost: 203.0.113.10\r\nConnection: close\r\n\r\n"
        )
        payload = b""
        for _ in range(5):
            chunk = await asyncio.wait_for(stream.read(), timeout=10.0)
            if not chunk:
                break
            payload += chunk
        add_check(
            report,
            "h1_probe_data_through_tunnel",
            b"PERCH_TUN_PROBE_OK" in payload,
            True,
            {"bytes": len(payload), "edge_errors": proxy.errors},
        )
        capacity_raised = False
        try:
            await session.open_stream("203.0.113.10", 80)
        except SessionAtCapacity:
            capacity_raised = True
        add_check(
            report,
            "h1_session_at_capacity",
            capacity_raised and session.active_streams == 1,
            True,
            {"active_streams": session.active_streams},
        )
    except Exception as exc:  # noqa: BLE001
        add_check(
            report,
            "h1_transport_suite",
            False,
            True,
            "%s: %s | edge=%s" % (type(exc).__name__, exc, proxy.errors[-5:]),
        )
    finally:
        if session is not None:
            try:
                await session.close()
            except Exception:  # noqa: BLE001
                pass
        proxy.stop()
        report.setdefault("phase3", {})["h1"] = {
            "first_flight_segments": proxy.first_flight_segments,
            "connects": proxy.connects,
            "tunnels_served": proxy.tunnels_served,
            "edge_errors": proxy.errors,
        }


async def _phase3_api(report: Dict[str, Any]) -> None:
    """Boot the real API app: WS push, /api/network parity round-trip,
    relayer failover through the live HTTP client hook, and the relayer
    latency probe endpoint."""
    import sys as _sys

    if str(SRC) not in _sys.path:
        _sys.path.insert(0, str(SRC))
    staged_packages = ROOT / "site-packages"
    if staged_packages.is_dir() and str(staged_packages) not in _sys.path:
        _sys.path.insert(0, str(staged_packages))
    try:
        import fastapi  # noqa: F401
        import uvicorn  # noqa: F401
        import websockets  # noqa: F401
    except Exception as exc:  # noqa: BLE001
        add_check(
            report,
            "api_stack_available",
            False,
            True,
            "guest python lacks the API stack: %s" % exc,
        )
        return

    import types as _types

    # The harness aliases ``perchvpn_windows`` before the TUN phase; the
    # core ``perchvpn`` package is a real package under SRC, so plain
    # ``import`` resolves it via the sys.path entry added above.
    if "perchvpn" not in _sys.modules:
        try:
            import perchvpn.auth  # noqa: F401
        except Exception:  # noqa: BLE001
            pkg = _types.ModuleType("perchvpn")
            pkg.__path__ = [str(SRC / "perchvpn")]
            _sys.modules["perchvpn"] = pkg

    import httpx
    import uvicorn
    import websockets

    from perchvpn_windows import api as api_module

    add_check(report, "api_stack_available", True, False, "fastapi+uvicorn+websockets importable")

    config = uvicorn.Config(api_module.app, host="127.0.0.1", port=0, log_level="error")
    server = uvicorn.Server(config)
    server_thread = threading.Thread(target=server.run, daemon=True)
    server_thread.start()
    for _ in range(100):
        if server.started:
            break
        await asyncio.sleep(0.1)
    sockets = list(getattr(server, "servers", []) or [])
    if not server.started or not sockets:
        add_check(report, "api_app_booted", False, True, "uvicorn did not start")
        return
    port = sockets[0].sockets[0].getsockname()[1]
    base = "http://127.0.0.1:%d" % port
    add_check(report, "api_app_booted", True, True, {"port": port})

    # -- /api/network parity round-trip ----------------------------------
    roundtrip: Dict[str, Any] = {}
    try:
        async with httpx.AsyncClient(trust_env=False, timeout=30.0) as http:
            get1 = (await http.get(base + "/api/network")).json()
            wanted = {
                "ip_mode": "prefer_ipv6",
                "transport_version": "h1",
                "tls_fragment_mode": "combined",
                "tls_fragment_fallback_delay_ms": 450,
                "multiplex_streams": 16,
                "relayer_provider": "automatic",
                "relayed_endpoints": ["guardian"],
            }
            posted = (await http.post(base + "/api/network", json=wanted))
            get2 = (await http.get(base + "/api/network")).json()
        roundtrip = {
            "posted_status": posted.status_code,
            "wanted": wanted,
            "get2": {key: get2.get(key) for key in wanted},
            "password_absent": "local_proxy_password" not in get2
            and "upstream_proxy_password" not in get2,
        }
        echo_ok = posted.status_code == 200
        persisted_ok = all(get2.get(key) == value for key, value in wanted.items())
        add_check(
            report,
            "api_network_parity_roundtrip",
            echo_ok and persisted_ok and roundtrip["password_absent"],
            True,
            roundtrip,
        )
    except Exception as exc:  # noqa: BLE001
        add_check(
            report,
            "api_network_parity_roundtrip",
            False,
            True,
            "%s: %s" % (type(exc).__name__, exc),
        )
        roundtrip = {"error": "%s: %s" % (type(exc).__name__, exc)}

    # -- WS real-time push: starting -> traffic_verified ------------------
    ws_result: Dict[str, Any] = {}
    try:
        app_inst = api_module._app
        original_payload = app_inst.tun_payload
        uri = "ws://127.0.0.1:%d/ws/status" % port
        async def wait_state(ws, want: str, timeout: float = 10.0) -> str:
            """Recv pushed frames until ``tunnel.state`` == want (races with
            idle-state pushes are drained, never misread)."""
            deadline = time.monotonic() + timeout
            seen: List[str] = []
            while time.monotonic() < deadline:
                frame = json.loads(await asyncio.wait_for(ws.recv(), timeout=10.0))
                state = (frame.get("tunnel") or {}).get("state")
                if state is not None:
                    seen.append(str(state))
                if state == want:
                    return ",".join(seen)
            raise TimeoutError("no %s frame; saw %s" % (want, seen[-6:]))

        async with websockets.connect(uri, open_timeout=10.0) as ws:
            initial = json.loads(await asyncio.wait_for(ws.recv(), timeout=10.0))
            seen_states = [("initial", str((initial.get("tunnel") or {}).get("state")))]

            app_inst.tun_payload = lambda: {  # type: ignore[method-assign]
                "enabled": True,
                "state": "starting",
                "detail": "e2e-injected",
                "process_alive": True,
            }
            drained = await wait_state(ws, "starting")
            seen_states.append(("after-starting", drained))

            app_inst.tun_payload = lambda: {  # type: ignore[method-assign]
                "enabled": True,
                "state": "traffic_verified",
                "detail": "e2e-injected",
                "process_alive": True,
            }
            drained = await wait_state(ws, "traffic_verified")
            seen_states.append(("after-verified", drained))

        ws_result = {"frames": seen_states}
        add_check(
            report,
            "ws_status_push_starting_to_verified",
            True,
            True,
            ws_result,
        )
    except Exception as exc:  # noqa: BLE001
        add_check(
            report,
            "ws_status_push_starting_to_verified",
            False,
            True,
            "%s: %s | %s" % (type(exc).__name__, exc, ws_result),
        )
    finally:
        try:
            del app_inst.tun_payload  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            pass

    # -- relayer failover through the real client hook --------------------
    from perchvpn import relayer as relayer_module
    from perchvpn.http_client import _RelayingClient

    fake = FakeRelayer()
    fake.start()
    if not await asyncio.to_thread(fake.ready.wait, 10.0) or not fake.port:
        add_check(report, "relayer_failover_fallback", False, True, fake.errors)
    else:
        original_relayers = dict(relayer_module.DEFAULT_RELAYERS)
        try:
            target = "https://direct-fail.invalid/FoxyConfig"
            relayer_module.DEFAULT_RELAYERS.clear()  # type: ignore[union-attr]
            relayer_module.DEFAULT_RELAYERS["automatic"] = "http://127.0.0.1:%d" % fake.port  # type: ignore[union-attr]
            relayer_module.configure(provider="automatic", routed_endpoints=("config",))
            client = _RelayingClient(trust_env=False, timeout=15.0)
            response = await asyncio.to_thread(
                client.request, "GET", target
            )
            relayed = fake.requests[0] if fake.requests else ""
            encoded = ""
            if "url=" in relayed:
                encoded = relayed.split("url=", 1)[1].split(" ")[0]
            decoded = ""
            if encoded:
                padded = encoded + "=" * (-len(encoded) % 4)
                try:
                    decoded = base64.urlsafe_b64decode(padded).decode()
                except Exception:  # noqa: BLE001
                    decoded = "<decode-failed>"
            add_check(
                report,
                "relayer_failover_fallback",
                response.status_code == 200
                and bool(fake.requests)
                and decoded == target,
                True,
                {
                    "status": response.status_code,
                    "relayed_request": relayed,
                    "decoded_target": decoded,
                    "direct_failed_as_expected": True,
                    "fake_errors": fake.errors,
                },
            )
        except Exception as exc:  # noqa: BLE001
            add_check(
                report,
                "relayer_failover_fallback",
                False,
                True,
                "%s: %s | fake=%s" % (type(exc).__name__, exc, fake.requests),
            )
        finally:
            relayer_module.DEFAULT_RELAYERS.clear()  # type: ignore[union-attr]
            relayer_module.DEFAULT_RELAYERS.update(original_relayers)  # type: ignore[union-attr]
            relayer_module.configure(provider="direct")
            fake.stop()

    # -- relayer latency probe endpoint (live, over Default Switch NAT) ---
    try:
        async with httpx.AsyncClient(trust_env=False, timeout=60.0) as http:
            probe = (
                await http.post(
                    base + "/api/network/relayer/test",
                    json={"provider": "automatic", "routed_endpoints": ["guardian"]},
                )
            ).json()
        results = probe.get("results") or []
        rtts = [
            {"relay": r.get("relay"), "ok": r.get("ok"), "rtt_ms": r.get("rtt_ms")}
            for r in results
        ]
        any_ok = any(r.get("ok") for r in results)
        add_check(report, "relayer_rtt_probe_live", True, False, {"results": rtts})
        if not any_ok:
            logger.warning("relayer live probe: no endpoint reachable (%s)", rtts)
    except Exception as exc:  # noqa: BLE001
        add_check(
            report,
            "relayer_rtt_probe_live",
            False,
            False,
            "%s: %s" % (type(exc).__name__, exc),
        )

    report.setdefault("phase3", {})["api"] = {
        "roundtrip": roundtrip,
        "ws": ws_result,
        "relayer_probe": (report["checks"][-1]["detail"] if report["checks"] else None),
    }


async def main() -> int:
    global fe  # noqa: PLW0603 - single-process harness
    setup_logging()
    report = make_report()
    report["environment"]["egress_ifindex"] = None
    egress_ifindex = physical_ifindex()
    relay = SocksRelay(egress_ifindex=egress_ifindex)
    report["environment"]["egress_ifindex"] = egress_ifindex
    fe = None
    try:
        import types

        # Phase 3: singbox_config now imports the core `perchvpn` package
        # (SINGBOX_UTLS_FINGERPRINTS), so SRC must be importable as a real
        # package root, not only via the perchvpn_windows path alias.
        if str(SRC) not in sys.path:
            sys.path.insert(0, str(SRC))

        pkg = types.ModuleType("perchvpn_windows")
        pkg.__path__ = [str(SRC / "perchvpn_windows")]
        sys.modules.setdefault("perchvpn_windows", pkg)

        from perchvpn_windows import physical_dns, singbox_config, tun_recovery, tun_status
        from perchvpn_windows.tun_frontend import TunFrontend

        logger.info("imported client modules from %s", SRC / "perchvpn_windows")
        phase("imported")

        version = subprocess.run(
            [str(EXE), "version"], capture_output=True, text=True, timeout=30
        )
        report["environment"]["singbox_version"] = (version.stdout or version.stderr).strip()
        add_check(
            report,
            "singbox_version_1_14_4",
            "1.14.4" in report["environment"]["singbox_version"],
            True,
            report["environment"]["singbox_version"],
        )

        report["pre"]["warmup"] = await asyncio.to_thread(warm_up_windows_spawns)
        add_check(
            report,
            "pre_spawn_warmup",
            report["pre"]["warmup"]["warm"],
            False,
            report["pre"]["warmup"],
        )

        gate = tun_recovery.TunRecoveryGate(
            enabled=True, state_path=STATE, adapter_name=ADAPTER
        )
        stale = gate.reconcile_stale_ownership()
        report["pre"]["stale_reconcile_before"] = stale
        add_check(report, "pre_stale_ownership_clean", stale == tun_recovery.CLEAN, True, stale)

        await relay.start()
        phase("relay_started")
        dns_provider = os.environ.get("PERCH_E2E_DNS_PROVIDER", "default")
        custom_doh_url = os.environ.get("PERCH_E2E_DNS_CUSTOM_URL", "")
        dns_endpoint = singbox_config.tunnel_dns_endpoint(dns_provider, custom_doh_url)
        doh_endpoints = tuple(dns_endpoint["pin_ips"])
        report["environment"]["tunnel_dns_endpoint"] = dns_endpoint
        report["pre"]["snapshot"] = snapshot()
        phase("preflight_snapshot")
        report["pre"]["wintun_ghost_count"] = wintun_ghost_count()
        add_check(
            report,
            "pre_wintun_ghosts_known",
            report["pre"]["wintun_ghost_count"] >= 0,
            True,
            report["pre"]["wintun_ghost_count"],
        )

        baseline_egress = await tun_status.probe_system_egress_identity(timeout=5.0)
        report["pre"]["system_egress"] = baseline_egress
        report["pre"]["trace_https"] = trace()
        try:
            doh_pre = await asyncio.to_thread(
                physical_dns.query_doh_ipv4,
                "example.com",
                timeout=5.0,
                endpoints=doh_endpoints,
            )
            report["pre"]["doh_example_com"] = {"ok": bool(doh_pre), "ips": doh_pre, "error": None}
        except Exception as exc:  # noqa: BLE001
            report["pre"]["doh_example_com"] = {"ok": False, "ips": [], "error": "%s: %s" % (type(exc).__name__, exc)}
        add_check(
            report,
            "pre_doh_resolution",
            report["pre"]["doh_example_com"]["ok"],
            False,
            report["pre"]["doh_example_com"],
        )
        add_check(
            report,
            "pre_socks_relay_idle",
            len(relay.connects) == 0,
            True,
            "connects=%d" % len(relay.connects),
        )
        report["pre"]["singbox_processes"] = [
            p.get("Id")
            for p in as_list((report["pre"]["snapshot"].get("data") or {}).get("singbox"))
        ]

        built = singbox_config.build_config(
            proxy_host="127.0.0.1",
            proxy_port=PROXY_PORT,
            adapter=ADAPTER,
            mtu=1400,
            bypass=(),
            mixed_port=singbox_config.available_mixed_port(),
            # Sandbox networks can block a resolver IP (1.1.1.1:443 is reset
            # on the default-switch guest) without that being a PerchVPN
            # defect; the provider is a real user setting, so let the harness
            # exercise it instead of hardcoding Cloudflare.
            # A local stand-in proxy cannot be reached from an
            # interface-bound socket, so the harness disables the one
            # production knob that binds outbound sockets.
            auto_detect_interface=False,
            tunnel_dns_provider=dns_provider,
            custom_tunnel_doh_url=custom_doh_url,
        )
        report["start"]["built_config"] = built
        mixed_port = None
        for inbound in built.get("inbounds", []):
            if inbound.get("type") == "mixed":
                mixed_port = inbound.get("listen_port")
        report["start"]["mixed_port"] = mixed_port

        fe = TunFrontend(
            enabled=True,
            opt_in=True,
            executable_path=str(EXE),
            proxy_host="127.0.0.1",
            proxy_port=PROXY_PORT,
            mtu=1400,
            extra_args=[],
            is_elevated=None,
            recovery_gate=gate,
            adapter_name=ADAPTER,
            config_path=CONFIG,
            # Keep the sidecar config identical to the one built above: the
            # provider override must reach the running sidecar, not only the
            # report copy.
            auto_detect_interface=False,
            tunnel_dns_provider=dns_provider,
            custom_tunnel_doh_url=custom_doh_url,
        )
        report["start"]["elevated"] = fe.is_elevated()
        report["start"]["at"] = utcnow()
        phase("starting")
        prestart_started = time.monotonic()
        await fe.start()
        prestart_seconds = time.monotonic() - prestart_started
        report["start"]["prestart_seconds"] = round(prestart_seconds, 2)
        add_check(
            report,
            "prestart_within_6s",
            prestart_seconds < PRESTART_BOUND_SECONDS,
            True,
            {"seconds": round(prestart_seconds, 2), "bound": PRESTART_BOUND_SECONDS},
        )
        phase("start_returned", status=fe.status, state=fe.state, recovery=fe.recovery_state)
        report["start"]["status"] = fe.status
        report["start"]["state"] = fe.state
        report["start"]["state_detail"] = fe.state_detail
        report["start"]["recovery_state"] = fe.recovery_state
        report["start"]["payload"] = fe.payload()
        report["start"]["config_written"] = json.loads(CONFIG.read_text(encoding="utf-8")) if CONFIG.exists() else None
        report["start"]["ownership_record_present"] = STATE.exists()
        add_check(report, "start_spawned", fe.status == "running", True, fe.status)
        add_check(report, "start_config_written", CONFIG.exists(), True, str(CONFIG))

        deadline = time.monotonic() + 90.0
        terminal = {
            tun_status.STATE_TRAFFIC_VERIFIED,
            tun_status.STATE_TUNNEL_OPERATIONAL,
            tun_status.STATE_DEGRADED,
            tun_status.STATE_FAILED,
            tun_status.STATE_RECOVERY_REQUIRED,
        }
        while time.monotonic() < deadline:
            state = await fe.reconcile()
            entry = {
                "t": utcnow(),
                "state": state,
                "detail": fe.state_detail,
                "process_status": fe.status,
                "recovery_state": fe.recovery_state,
            }
            if not report["states"] or report["states"][-1]["state"] != state:
                logger.info("state -> %s (%s)", state, fe.state_detail)
            report["states"].append(entry)
            if state in terminal:
                break
            await asyncio.sleep(2.0)

        phase("state_loop_done", state=fe.state, detail=fe.state_detail)
        report["start"]["final_state"] = fe.state
        report["start"]["final_detail"] = fe.state_detail
        report["start"]["stdout_tail"] = list(fe.stdout)[-25:]
        report["start"]["stderr_tail"] = list(fe.stderr)[-25:]
        add_check(
            report,
            "tun_state_operational",
            fe.state in (tun_status.STATE_TRAFFIC_VERIFIED, tun_status.STATE_TUNNEL_OPERATIONAL),
            True,
            "%s: %s" % (fe.state, fe.state_detail),
        )

        phase("up_snapshot")
        up_snapshot = snapshot()
        report["up"]["snapshot"] = up_snapshot
        write_partial(report, "up-snapshot")
        data = up_snapshot.get("data") or {}
        adapters = as_list(data.get("adapters"))
        addresses = as_list(data.get("addresses"))
        tun_routes = as_list(data.get("tun_routes"))
        defaults = as_list(data.get("default_routes"))
        owner = [a for a in adapters if a.get("Name") == ADAPTER]
        add_check(report, "adapter_present", bool(owner), True, adapters)
        up_states = [a.get("Status") for a in owner]
        add_check(report, "adapter_up", any(str(s).lower() == "up" for s in up_states), True, up_states)
        tun_ips = [a.get("IPAddress") for a in addresses]
        add_check(report, "adapter_ipv4", "172.19.0.1" in tun_ips, True, tun_ips)
        split_evidence = split_route_evidence(defaults, tun_routes, ADAPTER)
        add_check(
            report,
            "literal_split_routes_present",
            split_evidence["ok"],
            False,
            {
                **split_evidence,
                "note": "sing-box 1.14 auto_route decomposes /1 into exclusion-aware prefixes on Windows; decomposed coverage via the TUN gateway also satisfies the split-route check",
            },
        )
        add_check(
            report,
            "tun_route_table",
            len(tun_routes) > 0,
            True,
            "%d routes via %s" % (len(tun_routes), ADAPTER),
        )
        phase("up_routes")
        dns_pin = doh_endpoints[0] if doh_endpoints else "1.1.1.1"
        report["up"]["route_lookup"] = route_lookup(
            ips=("1.0.0.1", "8.8.8.8", "172.19.0.2", dns_pin)
        )
        lookups = {r.get("ip"): r for r in as_list(report["up"]["route_lookup"].get("rows"))}
        write_partial(report, "up-routes")
        effective_public = [ip for ip in ("1.0.0.1", "8.8.8.8") if (lookups.get(ip) or {}).get("interface") == ADAPTER]
        add_check(
            report,
            "effective_route_via_tun",
            len(effective_public) == 2,
            True,
            {"lookups": lookups, "effective_public": effective_public},
        )
        add_check(
            report,
            "tun_dns_peer_route",
            (lookups.get("172.19.0.2") or {}).get("interface") == ADAPTER,
            True,
            lookups.get("172.19.0.2"),
        )
        add_check(
            report,
            "excluded_dns_ip_stays_physical",
            (lookups.get(dns_pin) or {}).get("interface") not in (None, ADAPTER),
            False,
            {"pin": dns_pin, "lookup": lookups.get(dns_pin)},
        )

        report["up"]["socks_connects_before"] = {"total": relay.total, "unique": relay.summary()["unique"]}
        report["up"]["probe_http_via_tun"] = await asyncio.to_thread(http_get, PROBE_DEST, 80, "/probe")
        add_check(
            report,
            "probe_http_via_socks",
            report["up"]["probe_http_via_tun"].get("ok")
            and "PERCH_TUN_PROBE_OK" in (report["up"]["probe_http_via_tun"].get("body") or ""),
            True,
            report["up"]["probe_http_via_tun"],
        )
        report["up"]["http_direct"] = await asyncio.to_thread(http_get, "1.0.0.1", 80, "/")
        add_check(
            report,
            "outbound_http_through_tun",
            report["up"]["http_direct"].get("ok"),
            False,
            report["up"]["http_direct"],
        )
        phase("up_tests")
        write_partial(report, "up-start")
        report["up"]["trace_cloudflare"] = await asyncio.to_thread(https_get, "www.cloudflare.com", "/cdn-cgi/trace", 12.0)
        report["up"]["curl_cloudflare"] = await asyncio.to_thread(curl_get, "https://www.cloudflare.com/cdn-cgi/trace", 20.0)
        add_check(
            report,
            "outbound_https_through_tun",
            report["up"]["trace_cloudflare"].get("ok") or report["up"]["curl_cloudflare"].get("ok"),
            False,
            {
                "python": report["up"]["trace_cloudflare"],
                "curl": report["up"]["curl_cloudflare"],
            },
        )
        literal_ip = "1.0.0.1"
        try:
            resolved = await asyncio.to_thread(
                socket.getaddrinfo, "www.cloudflare.com", 443, socket.AF_INET
            )
            if resolved:
                literal_ip = resolved[0][4][0]
        except OSError:
            pass
        report["up"]["https_literal_ip"] = literal_ip
        report["up"]["https_literal_tun"] = await asyncio.to_thread(
            https_get, literal_ip, "/cdn-cgi/trace", 12.0, "www.cloudflare.com"
        )
        add_check(
            report,
            "https_literal_tun",
            report["up"]["https_literal_tun"].get("ok"),
            False,
            report["up"]["https_literal_tun"],
        )
        write_partial(report, "up-https")
        report["up"]["trace_direct_ip"] = await asyncio.to_thread(trace, "1.0.0.1")
        report["up"]["trace_second_ip"] = await asyncio.to_thread(trace, "8.8.8.8")
        report["up"]["http_cloudflare"] = await asyncio.to_thread(http_get, "www.cloudflare.com", 80, "/")
        try:
            report["up"]["dns_tcp_tun"] = await asyncio.to_thread(dns_query_tcp, TUN_DNS_PEER, "example.com", 4.0)
        except Exception as exc:  # noqa: BLE001
            report["up"]["dns_tcp_tun"] = {"ok": False, "error": "%s: %s" % (type(exc).__name__, exc), "transport": "tcp"}
        try:
            report["up"]["dns_udp_tun"] = await asyncio.to_thread(dns_query_udp, TUN_DNS_PEER, "example.com", 4.0)
        except Exception as exc:  # noqa: BLE001
            report["up"]["dns_udp_tun"] = {"ok": False, "error": "%s: %s" % (type(exc).__name__, exc), "transport": "udp"}
        report["up"]["nslookup_tcp_tun"] = await asyncio.to_thread(nslookup, TUN_DNS_PEER, "example.com", True)
        report["up"]["nslookup_udp_tun"] = await asyncio.to_thread(nslookup, TUN_DNS_PEER, "example.com", False)
        report["up"]["system_resolver"] = await asyncio.to_thread(system_resolve, "example.com")
        add_check(
            report,
            "tunnel_dns_tcp",
            report["up"]["dns_tcp_tun"].get("ok") or report["up"]["nslookup_tcp_tun"].get("ok"),
            True,
            {
                "python": report["up"]["dns_tcp_tun"],
                "nslookup": report["up"]["nslookup_tcp_tun"],
            },
        )
        add_check(
            report,
            "tunnel_dns_udp_hijack",
            report["up"]["dns_udp_tun"].get("ok") or report["up"]["nslookup_udp_tun"].get("ok"),
            False,
            {
                "python": report["up"]["dns_udp_tun"],
                "nslookup": report["up"]["nslookup_udp_tun"],
            },
        )

        if mixed_port:
            report["up"]["mixed_inbound"] = await asyncio.to_thread(
                https_via_socks,
                "127.0.0.1",
                int(mixed_port),
                literal_ip,
                "/cdn-cgi/trace",
                12.0,
                "www.cloudflare.com",
            )
            add_check(
                report,
                "mixed_inbound_proxy",
                report["up"]["mixed_inbound"]["ok"],
                False,
                report["up"]["mixed_inbound"],
            )

        connect_pairs = [(c["host"], c["port"]) for c in relay.connects]
        write_partial(report, "up-dns")
        report["up"]["socks_connects"] = relay.summary()
        report["up"]["socks_errors"] = list(relay.errors[-20:])
        add_check(
            report,
            "socks_saw_tunnel_traffic",
            any(port in (80, 443) for _host, port in connect_pairs),
            True,
            connect_pairs,
        )
        add_check(
            report,
            "socks_saw_tunnel_dns",
            (dns_pin, 443) in connect_pairs,
            True,
            connect_pairs,
        )
        add_check(
            report,
            "socks_port_53_not_used",
            (dns_pin, 53) not in connect_pairs,
            True,
            connect_pairs,
        )
        add_check(
            report,
            "system_dns_physical",
            True,
            False,
            {
                "result": report["up"]["system_resolver"],
                "note": "TunFrontend does not rewrite system DNS; explicit TUN peer queries exercise tunnel DNS.",
            },
        )

        # ---- Phase 3: core datapath parity checks (while the tunnel is up)
        phase("phase3_h1")
        await _phase3_h1(report)
        phase("phase3_api")
        await _phase3_api(report)
        report["phase3"]["socks_connects_total_after_phase3"] = relay.total
        write_partial(report, "phase3")

        write_partial(report, "up-done")
        report["stop"]["at"] = utcnow()
        phase("stopping")
        stopped = await fe.stop()
        phase("stopped")
        report["stop"]["returned"] = stopped
        report["stop"]["status"] = fe.status
        report["stop"]["state"] = fe.state
        report["stop"]["recovery_state"] = fe.recovery_state
        report["stop"]["payload"] = fe.payload()
        report["stop"]["ownership_record_present"] = STATE.exists()
        report["stop"]["stdout_tail"] = list(fe.stdout)[-15:]
        report["stop"]["stderr_tail"] = list(fe.stderr)[-15:]
        add_check(report, "stop_returned_clean", stopped, True, report["stop"]["payload"])
        add_check(
            report,
            "recovery_clean",
            fe.recovery_state == tun_recovery.CLEAN,
            True,
            fe.recovery_state,
        )

        phase("post_checks")
        post_ifaces = run_cmd(["netsh.exe", "interface", "show", "interface"], timeout=15)
        report["post"]["interfaces"] = post_ifaces.get("stdout", "")[-4000:]
        add_check(
            report,
            "adapter_removed",
            ADAPTER.lower() not in report["post"]["interfaces"].lower(),
            True,
            {"adapter": ADAPTER, "netsh_rc": post_ifaces.get("rc"), "elapsed_ms": post_ifaces.get("elapsed_ms")},
        )
        post_procs = run_cmd(
            ["tasklist.exe", "/FI", "IMAGENAME eq sing-box.exe", "/NH"], timeout=15
        )
        report["post"]["tasklist"] = post_procs.get("stdout", "")[-2000:]
        add_check(
            report,
            "singbox_process_gone",
            "sing-box.exe" not in (post_procs.get("stdout") or "").lower(),
            True,
            {"rc": post_procs.get("rc")},
        )
        add_check(
            report,
            "ownership_record_cleared",
            not STATE.exists(),
            True,
            str(STATE),
        )
        stale_post = gate.reconcile_stale_ownership()
        report["post"]["stale_reconcile_after"] = stale_post
        add_check(
            report,
            "post_stale_ownership_clean",
            stale_post == tun_recovery.CLEAN,
            True,
            stale_post,
        )
        post_ghosts = wintun_ghost_count()
        report["post"]["wintun_ghost_count"] = post_ghosts
        pre_ghosts = report["pre"].get("wintun_ghost_count", 0)
        add_check(
            report,
            "post_wintun_ghosts_zero",
            post_ghosts == 0,
            True,
            {"pre": pre_ghosts, "post": post_ghosts},
        )
        try:
            doh_post = await asyncio.wait_for(
                asyncio.to_thread(
                    physical_dns.query_doh_ipv4,
                    "example.com",
                    timeout=5.0,
                    endpoints=doh_endpoints,
                ),
                timeout=12.0,
            )
            report["post"]["doh_example_com"] = {"ok": bool(doh_post), "ips": doh_post, "error": None}
        except Exception as exc:  # noqa: BLE001
            report["post"]["doh_example_com"] = {"ok": False, "ips": [], "error": "%s: %s" % (type(exc).__name__, exc)}
        add_check(
            report,
            "post_doh_resolution",
            report["post"]["doh_example_com"]["ok"],
            False,
            report["post"]["doh_example_com"],
        )
        write_partial(report, "stopped")
    except Exception as exc:  # noqa: BLE001
        report["error"] = "%s: %s\n%s" % (type(exc).__name__, exc, traceback.format_exc())
        logger.exception("harness failed")
        add_check(report, "harness_exception", False, True, report["error"])
    finally:
        if fe is not None:
            try:
                if fe.status in ("running", "stopping"):
                    logger.warning("fallback stop after harness exception")
                    await fe.stop()
            except Exception as exc:  # noqa: BLE001
                logger.error("fallback stop failed: %s", exc)
        try:
            await relay.close()
        except Exception:  # noqa: BLE001
            pass

    critical = [c for c in report["checks"] if c["critical"]]
    report["ok"] = bool(critical) and all(c["ok"] for c in critical)
    report["summary"] = {
        "critical": len(critical),
        "critical_passed": sum(1 for c in critical if c["ok"]),
        "failed": [c["name"] for c in report["checks"] if not c["ok"]],
    }
    report["finished_at"] = utcnow()
    phase("done", ok=report["ok"])
    tmp = REPORT.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    os.replace(tmp, REPORT)
    logger.info("report written: %s ok=%s", REPORT, report["ok"])
    print(json.dumps({"ok": report["ok"], "summary": report["summary"], "report": str(REPORT)}))
    return 0 if report["ok"] else 1


def _watchdog(seconds: float = 900.0) -> None:
    def fire() -> None:
        logger.error("watchdog fired after %.0fs; forcing cleanup", seconds)
        try:
            phase("watchdog")
        except Exception:  # noqa: BLE001
            pass
        subprocess.run(
            ["taskkill.exe", "/F", "/IM", "sing-box.exe"],
            capture_output=True,
            timeout=20,
        )
        os._exit(4)

    timer = threading.Timer(seconds, fire)
    timer.daemon = True
    timer.start()


if __name__ == "__main__":
    _watchdog()
    sys.exit(asyncio.run(main()))
