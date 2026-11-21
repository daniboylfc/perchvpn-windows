"""Truthful TUN readiness evidence: read-only OS probes and direct egress.

A spawned sidecar, an existing adapter or a successful application-level
SOCKS5 request never prove that system traffic traverses the VPN. This module
collects the operating-system evidence required to distinguish those states:

  process alive -> adapter present -> adapter up -> addresses assigned ->
  split default routes installed -> system egress observed

All capture is read-only (Get-NetAdapter / Get-NetIPAddress / Get-NetRoute /
Get-DnsClientServerAddress) and never changes routes, DNS or adapters.

The egress probe deliberately opens a plain OS socket (no proxy, no
environment proxy settings) so it measures what *system* traffic does when it
is routed through the default route, not what an explicitly proxied client
does.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import socket
import ssl
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from perchvpn_windows.tun_state_capture import CaptureError, _run_ps

logger = logging.getLogger("perchvpn_windows.tun_status")

# Honest lifecycle states. Ordering matters: later states strictly imply the
# evidence of earlier ones.
STATE_DISABLED = "disabled"
STATE_NOT_OPTED_IN = "not_opted_in"
STATE_NOT_CONFIGURED = "not_configured"
STATE_NOT_ELEVATED = "not_elevated"
STATE_STARTING = "starting"
STATE_ADAPTER_READY = "adapter_ready"
STATE_ROUTES_CONFIGURED = "routes_configured"
STATE_TUNNEL_OPERATIONAL = "tunnel_operational"
STATE_TRAFFIC_VERIFIED = "traffic_verified"
STATE_DEGRADED = "degraded"
STATE_FAILED = "failed"
STATE_RECOVERY_REQUIRED = "recovery_required"

# Reconcile cadence control: only a verified-steady tunnel earns the backed-off
# polling cadence.  Every other state (starting, adapter_ready, routes_configured,
# tunnel_operational, degraded, failed, recovery) is transitioning and keeps the
# fast cadence so UI readiness and degradation never lag behind the evidence.
STABLE_RECONCILE_STATES = frozenset({STATE_TRAFFIC_VERIFIED})


def is_stable_reconcile_state(state: str) -> bool:
    """True when ``state`` is verified-steady and heavy probes may back off."""
    return state in STABLE_RECONCILE_STATES

# Split default routes that make the adapter authoritative without replacing
# the existing default route outright.
SPLIT_DEFAULT_ROUTES = ("0.0.0.0/1", "128.0.0.0/1")

# sing-box's Windows auto_route decomposes the default route into 80+ prefixes
# that exclude the physical adapter, loopback/link-local/private ranges and its
# own DNS endpoint.  A literal /1 or /0 check therefore never matches.  Public
# IPv4 sentinels spread across the unicast space prove that the decomposed
# table covers ordinary internet destinations; host routes do not count.
DEFAULT_ROUTE_COVERAGE_SENTINELS = (
    "1.0.0.1",
    "8.8.8.8",
    "203.0.113.10",
    "198.51.100.10",
)
_MAX_COVERAGE_PREFIX_LENGTH = 24

_ADAPTER_NAME_RE = re.compile(r"^[A-Za-z0-9 _.\-]{1,64}$")

# Direct egress probes: Cloudflare's trace endpoint returns ip= and loc=.
# The endpoint addresses are fixed literals so the probe never depends on the
# system resolver (which can be captured or broken while the TUN is up).
_EGRESS_HOST = "www.cloudflare.com"
_EGRESS_PATH = "/cdn-cgi/trace"
_EGRESS_IPV4_TARGETS = ("104.16.123.96", "104.16.124.96")
_EGRESS_IPV6_TARGETS = ("2606:4700::6810:7b60",)
# Egress TCP targets must not overlap with route_exclude_address (such as 1.1.1.1
# bootstrap DNS or physical resolvers); otherwise direct TCP probes bypass the TUN
# out the physical adapter and falsely report the tunnel as operational.
_EGRESS_TCP_TARGETS: tuple[tuple[str, int], ...] = (
    ("104.16.123.96", 443),
    ("104.16.124.96", 443),
)
# A single connect attempt is bounded to one second and the post-adapter
# settling loop re-probes every 250 ms.  Waiting on the (often blackholed)
# IPv6 trace for the full three-second budget delayed the UI transition even
# when IPv4 was already proven reachable.
_EGRESS_TIMEOUT = 1.0
_EGRESS_SETTLE_INTERVAL = 0.25
_EGRESS_SETTLE_TIMEOUT = 5.0
_MAX_EGRESS_BYTES = 16 * 1024


@dataclass
class AdapterEvidence:
    """Read-only operating-system evidence for the tunnel adapter."""

    present: bool = False
    up: bool = False
    if_index: Optional[int] = None
    ipv4: List[str] = field(default_factory=list)
    ipv6: List[str] = field(default_factory=list)
    dns_servers: List[str] = field(default_factory=list)
    routes: List[Dict[str, Any]] = field(default_factory=list)
    error: str = ""
    # IPv4 networks removed from the tunnel's route table via
    # route_exclude_address (DoH resolver pins, MASQUE edges, local nets).
    # A coverage sentinel inside one of these is an intentional gap.
    excluded_networks: Tuple[ipaddress.IPv4Network, ...] = ()

    @property
    def has_ipv4(self) -> bool:
        return bool(self.ipv4)

    @property
    def split_routes_present(self) -> bool:
        prefixes = {str(r.get("destination_prefix", "")) for r in self.routes}
        return all(prefix in prefixes for prefix in SPLIT_DEFAULT_ROUTES)

    @property
    def default_route_effective(self) -> bool:
        """True when the adapter owns broad coverage of the IPv4 unicast space.

        A literal /1 pair or 0.0.0.0/0 is authoritative.  sing-box 1.14+
        ``auto_route`` instead publishes a decomposed table that omits
        loopback/link-local/private ranges and the physical DNS path, so
        require broad routes covering public sentinels across the address
        space.  Narrow host routes must not satisfy the check.
        """
        prefixes = {str(r.get("destination_prefix", "")) for r in self.routes}
        if all(prefix in prefixes for prefix in SPLIT_DEFAULT_ROUTES):
            return True
        if "0.0.0.0/0" in prefixes:
            return True

        networks: List[ipaddress.IPv4Network] = []
        for prefix in prefixes:
            try:
                network = ipaddress.ip_network(prefix, strict=False)
            except ValueError:
                continue
            if (
                isinstance(network, ipaddress.IPv4Network)
                and network.prefixlen <= _MAX_COVERAGE_PREFIX_LENGTH
            ):
                networks.append(network)
        if not networks:
            return False
        # A sentinel inside route_exclude_address is an intentional hole
        # carved out of the decomposed table (for example the 1.1.1.1 DoH
        # pin); it must not count as missing coverage.
        for sentinel in DEFAULT_ROUTE_COVERAGE_SENTINELS:
            address = ipaddress.IPv4Address(sentinel)
            if any(address in excluded for excluded in self.excluded_networks):
                continue
            if not any(address in network for network in networks):
                return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "present": self.present,
            "up": self.up,
            "if_index": self.if_index,
            "ipv4": list(self.ipv4),
            "ipv6": list(self.ipv6),
            "dns_servers": list(self.dns_servers),
            "split_routes_present": self.split_routes_present,
            "routes": list(self.routes),
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AdapterEvidence":
        """Rebuild evidence published by the elevated helper."""
        data = data or {}
        return cls(
            present=bool(data.get("present")),
            up=bool(data.get("up")),
            if_index=data.get("if_index"),
            ipv4=[str(v) for v in data.get("ipv4") or []],
            ipv6=[str(v) for v in data.get("ipv6") or []],
            dns_servers=[str(v) for v in data.get("dns_servers") or []],
            routes=[r for r in data.get("routes") or [] if isinstance(r, dict)],
            error=str(data.get("error") or ""),
        )


def _validate_adapter_name(name: str) -> str:
    text = str(name or "").strip()
    if not _ADAPTER_NAME_RE.match(text):
        raise ValueError("unsafe adapter name: %r" % name)
    return text


def _ps_quote(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def _probe_script(adapter_name: str) -> str:
    """Single read-only PowerShell capture of adapter, addresses and routes."""
    q = _ps_quote(adapter_name)
    return (
        "$ErrorActionPreference='SilentlyContinue';"
        "$a = Get-NetAdapter -Name %s | Select-Object -First 1 Name,Status,ifIndex,InterfaceDescription;"
        "$ip = @(Get-NetIPAddress -InterfaceAlias %s -ErrorAction SilentlyContinue | "
        "  Select-Object IPAddress,AddressFamily,PrefixLength,InterfaceIndex);"
        "$rt = @(Get-NetRoute -InterfaceAlias %s -ErrorAction SilentlyContinue | "
        "  Select-Object DestinationPrefix,NextHop,RouteMetric,InterfaceMetric,AddressFamily);"
        "$dns = @(Get-DnsClientServerAddress -InterfaceAlias %s -ErrorAction SilentlyContinue | "
        "  Select-Object ServerAddresses,AddressFamily);"
        "[pscustomobject]@{adapter=$a; addresses=$ip; routes=$rt; dns=$dns} | "
        "ConvertTo-Json -Depth 5 -Compress"
    ) % (q, q, q, q)


def _parse_probe(raw: str, adapter_name: str) -> AdapterEvidence:
    evidence = AdapterEvidence()
    try:
        data = json.loads(raw) if raw.strip() else {}
    except (json.JSONDecodeError, TypeError) as exc:
        evidence.error = "probe returned invalid JSON: %s" % exc
        return evidence
    if not isinstance(data, dict):
        evidence.error = "probe returned unexpected payload"
        return evidence

    adapter = data.get("adapter") or {}
    if isinstance(adapter, list):
        adapter = adapter[0] if adapter else {}
    if isinstance(adapter, dict) and adapter:
        evidence.present = bool(adapter.get("Name"))
        evidence.up = str(adapter.get("Status", "")).lower() == "up"
        try:
            evidence.if_index = int(adapter.get("ifIndex"))
        except (TypeError, ValueError):
            evidence.if_index = None
    if not evidence.present:
        evidence.error = "adapter %r not present" % adapter_name

    for entry in data.get("addresses") or []:
        if not isinstance(entry, dict):
            continue
        address = str(entry.get("IPAddress") or "").strip()
        if not address:
            continue
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        if isinstance(ip, ipaddress.IPv6Address) and ip.is_link_local:
            continue
        (evidence.ipv6 if isinstance(ip, ipaddress.IPv6Address) else evidence.ipv4).append(address)

    for entry in data.get("routes") or []:
        if not isinstance(entry, dict):
            continue
        prefix = str(entry.get("DestinationPrefix") or "").strip()
        if not prefix:
            continue
        try:
            route_metric = int(entry.get("RouteMetric") or 0)
        except (TypeError, ValueError):
            route_metric = 0
        try:
            interface_metric = int(entry.get("InterfaceMetric") or 0)
        except (TypeError, ValueError):
            interface_metric = 0
        evidence.routes.append({
            "destination_prefix": prefix,
            "next_hop": str(entry.get("NextHop") or ""),
            "route_metric": route_metric,
            "interface_metric": interface_metric,
        })

    for entry in data.get("dns") or []:
        if not isinstance(entry, dict):
            continue
        for server in entry.get("ServerAddresses") or []:
            text = str(server or "").strip()
            if text and text not in evidence.dns_servers:
                evidence.dns_servers.append(text)

    return evidence


def _presence_script(adapter_name: str) -> str:
    """Single, cheap presence check: ``Get-NetAdapter -Name`` alone.

    Deliberately does not capture routes, addresses or DNS; callers use it
    only to gate the heavy full evidence capture.
    """
    q = _ps_quote(adapter_name)
    return (
        "$ErrorActionPreference='SilentlyContinue';"
        "$a = @(Get-NetAdapter -Name %s -ErrorAction SilentlyContinue | "
        "  Select-Object -First 1 Name);"
        "Write-Output ('present=' + [int]($a.Count -gt 0))"
    ) % (q,)


def _foreign_default_route_script(exclude_adapter: str) -> str:
    """List adapters other than ``exclude_adapter`` holding IPv4 0.0.0.0/0."""
    q = _ps_quote(exclude_adapter)
    return (
        "$ErrorActionPreference='SilentlyContinue';"
        "$own = %s;"
        "$r = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 "
        "  -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -and "
        "  $_.InterfaceAlias -ne $own } | Select-Object -ExpandProperty "
        "  InterfaceAlias -Unique);"
        "Write-Output ($r -join '|')"
    ) % (q,)


# Adapters whose alias or description marks them as a competing VPN tunnel.
# The physical adapter's normal gateway default route ("Wi-Fi", "Ethernet",
# "Realtek ...") must never match.
_COMPETING_TUNNEL_RE = re.compile(
    r"wintun|tap|tailscale|singbox|sing-box|wireguard|zero.?tier|openvpn|\btun",
    re.IGNORECASE,
)


def _competing_tunnel_script(exclude_adapter: str) -> str:
    """List ``alias|description`` pairs of other adapters holding 0.0.0.0/0."""
    q = _ps_quote(exclude_adapter)
    return (
        "$ErrorActionPreference='SilentlyContinue';"
        "$own = %s;"
        "$r = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 "
        "  -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -and "
        "  $_.InterfaceAlias -ne $own } | Select-Object -Unique "
        "  InterfaceAlias, InterfaceDescription | ForEach-Object { "
        "  \"$($_.InterfaceAlias)|$($_.InterfaceDescription)\" });"
        "Write-Output ($r -join \"`n\")"
    ) % (q,)


async def detect_competing_tunnel(
    adapter_name: str, *, timeout: float = 5.0
) -> Optional[str]:
    """Name of another TUN-like adapter holding an IPv4 default route.

    Preflight gate for starting the PerchVPN TUN sidecar.  Unlike
    :func:`detect_foreign_default_tunnel` (a stall-time hint), this must not
    flag the physical adapter's own gateway default route: only adapters
    whose alias or interface description looks like a tunnel (Wintun, TAP,
    singbox_tun, Tailscale, ...) count as a competing VPN.
    """
    if sys.platform != "win32":
        return None
    try:
        name = _validate_adapter_name(adapter_name)
    except ValueError:
        name = str(adapter_name or "").strip()
    holders = await asyncio.to_thread(_native_default_route_holders, name)
    if holders is not None:
        for alias, description in holders:
            haystack = "%s %s" % (alias, description)
            if alias and alias != name and _COMPETING_TUNNEL_RE.search(haystack):
                return alias
        return None
    try:
        raw = await asyncio.wait_for(
            asyncio.to_thread(_run_ps, _competing_tunnel_script(name)),
            timeout,
        )
    except Exception:  # noqa: BLE001 - the gate is best-effort
        return None
    text = str(raw or "").strip()
    if not text:
        return None
    for line in text.splitlines():
        line = line.strip()
        if not line or "|" not in line:
            continue
        alias, description = line.split("|", 1)
        alias = alias.strip()
        haystack = "%s %s" % (alias, description)
        if alias and alias != name and _COMPETING_TUNNEL_RE.search(haystack):
            return alias
    return None


async def detect_foreign_default_tunnel(
    adapter_name: str, *, timeout: float = 5.0
) -> Optional[str]:
    """Name of another adapter holding an IPv4 default route, if any.

    Used as a one-shot hint when a freshly pinned TUN adapter stalls: a
    competing tunnel (for example a foreign ``singbox_tun``) owning
    ``0.0.0.0/0`` is the most common reason no traffic traverses the new
    adapter.  Returns None when nothing competes, the check fails, or the
    platform does not support it — a None result must never be presented as
    evidence that everything is fine.
    """
    if sys.platform != "win32":
        return None
    try:
        name = _validate_adapter_name(adapter_name)
    except ValueError:
        name = str(adapter_name or "").strip()
    holders = await asyncio.to_thread(_native_default_route_holders, name)
    if holders is not None:
        # Prefer a tunnel-like holder: the stall hint is most useful when it
        # names the competing VPN, not the physical gateway route that also
        # exists with metric 0.
        for alias, description in holders:
            if _COMPETING_TUNNEL_RE.search("%s %s" % (alias, description)):
                return alias
        return holders[0][0] if holders else None
    try:
        raw = await asyncio.wait_for(
            asyncio.to_thread(_run_ps, _foreign_default_route_script(name)),
            timeout,
        )
    except Exception:  # noqa: BLE001 - the hint is best-effort
        return None
    text = str(raw or "").strip()
    if not text:
        return None
    first = text.split("|")[0].strip()
    return first or None


async def probe_adapter_presence(
    adapter_name: str, *, timeout: float = 5.0
) -> Optional[bool]:
    """Cheap adapter-presence check for reconcile cadence control.

    Returns True/False when the OS answered; None when the check is
    unsupported (non-Windows), the adapter name is invalid, or PowerShell
    failed/timed out.  Callers must treat None as inconclusive and run the
    full evidence probe.
    """
    try:
        name = _validate_adapter_name(adapter_name)
    except ValueError:
        return None
    # Native IP Helper check first: milliseconds, no PowerShell spawn.
    try:
        from perchvpn_windows import iphelper

        if iphelper.available():
            native = iphelper.adapter_present_native(None, name)
            if native is not None:
                return native
    except Exception:  # noqa: BLE001 - presence is a best-effort, cached gate
        pass
    if sys.platform != "win32":
        return None
    try:
        raw = await asyncio.wait_for(asyncio.to_thread(_run_ps, _presence_script(name)), timeout)
    except Exception:  # noqa: BLE001 - presence is a best-effort, cached gate
        return None
    text = str(raw or "").strip()
    if text == "present=1":
        return True
    if text == "present=0":
        return False
    return None


def _native_adapter_evidence(adapter_name: str) -> Optional[AdapterEvidence]:
    """Read the same evidence from ``iphlpapi`` without spawning PowerShell.

    A single ``GetAdaptersAddresses`` walk answers adapters, addresses and DNS
    in ~50 ms; routes come from ``GetIpForwardTable2``.  The batched
    PowerShell probe this replaces measured **6.3-7.6 s** on the production
    host, and the readiness loop calls it every reconcile tick, so the native
    path is both a startup-latency and an idle-CPU fix.

    Returns ``None`` when the native path is unavailable or incomplete; the
    caller then falls back to PowerShell.  A *missing* adapter is authoritative
    and returns ``present=False`` evidence instead.
    """
    try:
        from perchvpn_windows import iphelper

        if not iphelper.available():
            return None
        rows = iphelper.adapters_native()
    except Exception:  # noqa: BLE001 - native path is best-effort
        return None
    if not rows:
        return None

    evidence = AdapterEvidence()
    match = next(
        (row for row in rows if str(row.get("Name") or "") == adapter_name), None
    )
    if match is None:
        evidence.error = "adapter %r not present" % adapter_name
        return evidence

    evidence.present = True
    evidence.up = str(match.get("Status") or "").lower() == "up"
    try:
        evidence.if_index = int(match.get("InterfaceIndex"))
    except (TypeError, ValueError):
        evidence.if_index = None

    for entry in match.get("unicast") or ():
        address = str(entry.get("IPAddress") or "").strip()
        if not address:
            continue
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        if isinstance(ip, ipaddress.IPv6Address) and ip.is_link_local:
            continue
        (evidence.ipv6 if isinstance(ip, ipaddress.IPv6Address) else evidence.ipv4).append(
            address
        )

    for entry in match.get("dns") or ():
        text = str(entry.get("IPAddress") or "").strip()
        if text and text not in evidence.dns_servers:
            evidence.dns_servers.append(text)

    if evidence.if_index is None:
        return None
    try:
        routes = iphelper.routes_native(2) + iphelper.routes_native(23)
    except Exception:  # noqa: BLE001
        return None
    if not routes:
        return None
    interface_metric = 0
    try:
        interface_entry = iphelper.interface_entry_native(evidence.if_index)
        if interface_entry:
            interface_metric = int(interface_entry.get("InterfaceMetric") or 0)
    except Exception:  # noqa: BLE001 - metric is informational only
        interface_metric = 0
    for row in routes:
        try:
            if int(row.get("InterfaceIndex")) != evidence.if_index:
                continue
        except (TypeError, ValueError):
            continue
        prefix = str(row.get("DestinationPrefix") or "").strip()
        if not prefix:
            continue
        try:
            route_metric = int(row.get("RouteMetric") or 0)
        except (TypeError, ValueError):
            route_metric = 0
        metric = row.get("ifMetric")
        try:
            interface_metric_row = int(metric) if metric is not None else interface_metric
        except (TypeError, ValueError):
            interface_metric_row = interface_metric
        evidence.routes.append({
            "destination_prefix": prefix,
            "next_hop": str(row.get("NextHop") or ""),
            "route_metric": route_metric,
            "interface_metric": interface_metric_row,
        })
    return evidence


def _native_default_route_holders(
    exclude_name: str,
) -> Optional[List[tuple]]:
    """``(alias, description)`` of other adapters holding IPv4 0.0.0.0/0.

    ``None`` means the native path is unavailable and the caller must use the
    PowerShell probe.
    """
    try:
        from perchvpn_windows import iphelper

        if not iphelper.available():
            return None
        routes = iphelper.routes_native(2)
        adapters = iphelper.adapters_native()
    except Exception:  # noqa: BLE001
        return None
    if not routes or not adapters:
        return None
    by_index = {}
    for row in adapters:
        try:
            by_index[int(row.get("InterfaceIndex"))] = row
        except (TypeError, ValueError):
            continue
    holders: List[tuple] = []
    seen = set()
    for route in routes:
        if str(route.get("DestinationPrefix") or "") != "0.0.0.0/0":
            continue
        try:
            index = int(route.get("InterfaceIndex"))
        except (TypeError, ValueError):
            continue
        row = by_index.get(index)
        if row is None:
            continue
        alias = str(row.get("Name") or "")
        if not alias or alias == exclude_name or index in seen:
            continue
        seen.add(index)
        holders.append((alias, str(row.get("InterfaceDescription") or "")))
    return holders


async def probe_adapter(adapter_name: str, *, timeout: float = 15.0) -> AdapterEvidence:
    """Read-only capture of the TUN adapter's OS state."""
    try:
        name = _validate_adapter_name(adapter_name)
    except ValueError as exc:
        evidence = AdapterEvidence()
        evidence.error = str(exc)
        return evidence
    if sys.platform != "win32":
        evidence = AdapterEvidence()
        evidence.error = "OS adapter probing is only available on Windows"
        return evidence
    native = await asyncio.to_thread(_native_adapter_evidence, name)
    if native is not None:
        return native
    try:
        raw = await asyncio.wait_for(asyncio.to_thread(_run_ps, _probe_script(name)), timeout)
    except asyncio.TimeoutError:
        evidence = AdapterEvidence()
        evidence.error = "adapter probe timed out"
        return evidence
    except CaptureError as exc:
        evidence = AdapterEvidence()
        evidence.error = str(exc)
        return evidence
    except Exception as exc:  # noqa: BLE001
        evidence = AdapterEvidence()
        evidence.error = "adapter probe failed: %s" % exc
        return evidence
    return _parse_probe(raw, name)


def _parse_trace(body: str) -> Dict[str, str]:
    fields: Dict[str, str] = {}
    for line in body.split("\n"):
        line = line.strip()
        if "=" in line:
            key, _, value = line.partition("=")
            fields[key.strip().lower()] = value.strip()
    return fields


def _direct_https_trace(family: int, timeout: float) -> Dict[str, Any]:
    """Plain OS socket request (no proxy) to a fixed address literal.

    The TLS SNI/Host remain the public name, but no DNS lookup is performed:
    the socket connects straight to a known Cloudflare address. This keeps
    the identity probe working when the TUN's resolver is not yet usable.
    """
    if family == socket.AF_INET:
        targets = _EGRESS_IPV4_TARGETS
    elif family == socket.AF_INET6:
        targets = _EGRESS_IPV6_TARGETS
    else:
        targets = ()
    if not targets:
        return {"ok": False, "family": family, "error": "no IP literal for family"}
    last_error = ""
    for target in targets:
        sock = None
        try:
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, 443))
            context = ssl.create_default_context()
            with context.wrap_socket(sock, server_hostname=_EGRESS_HOST) as tls:
                tls.settimeout(timeout)
                request = (
                    "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n"
                    "User-Agent: perchvpn-tun-egress/1\r\n\r\n" % (_EGRESS_PATH, _EGRESS_HOST)
                )
                tls.sendall(request.encode("ascii"))
                chunks = []
                total = 0
                while total < _MAX_EGRESS_BYTES:
                    data = tls.recv(4096)
                    if not data:
                        break
                    chunks.append(data)
                    total += len(data)
            payload = b"".join(chunks).decode("utf-8", errors="replace")
            body = payload.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in payload else ""
            fields = _parse_trace(body)
            ip = fields.get("ip", "")
            if not ip:
                last_error = "trace response carried no ip field"
                continue
            return {
                "ok": True,
                "family": family,
                "ip": ip,
                "country": (fields.get("loc") or "").upper(),
            }
        except (OSError, ssl.SSLError) as exc:
            last_error = str(exc)
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
    return {"ok": False, "family": family, "error": last_error or "egress probe failed"}


def _direct_tcp_probe(timeout: float) -> Dict[str, Any]:
    """Prove direct IP connectivity without touching the system resolver."""
    last_error = ""
    for host, port in _EGRESS_TCP_TARGETS:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            return {"ok": True, "error": None}
        except OSError as exc:
            last_error = str(exc)
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
    return {"ok": False, "error": last_error or "direct IP probe failed"}


async def probe_system_egress(*, timeout: float = _EGRESS_TIMEOUT) -> Dict[str, Any]:
    """Measure whether *system* traffic can currently leave the machine.

    The resolver-free IP-literal TCP probe is attempted first.  As soon as it
    succeeds ``ok`` is true and the function returns immediately: the identity
    traces (which can be slow or blackholed while the adapter is settling) must
    not delay the readiness verdict.  Callers that need the observed exit
    identity use :func:`probe_system_egress_identity` afterwards.

    When TCP connectivity fails, the two trace probes are still consulted so a
    transient TCP failure does not hide a working tunnel.
    """
    connectivity = await asyncio.to_thread(_direct_tcp_probe, timeout)
    if connectivity.get("ok"):
        return {
            "ok": True,
            "error": None,
            "ipv4": {"ok": True, "error": None, "source": "tcp"},
            "ipv6": {"ok": False, "error": "skipped after TCP connectivity"},
            "tcp": connectivity,
            "checked_at": asyncio.get_running_loop().time(),
        }

    v4, v6 = await asyncio.gather(
        asyncio.to_thread(_direct_https_trace, socket.AF_INET, timeout),
        asyncio.to_thread(_direct_https_trace, socket.AF_INET6, timeout),
    )
    ok = bool(v4.get("ok") or v6.get("ok"))
    error = None if ok else (connectivity.get("error") or "egress probe failed")
    return {
        "ok": ok,
        "error": error,
        "ipv4": v4,
        "ipv6": v6,
        "tcp": connectivity,
        "checked_at": asyncio.get_running_loop().time(),
    }


async def probe_system_egress_identity(
    *, timeout: float = _EGRESS_TIMEOUT
) -> Dict[str, Any]:
    """Best-effort observed exit identity, without the TCP fast path.

    Used after :func:`probe_system_egress` has already proved connectivity but
    the fast result carried no address.  IPv4 is tried first; IPv6 is only
    attempted when IPv4 produced no identity, keeping the common path short.
    """
    v4 = await asyncio.to_thread(_direct_https_trace, socket.AF_INET, timeout)
    if v4.get("ok"):
        return {
            "ok": True,
            "error": None,
            "ipv4": v4,
            "ipv6": {"ok": False, "error": "skipped after IPv4 identity"},
            "checked_at": asyncio.get_running_loop().time(),
        }
    v6 = await asyncio.to_thread(_direct_https_trace, socket.AF_INET6, timeout)
    return {
        "ok": bool(v6.get("ok")),
        "error": None if v6.get("ok") else (v4.get("error") or v6.get("error")),
        "ipv4": v4,
        "ipv6": v6,
        "checked_at": asyncio.get_running_loop().time(),
    }


async def wait_for_system_egress(
    *,
    timeout: float = _EGRESS_SETTLE_TIMEOUT,
    interval: float = _EGRESS_SETTLE_INTERVAL,
    probe_timeout: float = _EGRESS_TIMEOUT,
) -> Dict[str, Any]:
    """Poll egress at the post-adapter settling cadence until it succeeds.

    The first successful IP-literal TCP probe ends the loop immediately, so a
    healthy tunnel is reported on the first (or next 250 ms) attempt instead of
    waiting for a slow identity trace.
    """
    deadline = asyncio.get_running_loop().time() + max(0.0, float(timeout))
    result: Dict[str, Any] = {}
    while True:
        result = await probe_system_egress(timeout=probe_timeout)
        if result.get("ok"):
            return result
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            return result
        await asyncio.sleep(min(max(0.0, float(interval)), remaining))


def classify(
    *,
    enabled: bool,
    opted_in: bool,
    configured: bool,
    elevated: bool,
    process_alive: bool,
    spawn_failed: bool,
    recovery_required: bool,
    evidence: Optional[AdapterEvidence],
    egress: Optional[Dict[str, Any]],
    expected_exit_ip: str,
    expected_country: str,
    baseline: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    """Map real evidence to one honest state + human-readable detail.

    Never reports traffic_verified without direct system-egress evidence.
    """
    if not enabled:
        return {"state": STATE_DISABLED, "detail": "TUN is not enabled; only SOCKS5 clients are tunnelled."}
    if not opted_in:
        return {"state": STATE_NOT_OPTED_IN, "detail": "TUN requires explicit opt-in (tun_opt_in)."}
    if not configured:
        return {"state": STATE_NOT_CONFIGURED, "detail": "sing-box.exe / wintun.dll not found."}
    if not elevated:
        return {"state": STATE_NOT_ELEVATED, "detail": "Administrator privileges are required to create the Wintun adapter and routes."}
    if recovery_required:
        return {"state": STATE_RECOVERY_REQUIRED, "detail": "Previous TUN ownership is unverified; operator action required."}
    if spawn_failed:
        return {"state": STATE_FAILED, "detail": "sing-box failed to start."}
    if not process_alive:
        return {"state": STATE_FAILED, "detail": "sing-box is not running."}

    ev = evidence
    if ev is None:
        return {"state": STATE_STARTING, "detail": "Awaiting first adapter probe."}
    if not ev.present:
        # Wintun adapter creation takes 1-3 s after the sidecar starts. A
        # missing adapter while the process is alive is normal startup
        # progress, never a failure; a premature "failed" verdict here made
        # the UI flip Disconnected and then back to Connecting on the next
        # probe. Only a dead/failed sidecar process is a real failure.
        return {
            "state": STATE_STARTING,
            "detail": "Awaiting Wintun adapter creation%s." % (": " + ev.error if ev.error else ""),
        }
    if not ev.up:
        return {
            "state": STATE_STARTING,
            "detail": "TUN adapter is not Up yet%s." % (": " + ev.error if ev.error else ""),
        }
    if not ev.has_ipv4:
        return {"state": STATE_ADAPTER_READY, "detail": "Adapter is up but has no IPv4 address yet."}
    egress_verified = bool(egress and egress.get("ipv4", {}).get("ok"))
    if not ev.default_route_effective and not egress_verified:
        return {
            "state": STATE_ADAPTER_READY,
            "detail": "Adapter is up with an address but no default-route coverage is installed.",
        }
    # Observed system egress outranks the route-table heuristic: when the
    # probe actually flows, the leak/mismatch verdicts below are strictly
    # stronger evidence than coverage of a decomposed route table.
    if not egress_verified:
        return {
            "state": STATE_ROUTES_CONFIGURED,
            "detail": "Adapter and split default routes are active; system egress not yet verified.",
        }

    v4 = egress.get("ipv4") or {}
    v6 = egress.get("ipv6") or {}
    observed_ips = {str(v4.get("ip") or ""), str(v6.get("ip") or "")} - {""}
    observed_countries = {str(v4.get("country") or ""), str(v6.get("country") or "")} - {""}

    matches_exit = bool(expected_exit_ip and expected_exit_ip in observed_ips)
    matches_country = bool(expected_country and expected_country.upper() in observed_countries)
    baseline_ips = set()
    if baseline:
        for key in ("ipv4", "ipv6"):
            entry = baseline.get(key) or {}
            if entry.get("ip"):
                baseline_ips.add(str(entry.get("ip")))
    leaked = bool(baseline_ips and (observed_ips & baseline_ips))

    if leaked:
        return {
            "state": STATE_DEGRADED,
            "detail": "System traffic still exits through the physical path (%s) - routes are not effective." % ", ".join(sorted(observed_ips)),
        }
    if (matches_exit or matches_country) or (not expected_exit_ip and not expected_country and observed_ips):
        return {
            "state": STATE_TRAFFIC_VERIFIED,
            "detail": "System traffic exits through the VPN (%s)." % ", ".join(sorted(observed_ips)),
        }
    if not observed_ips and v4.get("ok"):
        return {
            "state": STATE_TRAFFIC_VERIFIED,
            "detail": "System traffic exits through the VPN (verified).",
        }
    return {
        "state": STATE_TUNNEL_OPERATIONAL,
        "detail": "System traffic leaves the machine (egress %s) but does not yet match the expected VPN exit."
        % (", ".join(sorted(observed_ips)) or "unknown"),
    }
