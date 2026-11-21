"""Read-only capture and comparison of Windows network state for TUN trial."""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from perchvpn_windows.win_process import powershell_argv, run_hidden

_SILENTLY_CONTINUE_RE = re.compile(
    r"(?i)-ErrorAction(?::|\s+)['\"]?SilentlyContinue\b"
)
_MISSING_OBJECT_MARKERS = (
    "ObjectNotFound",
    "CmdletizationQuery_NotFound",
    "CimJobException",
    "Element not found",
    "No matching MSFT_NetRoute",
)


class CaptureError(Exception):
    """Raised when a read-only state capture fails or is incomplete."""


def _run_ps(script: str) -> str:
    """Run a PowerShell script and return stdout.  Read-only.

    Raises CaptureError on failure or timeout.
    """
    try:
        completed = run_hidden(
            powershell_argv(script, executable="powershell"),
            capture_output=True,
            text=True,
            timeout=30.0,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CaptureError("PowerShell execution failed: %s" % exc) from exc
    if completed.returncode != 0:
        raise CaptureError(
            "PowerShell returned %d: %s" % (completed.returncode, completed.stderr or "")
        )
    result = completed.stdout or ""
    if not result.strip():
        raise CaptureError("PowerShell returned empty output")
    return result


def _parse_json(out: str, label: str) -> Any:
    if not out.strip():
        raise CaptureError("%s capture returned empty output" % label)
    try:
        data = json.loads(out)
    except (json.JSONDecodeError, TypeError) as exc:
        raise CaptureError("%s capture returned invalid JSON: %s" % (label, exc)) from exc
    return data


def _validate_records(
    data: Any,
    label: str,
    required_keys: tuple,
    nullable_keys: tuple = (),
    allow_empty: bool = False,
) -> List[Dict[str, Any]]:
    """Normalize dict to list, validate type, emptiness, and required keys per record.

    Args:
        data: The parsed JSON data (list or single dict).
        label: Human-readable label for error messages.
        required_keys: Keys that must be present in each record with non-None values.
        nullable_keys: Keys that must be present in each record but may have None values.
        allow_empty: If True, empty list is allowed.
    """
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        raise CaptureError("%s capture returned unexpected type" % label)
    if not data and not allow_empty:
        raise CaptureError("%s capture returned empty list" % label)
    for item in data:
        if not isinstance(item, dict):
            raise CaptureError("%s capture returned non-object record" % label)
        for key in required_keys:
            if key not in item or item[key] is None:
                raise CaptureError(
                    "%s capture record missing required key: %s" % (label, key)
                )
        for key in nullable_keys:
            if key not in item:
                raise CaptureError(
                    "%s capture record missing nullable key: %s" % (label, key)
                )
    return data


def _validated_routes(data: Any) -> List[Dict[str, Any]]:
    data = _validate_records(
        data,
        "route",
        ("DestinationPrefix", "NextHop", "InterfaceIndex", "RouteMetric", "PolicyStore"),
        nullable_keys=("ifMetric",),
        allow_empty=False,
    )
    # Raise if no route has PolicyStore == "ActiveStore" (or 1)
    if not any(r.get("PolicyStore") in ("ActiveStore", 1) for r in data):
        raise CaptureError("route capture: no route found with PolicyStore ActiveStore")
    return data


def capture_routes() -> List[Dict[str, Any]]:
    """Capture IPv4/IPv6 routes (read-only). Raises CaptureError on failure."""
    script = (
        "@("
        "@(Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop | "
        "Select-Object DestinationPrefix, NextHop, InterfaceIndex, RouteMetric, ifMetric, "
        "@{Name='PolicyStore';Expression={'ActiveStore'}}) + "
        "@(Get-NetRoute -PolicyStore PersistentStore -ErrorAction SilentlyContinue | "
        "Select-Object DestinationPrefix, NextHop, InterfaceIndex, RouteMetric, ifMetric, "
        "@{Name='PolicyStore';Expression={'PersistentStore'}})"
        ") | ConvertTo-Json -Compress"
    )
    out = _run_ps(script)
    data = _parse_json(out, "route")
    return _validated_routes(data)


def _validated_dns(data: Any) -> List[Dict[str, Any]]:
    return _validate_records(
        data,
        "DNS",
        ("InterfaceIndex", "AddressFamily", "ServerAddresses"),
        allow_empty=False,
    )


def capture_dns() -> List[Dict[str, Any]]:
    """Capture DNS server assignments (read-only). Raises CaptureError on failure."""
    script = (
        "Get-DnsClientServerAddress | Select-Object InterfaceIndex, AddressFamily, "
        "ServerAddresses | ConvertTo-Json -Compress"
    )
    out = _run_ps(script)
    data = _parse_json(out, "DNS")
    return _validated_dns(data)


def _validated_adapters(data: Any) -> List[Dict[str, Any]]:
    return _validate_records(
        data,
        "adapter",
        ("Name", "InterfaceGuid", "InterfaceIndex", "Status"),
        allow_empty=False,
    )


def capture_adapters() -> List[Dict[str, Any]]:
    """Capture network adapters (read-only). Raises CaptureError on failure."""
    script = (
        "Get-NetAdapter | Select-Object Name, InterfaceGuid, InterfaceIndex, Status, "
        "InterfaceDescription | ConvertTo-Json -Compress"
    )
    out = _run_ps(script)
    data = _parse_json(out, "adapter")
    return _validated_adapters(data)


def _validated_ip_addresses(data: Any) -> List[Dict[str, Any]]:
    return _validate_records(
        data,
        "IP address",
        ("InterfaceIndex", "IPAddress", "PrefixLength", "AddressFamily"),
        allow_empty=False,
    )


def capture_ip_addresses() -> List[Dict[str, Any]]:
    """Capture IP addresses (read-only). Raises CaptureError on failure."""
    script = (
        "Get-NetIPAddress | Select-Object InterfaceIndex, IPAddress, PrefixLength, "
        "AddressFamily | ConvertTo-Json -Compress"
    )
    out = _run_ps(script)
    data = _parse_json(out, "IP address")
    return _validated_ip_addresses(data)


def _validated_interface_config(data: Any) -> List[Dict[str, Any]]:
    return _validate_records(
        data,
        "interface config",
        ("InterfaceIndex", "AddressFamily"),
        nullable_keys=("NlMtu", "InterfaceMetric", "ConnectionState"),
        allow_empty=False,
    )


def capture_interface_config() -> List[Dict[str, Any]]:
    """Capture interface metrics and MTU (read-only). Raises CaptureError on failure."""
    script = (
        "Get-NetIPInterface | Select-Object InterfaceIndex, InterfaceAlias, AddressFamily, "
        "@{Name='NlMtu';Expression={if ($null -ne $_.NlMtu) { $_.NlMtu } else { $_.NlMtuBytes }}}, "
        "InterfaceMetric, ConnectionState | ConvertTo-Json -Compress"
    )
    out = _run_ps(script)
    data = _parse_json(out, "interface config")
    return _validated_interface_config(data)


def capture_winhttp_proxy() -> str:
    """Capture WinHTTP proxy settings (read-only). Raises CaptureError on failure."""
    try:
        completed = run_hidden(
            ["netsh", "winhttp", "show", "proxy"],
            capture_output=True,
            text=True,
            timeout=10.0,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CaptureError("WinHTTP proxy capture failed: %s" % exc) from exc
    if completed.returncode != 0:
        raise CaptureError(
            "netsh winhttp returned %d: %s" % (completed.returncode, completed.stderr or "")
        )
    result = (completed.stdout or "").strip()
    if not result:
        raise CaptureError("WinHTTP proxy capture returned empty output")
    return result


# One PowerShell spawn answers every read-only question the pre-start recovery
# gate asks.  Each per-query capture above costs its own powershell.exe process
# startup (1-3 s wall, ~0.3-0.5 CPU-s), so the gate's snapshot used to cost six
# spawns even after the worker-pool parallelization; the batched script keeps
# the exact same read-only queries but pays the startup price once.
_BATCHED_SNAPSHOT_SCRIPT = (
    "$routes=$null;$dns=$null;$adapters=$null;$ips=$null;$ifc=$null;$winhttp='';"
    "$e=[ordered]@{};"
    "try { $routes = @("
    "@(Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop | "
    "Select-Object DestinationPrefix, NextHop, InterfaceIndex, RouteMetric, ifMetric, "
    "@{Name='PolicyStore';Expression={'ActiveStore'}}) + "
    "@(Get-NetRoute -PolicyStore PersistentStore -ErrorAction SilentlyContinue | "
    "Select-Object DestinationPrefix, NextHop, InterfaceIndex, RouteMetric, ifMetric, "
    "@{Name='PolicyStore';Expression={'PersistentStore'}})"
    ") } catch { $e.routes = $_.Exception.Message }"
    "try { $dns = @(Get-DnsClientServerAddress | Select-Object InterfaceIndex, "
    "AddressFamily, ServerAddresses) } catch { $e.dns = $_.Exception.Message }"
    "try { $adapters = @(Get-NetAdapter | Select-Object Name, InterfaceGuid, "
    "InterfaceIndex, Status, InterfaceDescription) } catch { $e.adapters = $_.Exception.Message }"
    "try { $ips = @(Get-NetIPAddress | Select-Object InterfaceIndex, IPAddress, "
    "PrefixLength, AddressFamily) } catch { $e.ip_addresses = $_.Exception.Message }"
    "try { $ifc = @(Get-NetIPInterface | Select-Object InterfaceIndex, InterfaceAlias, "
    "AddressFamily, "
    "@{Name='NlMtu';Expression={if ($null -ne $_.NlMtu) { $_.NlMtu } else { $_.NlMtuBytes }}}, "
    "InterfaceMetric, ConnectionState) } catch { $e.interface_config = $_.Exception.Message }"
    "try { $winhttp = (& netsh winhttp show proxy 2>&1 | Out-String).Trim() } "
    "catch { $e.winhttp_proxy = $_.Exception.Message }"
    "ConvertTo-Json -InputObject ([ordered]@{routes=$routes;dns=$dns;adapters=$adapters;"
    "ip_addresses=$ips;interface_config=$ifc;winhttp_proxy=$winhttp;errors=$e}) "
    "-Compress -Depth 6"
)


def capture_snapshot_batched() -> NetworkSnapshot:
    """Capture the full network snapshot in one PowerShell invocation.

    Raises CaptureError if the single spawn fails, the payload is malformed,
    or any section errored/failed validation — the caller then falls back to
    the per-query pool capture.
    """
    out = _run_ps(_BATCHED_SNAPSHOT_SCRIPT)
    data = _parse_json(out, "snapshot")
    if not isinstance(data, dict):
        raise CaptureError("snapshot capture returned unexpected payload")
    failures: Dict[str, str] = {
        str(k): str(v)
        for k, v in (data.get("errors") or {}).items()
        if v
    }

    def _section(key: str, validator) -> Any:
        payload = data.get(key)
        if payload is None and key not in failures:
            failures[key] = "section missing from batched capture"
            return None
        try:
            return validator(payload)
        except CaptureError as exc:
            failures[key] = str(exc)
            return None

    routes = _section("routes", _validated_routes)
    dns = _section("dns", _validated_dns)
    adapters = _section("adapters", _validated_adapters)
    ip_addresses = _section("ip_addresses", _validated_ip_addresses)
    interface_config = _section("interface_config", _validated_interface_config)
    winhttp = str(data.get("winhttp_proxy") or "")
    if not winhttp and "winhttp_proxy" not in failures:
        failures["winhttp_proxy"] = "empty output"

    if failures:
        # Deterministic canonical order regardless of section evaluation order.
        raise CaptureError("; ".join("%s: %s" % (k, failures[k]) for k in sorted(failures)))
    return NetworkSnapshot(
        routes=routes,
        dns=dns,
        adapters=adapters,
        ip_addresses=ip_addresses,
        interface_config=interface_config,
        winhttp_proxy=winhttp,
    )


def capture_snapshot_preferred() -> NetworkSnapshot:
    """Native IP Helper capture when possible, then batched, then the pool.

    The native path answers every section through ``iphlpapi.dll`` in
    milliseconds, which keeps the TUN pre-start gate inside the startup
    preflight budget even with a competing tunnel present.  Batched/pool
    PowerShell capture remains as the fallback when native capture is
    unavailable (non-Windows) or its sanity guards reject the data.
    """
    try:
        return capture_snapshot_native()
    except CaptureError:
        pass
    try:
        return capture_snapshot_batched()
    except CaptureError:
        return capture_snapshot()


def capture_snapshot_native() -> NetworkSnapshot:
    """Capture the full snapshot via ``iphlpapi.dll`` (no process spawn).

    Raises CaptureError when native capture is unavailable, returns no
    usable data, or fails a section validator — the caller then falls back
    to the PowerShell captures.
    """
    from perchvpn_windows import iphelper

    if not iphelper.available():
        raise CaptureError("native capture unavailable on this platform")
    adapters = iphelper.adapters_native()
    if not adapters:
        raise CaptureError("native adapter capture returned no rows")
    adapter_rows: List[Dict[str, Any]] = []
    dns_rows: List[Dict[str, Any]] = []
    for row in adapters:
        adapter_rows.append(
            {
                "Name": row.get("Name") or "",
                "InterfaceGuid": row.get("InterfaceGuid") or "",
                "InterfaceIndex": row.get("InterfaceIndex"),
                "Status": row.get("Status") or "",
                "InterfaceDescription": row.get("InterfaceDescription") or "",
            }
        )
        servers_by_family: Dict[int, List[str]] = {}
        for entry in row.get("dns") or ():
            family = entry.get("AddressFamily")
            text = str(entry.get("IPAddress") or "").strip()
            if family not in (2, 23) or not text:
                continue
            servers_by_family.setdefault(family, []).append(text)
        for family, servers in servers_by_family.items():
            dns_rows.append(
                {
                    "InterfaceIndex": row.get("InterfaceIndex"),
                    "AddressFamily": family,
                    "ServerAddresses": servers,
                }
            )
    if not dns_rows:
        raise CaptureError("native DNS capture returned no rows")
    ip_addresses = iphelper.unicast_native()
    if not ip_addresses:
        raise CaptureError("native unicast address capture returned no rows")
    routes = iphelper.routes_native(2) + iphelper.routes_native(23)
    if not routes:
        raise CaptureError("native route capture returned no rows")
    interface_config: List[Dict[str, Any]] = []
    v6_indexes = {
        int(rec["InterfaceIndex"])
        for rec in ip_addresses
        if rec.get("AddressFamily") == 23
    }
    for row in adapter_rows:
        index = row.get("InterfaceIndex")
        for family in (2, 23):
            if family == 23 and int(index or 0) not in v6_indexes:
                continue
            entry = iphelper.interface_entry_native(int(index or 0), family)
            if entry is None:
                # Filter/miniport sub-adapters have no IP interface of their
                # own (GetIpInterfaceEntry returns ERROR_NOT_FOUND); the
                # PowerShell capture lists only real IP interfaces either.
                continue
            connected = entry.get("Connected")
            interface_config.append(
                {
                    "InterfaceIndex": index,
                    "InterfaceAlias": row.get("Name") or "",
                    "AddressFamily": family,
                    "NlMtu": entry.get("NlMtu"),
                    "InterfaceMetric": entry.get("InterfaceMetric"),
                    "ConnectionState": (
                        "Connected" if connected else "Disconnected"
                    ),
                }
            )
    if not interface_config:
        raise CaptureError("native interface config capture returned no rows")
    winhttp = capture_winhttp_proxy()
    return NetworkSnapshot(
        routes=routes,
        dns=dns_rows,
        adapters=adapter_rows,
        ip_addresses=ip_addresses,
        interface_config=interface_config,
        winhttp_proxy=winhttp,
    )


@dataclass
class NetworkSnapshot:
    """A read-only snapshot of Windows network state."""

    routes: List[Dict[str, Any]] = field(default_factory=list)
    dns: List[Dict[str, Any]] = field(default_factory=list)
    adapters: List[Dict[str, Any]] = field(default_factory=list)
    ip_addresses: List[Dict[str, Any]] = field(default_factory=list)
    interface_config: List[Dict[str, Any]] = field(default_factory=list)
    winhttp_proxy: str = ""
    captured_at: float = 0.0

    def __post_init__(self) -> None:
        if not self.captured_at:
            self.captured_at = time.time()

    def validate(self) -> None:
        """Validate that the snapshot contains all required data.

        Raises CaptureError if any required field is empty or incomplete.
        """
        if not self.routes:
            raise CaptureError("snapshot has empty routes")
        if not self.dns:
            raise CaptureError("snapshot has empty dns")
        if not self.adapters:
            raise CaptureError("snapshot has empty adapters")
        if not self.ip_addresses:
            raise CaptureError("snapshot has empty ip_addresses")
        if not self.interface_config:
            raise CaptureError("snapshot has empty interface_config")
        if not self.winhttp_proxy.strip():
            raise CaptureError("snapshot has empty winhttp_proxy")

        # Re-validate each record type against its schema
        _validate_records(
            self.routes,
            "route",
            ("DestinationPrefix", "NextHop", "InterfaceIndex", "RouteMetric", "PolicyStore"),
            nullable_keys=("ifMetric",),
            allow_empty=False,
        )
        _validate_records(
            self.dns,
            "dns",
            ("InterfaceIndex", "AddressFamily", "ServerAddresses"),
            allow_empty=False,
        )
        _validate_records(
            self.adapters,
            "adapter",
            ("Name", "InterfaceGuid", "InterfaceIndex", "Status"),
            allow_empty=False,
        )
        _validate_records(
            self.ip_addresses,
            "ip_address",
            ("InterfaceIndex", "IPAddress", "PrefixLength", "AddressFamily"),
            allow_empty=False,
        )
        _validate_records(
            self.interface_config,
            "interface_config",
            ("InterfaceIndex", "AddressFamily"),
            nullable_keys=("NlMtu", "InterfaceMetric", "ConnectionState"),
            allow_empty=False,
        )

    def to_dict(self) -> dict:
        return {
            "routes": self.routes,
            "dns": self.dns,
            "adapters": self.adapters,
            "ip_addresses": self.ip_addresses,
            "interface_config": self.interface_config,
            "winhttp_proxy": self.winhttp_proxy,
            "captured_at": self.captured_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "NetworkSnapshot":
        if not isinstance(data, dict):
            raise ValueError("snapshot must be a dict")
        snap = cls(
            routes=data.get("routes", []),
            dns=data.get("dns", []),
            adapters=data.get("adapters", []),
            ip_addresses=data.get("ip_addresses", []),
            interface_config=data.get("interface_config", []),
            winhttp_proxy=data.get("winhttp_proxy", ""),
            captured_at=data.get("captured_at", 0.0),
        )
        # Always validate when from_dict is called (snapshot was provided)
        snap.validate()
        return snap


def capture_snapshot() -> NetworkSnapshot:
    """Capture a read-only snapshot of current network state.

    Raises CaptureError if any capture fails or returns incomplete data.

    The six captures are independent read-only queries, so they run in a
    small worker pool instead of six sequential ``powershell`` spawns: each
    spawn costs 1-3 s of Windows process startup, and serialized captures
    blocked the TUN launch path for ~15 s on the critical path.
    """
    import concurrent.futures

    captures = (
        ("routes", capture_routes),
        ("dns", capture_dns),
        ("adapters", capture_adapters),
        ("ip_addresses", capture_ip_addresses),
        ("interface_config", capture_interface_config),
        ("winhttp_proxy", capture_winhttp_proxy),
    )
    results: Dict[str, Any] = {}
    errors: List[tuple] = []
    order = {key: i for i, (key, _) in enumerate(captures)}
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(captures)) as pool:
        futures = {
            pool.submit(fn): key
            for key, fn in captures
        }
        for future in concurrent.futures.as_completed(futures):
            key = futures[future]
            try:
                results[key] = future.result()
            except CaptureError as exc:
                errors.append((key, str(exc)))
            except Exception as exc:  # noqa: BLE001 - normalize to CaptureError
                errors.append((key, str(exc)))
    if errors:
        # Deterministic canonical order regardless of thread completion order.
        parts = [msg for key, msg in sorted(errors, key=lambda item: order[item[0]])]
        raise CaptureError("; ".join(parts))
    return NetworkSnapshot(
        routes=results["routes"],
        dns=results["dns"],
        adapters=results["adapters"],
        ip_addresses=results["ip_addresses"],
        interface_config=results["interface_config"],
        winhttp_proxy=results["winhttp_proxy"],
    )


@dataclass
class StateDifference:
    """A single difference between baseline and current state."""

    category: str
    description: str
    baseline_value: Any = None
    current_value: Any = None


def compare_snapshots(
    baseline: NetworkSnapshot, current: NetworkSnapshot
) -> List[StateDifference]:
    """Compare two snapshots and return a list of differences.

    Raises CaptureError if either snapshot is empty or incomplete.
    """
    baseline.validate()
    current.validate()

    diffs: List[StateDifference] = []

    # Compare adapters by Name; also check Status/InterfaceIndex/InterfaceGuid
    baseline_adapters = {
        a["Name"]: a for a in baseline.adapters if isinstance(a, dict) and "Name" in a
    }
    current_adapters = {
        a["Name"]: a for a in current.adapters if isinstance(a, dict) and "Name" in a
    }
    for name in set(baseline_adapters) | set(current_adapters):
        if name in baseline_adapters and name not in current_adapters:
            diffs.append(
                StateDifference(
                    category="adapter",
                    description="Adapter removed: %s" % name,
                    baseline_value=baseline_adapters[name],
                    current_value=None,
                )
            )
        elif name not in baseline_adapters and name in current_adapters:
            diffs.append(
                StateDifference(
                    category="adapter",
                    description="Adapter added: %s" % name,
                    baseline_value=None,
                    current_value=current_adapters[name],
                )
            )
        else:
            ba = baseline_adapters[name]
            ca = current_adapters[name]
            for key in ("Status", "InterfaceIndex", "InterfaceGuid"):
                if ba.get(key) != ca.get(key):
                    diffs.append(
                        StateDifference(
                            category="adapter",
                            description="%s changed for adapter %s: %s" % (key, name, ca.get(key)),
                            # Full records: consistent identity payloads
                            # for partition_diffs and rollback.
                            baseline_value=ba,
                            current_value=ca,
                        )
                    )

    # Routes: key by (DestinationPrefix, NextHop, InterfaceIndex, PolicyStore)
    def route_key(r):
        return (
            r.get("DestinationPrefix"),
            r.get("NextHop"),
            r.get("InterfaceIndex"),
            r.get("PolicyStore", "ActiveStore"),
        )

    baseline_routes = {route_key(r): r for r in baseline.routes if isinstance(r, dict)}
    current_routes = {route_key(r): r for r in current.routes if isinstance(r, dict)}

    for key in set(baseline_routes) | set(current_routes):
        if key in baseline_routes and key not in current_routes:
            diffs.append(
                StateDifference(
                    category="route",
                    description="Route removed: %s" % str(key),
                    baseline_value=baseline_routes[key],
                    current_value=None,
                )
            )
        elif key not in baseline_routes and key in current_routes:
            diffs.append(
                StateDifference(
                    category="route",
                    description="Route added: %s" % str(key),
                    baseline_value=None,
                    current_value=current_routes[key],
                )
            )
        else:
            br = baseline_routes[key]
            cr = current_routes[key]
            for rkey in ("RouteMetric",):
                if br.get(rkey) != cr.get(rkey):
                    diffs.append(
                        StateDifference(
                            category="route",
                            description="%s changed for route %s: %s -> %s" % (rkey, key, br.get(rkey), cr.get(rkey)),
                            # Carry the full records so rollback can restore
                            # the exact route identity and metric.
                            baseline_value=br,
                            current_value=cr,
                        )
                    )

    # DNS: key by (InterfaceIndex, AddressFamily)
    baseline_dns = {
        (d.get("InterfaceIndex"), d.get("AddressFamily")): d for d in baseline.dns if isinstance(d, dict)
    }
    current_dns = {
        (d.get("InterfaceIndex"), d.get("AddressFamily")): d for d in current.dns if isinstance(d, dict)
    }
    for key in set(baseline_dns) | set(current_dns):
        b = baseline_dns.get(key)
        c = current_dns.get(key)
        if b is None:
            diffs.append(
                StateDifference(
                    category="dns",
                    description="DNS added for interface %s" % key[1] if key[1] else "DNS added",
                    baseline_value=None,
                    current_value=c,
                )
            )
        elif c is None:
            diffs.append(
                StateDifference(
                    category="dns",
                    description="DNS removed for interface %s" % key[1] if key[1] else "DNS removed",
                    baseline_value=b,
                    current_value=None,
                )
            )
        elif b.get("ServerAddresses") != c.get("ServerAddresses"):
            diffs.append(
                StateDifference(
                    category="dns",
                    description="DNS changed for interface %s" % key[1] if key[1] else "DNS changed",
                    baseline_value=b,
                    current_value=c,
                )
            )

    # IP addresses: key by (InterfaceIndex, IPAddress, AddressFamily)
    baseline_ips = {
        (ip.get("InterfaceIndex"), ip.get("IPAddress"), ip.get("AddressFamily")): ip
        for ip in baseline.ip_addresses
        if isinstance(ip, dict)
    }
    current_ips = {
        (ip.get("InterfaceIndex"), ip.get("IPAddress"), ip.get("AddressFamily")): ip
        for ip in current.ip_addresses
        if isinstance(ip, dict)
    }
    for key in set(baseline_ips) | set(current_ips):
        if key in baseline_ips and key not in current_ips:
            diffs.append(
                StateDifference(
                    category="ip_address",
                    description="IP removed: %s" % str(key),
                    baseline_value=baseline_ips[key],
                    current_value=None,
                )
            )
        elif key not in baseline_ips and key in current_ips:
            diffs.append(
                StateDifference(
                    category="ip_address",
                    description="IP added: %s" % str(key),
                    baseline_value=None,
                    current_value=current_ips[key],
                )
            )
        else:
            bi = baseline_ips[key]
            ci = current_ips[key]
            if bi.get("PrefixLength") != ci.get("PrefixLength"):
                diffs.append(
                    StateDifference(
                        category="ip_address",
                        description="PrefixLength changed for IP %s: %s -> %s" % (key[1], bi.get("PrefixLength"), ci.get("PrefixLength")),
                        # Full records: rollback needs identity + address family.
                        baseline_value=bi,
                        current_value=ci,
                    )
                )

    # Interface config: key by (InterfaceIndex, AddressFamily)
    baseline_iface = {
        (i.get("InterfaceIndex"), i.get("AddressFamily")): i for i in baseline.interface_config if isinstance(i, dict)
    }
    current_iface = {
        (i.get("InterfaceIndex"), i.get("AddressFamily")): i for i in current.interface_config if isinstance(i, dict)
    }
    for key in set(baseline_iface) | set(current_iface):
        b = baseline_iface.get(key)
        c = current_iface.get(key)
        if b is None:
            diffs.append(
                StateDifference(
                    category="interface",
                    description="Interface %s added" % key[1] if key[1] else "Interface added",
                    baseline_value=None,
                    current_value=c,
                )
            )
        elif c is None:
            diffs.append(
                StateDifference(
                    category="interface",
                    description="Interface %s removed" % key[1] if key[1] else "Interface removed",
                    baseline_value=b,
                    current_value=None,
                )
            )
        else:
            for ckey in ("NlMtu", "InterfaceMetric"):
                if b.get(ckey) != c.get(ckey):
                    diffs.append(
                        StateDifference(
                            category="interface",
                            description="%s changed for interface %s: %s -> %s" % (ckey, key, b.get(ckey), c.get(ckey)),
                            # Full records: rollback needs index + family.
                            baseline_value=b,
                            current_value=c,
                        )
                    )

    # WinHTTP proxy
    if baseline.winhttp_proxy.strip() != current.winhttp_proxy.strip():
        diffs.append(
            StateDifference(
                category="proxy",
                description="WinHTTP proxy changed",
                baseline_value=baseline.winhttp_proxy,
                current_value=current.winhttp_proxy,
            )
        )

    return diffs


def _is_tproxy_route(route: dict) -> bool:
    """True for route records tproxy-config is known to write on host interfaces:
    the IPv4 default route and the trial TUN subnet/gateway (10.0.0.x)."""
    dst = str(route.get("DestinationPrefix", ""))
    nh = str(route.get("NextHop", ""))
    return dst == "0.0.0.0/0" or nh == "10.0.0.1" or dst.startswith("10.0.0.")


def partition_diffs(
    diffs: List[StateDifference],
    *,
    adapter_name: str,
    current_snapshot: Optional["NetworkSnapshot"] = None,
    baseline_snapshot: Optional["NetworkSnapshot"] = None,
) -> tuple:
    """Split diffs into trial-owned versus ambient (external) drift.

    A diff is considered trial-owned when it targets a resource the trial
    manifest owns:

    - route/ip_address/interface diffs whose ``InterfaceIndex`` belong to an
      adapter named *adapter_name* present in ``current_snapshot``;
    - when *baseline_snapshot* is given, route/ip_address/interface diffs on
      an ``InterfaceIndex`` absent from the baseline adapters (a trial-created
      interface, or a residual record — e.g. a PersistentStore route — still
      bound to a vanished trial adapter's ifIndex);
    - when *baseline_snapshot* is given, route diffs on pre-existing
      interfaces matching one of tproxy-config's known mutations: the IPv4
      default route (``0.0.0.0/0``) or the trial TUN subnet/gateway
      (``10.0.0.*``, next hop ``10.0.0.1``);
    - adapter diffs naming *adapter_name* itself;
    - DNS diffs (the sidecar's DNS shim mutates host interfaces);
    - proxy diffs (owned by design).

    Everything else — e.g. an ambient multicast-route removal on a foreign
    tunnel adapter such as ``singbox_tun`` — is ambient: it must be reported
    and preserved, never remediated.
    """
    trial_indexes = set()
    if current_snapshot is not None:
        for adapter in current_snapshot.adapters:
            if str(adapter.get("Name", "")) == adapter_name:
                try:
                    trial_indexes.add(int(adapter.get("InterfaceIndex", 0)))
                except (TypeError, ValueError):
                    continue

    baseline_if_indexes = set()
    if baseline_snapshot is not None:
        for adapter in baseline_snapshot.adapters:
            idx = adapter.get("InterfaceIndex")
            if idx is None:
                continue
            try:
                baseline_if_indexes.add(int(idx))
            except (TypeError, ValueError):
                continue

    owned: List[StateDifference] = []
    ambient: List[StateDifference] = []

    for diff in diffs:
        if diff.category == "dns" or diff.category == "proxy":
            owned.append(diff)
            continue
        if diff.category == "adapter":
            name = str((diff.current_value or {}).get("Name", ""))
            (owned if name == adapter_name else ambient).append(diff)
            continue
        if diff.category in ("route", "ip_address", "interface"):
            # For changed-property diffs (RouteMetric, NlMtu, PrefixLength)
            # the current value is the bare scalar; the identity record
            # (InterfaceIndex) lives in the baseline value.
            value = (
                diff.current_value
                if isinstance(diff.current_value, dict)
                else diff.baseline_value
            )
            if not isinstance(value, dict):
                value = {}
            try:
                index = int(value.get("InterfaceIndex", 0))
            except (TypeError, ValueError, AttributeError):
                index = 0
            if index in trial_indexes:
                owned.append(diff)
                continue
            if baseline_snapshot is not None:
                if index not in baseline_if_indexes:
                    # ifIndex created after baseline capture: trial-created
                    # interface, or residual record bound to a vanished
                    # trial adapter's ifIndex.
                    owned.append(diff)
                    continue
                if diff.category == "route" and _is_tproxy_route(value):
                    owned.append(diff)
                    continue
            ambient.append(diff)
            continue
        ambient.append(diff)

    return owned, ambient


def generate_rollback_commands(
    diffs: List[StateDifference],
) -> List[str]:
    """Generate PowerShell remediation commands from snapshot diffs.

    Each diff is translated into one or more targeted PowerShell commands that
    attempt to restore the network state to its baseline value.  Commands are
    returned as strings and should be executed via :func:`_run_ps_write`.

    Args:
        diffs: List of :class:`StateDifference` objects describing mutations
               between baseline and current network state.

    Returns:
        A list of PowerShell command strings, in execution order.
    """
    commands: List[str] = []

    for d in diffs:
        cat = d.category
        desc = d.description
        baseline = d.baseline_value
        current = d.current_value

        if cat == "route":
            commands.extend(_rollback_route(desc, baseline, current))
        elif cat == "dns":
            commands.extend(_rollback_dns(desc, baseline, current))
        elif cat == "adapter":
            commands.extend(_rollback_adapter(desc, baseline, current))
        elif cat == "ip_address":
            commands.extend(_rollback_ip_address(desc, baseline, current))
        elif cat == "interface":
            commands.extend(_rollback_interface(desc, baseline))
        elif cat == "proxy":
            baseline_proxy = (baseline or "").strip()
            if "Direct access" in baseline_proxy:
                commands.append("netsh winhttp reset proxy -ErrorAction Stop")
            else:
                raise RollbackError(
                    "cannot exactly restore winhttp proxy baseline %r; "
                    "refusing reset-to-direct" % baseline_proxy
                )

    return commands


class RollbackError(Exception):
    """Raised when trial rollback cannot fully restore baseline network state."""

    pass


def _tolerates_missing_objects(script: str) -> bool:
    """Return True when the script opted out of missing-object errors."""
    return bool(_SILENTLY_CONTINUE_RE.search(script or ""))


def _is_missing_object_text(text: str) -> bool:
    """Return True when PowerShell output is only a missing-object notice."""
    lowered = (text or "").casefold()
    return any(marker.casefold() in lowered for marker in _MISSING_OBJECT_MARKERS)


def _run_ps_write(script: str) -> str:
    """Run a mutating PowerShell script and return stdout.

    This function executes state-changing PowerShell commands (route add/remove,
    DNS changes, interface changes).  It is intentionally separate from
    :func:`_run_ps` so tests can mock write operations without affecting
    read-only capture operations.

    Mutating cmdlets such as Set-NetRoute/Remove-NetRoute emit empty stdout on
    success.  ``-ErrorAction Stop`` surfaces terminating failures as nonzero
    exit codes.  Commands that deliberately use ``-ErrorAction
    SilentlyContinue`` are wrapped so an already-remediated object cannot fail
    the recovery gate with PowerShell exit code 1; the post-rollback snapshot
    still proves whether the restore actually landed.

    Raises RollbackError on failure or timeout.
    """
    tolerant = _tolerates_missing_objects(script)
    command = script
    if tolerant:
        command = (
            "$ErrorActionPreference='SilentlyContinue'; %s; exit 0" % script
        )
    try:
        completed = run_hidden(
            powershell_argv(command, executable="powershell"),
            capture_output=True,
            text=True,
            timeout=30.0,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RollbackError("PowerShell execution failed: %s" % exc) from exc
    if completed.returncode != 0:
        output = "\n".join(
            part.strip()
            for part in (completed.stderr, completed.stdout)
            if part and part.strip()
        )
        if (
            tolerant
            and completed.returncode == 1
            and _is_missing_object_text(output)
        ):
            return (completed.stdout or "").strip()
        raise RollbackError(
            "PowerShell returned %d: %s" % (completed.returncode, output)
        )
    return (completed.stdout or "").strip()


def _rollback_route(desc, baseline, current):
    commands = []
    if desc.startswith("Route added"):
        r = current or {}
        policy = r.get("PolicyStore") or "ActiveStore"
        cmd = (
            "Remove-NetRoute -DestinationPrefix '{dst}' -NextHop '{nh}' "
            "-InterfaceIndex {ii} -PolicyStore {ps} "
            "-Confirm:$false -ErrorAction SilentlyContinue"
        ).format(
            dst=r.get("DestinationPrefix", ""),
            nh=r.get("NextHop", ""),
            ii=r.get("InterfaceIndex", 0),
            ps=policy,
        )
        commands.append(cmd)
    elif desc.startswith("Route removed"):
        r = baseline or {}
        policy = r.get("PolicyStore") or "ActiveStore"
        cmd = (
            "New-NetRoute -DestinationPrefix '{dst}' -NextHop '{nh}' "
            "-InterfaceIndex {ii} -RouteMetric {rm} -PolicyStore {ps} "
            "-ErrorAction Stop"
        ).format(
            dst=r.get("DestinationPrefix", ""),
            nh=r.get("NextHop", ""),
            ii=r.get("InterfaceIndex", 0),
            rm=r.get("RouteMetric", 0),
            ps=policy,
        )
        commands.append(cmd)
    elif "RouteMetric" in desc:
        r = baseline or {}
        policy = r.get("PolicyStore") or "ActiveStore"
        cmd = (
            "Set-NetRoute -DestinationPrefix '{dst}' -NextHop '{nh}' "
            "-InterfaceIndex {ii} -PolicyStore {ps} "
            "-RouteMetric {rm} -ErrorAction Stop"
        ).format(
            dst=r.get("DestinationPrefix", ""),
            nh=r.get("NextHop", ""),
            ii=r.get("InterfaceIndex", 0),
            rm=r.get("RouteMetric", 0),
            ps=policy,
        )
        commands.append(cmd)
    return commands


def _dns_rollback_command(iface_idx, addrs):
    # Set-DnsClientServerAddress has no -AddressFamily parameter: passing one
    # makes PowerShell reject the rollback command and leaves the recovery
    # gate unverified.  The address list selects the family; a reset clears
    # the interface only when the baseline had no servers at all.
    addrs = [str(addr) for addr in (addrs or []) if str(addr or "").strip()]
    if addrs:
        addr_list = ", ".join("'%s'" % addr for addr in addrs)
        return (
            "Set-DnsClientServerAddress -InterfaceIndex %s "
            "-ServerAddresses (%s) -ErrorAction Stop"
        ) % (iface_idx, addr_list)
    return (
        "Set-DnsClientServerAddress -InterfaceIndex %s "
        "-ResetServerAddresses -ErrorAction Stop"
    ) % iface_idx


def _rollback_dns(desc, baseline, current):
    commands = []
    if "DNS changed" in desc:
        dns_data = baseline or {}
        commands.append(
            _dns_rollback_command(
                dns_data.get("InterfaceIndex", 0),
                dns_data.get("ServerAddresses", []),
            )
        )
    elif "DNS added" in desc:
        dns_data = current or {}
        commands.append(
            _dns_rollback_command(dns_data.get("InterfaceIndex", 0), [])
        )
    elif "DNS removed" in desc:
        dns_data = baseline or {}
        commands.append(
            _dns_rollback_command(
                dns_data.get("InterfaceIndex", 0),
                dns_data.get("ServerAddresses", []),
            )
        )
    return commands


def _rollback_adapter(desc, baseline, current):
    commands = []
    if "added" in desc:
        a = current or {}
        name = a.get("Name", "")
        raise RollbackError(
            "unexpected adapter appears during trial"
            + (" (%s); refusing to disable it" % name if name else "")
        )
    elif "removed" in desc:
        a = baseline or {}
        name = a.get("Name", "")
        if name:
            commands.append(
                "Enable-NetAdapter -Name '%s' -ErrorAction Stop" % name
            )
    elif "changed" in desc:
        a = baseline or {}
        name = a.get("Name", "")
        if name:
            status = a.get("Status", "Up")
            if status.lower() == "up":
                commands.append(
                    "Enable-NetAdapter -Name '%s' -ErrorAction Stop" % name
                )
            else:
                raise RollbackError(
                    "baseline adapter (%s) was %s; refusing to disable "
                    "an adapter to match it" % (name, a.get("Status"))
                )
    return commands


def _rollback_ip_address(desc, baseline, current):
    commands = []
    if "added" in desc:
        ip = current or {}
        cmd = (
            "Remove-NetIPAddress -InterfaceIndex {ii} -IPAddress '{ip}' "
            "-PrefixLength {pl} -AddressFamily {af} "
            "-Confirm:$false -ErrorAction Stop"
        ).format(
            ii=ip.get("InterfaceIndex", 0),
            ip=ip.get("IPAddress", ""),
            pl=ip.get("PrefixLength", 0),
            af=ip.get("AddressFamily", 2),
        )
        commands.append(cmd)
    elif "removed" in desc:
        ip = baseline or {}
        cmd = (
            "New-NetIPAddress -InterfaceIndex {ii} -IPAddress '{ip}' "
            "-PrefixLength {pl} -AddressFamily {af} -ErrorAction Stop"
        ).format(
            ii=ip.get("InterfaceIndex", 0),
            ip=ip.get("IPAddress", ""),
            pl=ip.get("PrefixLength", 0),
            af=ip.get("AddressFamily", 2),
        )
        commands.append(cmd)
    elif "PrefixLength" in desc:
        ip = baseline or {}
        commands.append(
            "Remove-NetIPAddress -InterfaceIndex {ii} -IPAddress '{ip}' "
            "-AddressFamily {af} -Confirm:$false -ErrorAction Stop".format(
                ii=ip.get("InterfaceIndex", 0),
                ip=ip.get("IPAddress", ""),
                af=ip.get("AddressFamily", 2),
            )
        )
        commands.append(
            "New-NetIPAddress -InterfaceIndex {ii} -IPAddress '{ip}' "
            "-PrefixLength {pl} -AddressFamily {af} -ErrorAction Stop".format(
                ii=ip.get("InterfaceIndex", 0),
                ip=ip.get("IPAddress", ""),
                pl=ip.get("PrefixLength", 0),
                af=ip.get("AddressFamily", 2),
            )
        )
    return commands


def _rollback_interface(desc, baseline):
    commands = []
    iface = baseline or {}
    ii = iface.get("InterfaceIndex", 0)
    family = iface.get("AddressFamily", 2)
    af_name = "IPv6" if family == 23 else "IPv4"
    if "NlMtu" in desc:
        mtu = iface.get("NlMtu", 1500)
        commands.append(
            "Set-NetIPInterface -InterfaceIndex {ii} -AddressFamily {af} "
            "-NlMtuBytes {mtu} -ErrorAction Stop"
            .format(ii=ii, af=af_name, mtu=mtu)
        )
    if "InterfaceMetric" in desc:
        metric = iface.get("InterfaceMetric")
        if metric is None:
            commands.append(
                "Set-NetIPInterface -InterfaceIndex {ii} "
                "-AddressFamily {af} -AutomaticMetric Enabled "
                "-ErrorAction Stop"
                .format(ii=ii, af=af_name)
            )
        else:
            commands.append(
                "Set-NetIPInterface -InterfaceIndex {ii} "
                "-AddressFamily {af} -InterfaceMetric {metric} "
                "-ErrorAction Stop"
                .format(ii=ii, af=af_name, metric=metric)
            )
    return commands


# Adapter name/description fragments that mark a virtual tunnel interface.
# Names are only ever used to EXCLUDE candidates: a physical egress address
# is always selected from interface indexes that independently own an
# IPv4 address and a default route, never by name alone.
_TUNNEL_ADAPTER_PATTERN = re.compile(
    r"perchvpn|wintun|singbox|sing[-\s]?tun|tailscale|wireguard|"
    r"vethernet|hyper-?v|loopback|zerotier|openvpn|tun2proxy",
    re.IGNORECASE,
)


def _trust_virtual_nic() -> bool:
    """VM-verification escape hatch, off by default (fail closed).

    ``PERCH_TRUST_VIRTUAL_NIC=1`` lets a Hyper-V/virtual NIC count as the
    physical egress in sandboxed verification runs where the guest has no
    physical adapter at all. Everything else (Up state, IPv4 unicast,
    default-route ownership, metric ordering) is still enforced.
    """
    return os.environ.get("PERCH_TRUST_VIRTUAL_NIC", "") == "1"


def detect_physical_egress(
    snapshot: Optional[NetworkSnapshot] = None,
) -> Optional[tuple]:
    """Best primary Up non-tunnel adapter as ``(ipv4, interface_index)``.

    Never mutates host state and never selects an interface by name alone:
    tunnel-named adapters are excluded, and every remaining candidate must
    be Up, own an IPv4 unicast address, and have a ``0.0.0.0/0`` route.
    Candidates are ordered by the effective route metric
    (route metric + interface metric), then by InterfaceIndex, so the
    result is deterministic even with multiple physical adapters.

    Returns ``None`` when nothing qualifies or ``snapshot`` is None after
    capture failure.
    """
    if snapshot is None:
        try:
            snap = capture_snapshot_preferred()
        except CaptureError:
            return None
    else:
        snap = snapshot

    def _ifindex(value: Any) -> Optional[int]:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    default_ifindexes = {
        idx
        for idx in (
            _ifindex(r.get("InterfaceIndex"))
            for r in snap.routes
            if str(r.get("DestinationPrefix", "")).strip() == "0.0.0.0/0"
        )
        if idx is not None
    }

    route_metric = {
        _ifindex(r.get("InterfaceIndex")): (r.get("RouteMetric") if isinstance(r.get("RouteMetric"), (int, float)) else None)
        for r in snap.routes
        if str(r.get("DestinationPrefix", "")).strip() == "0.0.0.0/0"
    }
    iface_metric = {
        _ifindex(c.get("InterfaceIndex")): (c.get("InterfaceMetric") if isinstance(c.get("InterfaceMetric"), (int, float)) else None)
        for c in snap.interface_config
    }

    ipv4_by_index: Dict[int, str] = {}
    for rec in snap.ip_addresses:
        idx = _ifindex(rec.get("InterfaceIndex"))
        ip = rec.get("IPAddress")
        if idx is None or not ip or ":" in str(ip):
            continue
        ipv4_by_index[idx] = str(ip)

    candidates: List[tuple] = []
    for adapter in snap.adapters:
        name = str(adapter.get("Name", ""))
        description = str(adapter.get("InterfaceDescription", ""))
        status = str(adapter.get("Status", ""))
        idx = _ifindex(adapter.get("InterfaceIndex"))
        if idx is None:
            continue
        if status.lower() != "up":
            continue
        if not _trust_virtual_nic() and (
            _TUNNEL_ADAPTER_PATTERN.search(name)
            or _TUNNEL_ADAPTER_PATTERN.search(description)
        ):
            continue
        if idx not in default_ifindexes:
            continue
        ip = ipv4_by_index.get(idx)
        if not ip:
            continue
        r_metric = route_metric.get(idx)
        i_metric = iface_metric.get(idx)
        effective = (
            r_metric if isinstance(r_metric, (int, float)) else 0
        ) + (
            i_metric if isinstance(i_metric, (int, float)) else 0
        )
        candidates.append((effective, idx, ip))

    if not candidates:
        return None
    candidates.sort(key=lambda c: (c[0], c[1]))
    return candidates[0][2], candidates[0][1]


def detect_physical_ipv4(
    snapshot: Optional[NetworkSnapshot] = None,
) -> Optional[str]:
    """Best primary Up non-tunnel adapter IPv4 owning a default route."""
    egress = detect_physical_egress(snapshot)
    return egress[0] if egress else None
