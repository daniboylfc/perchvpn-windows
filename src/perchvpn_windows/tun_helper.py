"""Elevated TUN helper: run sing-box without admin in the GUI.

The GUI process stays non-elevated.  When the user selects TUN mode the app
writes a small spec file and launches ``PerchVPN.exe --tun-helper <spec>``
through UAC (``ShellExecuteExW`` with ``runas``).  The helper owns the only
privileged work: it writes a sing-box JSON configuration, starts
``sing-box.exe run -c <config>``, waits for operating-system evidence that
the Wintun adapter is up and effective, publishes that evidence, and then
tears everything down when the GUI writes the stop file, the sidecar exits,
or the parent process disappears.

sing-box owns the Windows routing table and adapter entirely through
native ``auto_route``.  All legacy PowerShell route injection, adapter metric
tweaking, and coexistence scripts have been stripped out.
"""

from __future__ import annotations

import asyncio
import ctypes
import hashlib
import inspect
import ipaddress
import json
import logging
import os
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Union

from perchvpn_windows import singbox_config, tun_status
from perchvpn_windows.win_process import (
    popen_hidden,
    powershell_argv,
    run_hidden,
)
from perchvpn_windows.tun_state_capture import (
    CaptureError,
    NetworkSnapshot,
    _run_ps_write,
    capture_snapshot,
    capture_snapshot_preferred,
    compare_snapshots,
    detect_physical_ipv4,
)

logger = logging.getLogger("perchvpn_windows.tun_helper")

__all__ = [
    "ADAPTER_NAME",
    "CoexistenceError",
    "PHASE_CANCELLED",
    "PHASE_FAILED",
    "PHASE_READY",
    "PHASE_RECOVERY",
    "PHASE_STARTING",
    "PHASE_STOPPED",
    "PHASE_STOPPING",
    "PowerShellError",
    "PrerequisiteReport",
    "STATE_VERSION",
    "TunHelperClient",
    "TunHelperSpec",
    "adapter_reuse_plan",
    "build_sidecar_command",
    "check_prerequisites",
    "cleanup_stale_wintun_adapters",
    "detect_tunnel_conflict",
    "established_remote_endpoints",
    "find_route_interface",
    "helper_main",
    "helper_supported",
    "journal_path",
    "launch_elevated",
    "load_journal",
    "physical_route_gateway",
    "process_elevated",
    "recover_ownership",
    "resolve_sidecar",
    "run_helper",
    "terminate_pid",
]

ADAPTER_NAME = "PerchVPN"
STATE_VERSION = 1

_IPC_HANDSHAKE_TIMEOUT_SECONDS = 2.0
_IPC_HANDSHAKE_POLL_SECONDS = 0.05

PHASE_STARTING = "starting"
PHASE_READY = "ready"
PHASE_STOPPING = "stopping"
PHASE_STOPPED = "stopped"
PHASE_FAILED = "failed"
PHASE_RECOVERY = "recovery_required"
PHASE_CANCELLED = "cancelled"

_TUNNEL_HINTS = (
    "wintun",
    "wireguard",
    "tap-windows",
    "tun",
    "sing-box",
    "singbox",
    "clash",
)

_VIRTUAL_ADAPTER_HINTS = (
    "perchvpn",
    "wintun",
    "singbox",
    "sing-tun",
    "sing tun",
    "tailscale",
    "wireguard",
    "vethernet",
    "hyper-v",
    "tap-windows",
    "tun2proxy",
    "openvpn",
    "zerotier",
    "loopback",
)

_IGNORED_ROUTE_PREFIXES = (
    "ff00::/8",
    "fe80::/64",
    "224.0.0.0/4",
    "255.255.255.255/32",
)

_ERROR_CANCELLED = 1223


class PowerShellError(RuntimeError):
    """A PowerShell command failed (non-zero exit / invocation error)."""


class CoexistenceError(RuntimeError):
    """Raised on coexistence conflict or bypass failure."""

    def __init__(
        self,
        message: str,
        pinned: Optional[List[Dict[str, Any]]] = None,
        owned: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        super().__init__(message)
        self.pinned = list(pinned or [])
        self.owned = list(owned or [])


def _run_powershell(script: str) -> str:
    """Stub retained for backwards-compatibility with monkeypatched tests."""
    return ""


# ---------------------------------------------------------------------------
# Spec / JSON storage
# ---------------------------------------------------------------------------


@dataclass
class TunHelperSpec:
    proxy_host: str
    proxy_port: int
    executable: str
    adapter: str = ADAPTER_NAME
    mtu: int = 1400
    bypass: List[str] = field(default_factory=list)
    extra_args: List[str] = field(default_factory=list)
    parent_pid: int = 0
    owner_pid: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": STATE_VERSION,
            "proxy_host": self.proxy_host,
            "proxy_port": int(self.proxy_port),
            "executable": self.executable,
            "adapter": self.adapter,
            "mtu": int(self.mtu),
            "bypass": list(self.bypass),
            "extra_args": list(self.extra_args),
            "parent_pid": int(self.parent_pid),
            "owner_pid": int(self.owner_pid),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TunHelperSpec":
        if int(data.get("version", 0)) != STATE_VERSION:
            raise ValueError("unsupported tun helper spec version")
        return cls(
            proxy_host=str(data["proxy_host"]),
            proxy_port=int(data["proxy_port"]),
            executable=str(data["executable"]),
            adapter=str(data.get("adapter") or ADAPTER_NAME),
            mtu=int(data.get("mtu") or 1400),
            bypass=[str(v) for v in data.get("bypass") or []],
            extra_args=[str(v) for v in data.get("extra_args") or []],
            parent_pid=int(data.get("parent_pid") or 0),
            owner_pid=int(data.get("owner_pid") or 0),
        )

    @property
    def fingerprint(self) -> str:
        payload = json.dumps(self.to_dict(), sort_keys=True).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()[:16]


def build_sidecar_command(
    spec: TunHelperSpec,
    *,
    config_path: Optional[Union[Path, str]] = None,
    ipv6: bool = False,
    setup: bool = True,
) -> List[str]:
    """Write a sing-box config and return its ``run`` command line."""
    target = (
        Path(config_path)
        if config_path is not None
        else Path(tempfile.gettempdir())
        / ("perchvpn-singbox-%s.json" % spec.fingerprint)
    )
    config = singbox_config.build_config(
        proxy_host=spec.proxy_host,
        proxy_port=spec.proxy_port,
        adapter=spec.adapter,
        mtu=spec.mtu,
        bypass=spec.bypass,
        ipv6=ipv6,
        mixed_port=singbox_config.available_mixed_port(),
        auto_route=bool(setup),
        strict_route=bool(setup),
    )
    singbox_config.write_config(target, config)

    cmd = [spec.executable]
    cmd.extend(str(arg) for arg in spec.extra_args)
    cmd.extend(["run", "-c", str(target)])
    return cmd


def _atomic_write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def _read_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _unlink(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Prerequisites and conflict detection
# ---------------------------------------------------------------------------


@dataclass
class PrerequisiteReport:
    ok: bool
    code: str
    detail: str
    physical_ip: str = ""
    adapter_conflict: Optional[str] = None
    sidecar_resolved: str = ""
    wintun_dll_present: bool = True
    elevated: bool = False
    helper_available: bool = False

    @property
    def reason(self) -> str:
        return self.detail

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "code": self.code,
            "detail": self.detail,
            "reason": self.reason,
            "physical_ip": self.physical_ip,
            "adapter_conflict": self.adapter_conflict,
            "sidecar_resolved": self.sidecar_resolved,
            "wintun_dll_present": self.wintun_dll_present,
            "elevated": self.elevated,
            "helper_available": self.helper_available,
        }


def resolve_sidecar(executable_path: str) -> str:
    """Resolve sing-box.exe and require wintun.dll next to it."""
    import shutil

    raw = (executable_path or "").strip()
    if not raw:
        raise ValueError("tun_executable_path is not configured")
    path = Path(raw)
    if not path.is_file():
        resolved = shutil.which(raw)
        if not resolved:
            raise ValueError("sing-box executable not found: %r" % raw)
        path = Path(resolved)
    if sys.platform == "win32":
        dll = path.parent / "wintun.dll"
        if not dll.is_file():
            raise ValueError("wintun.dll not found alongside sing-box.exe: %s" % dll)
    return str(path)


def _effective_metrics(snapshot: NetworkSnapshot) -> Dict[int, float]:
    route_metric: Dict[int, float] = {}
    for route in snapshot.routes:
        if not isinstance(route, dict):
            continue
        if str(route.get("DestinationPrefix", "")).strip() != "0.0.0.0/0":
            continue
        try:
            index = int(route.get("InterfaceIndex"))
        except (TypeError, ValueError):
            continue
        try:
            metric = float(route.get("RouteMetric") or 0)
        except (TypeError, ValueError):
            metric = 0.0
        route_metric[index] = min(route_metric.get(index, metric), metric)
    iface_metric: Dict[int, float] = {}
    for entry in snapshot.interface_config:
        if not isinstance(entry, dict):
            continue
        try:
            index = int(entry.get("InterfaceIndex"))
        except (TypeError, ValueError):
            continue
        try:
            iface_metric[index] = float(entry.get("InterfaceMetric") or 0)
        except (TypeError, ValueError):
            iface_metric[index] = 0.0
    return {
        index: metric + iface_metric.get(index, 0.0)
        for index, metric in route_metric.items()
    }


def _looks_like_tunnel(name: str, description: str) -> bool:
    haystack = ("%s %s" % (name, description)).lower()
    return any(hint in haystack for hint in _TUNNEL_HINTS)


def detect_tunnel_conflict(
    snapshot: NetworkSnapshot, adapter: str = ADAPTER_NAME
) -> Optional[str]:
    """Name of a foreign tunnel that currently owns the default route."""
    default_owners = set(_effective_metrics(snapshot))
    if not default_owners:
        return None
    for record in snapshot.adapters:
        if not isinstance(record, dict):
            continue
        try:
            index = int(record.get("InterfaceIndex"))
        except (TypeError, ValueError):
            continue
        name = str(record.get("Name") or "")
        description = str(record.get("InterfaceDescription") or "")
        if not name or name.lower() == adapter.lower():
            continue
        if index not in default_owners:
            continue
        if _looks_like_tunnel(name, description):
            return name
    return None


def _adapter_present(snapshot: NetworkSnapshot, adapter: str) -> Optional[Dict[str, Any]]:
    for record in snapshot.adapters:
        if not isinstance(record, dict):
            continue
        if str(record.get("Name") or "").lower() == adapter.lower():
            return record
    return None


def _adapter_has_ipv4(snapshot: NetworkSnapshot, interface_index: int) -> bool:
    for entry in snapshot.ip_addresses:
        if not isinstance(entry, dict):
            continue
        try:
            if int(entry.get("InterfaceIndex")) != int(interface_index):
                continue
        except (TypeError, ValueError):
            continue
        address = str(entry.get("IPAddress") or "").strip()
        if address and ":" not in address:
            return True
    return False


def _is_virtual_adapter(record: Optional[Dict[str, Any]]) -> bool:
    if not isinstance(record, dict):
        return False
    haystack = ("%s %s" % (
        record.get("Name") or "", record.get("InterfaceDescription") or ""
    )).lower()
    return any(hint in haystack for hint in _VIRTUAL_ADAPTER_HINTS)


def adapter_reuse_plan(
    snapshot: NetworkSnapshot,
    adapter: str,
    journal: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    existing = _adapter_present(snapshot, adapter)
    if existing is None:
        return {"action": "create", "adapter": None, "guid": "", "reason": "absent"}

    guid = str(existing.get("InterfaceGuid") or "")
    try:
        index = int(existing.get("InterfaceIndex"))
    except (TypeError, ValueError):
        index = 0
    status = str(existing.get("Status") or "").lower()
    journal_guid = str((journal or {}).get("adapter_guid") or "")
    owned = _journal_owns_adapter(journal, adapter)
    guid_mismatch = bool(
        owned and journal_guid and guid and journal_guid.lower() != guid.lower()
    )
    if guid_mismatch:
        owned = False

    description_only = {
        "InterfaceDescription": str(existing.get("InterfaceDescription") or "")
    }
    ours = owned or _is_virtual_adapter(description_only)
    if guid_mismatch:
        return {
            "action": "replace",
            "adapter": existing,
            "guid": guid,
            "reason": "journal GUID does not match the existing adapter",
        }
    if not ours:
        return {
            "action": "foreign",
            "adapter": existing,
            "guid": guid,
            "reason": "existing adapter is not PerchVPN-owned",
        }

    healthy = status == "up" and index > 0 and _adapter_has_ipv4(snapshot, index)
    if healthy:
        return {
            "action": "reuse",
            "adapter": existing,
            "guid": guid,
            "reason": "existing adapter is up with an IPv4 address",
        }
    return {
        "action": "replace",
        "adapter": existing,
        "guid": guid,
        "reason": "existing adapter is not usable (status=%s)" % (status or "unknown"),
    }


def check_prerequisites(
    executable_path: str = "",
    *,
    adapter: str = ADAPTER_NAME,
    opt_in: bool = True,
    elevated: Optional[bool] = None,
    helper_can_elevate: Optional[bool] = None,
    snapshot: Optional[NetworkSnapshot] = None,
    sidecar_resolver: Callable[[str], str] = resolve_sidecar,
) -> PrerequisiteReport:
    """Read-only validation before activating TUN mode."""
    if not opt_in:
        return PrerequisiteReport(
            False,
            "opt_in_required",
            "TUN mode requires explicit opt-in (tun_opt_in) in the config.",
        )
    sidecar = ""
    try:
        sidecar = sidecar_resolver(executable_path)
    except (ValueError, OSError) as exc:
        return PrerequisiteReport(
            False,
            "sidecar_missing",
            "TUN sidecar not ready: %s" % exc,
        )

    wintun_ok = True
    if sys.platform == "win32" and sidecar:
        wintun_ok = (Path(sidecar).parent / "wintun.dll").is_file()
        if not wintun_ok:
            return PrerequisiteReport(
                False,
                "wintun_dll_missing",
                "wintun.dll missing alongside %s" % sidecar,
                sidecar_resolved=sidecar,
                wintun_dll_present=False,
            )

    is_elev = process_elevated() if elevated is None else bool(elevated)
    can_elev = helper_supported() if helper_can_elevate is None else bool(helper_can_elevate)
    if not is_elev and not can_elev:
        return PrerequisiteReport(
            False,
            "elevation_unavailable",
            "TUN requires Administrator privileges and the elevated helper "
            "cannot be launched on this system.",
            sidecar_resolved=sidecar,
            wintun_dll_present=wintun_ok,
            elevated=is_elev,
            helper_available=can_elev,
        )

    if snapshot is None:
        try:
            snapshot = capture_snapshot()
        except CaptureError as exc:
            return PrerequisiteReport(
                False,
                "state_capture_failed",
                "network state capture failed: %s" % exc,
                sidecar_resolved=sidecar,
                wintun_dll_present=wintun_ok,
                elevated=is_elev,
                helper_available=can_elev,
            )

    conflict = detect_tunnel_conflict(snapshot, adapter)
    try:
        physical = detect_physical_ipv4(snapshot)
    except Exception:
        physical = None

    if not physical:
        return PrerequisiteReport(
            False,
            "no_physical_egress",
            "No physical IPv4 interface with a default route is available; "
            "starting TUN would loop the upstream into its own tunnel.",
            sidecar_resolved=sidecar,
            wintun_dll_present=wintun_ok,
            elevated=is_elev,
            helper_available=can_elev,
        )

    existing = _adapter_present(snapshot, adapter)
    if existing is not None:
        return PrerequisiteReport(
            False,
            "adapter_owned_by_other",
            "An adapter named %r already exists and is not journaled as "
            "PerchVPN-owned; refusing to adopt it." % adapter,
            physical_ip=physical,
            adapter_conflict=str(existing.get("Name") or ""),
            sidecar_resolved=sidecar,
            wintun_dll_present=wintun_ok,
            elevated=is_elev,
            helper_available=can_elev,
        )

    if conflict:
        return PrerequisiteReport(
            True,
            "coexist",
            "Active tunnel %r detected; coexistence route policy will be used."
            % conflict,
            physical_ip=physical,
            adapter_conflict=conflict,
            sidecar_resolved=sidecar,
            wintun_dll_present=wintun_ok,
            elevated=is_elev,
            helper_available=can_elev,
        )

    return PrerequisiteReport(
        True,
        "ok",
        "TUN prerequisites satisfied.",
        physical_ip=physical,
        sidecar_resolved=sidecar,
        wintun_dll_present=wintun_ok,
        elevated=is_elev,
        helper_available=can_elev,
    )


# ---------------------------------------------------------------------------
# Read-only network queries (for app control plane)
# ---------------------------------------------------------------------------


def capture_adapter_dns(*args: Any, **kwargs: Any) -> List[str]:
    """IPv4/IPv6 DNS servers configured on one interface (native).

    Reads ``GetAdaptersAddresses`` directly (milliseconds); fails closed to
    an empty list when the native query is unavailable so callers treat
    absence as "zero servers" exactly as before.
    """
    if args:
        interface_index = args[0]
        family = args[1] if len(args) > 1 else kwargs.get("family", "IPv4")
    else:
        interface_index = kwargs.get("interface_index", 0)
        family = kwargs.get("family", "IPv4")
    try:
        from perchvpn_windows import iphelper

        return iphelper.dns_servers_native(interface_index, family)
    except Exception:  # noqa: BLE001 - absence is reported as zero servers
        return []


def find_route_interface(*args: Any, **kwargs: Any) -> Optional[int]:
    """Interface index the live route table selects for ``destination``.

    Uses ``GetBestRoute2`` natively (milliseconds, fail closed); returning
    ``None`` means "unverifiable route" exactly as the previous stub did.
    """
    if args:
        destination = args[0]
    else:
        destination = kwargs.get("destination", "")
    try:
        from perchvpn_windows import iphelper

        return iphelper.best_route_interface(destination)
    except Exception:  # noqa: BLE001 - unverifiable route fails closed
        return None


def physical_route_gateway(
    snapshot: NetworkSnapshot, physical_ip: str
) -> tuple[Optional[int], str]:
    """Locate the physical NIC that owns ``physical_ip`` and its gateway."""
    ip_by_index: Dict[int, str] = {}
    for record in snapshot.ip_addresses:
        if not isinstance(record, dict):
            continue
        try:
            index = int(record.get("InterfaceIndex"))
        except (TypeError, ValueError):
            continue
        address = str(record.get("IPAddress") or "")
        if address and ":" not in address:
            ip_by_index[index] = address

    target_index: Optional[int] = None
    for index, address in ip_by_index.items():
        if address == physical_ip:
            target_index = index
            break
    if target_index is None:
        return None, ""

    gateway = ""
    for route in snapshot.routes:
        if not isinstance(route, dict):
            continue
        if str(route.get("DestinationPrefix", "")).strip() != "0.0.0.0/0":
            continue
        try:
            index = int(route.get("InterfaceIndex"))
        except (TypeError, ValueError):
            continue
        if index != target_index:
            continue
        gateway = str(route.get("NextHop") or "")
        break
    return target_index, gateway


def _physical_adapter_record(
    snapshot: NetworkSnapshot, index: int
) -> Optional[Dict[str, Any]]:
    for adapter in snapshot.adapters:
        if not isinstance(adapter, dict):
            continue
        try:
            if int(adapter.get("InterfaceIndex")) != int(index):
                continue
        except (TypeError, ValueError):
            continue
        return adapter
    return None


def established_remote_endpoints(
    run_ps: Optional[Callable[[str], str]] = None,
    *,
    limit: int = 64,
) -> List[str]:
    """Public remote IPv4 endpoints of live host TCP connections."""
    ps_fn = run_ps if run_ps is not None else _run_powershell
    script = (
        "Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | "
        "Where-Object { $_.RemotePort -eq 443 } | "
        "Select-Object -ExpandProperty RemoteAddress -Unique"
    )
    raw = ""
    if ps_fn is not None:
        try:
            raw = ps_fn(script)
        except Exception:
            return []
    else:
        try:
            res = run_hidden(
                powershell_argv(script),
                capture_output=True,
                text=True,
                timeout=5,
            )
            raw = res.stdout or ""
        except Exception:
            return []

    endpoints: List[str] = []
    for line in str(raw or "").splitlines():
        text = line.strip()
        if not text:
            continue
        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            continue
        if address.version == 4 and not address.is_private and not address.is_loopback:
            addr_str = str(address)
            if addr_str not in endpoints:
                endpoints.append(addr_str)
                if len(endpoints) >= limit:
                    break
    return endpoints


# ---------------------------------------------------------------------------
# Journal and ownership recovery
# ---------------------------------------------------------------------------


def journal_path() -> Path:
    from perchvpn_windows.platform import get_config_dir

    return get_config_dir() / "tun-helper-journal.json"


def load_journal(path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    return _read_json(path or journal_path())


def _journal_owns_adapter(journal: Optional[Dict[str, Any]], adapter: str) -> bool:
    if not journal:
        return False
    return (
        str(journal.get("adapter") or "").lower() == str(adapter).lower()
        and journal.get("phase") not in (PHASE_STOPPED, PHASE_FAILED, None)
    )


def recover_ownership(
    journal: Optional[Dict[str, Any]] = None,
    *,
    snapshot: Optional[NetworkSnapshot] = None,
    capture: Callable[[], NetworkSnapshot] = capture_snapshot,
    terminate: Optional[Callable[[int], bool]] = None,
    remove_adapter: Optional[Callable[[str, str], bool]] = None,
    run_ps: Optional[Callable[[str], str]] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Roll back resources when the journal proves PerchVPN owns them."""
    journal = journal if journal is not None else load_journal()
    if not journal:
        return {"recovered": True, "detail": "no ownership journal"}

    child_pid = int(journal.get("child_pid") or 0)
    if child_pid and callable(terminate):
        try:
            terminate(child_pid)
        except Exception as exc:
            return {"recovered": False, "detail": "sidecar terminate failed: %s" % exc}

    adapter = str(journal.get("adapter") or "")
    guid = str(journal.get("adapter_guid") or "")
    if not adapter:
        return {"recovered": True, "detail": "journal has no adapter record; routes clean"}

    try:
        disk_snapshot = snapshot if snapshot is not None else (capture() if callable(capture) else None)
    except Exception as exc:
        return {"recovered": False, "detail": "state capture failed: %s" % exc}

    if disk_snapshot is not None:
        existing = _adapter_present(disk_snapshot, adapter)
        if existing is None:
            return {"recovered": True, "detail": "adapter already absent"}
        current_guid = str(existing.get("InterfaceGuid") or "")
        if not guid or current_guid.lower() != guid.lower():
            return {
                "recovered": False,
                "detail": "adapter GUID does not match the journal; refusing to remove %r"
                % adapter,
            }

    if not callable(remove_adapter):
        return {"recovered": True, "detail": "recovered"}
    ok = bool(remove_adapter(adapter, guid))
    return {"recovered": ok, "detail": "adapter removed" if ok else "adapter removal failed"}


def _remove_adapter(name: str, guid: str) -> bool:
    return True


def _remove_adapter_by_name(name: str) -> bool:
    return True


def _stale_wintun_cleanup_script(adapter_name: str) -> str:
    quoted = "'" + str(adapter_name).replace("'", "''") + "'"
    return (
        "$ErrorActionPreference='SilentlyContinue';"
        "$n=%s;"
        "$live=@(Get-NetAdapter -ErrorAction SilentlyContinue | "
        "  ForEach-Object { [string]$_.PnPDeviceID });"
        "$f={"
        "  $id=[string]$_.InstanceId;"
        "  if (-not $id) { return $false };"
        "  if ($live -contains $id) { return $false };"
        "  if ($id -like 'SWD\\WINTUN*') { return $true };"
        "  if ($_.Present) { return $false };"
        "  return ($_.FriendlyName -eq $n);"
        "};"
        "$removed=@();"
        "$deadline=(Get-Date).AddSeconds(1.5);"
        "do {"
        "  $targets=@(Get-PnpDevice -Class Net -ErrorAction SilentlyContinue | Where-Object $f);"
        "  foreach ($d in $targets) {"
        "    $id=[string]$d.InstanceId;"
        "    & pnputil.exe /remove-device $id 2>&1 | Out-Null;"
        "    if ($LASTEXITCODE -eq 0) { $removed += $id };"
        "  };"
        "  if ($targets.Count -eq 0) { break };"
        "  Start-Sleep -Milliseconds 200;"
        "} while ((Get-Date) -lt $deadline);"
        "$left=@(Get-PnpDevice -Class Net -ErrorAction SilentlyContinue | Where-Object $f);"
        "[pscustomobject]@{removed=$removed;remaining=$left.Count} | ConvertTo-Json -Compress"
    ) % quoted


_WINTUN_ENUM_KEY = r"SYSTEM\CurrentControlSet\Enum\SWD\WINTUN"


def _native_stale_wintun_devices() -> Optional[List[str]]:
    """Stale ``SWD\\WINTUN\\*`` device instance ids, without PowerShell.

    ``Get-PnpDevice -Class Net`` costs 5-6 s on the 2-vCPU sandbox guest and
    the start gate paid it on every connect even when no ghosts existed.
    The registry Enum key lists every Wintun instance ever created; a device
    that no longer locates in the live device tree (or that is located but
    not started) is a ghost eligible for ``pnputil /remove-device``.

    Returns ``None`` when the native path is unavailable and the caller must
    fall back to the PowerShell script (fail-open to the old behavior).
    """
    if sys.platform != "win32":
        return None
    try:
        import winreg
        from ctypes import wintypes

        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _WINTUN_ENUM_KEY)
        except FileNotFoundError:
            return []
        except OSError:
            return None
        names: List[str] = []
        try:
            index = 0
            while True:
                try:
                    name = winreg.EnumKey(key, index)
                except OSError:
                    break
                index += 1
                if name and name.lower() != "properties":
                    names.append(name)
        finally:
            winreg.CloseKey(key)
        if not names:
            return []
        try:
            cfgmgr = ctypes.WinDLL("cfgmgr32.dll")
        except OSError:
            return None
        cm_locate_devnode_normal = 0
        dn_started = 0x00000008
        stale: List[str] = []
        for name in names:
            instance_id = "SWD\\WINTUN\\%s" % name
            devinst = wintypes.DWORD(0)
            locate = cfgmgr.CM_Locate_DevNodeW(
                ctypes.byref(devinst), wintypes.LPCWSTR(instance_id),
                cm_locate_devnode_normal,
            )
            if locate != 0:
                stale.append(instance_id)
                continue
            status = wintypes.ULONG(0)
            problem = wintypes.ULONG(0)
            get_status = cfgmgr.CM_Get_DevNode_Status(
                ctypes.byref(status), ctypes.byref(problem), devinst, 0
            )
            if get_status != 0:
                return None
            if not (status.value & dn_started) or problem.value != 0:
                stale.append(instance_id)
        return stale
    except Exception:  # noqa: BLE001 - native scan is best-effort
        logger.debug("native stale Wintun scan failed", exc_info=True)
        return None


def cleanup_stale_wintun_adapters(
    adapter_name: str,
    *,
    run_ps: Optional[Callable[[str], str]] = None,
) -> Dict[str, Any]:
    """Remove non-present Wintun PnP nodes left by a crashed sidecar.

    Windows keeps the PnP device after sing-box exits or is killed.  The next
    adapter creation then fails with ``Cannot create a file when that file
    already exists`` even though ``Get-NetAdapter`` no longer lists it.
    Eligibility is decided ONLY against the live-adapter list
    (``Get-NetAdapter``'s PnPDeviceID): Wintun SWD nodes can report
    ``Present=False`` and Status ``Unknown`` while their adapter is Up, and
    every Wintun VPN shares the fixed FriendlyName ``sing-tun Tunnel``, so a
    live foreign adapter (for example ``singbox_tun``) must be excluded by
    its live PnPDeviceID — never by name, Present, or Status.
    """
    name = str(adapter_name or "").strip()
    if not name:
        raise ValueError("adapter name is required")
    if sys.platform != "win32":
        return {"removed": [], "remaining": 0, "skipped": "not Windows"}

    # Native fast path (only when the caller did not inject a runner): a
    # registry + cfgmgr32 scan finds ghosts in ~1 ms, so a clean start pays
    # no PowerShell at all.  Removal still goes through pnputil (elevation).
    if run_ps is None:
        stale = _native_stale_wintun_devices()
        if stale is not None:
            removed: List[str] = []
            for instance_id in stale:
                try:
                    completed = run_hidden(
                        ["pnputil.exe", "/remove-device", instance_id],
                        capture_output=True,
                        timeout=30,
                    )
                except Exception:  # noqa: BLE001 - best effort, retried nowhere
                    continue
                if completed.returncode == 0:
                    removed.append(instance_id)
            after = _native_stale_wintun_devices()
            remaining = len(after) if after is not None else (len(stale) - len(removed))
            if remaining:
                logger.warning(
                    "stale Wintun devices for %r survived cleanup (%d remain)",
                    name,
                    remaining,
                )
            elif removed:
                logger.info(
                    "removed %d stale Wintun device(s) before start: %s",
                    len(removed),
                    ", ".join(removed),
                )
            return {"removed": removed, "remaining": remaining}

    raw = (run_ps or _run_ps_write)(_stale_wintun_cleanup_script(name))
    try:
        payload = json.loads(raw) if raw and raw.strip() else {}
    except (json.JSONDecodeError, TypeError) as exc:
        raise RuntimeError(
            "stale Wintun cleanup returned invalid JSON: %s" % exc
        ) from exc
    if not isinstance(payload, dict):
        raise RuntimeError("stale Wintun cleanup returned unexpected payload")
    remaining = int(payload.get("remaining") or 0)
    removed = [str(item) for item in payload.get("removed") or []]
    if remaining:
        # Not fatal: pnputil /remove-device requires elevation, so a
        # non-elevated caller (or an unremovable foreign phantom) leaves
        # nodes behind.  The caller logs a warning and proceeds — the real
        # CreateAdapter collision, if any, surfaces with its own error.
        logger.warning(
            "stale Wintun devices for %r survived cleanup (%d remain)",
            name,
            remaining,
        )
    return {"removed": removed, "remaining": remaining}


# ---------------------------------------------------------------------------
# Elevation (UAC)
# ---------------------------------------------------------------------------


def _process_elevated() -> bool:
    if sys.platform != "win32":
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def process_elevated() -> bool:
    return _process_elevated()


def helper_supported() -> bool:
    return sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0)


def helper_argv(spec_path: str) -> List[str]:
    executable = sys.executable
    if getattr(sys, "frozen", False):
        return [executable, "--tun-helper", str(spec_path)]
    return [executable, "-m", "perchvpn_windows.tun_helper", str(spec_path)]


def _shell_execute_runas(argv: Sequence[str]) -> Dict[str, Any]:
    if sys.platform != "win32":
        raise OSError("ShellExecuteExW is only supported on Windows")

    file_to_run = str(argv[0])
    params = subprocess.list2cmdline([str(a) for a in argv[1:]])

    SEE_MASK_NOCLOSEPROCESS = 0x00000040
    SW_HIDE = 0

    class SHELLEXECUTEINFOW(ctypes.Structure):
        _fields_ = [
            ("cbSize", ctypes.c_ulong),
            ("fMask", ctypes.c_ulong),
            ("hwnd", ctypes.c_void_p),
            ("lpVerb", ctypes.c_wchar_p),
            ("lpFile", ctypes.c_wchar_p),
            ("lpParameters", ctypes.c_wchar_p),
            ("lpDirectory", ctypes.c_wchar_p),
            ("nShow", ctypes.c_int),
            ("hInstApp", ctypes.c_void_p),
            ("lpIDList", ctypes.c_void_p),
            ("lpClass", ctypes.c_wchar_p),
            ("hkeyClass", ctypes.c_void_p),
            ("dwHotKey", ctypes.c_ulong),
            ("hIconOrMonitor", ctypes.c_void_p),
            ("hProcess", ctypes.c_void_p),
        ]

    sei = SHELLEXECUTEINFOW()
    sei.cbSize = ctypes.sizeof(SHELLEXECUTEINFOW)
    sei.fMask = SEE_MASK_NOCLOSEPROCESS
    sei.hwnd = None
    sei.lpVerb = "runas"
    sei.lpFile = file_to_run
    sei.lpParameters = params
    sei.lpDirectory = None
    sei.nShow = SW_HIDE

    if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(sei)):
        err = ctypes.GetLastError()
        if err == _ERROR_CANCELLED:
            return {"ok": False, "cancelled": True, "error": "UAC prompt was cancelled"}
        return {"ok": False, "cancelled": False, "error": "ShellExecuteExW failed: winerror %d" % err}

    h_process = sei.hProcess
    pid = 0
    if h_process:
        pid = int(ctypes.windll.kernel32.GetProcessId(h_process))
        ctypes.windll.kernel32.CloseHandle(h_process)
    return {"ok": True, "cancelled": False, "pid": pid}


def launch_elevated(
    spec_path: Path,
    *,
    shell_execute: Callable[[Sequence[str]], Dict[str, Any]] = _shell_execute_runas,
) -> Dict[str, Any]:
    argv = helper_argv(str(spec_path))
    res = shell_execute(argv)
    res.setdefault("launched", res.get("ok", False))
    return res


def _terminate_helper_pid(pid: int, executable: str = "") -> bool:
    if sys.platform != "win32":
        return False
    try:
        return bool(terminate_pid(int(pid), str(executable or "")))
    except Exception:
        return False


# ---------------------------------------------------------------------------
# GUI-side client
# ---------------------------------------------------------------------------


class TunHelperClient:
    def __init__(
        self,
        *,
        spec: TunHelperSpec,
        state_path: Path,
        stop_path: Path,
        spec_path: Optional[Path] = None,
        launcher: Callable[[str], Dict[str, Any]] = launch_elevated,
        sleep: Callable[[float], Any] = asyncio.sleep,
        clock: Callable[[], float] = time.monotonic,
        poll_interval: float = 0.25,
        handshake_timeout: float = _IPC_HANDSHAKE_TIMEOUT_SECONDS,
        terminator: Optional[Callable[[int, str], bool]] = None,
    ) -> None:
        self.spec = spec
        self.state_path = Path(state_path)
        self.stop_path = Path(stop_path)
        self.spec_path = (
            Path(spec_path)
            if spec_path is not None
            else self.state_path.with_name("tun-helper-spec.json")
        )
        self.bypass_path = self.spec_path.with_name("tun-helper-bypass.json")
        self._launcher = launcher
        self._sleep = sleep
        self._clock = clock
        self._poll_interval = poll_interval
        self._handshake_timeout = max(0.0, float(handshake_timeout))
        self._terminator = terminator
        self.launch_info: Dict[str, Any] = {}
        self._last_state: Dict[str, Any] = {}

    def snapshot(self) -> Dict[str, Any]:
        state = self._read_state()
        if state:
            self._last_state = state
            return dict(state)
        return dict(self._last_state)

    async def snapshot_async(self) -> Dict[str, Any]:
        """Read the helper state off the event loop (status/watch hot path)."""
        return await asyncio.to_thread(self.snapshot)

    def is_running(self) -> bool:
        phase = str(self.snapshot().get("phase") or "")
        return phase in (PHASE_STARTING, PHASE_READY, PHASE_STOPPING)

    async def wait_for_ipc(
        self, timeout: float = _IPC_HANDSHAKE_TIMEOUT_SECONDS
    ) -> Dict[str, Any]:
        timeout = max(0.0, timeout)
        deadline = self._clock() + timeout
        step = max(0.001, min(self._poll_interval, _IPC_HANDSHAKE_POLL_SECONDS))
        max_attempts = max(1, int(timeout / step) + 1)
        try:
            launched_pid = int(self.launch_info.get("pid") or 0)
        except (TypeError, ValueError):
            launched_pid = 0
        attempts = 0
        while attempts < max_attempts:
            state = await self._read_state_async()
            phase = str(state.get("phase") or "")
            try:
                state_pid = int(state.get("pid") or 0)
            except (TypeError, ValueError):
                state_pid = 0
            stale_writer = bool(
                launched_pid and state_pid and state_pid != launched_pid
            )
            if stale_writer:
                self.launch_info["stale_helper_pid"] = state_pid
            elif state.get("pid") or phase:
                self.launch_info["ipc_ready"] = True
                self.launch_info["helper_pid"] = state_pid
                self._publish(state)
                return state
            if self._clock() >= deadline:
                break
            attempts += 1
            await self._sleep(step)
        self.launch_info["ipc_ready"] = False
        return {}

    def _helper_image(self) -> str:
        try:
            return str(helper_argv(str(self.spec_path))[0])
        except Exception:
            return str(sys.executable)

    def _terminate_helper(self, pid: Optional[int] = None) -> bool:
        try:
            target = int(pid if pid is not None else (self.launch_info.get("pid") or 0))
        except (TypeError, ValueError):
            target = 0
        if target <= 0:
            return False
        terminate = self._terminator or _terminate_helper_pid
        try:
            return bool(terminate(target, self._helper_image()))
        except Exception:
            return False

    def _publish(self, state: Dict[str, Any]) -> None:
        self._last_state = state

    def _read_state(self) -> Dict[str, Any]:
        return _read_json(self.state_path) or {}

    async def _read_state_async(self) -> Dict[str, Any]:
        return await asyncio.to_thread(self._read_state)

    async def start(self, timeout: float = 35.0) -> Dict[str, Any]:
        stale = self._read_state()
        try:
            stale_pid = int(stale.get("pid") or 0)
        except (TypeError, ValueError):
            stale_pid = 0
        # A previous helper can outlive a failed stop and publish a terminal
        # phase (failed/recovery_required) while its elevated process still
        # owns the adapter/journal.  Always terminate a stale PID for those
        # phases, not only the ones that look active; otherwise the next
        # launch races the old helper and its IPC state never appears.
        # A cleanly stopped/cancelled helper whose PID is already gone needs
        # no taskkill spawn on the pre-UAC path.
        if stale_pid:
            stale_phase = str(stale.get("phase") or "")
            if stale_phase not in (PHASE_STOPPED, PHASE_CANCELLED) or _parent_alive(
                stale_pid
            ):
                self._terminate_helper(stale_pid)
        _unlink(self.stop_path)
        _unlink(self.state_path)

        _atomic_write_json(self.spec_path, self.spec.to_dict())
        return await self._launch_and_acknowledge(timeout, allow_retry=True)

    async def _launch_and_acknowledge(
        self, timeout: float, *, allow_retry: bool
    ) -> Dict[str, Any]:
        launch_started = self._clock()
        self.launch_info = await asyncio.to_thread(
            self._launcher, str(self.spec_path)
        )
        # ShellExecuteExW("runas") blocks until the UAC prompt is answered.
        # Recording that dwell separately from the helper's own IPC/readiness
        # wait makes "slow Connect" measurable instead of anecdotal.
        self.launch_info["launch_seconds"] = max(
            0.0, self._clock() - launch_started
        )
        if not self.launch_info.get("launched"):
            state = {
                "version": STATE_VERSION,
                "phase": PHASE_CANCELLED if self.launch_info.get("cancelled") else PHASE_FAILED,
                "error": self.launch_info.get("error") or "helper did not launch",
                "adapter": self.spec.adapter,
            }
            self._publish(state)
            return state

        handshake_timeout = min(self._handshake_timeout, max(0.0, timeout))
        await self.wait_for_ipc(timeout=handshake_timeout)
        if not self.launch_info.get("ipc_ready"):
            stale_pid = int(self.launch_info.get("stale_helper_pid") or 0)
            if stale_pid:
                self._terminate_helper(stale_pid)
            self._terminate_helper()
            _unlink(self.stop_path)
            _unlink(self.state_path)
            if allow_retry and timeout > 0:
                logger.warning(
                    "TUN helper did not publish IPC within %.1fs; starting clean instance",
                    handshake_timeout,
                )
                return await self._launch_and_acknowledge(
                    timeout, allow_retry=False
                )
            state = {
                "version": STATE_VERSION,
                "phase": PHASE_FAILED,
                "error": (
                    "TUN helper did not acknowledge IPC within %.1fs"
                    % handshake_timeout
                ),
                "adapter": self.spec.adapter,
            }
            self._publish(state)
            return state

        deadline = self._clock() + max(0.0, timeout)
        step = max(0.001, self._poll_interval)
        max_attempts = max(1, int(max(0.0, timeout) / step) + 1)
        attempts = 0
        while self._clock() < deadline and attempts < max_attempts:
            state = self._read_state()
            if state.get("phase") in (
                PHASE_READY,
                PHASE_FAILED,
                PHASE_RECOVERY,
                PHASE_STOPPED,
                PHASE_CANCELLED,
            ):
                self._publish(state)
                return state
            attempts += 1
            await self._sleep(self._poll_interval)
        state = self._read_state()
        state = dict(state or {})
        state.setdefault("phase", PHASE_FAILED)
        state.setdefault("error", "timed out waiting for the TUN helper")
        self._publish(state)
        return state

    async def stop(self, timeout: float = 20.0) -> Dict[str, Any]:
        state = await self._read_state_async()
        if state.get("phase") in (PHASE_STOPPED, PHASE_CANCELLED):
            self._publish(state)
            return state
        await asyncio.to_thread(self.stop_path.parent.mkdir, parents=True, exist_ok=True)
        await asyncio.to_thread(self.stop_path.write_text, "stop", encoding="utf-8")
        deadline = self._clock() + timeout
        while self._clock() < deadline:
            state = await self._read_state_async()
            if state.get("phase") == PHASE_STOPPED:
                self._publish(state)
                return state
            if state.get("phase") in (PHASE_FAILED, PHASE_RECOVERY):
                # The helper already gave up.  It may still be alive (for
                # example a failed route cleanup) and must not survive into
                # the next Connect attempt.
                break
            await self._sleep(self._poll_interval)
        state = dict(await self._read_state_async() or {})
        try:
            pid = int(state.get("pid") or 0)
        except (TypeError, ValueError):
            pid = 0
        if not pid:
            try:
                pid = int(self.launch_info.get("pid") or 0)
            except (TypeError, ValueError):
                pid = 0
        terminated = bool(pid) and self._terminate_helper(pid)
        if terminated:
            result = {
                "phase": PHASE_STOPPED,
                "error": "",
                "stop_reason": "force-terminated",
                "adapter": self.spec.adapter,
            }
            self._publish(result)
            return result
        state.setdefault("phase", PHASE_RECOVERY)
        state.setdefault("error", "helper did not confirm stop before timeout")
        self._publish(state)
        return state

    async def update_bypass(
        self,
        ips: Sequence[str],
        *,
        persist: Sequence[str] = (),
        prune: bool = False,
        version: Optional[int] = None,
        timeout: float = 20.0,
    ) -> Dict[str, Any]:
        state = self._read_state()
        try:
            current = int(state.get("bypass_version") or 0)
        except (TypeError, ValueError):
            current = 0
        target = int(version) if version is not None else current + 1
        if target <= current:
            target = current + 1
        payload = {
            "version": target,
            "ips": [str(v).strip() for v in ips if str(v or "").strip()],
            "persist": [str(v).strip() for v in persist if str(v or "").strip()],
            "prune": bool(prune),
        }
        self.bypass_path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write_json(self.bypass_path, payload)
        deadline = self._clock() + timeout
        while self._clock() < deadline:
            state = self._read_state()
            try:
                acked = int(state.get("bypass_version") or 0)
            except (TypeError, ValueError):
                acked = 0
            error = str(state.get("bypass_error") or "")
            if acked >= target:
                if error:
                    raise CoexistenceError(
                        "bypass update %d was refused: %s" % (target, error)
                    )
                self._publish(state)
                return state
            phase = str(state.get("phase") or "")
            if phase in (PHASE_FAILED, PHASE_RECOVERY, PHASE_STOPPED, PHASE_CANCELLED):
                raise CoexistenceError(
                    "TUN helper is %s; bypass update %d was not applied" % (phase, target)
                )
            await self._sleep(self._poll_interval)
        raise CoexistenceError(
            "timed out waiting for the helper to acknowledge bypass update %d" % target
        )


# ---------------------------------------------------------------------------
# Helper process lifecycle & runners
# ---------------------------------------------------------------------------


_CTRL_BREAK_EVENT = signal.CTRL_BREAK_EVENT if hasattr(signal, "CTRL_BREAK_EVENT") else None


def _default_spawn(cmd: Sequence[str], log_path: Optional[Path] = None):
    stdout_dest = None
    stderr_dest = None
    if log_path is not None:
        log_f = open(log_path, "a", encoding="utf-8")
        stdout_dest = log_f
        stderr_dest = log_f
    return popen_hidden(
        [str(c) for c in cmd],
        new_process_group=True,
        stdout=stdout_dest,
        stderr=stderr_dest,
    )


async def _default_probe(adapter: str) -> tun_status.AdapterEvidence:
    return await tun_status.probe_adapter(adapter)


async def _default_egress() -> Dict[str, Any]:
    return await tun_status.probe_system_egress()


def _parent_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if sys.platform != "win32":
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    SYNCHRONIZE = 0x00100000
    handle = ctypes.windll.kernel32.OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, False, pid
    )
    if not handle:
        return False
    try:
        exit_code = ctypes.c_ulong()
        if ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
            STILL_ACTIVE = 259
            return exit_code.value == STILL_ACTIVE
        return False
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


_CTRL_BREAK_DRAIN_SECONDS = 1.5


def _terminate(proc, timeout: float = 5.0) -> None:
    if proc is None or getattr(proc, "returncode", None) is not None:
        return
    if getattr(proc, "poll", lambda: None)() is not None:
        return
    if sys.platform == "win32" and _CTRL_BREAK_EVENT is not None:
        try:
            proc.send_signal(_CTRL_BREAK_EVENT)
        except Exception:
            pass
        try:
            proc.wait(timeout=_CTRL_BREAK_DRAIN_SECONDS)
            return
        except Exception:
            pass
    try:
        proc.terminate()
        proc.wait(timeout=timeout)
        return
    except Exception:
        pass
    try:
        proc.kill()
        proc.wait(timeout=2.0)
    except Exception:
        pass


def terminate_pid(pid: int, executable: str = "") -> bool:
    if pid <= 0:
        return False
    if sys.platform != "win32":
        try:
            os.kill(pid, signal.SIGTERM)
            return True
        except OSError:
            return False
    try:
        res = run_hidden(
            ["taskkill", "/F", "/PID", str(pid)],
            capture_output=True,
            check=False,
        )
        return res.returncode == 0
    except Exception:
        return False


def _residual_diffs(
    baseline: NetworkSnapshot,
    after: Optional[NetworkSnapshot],
    adapter: str,
    *,
    managed_prefixes: Sequence[str] = (),
    managed_interfaces: Sequence[int] = (),
    compare: Optional[Callable[[NetworkSnapshot, NetworkSnapshot], Sequence[Any]]] = None,
) -> List[str]:
    """Differences that this helper is responsible for leaving behind."""
    if after is None:
        return ["post-teardown network state could not be captured"]
    compare_fn = compare or compare_snapshots
    try:
        diffs = compare_fn(baseline, after)
    except Exception as exc:
        return ["snapshot comparison failed: %s" % exc]
    prefixes = {str(v).strip().lower() for v in managed_prefixes if str(v or "").strip()}
    interfaces = set()
    for index in managed_interfaces:
        try:
            interfaces.add(int(index))
        except (TypeError, ValueError):
            continue
    ignored = {p.lower() for p in _IGNORED_ROUTE_PREFIXES}
    residual: List[str] = []
    for diff in diffs:
        record = diff.current_value or diff.baseline_value or {}
        if not isinstance(record, dict):
            record = {}
        if diff.category == "adapter":
            name = str(record.get("Name") or "").strip().lower()
            if name != str(adapter).strip().lower():
                continue
        elif diff.category in ("dns", "ip_address", "interface"):
            iface = record.get("InterfaceIndex")
            try:
                iface = int(iface) if iface is not None else None
            except (TypeError, ValueError):
                iface = None
            if iface not in interfaces:
                continue
        elif diff.category == "route":
            prefix = str(record.get("DestinationPrefix") or "").strip().lower()
            if prefix in ignored:
                continue
            iface = record.get("InterfaceIndex")
            try:
                iface = int(iface) if iface is not None else None
            except (TypeError, ValueError):
                iface = None
            if prefix and prefix not in prefixes and iface not in interfaces:
                continue
        residual.append("%s: %s" % (diff.category, diff.description))
    return residual


async def run_helper(
    spec: TunHelperSpec,
    *,
    state_path: Path,
    stop_path: Path,
    journal: Optional[Path] = None,
    bypass_path: Optional[Path] = None,
    spawn: Callable[..., Any] = _default_spawn,
    probe: Callable[[str], Any] = _default_probe,
    egress: Callable[[], Any] = _default_egress,
    capture: Callable[[], NetworkSnapshot] = capture_snapshot_preferred,
    sleep: Callable[[float], Any] = asyncio.sleep,
    clock: Callable[[], float] = time.monotonic,
    parent_alive: Callable[[int], bool] = _parent_alive,
    terminate: Callable[[Any], None] = _terminate,
    startup_timeout: float = 25.0,
    poll_interval: float = 0.5,
    fast_adapter: bool = False,
    compare: Optional[Callable[..., Any]] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Run elevated sing-box lifecycle until stop or exit."""
    helper_started = clock()
    journal_path_ = Path(journal) if journal is not None else journal_path()
    state: Dict[str, Any] = {
        "version": STATE_VERSION,
        "phase": PHASE_STARTING,
        "adapter": spec.adapter,
        "pid": os.getpid(),
        "spec_fingerprint": spec.fingerprint,
        "error": "",
        "bypass_version": 0,
        "physical": None,
        "timings": {},
    }

    def publish(**updates: Any) -> Dict[str, Any]:
        state.update(updates)
        _atomic_write_json(state_path, state)
        return dict(state)

    def _write_journal(phase: str, child_pid: int = 0, **extra: Any) -> None:
        rec = {
            "version": STATE_VERSION,
            "phase": phase,
            "adapter": spec.adapter,
            "child_pid": child_pid,
            "executable": spec.executable,
            "spec_fingerprint": spec.fingerprint,
            "started_at": time.time(),
            "parent_pid": spec.parent_pid,
            "owner_pid": spec.owner_pid,
            "bypass_version": int(state.get("bypass_version") or 0),
        }
        rec.update(extra)
        _atomic_write_json(journal_path_, rec)

    # 1. Fast IPC handshake: notify the GUI client that elevated helper is running
    publish(phase=PHASE_STARTING, ipc_ready=True)

    # Clean any stale journal from a previous crash
    stale = load_journal(journal_path_)
    if stale and str(stale.get("phase") or "") not in (PHASE_STOPPED, ""):
        recover_ownership(
            stale,
            terminate=lambda p: terminate_pid(p, str(stale.get("executable") or "")),
        )
        _unlink(journal_path_)

    # 2. Baseline capture & physical egress validation
    try:
        baseline = capture()
    except Exception as exc:
        logger.error("Failed to capture baseline network state: %s", exc)
        return publish(phase=PHASE_FAILED, error="capture failed: %s" % exc)
    timings = {"capture_seconds": round(clock() - helper_started, 3)}

    physical_ip = detect_physical_ipv4(baseline)
    if not physical_ip:
        return publish(
            phase=PHASE_FAILED,
            error="no physical IPv4 egress interface available",
        )

    if_idx, gw = physical_route_gateway(baseline, physical_ip)
    physical_rec = _physical_adapter_record(baseline, if_idx) if if_idx is not None else None
    if physical_rec and _is_virtual_adapter(physical_rec):
        return publish(
            phase=PHASE_FAILED,
            error="no physical IPv4 egress (adapter %s is virtual)" % (physical_rec.get("Name") or ""),
        )

    conflict = detect_tunnel_conflict(baseline, spec.adapter)
    publish(
        physical={
            "adapter": str((physical_rec or {}).get("Name") or ""),
            "interface_index": if_idx,
            "gateway": gw,
            "ip": physical_ip,
        },
        coexisting_with=conflict,
        dns_policy="perchvpn",
        timings=dict(timings),
    )

    # 3. Check early stop request
    if await asyncio.to_thread(stop_path.exists):
        _unlink(journal_path_)
        return publish(
            phase=PHASE_STOPPED,
            error="",
            stop_reason="stop-request",
        )

    # 4. Build sing-box configuration (delegating all routes/interface to sing-box auto_route)
    config_started = clock()
    singbox_config_path = state_path.with_name("sing-box.json")
    try:
        cmd = build_sidecar_command(spec, config_path=singbox_config_path, setup=True)
    except Exception as exc:
        logger.error("Failed to build sing-box command: %s", exc)
        return publish(phase=PHASE_FAILED, error="config generation failed: %s" % exc)
    timings["config_seconds"] = round(clock() - config_started, 3)

    # 5. Launch sing-box sidecar process with CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW
    spawn_started = clock()
    _write_journal(PHASE_STARTING, child_pid=0)
    sidecar_log = state_path.with_name("tun-helper-sidecar.log")
    try:
        proc = spawn(cmd, sidecar_log) if spawn is _default_spawn else spawn(cmd)
    except Exception as exc:
        logger.error("Failed to spawn sing-box: %s", exc)
        _unlink(journal_path_)
        return publish(phase=PHASE_FAILED, error="sidecar spawn failed: %s" % exc)
    timings["spawn_seconds"] = round(clock() - spawn_started, 3)
    sidecar_started = clock()

    child_pid = int(getattr(proc, "pid", 0) or 0)
    publish(phase=PHASE_STARTING, child_pid=child_pid, command=cmd, timings=dict(timings))
    _write_journal(PHASE_STARTING, child_pid=child_pid)

    # 6. Wait for Wintun adapter to appear and become ready
    evidence = None
    deadline = clock() + startup_timeout
    adapter_ready = False
    adapter_ifindex = None
    adapter_guid = ""

    while clock() < deadline:
        returncode = getattr(proc, "poll", lambda: None)()
        if returncode is not None:
            _unlink(journal_path_)
            return publish(
                phase=PHASE_FAILED,
                error="sing-box exited before becoming ready (code %s)" % returncode,
                sidecar_exit_code=returncode,
            )
        try:
            pending = probe(spec.adapter)
            evidence = await pending if inspect.isawaitable(pending) else pending
        except Exception as exc:
            evidence = None
            logger.debug("adapter probe error: %s", exc)

        if (
            evidence is not None
            and getattr(evidence, "up", False)
            and getattr(evidence, "has_ipv4", False)
        ):
            adapter_ready = True
            adapter_ifindex = getattr(
                evidence, "if_index", getattr(evidence, "interface_index", None)
            )
            adapter_guid = getattr(evidence, "guid", "")
            break
        await sleep(poll_interval)

    if not adapter_ready:
        terminate(proc)
        _unlink(journal_path_)
        return publish(
            phase=PHASE_FAILED,
            error="tunnel adapter %r did not come up with an IPv4 address within %.0fs"
            % (spec.adapter, startup_timeout),
        )

    # 7. Publish ready state and optional egress evidence
    timings["sidecar_seconds"] = round(clock() - sidecar_started, 3)
    timings["total_seconds"] = round(clock() - helper_started, 3)
    publish(
        phase=PHASE_READY,
        evidence=evidence.to_dict() if hasattr(evidence, "to_dict") else None,
        timings=dict(timings),
    )
    _write_journal(PHASE_READY, child_pid=child_pid, adapter_guid=adapter_guid)

    try:
        egress_probe = (
            await egress() if inspect.iscoroutinefunction(egress) else egress()
        )
        if inspect.isawaitable(egress_probe):
            egress_probe = await egress_probe
    except Exception as exc:
        egress_probe = {"ok": False, "error": str(exc)}

    publish(
        phase=PHASE_READY,
        system_egress=egress_probe,
        bypass_version=int(state.get("bypass_version") or 0),
        bypass_error="",
    )

    # 8. Monitor process health, parent lifecycle, stop file, and bypass updates
    watch_pid = spec.owner_pid or spec.parent_pid
    seen_bypass_version = 0
    stop_reason = ""
    sidecar_died = False
    sidecar_exit_code = None

    while True:
        if await asyncio.to_thread(stop_path.exists):
            stop_reason = "stop-request"
            break
        if watch_pid and not parent_alive(watch_pid):
            stop_reason = "parent-exited"
            break
        returncode = getattr(proc, "poll", lambda: None)()
        if returncode is not None:
            sidecar_died = True
            sidecar_exit_code = returncode
            stop_reason = "sidecar-exited"
            break

        if bypass_path is not None and await asyncio.to_thread(bypass_path.exists):
            request = await asyncio.to_thread(_read_json, bypass_path)
            if isinstance(request, dict):
                try:
                    version = int(request.get("version") or 0)
                except (TypeError, ValueError):
                    version = 0
                if version > seen_bypass_version:
                    seen_bypass_version = version
                    new_ips = [
                        str(v).strip()
                        for v in (request.get("ips") or [])
                        if str(v).strip()
                    ]
                    for ip in new_ips:
                        if ip not in spec.bypass:
                            spec.bypass.append(ip)
                    try:
                        build_sidecar_command(
                            spec, config_path=singbox_config_path, setup=True
                        )
                        publish(
                            phase=PHASE_READY,
                            bypass_version=version,
                            bypass_error="",
                        )
                        _write_journal(PHASE_READY, child_pid=child_pid, adapter_guid=adapter_guid)
                    except Exception as exc:
                        publish(
                            phase=PHASE_READY,
                            bypass_version=version,
                            bypass_error=str(exc),
                        )
        await sleep(poll_interval)

    # 9. Clean teardown: signal stop, terminate sidecar, publish terminal state
    publish(phase=PHASE_STOPPING)
    _write_journal(PHASE_STOPPING, child_pid=child_pid, adapter_guid=adapter_guid)
    await asyncio.to_thread(terminate, proc)

    # Residual check
    residual_managed_ifaces = [adapter_ifindex] if adapter_ifindex else []
    post_snap = None
    try:
        post_snap = capture()
    except Exception:
        pass
    diffs = _residual_diffs(
        baseline,
        post_snap,
        spec.adapter,
        managed_interfaces=residual_managed_ifaces,
        compare=compare or compare_snapshots,
    )
    if diffs:
        return publish(
            phase=PHASE_RECOVERY,
            error="residual state detected after teardown: %s" % "; ".join(diffs),
            residual=diffs,
        )

    _unlink(journal_path_)

    if sidecar_died:
        publish(
            phase=PHASE_FAILED,
            error="sing-box exited unexpectedly (code %s)" % sidecar_exit_code,
            stop_reason=stop_reason,
            sidecar_exit_code=sidecar_exit_code,
        )
    else:
        publish(
            phase=PHASE_STOPPED,
            error="",
            stop_reason=stop_reason,
        )

    return dict(state)


def _helper_log(message: str) -> None:
    stream = sys.stderr
    if stream is None:
        return
    try:
        print(message, file=stream)
        stream.flush()
    except Exception:
        return


def helper_main(spec_path: str) -> int:
    """Entry point for the elevated helper CLI process."""
    if not spec_path:
        _helper_log("tun helper: missing spec path")
        return 2
    spec_file = Path(spec_path)
    data = _read_json(spec_file)
    if not data:
        _helper_log("tun helper: unreadable spec")
        return 2
    try:
        spec = TunHelperSpec.from_dict(data)
    except (KeyError, ValueError) as exc:
        _helper_log("tun helper: invalid spec: %s" % exc)
        return 2
    state_path = spec_file.with_name("tun-helper-state.json")
    stop_path = spec_file.with_name("tun-helper-stop")
    bypass_path = spec_file.with_name("tun-helper-bypass.json")
    try:
        final = asyncio.run(
            run_helper(
                spec,
                state_path=state_path,
                stop_path=stop_path,
                bypass_path=bypass_path,
                fast_adapter=True,
            )
        )
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # noqa: BLE001
        try:
            _atomic_write_json(
                state_path,
                {
                    "version": STATE_VERSION,
                    "phase": PHASE_FAILED,
                    "adapter": spec.adapter,
                    "error": "tun helper crashed: %s" % exc,
                },
            )
        except Exception:
            pass
        _helper_log("tun helper: fatal: %s" % exc)
        return 1
    return 0 if final.get("phase") == PHASE_STOPPED else 1
