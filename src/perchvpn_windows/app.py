"""Windows application orchestrator: composes the owned Perch VPN core components."""

from __future__ import annotations

import asyncio
import logging
import socket
import os
import signal
import subprocess
import sys
import time
from collections import deque
from typing import Callable, Optional

from pathlib import Path

from perchvpn import auth as auth_module
from perchvpn import guardian, serverlist, tokens as tokens_module
from perchvpn.controller import ControllerConfig, ProxyController
from perchvpn.exitcheck import verify_exit_country
from perchvpn.http_client import set_control_plane_proxy, set_control_plane_timeout
from perchvpn.logging_config import configure_logger
from perchvpn_windows.platform import discard_legacy_tokens, get_token_path
from perchvpn.proxy.pool import SessionPool
from perchvpn.proxystate import ProxyCandidate, ProxyStateStore, resolve_proxy, alternate_candidates
from perchvpn_windows.frontend import Socks5Frontend
from perchvpn_windows.tun_frontend import TunFrontend
from perchvpn_windows import tun_status
from perchvpn_windows.tun_recovery import RECOVERY_UNVERIFIED
from perchvpn_windows.http_proxy import HttpProxyServer
from perchvpn_windows.metrics import TrafficMetrics
from perchvpn_windows.ui import Dashboard, DashboardData

logger = logging.getLogger("perchvpn_windows.app")

# How often a verified control-plane pin is re-resolved while the TUN is up.
CONTROL_PLANE_PIN_REFRESH_SECONDS = 300.0
# A country switch has no OS fallback: give the physical resolver enough time
# to exhaust port 53 and complete its DoH fallback before failing closed.
COUNTRY_SWITCH_PIN_TIMEOUT_SECONDS = 5.0
# Startup route/DNS probes are a hint only.  Never let a foreign tunnel or a
# slow PowerShell route lookup hold the API/UI boot open.
PREFLIGHT_TIMEOUT_SECONDS = 1.0
# A mode switch must acknowledge the UI quickly; readiness evidence can take
# minutes on a cold/AV-scanned host and continues in the background.
MODE_APPLY_ACK_SECONDS = 5.0
MODE_STARTUP_TIMEOUT_SECONDS = 660.0


def auth_helper_command(sys_executable: str, env: dict) -> list[str]:
    """Build the auth-only helper invocation, frozen-build aware.

    Under PyInstaller, ``sys.executable`` is the app exe itself and its
    entrypoint already dispatches any argv through the CLI — so the helper
    must simply be ``<exe> --auth-only``. Passing ``-m perchvpn_windows.cli``
    makes argparse fail on ``-m`` and the terminal helper exits before doing
    anything (the GUI sign-in button then appears dead).

    The optional ``env`` may flag a frozen build via ``PERCHVPN_FROZEN=1``
    to make tests deterministic on POSIX; `sys.frozen` only exists under the
    PyInstaller interpreter.
    """

    frozen = bool(getattr(sys, "frozen", False)) or env.get("PERCHVPN_FROZEN") == "1"
    if frozen:
        return [sys_executable, "--auth-only"]
    return [sys_executable, "-m", "perchvpn_windows.cli", "--auth-only"]


class _LogCaptureHandler(logging.StreamHandler):
    """Logging handler that captures log records for test assertions.

    Used during app initialization to capture and verify log output,
    particularly in lifecycle tests.
    """

    def __init__(self):
        super().__init__(stream=sys.stdout)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)
        # Pass to parent for default output
        super().emit(record)


def _is_windows() -> bool:
    """Platform gate for Windows-only socket/route controls (tests patch it)."""
    return sys.platform == "win32"


def _is_singbox_name(path: str) -> bool:
    """True when a configured executable is a sing-box binary.

    ``tun_executable_path`` predates the sing-box engine and old installs
    still point at ``tun2proxy-bin.exe``.  Honouring that stale value makes
    the app launch tun2proxy with ``run -c`` and crash immediately, so only
    a sing-box-named path is accepted.
    """
    name = Path(str(path or "")).name.lower()
    return name.startswith("sing-box") and not name.endswith(".dll")


def resolve_tun_executable(configured: str = "") -> str:
    """Resolve the sing-box sidecar, ignoring stale tun2proxy config values."""
    configured = str(configured or "").strip()
    if configured and _is_singbox_name(configured):
        return configured
    if configured:
        logger.warning(
            "ignoring stale tun_executable_path %r (expected sing-box.exe); "
            "falling back to the bundled sidecar",
            configured,
        )
    if sys.platform != "win32":
        return ""

    bases = []
    if getattr(sys, "frozen", False):
        bases.append(Path(sys.executable).resolve().parent)
    bases.append(Path(__file__).resolve().parent)
    bases.append(Path.cwd())
    bases.append(Path.cwd() / "bin")
    for base in bases:
        candidate = base / "sing-box.exe"
        if candidate.is_file():
            return str(candidate)
    return ""


def _physical_dns_servers(interface_index: int) -> list[str]:
    """IPv4 DNS servers configured on the physical adapter."""
    from perchvpn_windows import tun_helper

    try:
        servers = tun_helper.capture_adapter_dns(interface_index, family="IPv4")
    except Exception:  # noqa: BLE001 - absence is reported as zero servers
        return []
    return [str(value) for value in servers if value and ":" not in str(value)]


def _route_interface(destination: str) -> Optional[int]:
    """Interface index the route table selects for ``destination``."""
    from perchvpn_windows import tun_helper

    try:
        return tun_helper.find_route_interface(destination)
    except Exception:  # noqa: BLE001 - unverifiable route fails closed
        return None


def _select_physical_dns_servers(
    interface_index: int,
    servers: list[str],
    route_lookup=_route_interface,
) -> tuple[list[str], list[tuple[str, Optional[int]]]]:
    """Keep only DNS servers the route table sends out the physical NIC.

    A configured server that the route table would send into another tunnel
    (for example PattN's loopback adapter) is dropped: querying it would make
    the answer depend on that tunnel, even though the resulting address is
    later pinned to the physical adapter.

    Returns ``(selected, rejected)`` where ``rejected`` maps every dropped
    server to the interface index its route actually leaves through (or
    None when the route lookup failed) so the refusal warning can name the
    competing tunnel instead of only reporting that zero servers survived.
    """
    selected: list[str] = []
    rejected: list[tuple[str, Optional[int]]] = []
    for server in servers:
        text = str(server or "").strip()
        if not text or ":" in text:
            continue
        route_index = route_lookup(text)
        if route_index != interface_index:
            rejected.append((text, route_index))
            continue
        if text not in selected:
            selected.append(text)
    return selected, rejected


def _physical_ipv4_addresses(
    name: str,
    *,
    physical_ip: str,
    physical_index: int,
) -> list[str]:
    """Resolve ``name`` over the physical adapter's own DNS servers.

    ``socket.getaddrinfo`` honours interface metrics and NRPT/split-DNS, so
    with another tunnel active it can resolve through that tunnel.  These
    queries are sent to a DNS server whose route was verified to leave via
    the physical interface, from a socket bound to the physical address, so
    the resolution path is proven rather than assumed.  When local filters
    block UDP/53, ``resolve_ipv4`` falls back to source-bound DoH to an
    IP-literal resolver; any DoH failure still fails closed.
    """
    from perchvpn_windows import physical_dns

    servers, rejected = _select_physical_dns_servers(
        physical_index,
        _physical_dns_servers(physical_index),
        route_lookup=_route_interface,
    )
    if not servers:
        detail = "; ".join(
            "%s -> ifIndex %s" % (server, route_index if route_index is not None else "?")
            for server, route_index in rejected
        )
        raise RuntimeError(
            "no DNS server configured on the physical adapter leaves via "
            "interface %d%s; refusing to resolve %r on an unverified path"
            % (
                physical_index,
                (" (routes: %s)" % detail) if detail else "",
                name,
            )
        )
    return physical_dns.resolve_ipv4(
        name,
        servers,
        source_ip=physical_ip,
        interface_index=physical_index,
        timeout=1.0,
    )


def _getaddrinfo_ipv4_addresses(name: str) -> list[str]:
    """Resolve IPv4 addresses with the standard OS resolver.

    Native sing-box mode excludes upstream destinations at the driver level
    via ``route_exclude_address``, so a plain resolver answer is sufficient
    here: the TUN's route excludes keep the dial on the physical path even
    when interface-specific DNS servers or gateway next-hops cannot be
    enumerated.
    """
    addresses: list[str] = []
    for info in socket.getaddrinfo(
        name, None, family=socket.AF_INET, type=socket.SOCK_STREAM
    ):
        address = info[4][0]
        if address and address not in addresses:
            addresses.append(address)
    return addresses


_GLOBAL_DNS_CACHE: dict[str, list[str]] = {}


class PerchVPNApp:
    """Main Windows application: owns the proxy controller, session pool, and frontend."""

    def __init__(self, config: WindowsConfig):
        self.config = config
        self._controller: Optional[ProxyController] = None
        self._pool: Optional[SessionPool] = None
        self._frontend: Optional[Socks5Frontend] = None
        self._http_proxy: Optional[HttpProxyServer] = None
        self._exit_check_task: Optional[asyncio.Task] = None
        self._runtime_auth: Optional[auth_module.RuntimeAuth] = None
        self._candidate: Optional[ProxyCandidate] = None
        self._selected_from_state = False
        self._exit_ip: str = "0.0.0.0"
        self._exit_country: str = "--"
        # not_applicable | pending | verified | failed | proxy_only
        self._exit_verification_state: str = "not_applicable"
        self._status_state: str = "disconnected"  # disconnected | connecting | connected | proxy_active
        self._log_handler = _LogCaptureHandler()
        self._original_log_level = logging.NOTSET
        self._resize_event = asyncio.Event()
        self._terminal_process: Optional[subprocess.Popen] = None
        self._auth_handoff_lock = asyncio.Lock()
        self._auth_handoff_disabled = False
        self._auth_helper_process: Optional[subprocess.Popen] = None
        self._tun_frontend: Optional[TunFrontend] = None
        self._tun_baseline: Optional[dict] = None
        self._tun_start_error = ""
        # Elevated helper lifecycle (UAC): the GUI never needs admin rights.
        self._tun_helper = None
        self._tun_helper_watch: Optional[asyncio.Task] = None
        self._status_notifier: Optional[Callable[[], None]] = None
        self._mode_transition: Optional[dict] = None
        self._mode_transition_seq = 0
        self._mode_lock = asyncio.Lock()
        self._mode_task: Optional[asyncio.Task] = None
        # --- Country hot-swap state (SOCKS5/TUN stay up; only the upstream
        # pool is exchanged). _switch_id is monotonic so superseded work and
        # stale exit checks can be discarded without cancelling safely.
        self._switch_id = 0
        self._switch_task: Optional[asyncio.Task] = None
        self._switch_state = "idle"  # idle | switching | verifying | complete | stale | failed
        self._switch_target = ""
        self._switch_started_at = 0.0
        self._switch_duration_ms = 0.0
        self._switch_phases: list = []
        self._switch_error = ""
        self._source_bind_ip: Optional[str] = None
        self._resolved_edge_host: Optional[str] = None
        # Persistent control-plane endpoints resolved on the physical path
        # at TUN activation (guardian, custom edge, upstream proxy).  Cached
        # so they stay pinned across country hot-swaps and hot-swap prunes.
        self._tun_control_plane_ips: list[str] = []
        # Physical interface index verified at activation and the verified
        # hostname pins currently used for control-plane dials.
        self._physical_index: Optional[int] = None
        self._control_plane_dial_ips: dict[str, list[str]] = {}
        self._upstream_proxy_pin: Optional[str] = None
        self._control_plane_refresh_task: Optional[asyncio.Task] = None
        # Backing storage for the _dns_cache property below; assigning to the
        # property itself would raise AttributeError during app startup.
        self._dns_cache_dict: dict[str, list[str]] = {}
        # True when boot completed fully signed out (no credentials yet).
        self._signed_out_boot = False
        # True while the app is booting without dialling; cleared as soon as
        # an explicit Connect starts initialization.
        self._boot_idle = False

    @property
    def _dns_cache(self) -> dict[str, list[str]]:
        cache = getattr(self, "_dns_cache_dict", None)
        if cache is None:
            cache = {}
            self._dns_cache_dict = cache
        return cache

    def _record_cached_ip(self, host: str, ips: Sequence[str]) -> None:
        from perchvpn.doh_resolver import _is_ip

        clean = str(host or "").strip().lower()
        if not clean:
            return
        valid = [str(ip).strip() for ip in ips if ip and _is_ip(str(ip).strip())]
        if valid:
            self._dns_cache[clean] = list(valid)
            _GLOBAL_DNS_CACHE[clean] = list(valid)

    def _lookup_cached_ip(self, host: str) -> Optional[str]:
        from perchvpn.doh_resolver import _is_ip

        clean = str(host or "").strip().lower()
        if not clean:
            return None
        cached = self._dns_cache.get(clean) or _GLOBAL_DNS_CACHE.get(clean)
        if cached:
            return cached[0]
        resolved_edge = getattr(self, "_resolved_edge_host", None)
        if resolved_edge and _is_ip(resolved_edge):
            cand = getattr(self, "_candidate", None)
            cand_host = str(getattr(cand, "host", "") or "").strip().lower()
            if clean == cand_host:
                return resolved_edge
        cand = getattr(self, "_candidate", None)
        if cand and _is_ip(getattr(cand, "host", "")):
            if clean == str(cand.host).strip().lower():
                return str(cand.host).strip()
        for h, dial_ips in getattr(self, "_control_plane_dial_ips", {}).items():
            if h.lower() == clean and dial_ips:
                return dial_ips[0]
        return None

    def _launch_in_new_terminal(self) -> bool:
        """Launch the app in a dedicated Windows Terminal window.
        
        Returns True if launched in new window, False if running in current terminal.
        """
        if not self.config.dashboard:
            return False
        
        if os.environ.get("PERCHVPN_DASHBOARD_WINDOW") == "1":
            return False
        
        try:
            wt_path = self._find_windows_terminal()
            if not wt_path:
                logger.debug("Windows Terminal not found, running in current terminal")
                return False
            
            cmd = [sys.executable, "-m", "perchvpn_windows.cli"]
            for arg in sys.argv[1:]:
                if arg not in ("--new-window", "--dashboard"):
                    cmd.append(arg)
            cmd.append("--dashboard")
            
            env = os.environ.copy()
            env["PERCHVPN_DASHBOARD_WINDOW"] = "1"
            
            self._terminal_process = subprocess.Popen(
                [wt_path, "-w", "0", "new-tab", "--"] + cmd,
                env=env,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
            )
            
            logger.info("Launched dashboard in dedicated Windows Terminal window")
            return True
        except Exception as e:
            logger.debug(f"Failed to launch dedicated terminal: {e}")
            return False
    
    def _find_windows_terminal(self) -> Optional[str]:
        """Find Windows Terminal executable."""
        candidates = [
            r"C:\Users\{}\AppData\Local\Microsoft\WindowsApps\wt.exe".format(os.getenv("USERNAME", "")),
            r"C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_*\wt.exe",
            "wt.exe",
        ]
        
        for candidate in candidates:
            if candidate == "wt.exe":
                import shutil
                if shutil.which("wt"):
                    return "wt"
            else:
                import glob
                matches = glob.glob(candidate)
                if matches:
                    return matches[0]
        
        import shutil
        return shutil.which("wt")

    def set_status_notifier(self, notifier: Optional[Callable[[], None]]) -> None:
        """Register the API's immediate status-push hook (event-driven WS)."""
        self._status_notifier = notifier

    def _notify_status(self) -> None:
        notifier = getattr(self, "_status_notifier", None)
        if notifier is None:
            return
        try:
            notifier()
        except Exception:  # noqa: BLE001 - status push must never break lifecycle
            logger.debug("status notifier failed", exc_info=True)

    def _start_tun_helper_watch(self) -> None:
        watch = getattr(self, "_tun_helper_watch", None)
        if watch is not None and not watch.done():
            return
        self._tun_helper_watch = asyncio.create_task(
            self._watch_tun_helper_state()
        )

    async def _watch_tun_helper_state(self) -> None:
        """Push helper phase changes as soon as the state file changes.

        The API monitor polls /api/status every 250 ms; this watcher cuts
        the elevated-helper path (UAC -> starting -> ready -> verifying) to
        ~200 ms without adding an IPC channel.
        """
        last = None
        try:
            while getattr(self, "_tun_helper", None) is not None:
                try:
                    read = getattr(self._tun_helper, "snapshot_async", None)
                    if callable(read):
                        snapshot = await read()
                    else:
                        snapshot = await asyncio.to_thread(self._tun_helper.snapshot)
                except Exception:  # noqa: BLE001 - transient file read
                    snapshot = {}
                signature = (
                    snapshot.get("phase"),
                    snapshot.get("error"),
                    snapshot.get("stop_reason"),
                    snapshot.get("pid"),
                )
                if signature != last:
                    last = signature
                    self._notify_status()
                await asyncio.sleep(0.2)
        except asyncio.CancelledError:
            raise
        finally:
            self._tun_helper_watch = None

    async def _stop_tun_helper_watch(self) -> None:
        task = getattr(self, "_tun_helper_watch", None)
        self._tun_helper_watch = None
        if task is None or task.done():
            return
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass

    async def initialize(self, *, auto_connect: bool = True) -> None:
        """Initialize logging and, only when connecting, the VPN components.

        ``auto_connect=False`` is the boot path: it prepares logging/token
        migration and then returns with the app idle and disconnected.  No
        auth dial, proxy listener, TUN helper, or mode switch is started.
        """
        started_controller: Optional[ProxyController] = None
        started_pool: Optional[SessionPool] = None
        started_frontend: Optional[Socks5Frontend] = None
        started_exit_check_task: Optional[asyncio.Task] = None
        self._boot_idle = not auto_connect
        # Honest early status: while an explicit Connect is dialling, claim
        # "connecting" up front.  Idle boot must stay disconnected.
        self._status_state = "connecting" if auto_connect else "disconnected"

        try:
            if self.config.dashboard:
                self._setup_dashboard_logging()
            else:
                from perchvpn.logging_config import configure_logger
                configure_logger(self.config.log_level, self.config.log_format)
            set_control_plane_timeout(self.config.handshake_timeout * 2)

            # Physical egress source pin (see _tun_bypass_ips / tun_frontend):
            # explicit config wins; otherwise the TUN preflight below
            # autodetects the primary non-tunnel IPv4. Autodetect failure is
            # tolerated here (auth/dials stay unbound); starting the TUN
            # itself still fails closed in _start_tun_frontend.
            from perchvpn.http_client import set_local_address

            # Rebrand continuity: migrated legacy tokens let the boot's
            # non-interactive auth see an otherwise-stranded session.
            from perchvpn_windows.platform import migrate_legacy_tokens
            migrate_legacy_tokens()

            source_ip = self.config.source_bind_ip or None
            if source_ip:
                logger.info("pinning control-plane egress to %s", source_ip)
                set_local_address(source_ip)
            self._source_bind_ip = source_ip

            if not auto_connect:
                logger.info(
                    "boot idle: no connection started; waiting for explicit Connect"
                )
                return

            # TUN mode: the tunnel will own the default route, so the pre-TUN
            # control-plane bootstrap (auth, Guardian) must already be bound
            # to the physical adapter.  This is a startup hint, not a
            # readiness gate: route/DNS probes are timeout-bounded and a
            # foreign tunnel or secondary default route must not block the
            # API/UI from coming up.  Activation re-runs the strict checks.
            if self.config.tun_enabled:
                await self._startup_physical_preflight()

            try:
                # The backend never performs an interactive login
                # (non-interactive: the terminal helper is the only
                # interactive entry point). With no credentials this raises
                # InteractiveLoginRequired and the boot completes fully
                # signed out so the GUI can drive sign-in via the helper.
                self._runtime_auth = await self._obtain_auth(False)
            except auth_module.InteractiveLoginRequired as exc:
                self._runtime_auth = None
                self._signed_out_boot = True
                self._status_state = "disconnected"
                logger.info("starting signed out; no credentials yet (%s)", exc)
                # No controller/proxy/SOCKS frontend without auth: the GUI
                # stays on the disconnected state until the helper persists
                # tokens and the user connects (/api/restart applies them).
                return

            # --- Proxy-only mode: skip tunnel establishment ---
            if self.config.proxy_only_mode:
                self._status_state = "proxy_active"
                self._exit_verification_state = "not_applicable"
                logger.info("proxy-only mode: local SOCKS5 proxy active, VPN tunnel disabled")
                self._frontend = Socks5Frontend(
                    pool=None,
                    host=self.config.listen_host,
                    port=self.config.listen_port,
                    max_connections=self.config.max_conns,
                    idle_timeout=self.config.idle_timeout,
                    proxy_only_mode=True,
                    local_proxy_users=self._local_proxy_users(),
                )
                await self._frontend.start()
                started_frontend = self._frontend
                if self.config.http_proxy_enabled:
                    self._http_proxy = HttpProxyServer(
                        host=self.config.listen_host,
                        port=self.config.http_proxy_port,
                        session_provider=lambda: self._pool,
                        proxy_only_mode=True,
                        local_proxy_users=self._local_proxy_users(),
                    )
                    await self._http_proxy.start()
                # proxy_only is explicitly tunnel-free; keep TUN out of it.
                return

            # --- Normal tunnel mode ---
            if self.config.explicit_proxy:
                countries = []
            else:
                # Remote Settings/disk I/O must not hold the API event loop:
                # /api/status polling and country selection share this loop.
                countries = await asyncio.to_thread(
                    serverlist.fetch_server_list,
                    self.config.serverlist_cache_path,
                )

            state_store = ProxyStateStore(self.config.proxy_state_path)
            self._candidate, self._selected_from_state = resolve_proxy(
                countries,
                explicit_proxy=self.config.explicit_proxy,
                country_code=self.config.country,
                state_store=state_store,
            )
            logger.info("selected upstream proxy %s (%s)", self._candidate.authority, self._candidate.country_code or "explicit")

            alternates = [] if self.config.explicit_proxy else alternate_candidates(countries, self._candidate)
            edge_host, edge_port = self._parse_edge_address(self.config.edge_address)
            if edge_host is None and self.config.resolver_dns_provider != "system":
                from perchvpn.doh_resolver import resolve_hostname, ResolverError

                try:
                    resolved = await resolve_hostname(
                        self._candidate.host,
                        self.config.resolver_dns_provider,
                        self.config.custom_resolver_ip,
                        timeout=min(self.config.handshake_timeout, 10.0),
                        local_address=self._source_bind_ip,
                    )
                except ResolverError as exc:
                    raise RuntimeError(f"resolver DNS failed: {exc}") from exc
                if resolved:
                    edge_host = resolved[0]
                    edge_port = self._candidate.port
                    self._resolved_edge_host = edge_host
            ctrl_config = ControllerConfig(
                guardian_endpoint=self.config.guardian_endpoint,
                candidate=self._candidate,
                upstream_conns=self.config.upstream_conns,
                handshake_timeout=self.config.handshake_timeout,
                status_file=self.config.status_path,
                upstream_proxy=self.config.upstream_proxy if self.config.upstream_proxy_enabled else None,
                use_http3=self.config.effective_use_http3,
                alternates=alternates,
                edge_host=edge_host,
                edge_port=edge_port,
                source_bind_ip=self._source_bind_ip,
                upstream_proxy_host=(
                    self._upstream_proxy_pin if self.config.tun_enabled else None
                ),
                physical_interface=self._physical_index,
                require_pinned_upstream=bool(
                    self.config.tun_enabled and self.config.upstream_proxy_enabled
                ),
                transport_version=self.config.transport_version,
                utls_fingerprint=self.config.utls_fingerprint,
                tls_fragment_mode=self.config.tls_fragment_mode,
                tls_fragment_fallback_delay_ms=self.config.tls_fragment_fallback_delay_ms,
                multiplex_streams=self.config.multiplex_streams,
                transport_pinned=bool(self.config.strict_transport_pinning),
            )
            started_controller = self._controller = ProxyController(ctrl_config, self._runtime_auth)
            started_controller.on_pool_replaced = self._repoint_frontend_pool
            self._pool = started_pool = await started_controller.start()
            # Reflect the edge actually in use (failover may have selected an
            # alternate) for status and exit verification; the persisted
            # primary selection is deliberately left untouched.
            self._candidate = started_controller.current_candidate

            self._frontend = Socks5Frontend(
                pool=started_pool,
                host=self.config.listen_host,
                port=self.config.listen_port,
                max_connections=self.config.max_conns,
                idle_timeout=self.config.idle_timeout,
                upstream_proxy=self.config.upstream_proxy if self.config.upstream_proxy_enabled else None,
                proxy_only_mode=self.config.proxy_only_mode,
                metrics=self._controller.metrics,
                local_proxy_users=self._local_proxy_users(),
            )
            await self._frontend.start()
            started_frontend = self._frontend
            if self.config.http_proxy_enabled:
                self._http_proxy = HttpProxyServer(
                    host=self.config.listen_host,
                    port=self.config.http_proxy_port,
                    session_provider=lambda: self._pool,
                    proxy_only_mode=self.config.proxy_only_mode,
                    local_proxy_users=self._local_proxy_users(),
                )
                await self._http_proxy.start()
            if self.config.tun_enabled:
                await self._start_tun_frontend()
            if self.config.verify_exit and self._candidate and self._candidate.country_code and (
                self._exit_check_task is None or self._exit_check_task.done()
            ):
                host = self.config.listen_host
                if host in ("0.0.0.0", "::", "*"):
                    host = "127.0.0.1"
                if ":" in host and not host.startswith("["):
                    host = f"[{host}]"
                local_proxy_url = f"socks5h://{host}:{self.config.listen_port}"
                self._exit_check_task = started_exit_check_task = asyncio.create_task(
                    self._run_exit_check(local_proxy_url)
                )
        except BaseException as exc:
            if not isinstance(exc, asyncio.CancelledError):
                logger.exception(
                    "initialization failed; local SOCKS5 proxy was not established: "
                    "%s: %s",
                    type(exc).__name__,
                    exc,
                )
            # Clean up any components that were started before the failure.
            if started_controller is not None:
                try:
                    await started_controller.stop()
                except BaseException:
                    pass
            if started_pool is not None and started_pool != self._pool:
                try:
                    await started_pool.close()
                except BaseException:
                    pass
            if self._tun_frontend is not None:
                tun = self._tun_frontend
                stopped = False
                try:
                    stopped = await tun.stop()
                except asyncio.CancelledError:
                    raise
                except Exception:  # noqa: BLE001
                    stopped = False
                if (
                    stopped is True
                    and getattr(tun, "recovery_state", RECOVERY_UNVERIFIED)
                    != RECOVERY_UNVERIFIED
                ):
                    self._tun_frontend = None
                else:
                    logger.error(
                        "TUN rollback stop was incomplete; retaining frontend "
                        "reference for recovery"
                    )
            if started_frontend is not None:
                try:
                    await started_frontend.stop()
                except BaseException:
                    pass
            if self._http_proxy is not None:
                try:
                    await self._http_proxy.stop()
                except BaseException:
                    pass
            if started_exit_check_task is not None:
                started_exit_check_task.cancel()
                try:
                    await started_exit_check_task
                except (asyncio.CancelledError, Exception):  # noqa: BLE001
                    pass
            self._controller = None
            self._pool = None
            self._frontend = None
            self._http_proxy = None
            self._candidate = None
            self._exit_check_task = None
            # Nothing survived the rollback: never leave "proxy_active" or
            # "connected" behind when initialize() fails.
            self._status_state = "disconnected"
            raise
    
    async def initialize_idle(self) -> None:
        """Boot without connecting: stay disconnected until Connect is pressed."""
        await self.initialize(auto_connect=False)

    def is_connected(self) -> bool:
        """True when any live connection component exists (dial/listener/TUN)."""
        return any(
            component is not None
            for component in (
                self._controller,
                self._pool,
                self._frontend,
                self._tun_helper,
                self._tun_frontend,
            )
        )

    def _setup_dashboard_logging(self) -> None:
        """Set up logging for dashboard mode: capture logs for viewport, output to stderr."""
        from perchvpn.logging_config import parse_log_format, parse_log_level, _TextFormatter, _JsonFormatter

        perchvpn_logger = logging.getLogger("perchvpn")
        app_logger = logging.getLogger("perchvpn_windows")
        loggers = (perchvpn_logger, app_logger)
        handler = logging.StreamHandler(stream=sys.stderr)
        handler.setFormatter(_JsonFormatter() if parse_log_format(self.config.log_format) == "json" else _TextFormatter())
        level = parse_log_level(self.config.log_level)
        for target in loggers:
            target.handlers.clear()
            target.addHandler(handler)
            target.setLevel(level)
            target.propagate = False
            target.addHandler(self._log_handler)
        # Keep app-level records visible to the root diagnostics handler.
        app_logger.propagate = True
        # The windowed build has no console, so a failed activation left no
        # trace of what the GUI did (start/stop/module decisions).  Keep a
        # small rotating file next to the proxy state for diagnosis.
        try:
            from logging.handlers import RotatingFileHandler

            log_path = Path(self.config.proxy_state_path).with_name("perchvpn.log")
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = RotatingFileHandler(
                log_path, maxBytes=2_000_000, backupCount=2, encoding="utf-8"
            )
            file_handler.setFormatter(handler.formatter)
            file_handler.setLevel(level)
            for target in loggers:
                target.addHandler(file_handler)
        except Exception as exc:  # noqa: BLE001
            logger.warning("file logging unavailable: %s", exc)
    
    def _local_proxy_users(self) -> Optional[dict[str, str]]:
        """Credentials for the local SOCKS5/HTTP listeners when auth is on."""
        if (
            self.config.local_proxy_auth_enabled
            and self.config.local_proxy_username
            and self.config.local_proxy_password
        ):
            return {self.config.local_proxy_username: self.config.local_proxy_password}
        return None

    async def _run_exit_check(
        self, local_proxy_url: str, switch_id: Optional[int] = None
    ) -> None:
        """Run exit check and update exit IP/country.
        
        The probe only runs when exit verification is enabled and a country code
        is available. Otherwise the state stays ``not_applicable`` — an absent
        check is never presented as either verified or failed.
        """
        if not self.config.verify_exit or not (self._candidate and self._candidate.country_code):
            self._exit_verification_state = "not_applicable"
            return

        self._exit_verification_state = "pending"
        try:
            result = await verify_exit_country(
                local_proxy_url,
                self._candidate.country_code,
            )
            if switch_id is not None and switch_id != self._switch_id:
                # A newer switch owns the visible state now; do not publish a
                # stale exit observation for the previous country.
                return
            if result:
                exit_ip, observed_country = result
                self._exit_ip = exit_ip
                self._exit_country = observed_country.upper()
                expected = getattr(self._candidate, "country_code", "") or ""
                is_auto_select = expected.upper() in {"REC"}
                if is_auto_select or observed_country.upper() == expected.upper():
                    self._exit_verification_state = "verified"
                else:
                    self._exit_verification_state = "failed"
            else:
                self._exit_verification_state = "failed"
        except Exception as exc:  # noqa: BLE001
            logger.debug("exit check failed: %s", exc)
            self._exit_verification_state = "failed"
        finally:
            if switch_id is not None and switch_id == self._switch_id:
                self._switch_state = (
                    "complete" if self._exit_verification_state == "verified"
                    else "degraded"
                )
                self._switch_duration_ms = (
                    (asyncio.get_running_loop().time() - self._switch_started_at) * 1000.0
                    if self._switch_started_at else self._switch_duration_ms
                )
            # The direct system-egress check needs the verified expected exit;
            # feed it after every exit-check completion (never before).
            try:
                self._sync_tun_verification_target()
            except Exception:  # noqa: BLE001
                pass
            self._notify_status()
    
    async def run(self) -> None:
        """Run the application until stopped."""
        if not self._frontend:
            raise RuntimeError("Application not initialized")

        if self.config.dashboard and not os.environ.get("PERCHVPN_DASHBOARD_WINDOW"):
            launched = self._launch_in_new_terminal()
            if launched:
                return
        
        if self.config.dashboard:
            await self._run_with_dashboard()
        else:
            await self._frontend.serve_forever()
    
    async def _run_with_dashboard(self) -> None:
        """Run the proxy server with live dashboard."""
        import time
        dashboard = Dashboard()
        dashboard.hide_cursor()
        serve_task = asyncio.create_task(self._frontend.serve_forever())
        try:
            last_render = 0.0
            while not serve_task.done():
                now = time.monotonic()
                if now - last_render >= 0.5:
                    data = self._build_dashboard_data()
                    dashboard.print_frame(data)
                    last_render = now
                await asyncio.sleep(0.1)
        except KeyboardInterrupt:
            serve_task.cancel()
        finally:
            dashboard.show_cursor()
            try:
                await serve_task
            except asyncio.CancelledError:
                pass
    
    def _install_resize_handler(self) -> None:
        """Install SIGWINCH handler for terminal resize."""
        if hasattr(signal, "SIGWINCH"):
            def _handle_resize(signum, frame):
                self._resize_event.set()
            signal.signal(signal.SIGWINCH, _handle_resize)
    
    def _build_dashboard_data(self) -> DashboardData:
        if self.config.proxy_only_mode:
            # Proxy-only: no VPN tunnel, no controller, no candidate.
            return DashboardData(
                status="proxy_active",
                uptime=0.0,
                socks5_addr=f"{self.config.listen_host}:{self.config.listen_port}",
                exit_ip="n/a (proxy-only)",
                country="--",
                transport="-",
                downloaded=0,
                uploaded=0,
                download_speed=0.0,
                upload_speed=0.0,
                active_connections=0,
                email="",
                account_status="signed in" if self._runtime_auth and self._runtime_auth.token else "",
                log_lines=self._log_handler.get_lines(),
            )

        if not self._controller or not self._candidate:
            return DashboardData(
                status="disconnected",
                uptime=0.0,
                socks5_addr=f"{self.config.listen_host}:{self.config.listen_port}",
                exit_ip=self._exit_ip,
                country=self._exit_country.lower(),
                transport="--",
                downloaded=0,
                uploaded=0,
                download_speed=0.0,
                upload_speed=0.0,
                active_connections=0,
                email="",
                account_status="",
                log_lines=self._log_handler.get_lines(),
            )

        metrics = self._controller.metrics
        if metrics is None:
            downloaded = uploaded = 0
            download_speed = upload_speed = 0.0
            active_connections = 0
        else:
            downloaded = metrics.downloaded
            uploaded = metrics.uploaded
            download_speed = metrics.download_speed
            upload_speed = metrics.upload_speed
            active_connections = metrics.active_connections

        email = ""
        account_status = ""
        if self._runtime_auth and self._runtime_auth.token:
            email = getattr(self._runtime_auth.token, "email", "") or ""
            account_status = "signed in"

        return DashboardData(
            status=self._controller.status,
            uptime=self._controller.uptime,
            socks5_addr=f"{self.config.listen_host}:{self.config.listen_port}",
            exit_ip=self._exit_ip,
            country=self._exit_country.lower(),
            transport=self._controller.transport,
            downloaded=downloaded,
            uploaded=uploaded,
            download_speed=download_speed,
            upload_speed=upload_speed,
            active_connections=active_connections,
            email=email,
            account_status=account_status,
            log_lines=self._log_handler.get_lines(),
        )
    
    @staticmethod
    def _parse_edge_address(value: str) -> tuple[Optional[str], Optional[int]]:
        value = (value or "").strip()
        if not value:
            return None, None
        if value.startswith("["):
            end = value.find("]")
            if end != -1 and value[end + 1 :].startswith(":"):
                host = value[1:end]
                port_text = value[end + 2 :]
                try:
                    return host, int(port_text)
                except ValueError:
                    return host, None
            return value[1:].rstrip("]"), None
        if ":" in value:
            host, _, port_text = value.rpartition(":")
            try:
                return host, int(port_text)
            except ValueError:
                return value, None
        return value, None

    def _tun_bypass_ips(
        self,
        source_ip: str,
        *,
        candidate=None,
        edge_host: Optional[str] = None,
    ) -> list[str]:
        """Destination IPs sing-box must exclude from the tunnel.

        Without these, source-pinned upstream dials still follow the
        looped default route into the TUN device ("tunnel-ception"):
        the pinned edge/upstream/DoH targets must be excluded at the
        sing-box level so its forwarding sends them back out the
        physical NIC.

        ``candidate``/``edge_host`` override the currently active endpoint so
        a country switch can pin the *next* upstream before dialing it.
        """
        from perchvpn.doh_resolver import _is_ip

        bypass: list[str] = []

        def _add(value: object) -> None:
            text = str(value or "").strip()
            if text and _is_ip(text) and text not in bypass:
                bypass.append(text)

        for value in self._tun_persistent_ips(source_ip):
            _add(value)

        # Resolved edge / selected server address: this is the active
        # country's upstream node, prunable once the country changes.
        _add(edge_host if edge_host is not None else self._resolved_edge_host)
        target = candidate if candidate is not None else self._candidate
        if target:
            _add(target.host)

        return bypass

    def _tun_persistent_ips(self, source_ip: str) -> list[str]:
        """Infrastructure pins that must survive every country hot-swap.

        These are not country endpoints: the physical egress source, the
        operator's static bypasses, an IP-addressed upstream proxy, and the
        DoH resolvers used for control-plane bootstrap.  Only active country
        endpoints are ever pruned from the physical NIC.
        """
        from perchvpn.doh_resolver import _is_ip
        from perchvpn.doh_resolver import _PROVIDER_ENDPOINTS

        persistent: list[str] = []

        def _add(value: object) -> None:
            text = str(value or "").strip()
            if text and _is_ip(text) and text not in persistent:
                persistent.append(text)

        _add(source_ip)
        for entry in self.config.tun_bypass:
            _add(entry)
        # Remote endpoints of live host connections captured when TUN
        # activated: they are infrastructure pins (never country endpoints)
        # and must survive every hot-swap prune.
        for entry in getattr(self, "_tun_protected_endpoints", ()) or ():
            _add(entry)
        # Control-plane hostnames resolved at activation (guardian, an edge
        # the configured resolver policy could not resolve, upstream proxy).
        for entry in getattr(self, "_tun_control_plane_ips", ()) or ():
            _add(entry)
        if self.config.upstream_proxy:
            _add(self.config.upstream_proxy.host)

        provider = (self.config.resolver_dns_provider or "system").strip().lower()
        if provider == "automatic":
            for pair in _PROVIDER_ENDPOINTS.values():
                for endpoint in pair:
                    _add(endpoint)
        elif provider in _PROVIDER_ENDPOINTS:
            for endpoint in _PROVIDER_ENDPOINTS[provider]:
                _add(endpoint)
        elif provider == "custom":
            _add(self.config.custom_resolver_ip)
        return persistent

    @staticmethod
    def _endpoint_hostname(value: str) -> str:
        """Hostname part of a URL or ``host:port`` endpoint ("" if absent)."""
        from urllib.parse import urlsplit

        text = str(value or "").strip()
        if not text:
            return ""
        if "://" in text:
            return str(urlsplit(text).hostname or "")
        return PerchVPNApp._parse_edge_address(text)[0] or ""

    def _bind_control_plane_to_physical(
        self, physical_ip: str, physical_index: int
    ) -> None:
        """Keep control-plane sockets bound to the verified physical egress
        (the interface can change between boot and activation)."""
        from perchvpn import http_client

        if self._source_bind_ip != physical_ip:
            self._source_bind_ip = physical_ip
        http_client.set_local_address(physical_ip)
        http_client.set_physical_interface(physical_index)

    def _upstream_proxy_hostname(self) -> str:
        """Configured upstream-proxy hostname ("" when disabled or literal)."""
        if not self.config.upstream_proxy_enabled or not self.config.upstream_proxy:
            return ""
        return str(self.config.upstream_proxy.host or "").strip()

    async def _startup_physical_preflight(self) -> None:
        """Bound startup route/DNS discovery to one second.

        ``_bootstrap_physical_path`` performs route/DNS work through
        PowerShell and per-server route lookups.  With a foreign tunnel such
        as ``singbox_tun`` or a secondary default route present those probes
        can stall for seconds (or longer) and used to hold the whole boot.
        Startup only needs a best-effort hint: log the condition and continue,
        then let the activation path re-check and fail closed if necessary.
        """
        try:
            egress = await asyncio.wait_for(
                asyncio.to_thread(self._bootstrap_physical_path),
                timeout=PREFLIGHT_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            logger.warning(
                "startup physical/route preflight exceeded %.1fs; "
                "continuing without blocking the API/UI",
                PREFLIGHT_TIMEOUT_SECONDS,
            )
            # The orphaned discovery thread must not mutate the shared
            # control-plane client later (an uncancellable to_thread call
            # used to rebuild it mid-request and fail initialization with
            # httpx's "Cannot send a request, as the client has been
            # closed."). Binding is applied here, on the loop, only when
            # discovery completed inside the window.
            return
        except Exception as exc:  # noqa: BLE001 - startup must not die here
            logger.warning(
                "startup physical/route preflight failed (%s); continuing; "
                "TUN activation will re-check and fail closed if the path is "
                "still unsafe",
                exc,
            )
            return
        if egress is not None:
            from perchvpn import http_client

            physical_ip, physical_index = egress
            self._source_bind_ip = physical_ip
            self._physical_index = physical_index
            http_client.set_local_address(physical_ip)
            http_client.set_physical_interface(physical_index)

    def _bootstrap_physical_path(self) -> Optional[tuple[str, int]]:
        """Discover the physical bootstrap path and pin control-plane dials.

        Returns the ``(physical_ip, if_index)`` egress pair so the caller can
        apply the client binding on the event loop (the shared control-plane
        client must never be rebuilt from a possibly-orphaned worker thread).
        Returns ``None`` off Windows.
        """
        if not _is_windows():
            return None
        from perchvpn import http_client
        from perchvpn.doh_resolver import _is_ip
        from perchvpn_windows.tun_state_capture import detect_physical_egress

        egress = detect_physical_egress()
        if egress is None:
            raise RuntimeError(
                "no physical egress IPv4 with a default route could be "
                "detected; refusing to bootstrap control-plane traffic on an "
                "unverified path"
            )
        physical_ip, physical_index = egress
        if self._source_bind_ip and self._source_bind_ip != physical_ip:
            raise RuntimeError(
                "configured source address %s is not the physical egress %s; "
                "refusing to bootstrap control-plane traffic on it"
                % (self._source_bind_ip, physical_ip)
            )

        hosts: list[str] = []
        guardian = self._endpoint_hostname(self.config.guardian_endpoint)
        proxy_host = self._upstream_proxy_hostname()
        for host in (guardian, proxy_host):
            if host and not _is_ip(host) and host.lower() not in [h.lower() for h in hosts]:
                hosts.append(host)
        mapping: dict[str, str] = {}
        for host in hosts:
            try:
                addresses = _physical_ipv4_addresses(
                    host, physical_ip=physical_ip, physical_index=physical_index
                )
            except Exception as exc:  # noqa: BLE001 - fail closed
                raise RuntimeError(
                    "control-plane hostname %r could not be resolved on the "
                    "physical path; refusing to bootstrap it through an "
                    "unverified route: %s" % (host, exc)
                ) from exc
            if not addresses:
                raise RuntimeError(
                    "control-plane hostname %r resolved to no IPv4 address on "
                    "the physical path; refusing to bootstrap it" % host
                )
            self._record_cached_ip(host, addresses)
            mapping[host.lower()] = addresses[0]
            self._control_plane_dial_ips[host.lower()] = list(addresses)
            if host.lower() == proxy_host.lower():
                self._upstream_proxy_pin = addresses[0]
        if mapping:
            http_client.set_control_plane_address_overrides(mapping)
        logger.info(
            "pre-TUN control-plane bootstrap path to %s (ifIndex %d)%s",
            physical_ip,
            physical_index,
            ": " + ", ".join("%s=%s" % item for item in mapping.items()) if mapping else "",
        )
        return physical_ip, physical_index

    async def _control_plane_bypass_ips(
        self, physical_ip: str, physical_index: int
    ) -> tuple[list[str], list[str], dict[str, list[str]]]:
        """Resolve control-plane hostnames before pinning them outside the TUN.

        ``_tun_bypass_ips`` only keeps IP literals, so a hostname endpoint
        (the guardian for every resolver policy, and the edge under the
        ``system`` policy) would otherwise be dialed through the tunnel.

        Native sing-box mode bypasses these endpoints directly at the driver
        level via ``route_exclude_address``, so the resolved answers only
        need to exist as IP exclusions: resolution prefers the physical
        adapter's verified DNS path but falls back to the standard OS
        resolver (``socket.getaddrinfo``) when interface-specific DNS
        servers or gateway next-hops are absent.  An endpoint that cannot be
        resolved at all is skipped with a warning — it stays reachable
        through the tunnel's normal path instead of aborting TUN startup.

        Returns ``(persistent, active_edge, resolved)`` where ``resolved``
        maps each resolved hostname to all of its current IPv4 answers so the
        caller can dial only verified pins.
        """
        from perchvpn.doh_resolver import _is_ip

        required: list[tuple[str, str, bool]] = []
        guardian = self._endpoint_hostname(self.config.guardian_endpoint)
        if guardian:
            required.append(("guardian endpoint", guardian, True))
        edge = self._endpoint_hostname(self.config.edge_address)
        if edge:
            required.append(("custom edge", edge, True))
        elif not self._resolved_edge_host and self._candidate is not None:
            required.append(("edge endpoint", str(self._candidate.host or ""), False))
        if self.config.upstream_proxy_enabled and self.config.upstream_proxy:
            required.append(
                ("upstream proxy", str(self.config.upstream_proxy.host or ""), True)
            )

        persistent: list[str] = []
        active_edge: list[str] = []
        resolved: dict[str, list[str]] = {}
        async def _resolve_host(label: str, name: str) -> list[str]:
            """Resolve one hostname, preferring the physical DNS path.

            Returns ``[]`` when the host must stay reachable through the
            tunnel instead of aborting TUN startup.
            """
            name = name.strip()
            if not name:
                return []
            if _is_ip(name):
                return [name]
            addresses: list[str] = []
            try:
                addresses = await asyncio.wait_for(
                    asyncio.to_thread(
                        _physical_ipv4_addresses,
                        name,
                        physical_ip=physical_ip,
                        physical_index=physical_index,
                    ),
                    timeout=1.0,
                )
            except (asyncio.TimeoutError, Exception) as exc:  # noqa: BLE001 - resolved below
                logger.warning(
                    "physical-path resolution for %s hostname %r failed or timed out "
                    "(%s); using the OS resolver for the sing-box "
                    "route_exclude_address bypass instead",
                    label,
                    name,
                    exc,
                )
            if not addresses:
                try:
                    addresses = await asyncio.wait_for(
                        asyncio.to_thread(
                            _getaddrinfo_ipv4_addresses, name
                        ),
                        timeout=1.0,
                    )
                except (asyncio.TimeoutError, Exception) as exc:  # noqa: BLE001 - skip, not abort
                    logger.warning(
                        "%s hostname %r could not be resolved by the OS "
                        "resolver either (%s); falling back to cached direct IP",
                        label,
                        name,
                        exc,
                    )
            if not addresses:
                cached_ip = self._lookup_cached_ip(name)
                if cached_ip:
                    logger.info(
                        "using known cached/direct IP %s for %s (%s)",
                        cached_ip,
                        label,
                        name,
                    )
                    addresses = [cached_ip]
                else:
                    logger.warning(
                        "%s hostname %r could not be resolved or found in cache; "
                        "leaving it reachable through the tunnel instead of "
                        "aborting TUN startup",
                        label,
                        name,
                    )
            return addresses

        # The guardian and edge lookups are independent (each internally
        # bounded by its own 1.0 s timeouts); resolving them concurrently
        # caps the wall clock at the slowest single lookup instead of the
        # sum of all sequential timeouts.
        answers = await asyncio.gather(
            *(_resolve_host(label, name) for label, name, _keep in required)
        )
        for (_label, name, keep), addresses in zip(required, answers):
            name = name.strip()
            if not name:
                continue
            if addresses:
                self._record_cached_ip(name, addresses)
                resolved[name] = list(addresses)
            target = persistent if keep else active_edge
            for address in addresses:
                if address not in target:
                    target.append(address)
        return persistent, active_edge, resolved

    async def _edge_host_pins(
        self,
        candidate,
        alternates,
        *,
        physical_ip: str,
        physical_index: int,
        extra_hosts=(),
        allow_os_fallback: bool = False,
        timeout: float = 1.0,
    ) -> tuple[dict[str, str], list[str], list[str]]:
        """Resolve every candidate hostname on the physical path.

        Returns ``(pins, ips, blocked)``: ``pins`` maps hostname -> the
        verified address a session should dial, ``ips`` lists every answer
        that must stay outside the TUN, and ``blocked`` names could not be
        resolved and therefore must not be dialed at all (fail closed instead
        of letting the OS resolve them into the tunnel later).

        ``allow_os_fallback`` permits an OS-resolver answer when the physical
        adapter's DNS path is blocked (for example public resolvers are
        filtered while a competing tunnel owns the default route).  Every
        answer is still recorded and pinned before any session dials it, so
        the OS resolver only supplies an address; it never becomes the dial
        path.  Pre-TUN activation and country hot-swap both use this fallback.

        ``timeout`` must cover the physical resolver's own deadline.  Pre-TUN
        activation uses the short default because an OS fallback is available;
        a country switch uses a longer budget so the resolver can finish its
        port-53 attempt and DoH fallback instead of being cut off first.
        """
        from perchvpn.doh_resolver import _is_ip

        hosts: list[str] = []
        names = [
            str(getattr(entry, "host", "") or "") for entry in (candidate, *(alternates or ()))
        ] + [str(value or "") for value in (extra_hosts or ())]
        for name in names:
            host = name.strip()
            if not host or _is_ip(host) or host in hosts:
                continue
            hosts.append(host)
        pins: dict[str, str] = {}
        ips: list[str] = []
        blocked: list[str] = []

        async def _pin_host(host: str) -> list[str]:
            """Resolve one candidate hostname on the physical path.

            Returns ``[]`` when the host must be blocked (never dialed) instead
            of letting the OS resolve it into the tunnel later.
            """
            try:
                addresses = await asyncio.wait_for(
                    asyncio.to_thread(
                        _physical_ipv4_addresses,
                        host,
                        physical_ip=physical_ip,
                        physical_index=physical_index,
                    ),
                    timeout=timeout,
                )
            except (asyncio.TimeoutError, Exception) as exc:  # noqa: BLE001 - fallback is optional
                addresses = []
                logger.warning(
                    "physical-path resolution for edge hostname %s failed or timed out (%s)%s",
                    host,
                    exc,
                    "; using the OS resolver and pinning the answer outside "
                    "the TUN"
                    if allow_os_fallback
                    else "",
                )
            if not addresses and allow_os_fallback:
                try:
                    addresses = await asyncio.wait_for(
                        asyncio.to_thread(
                            _getaddrinfo_ipv4_addresses, host
                        ),
                        timeout=1.0,
                    )
                except (asyncio.TimeoutError, Exception) as exc:  # noqa: BLE001 - reported as blocked
                    logger.warning(
                        "cannot pin edge hostname %s: physical and OS "
                        "resolution both failed or timed out (%s)",
                        host,
                        exc,
                    )
                if not addresses:
                    cached_ip = self._lookup_cached_ip(host)
                    if cached_ip:
                        logger.info("using known cached/direct IP %s for edge %s", cached_ip, host)
                        addresses = [cached_ip]
            return addresses

        # Every candidate/alternate edge resolves independently; running the
        # lookups concurrently bounds the wall clock by the slowest single
        # lookup instead of the sum of all sequential timeouts.
        answers = await asyncio.gather(*(_pin_host(host) for host in hosts))
        for host, addresses in zip(hosts, answers):
            if not addresses:
                blocked.append(host)
                continue
            self._record_cached_ip(host, addresses)
            pins[host] = addresses[0]
            for address in addresses:
                if address not in ips:
                    ips.append(address)
        return pins, ips, blocked

    async def _switch_bypass_ips(
        self, candidate, edge_host: str, alternates=None
    ) -> tuple[list[str], list[str], list[str], list[str], dict[str, str]]:
        """Collect and resolve every IP the new upstream may dial.

        Resolution uses the physical adapter's own DNS path, and every
        answer is pinned before the guardian dials it.  A newly returned
        address therefore cannot enter the TUN before it is verified.
        Returns ``(ips, targets, unresolved, blocked, host_pins)`` where
        ``unresolved`` makes the switch unsafe and ``blocked`` hostnames are
        dropped from failover because they could not be pinned.
        """
        from perchvpn.doh_resolver import _is_ip

        ips = self._tun_bypass_ips(
            self._source_bind_ip or "",
            candidate=candidate,
            edge_host=edge_host or "",
        )
        targets: list[str] = []
        names: list[str] = []
        for value in (edge_host or "", getattr(candidate, "host", "") or ""):
            value = str(value or "").strip()
            if not value:
                continue
            if _is_ip(value):
                if value not in targets:
                    targets.append(value)
            elif value not in names:
                names.append(value)

        physical_ip = self._source_bind_ip or ""
        physical_index = getattr(self, "_physical_index", None)
        if physical_index is None and physical_ip:
            from perchvpn_windows.tun_state_capture import detect_physical_egress

            egress = await asyncio.to_thread(detect_physical_egress)
            if egress is not None:
                physical_index = egress[1]
                self._physical_index = physical_index
        if not physical_index:
            return ips, targets, names, [], {}

        pins, pinned_ips, blocked = await self._edge_host_pins(
            candidate,
            alternates,
            physical_ip=physical_ip,
            physical_index=physical_index,
            extra_hosts=names,
            allow_os_fallback=True,
            timeout=COUNTRY_SWITCH_PIN_TIMEOUT_SECONDS,
        )
        # The active candidate was already included above via ``names``; keep
        # its pin so the session dials the verified address, not a re-resolve.
        for host in names:
            if host in pins and pins[host] not in targets:
                targets.append(pins[host])
        for address in pinned_ips:
            if address not in ips:
                ips.append(address)
            if address not in targets:
                targets.append(address)
        unresolved = [host for host in names if host not in pins]
        blocked = [host for host in blocked if host not in names]
        return ips, targets, unresolved, blocked, pins

    async def _pin_upstream_for_switch(
        self, candidate, edge_host: str, alternates=None
    ) -> Optional[tuple[list[str], list[str], dict[str, str], list[str]]]:
        """Prove the next upstream leaves via the physical NIC before dialing.

        With TUN active the new edge must be pinned *before* the guardian
        dials it, otherwise the dial enters the tunnel and loops.  Serialized
        so two switches cannot interleave bypass updates, and refused when
        the edge cannot be proven to leave via the physical interface.
        """
        helper = getattr(self, "_tun_helper", None)
        if helper is None:
            return None
        from perchvpn_windows import tun_helper

        loop = asyncio.get_running_loop()
        deadline = loop.time() + float(getattr(self, "_tun_pin_wait", 30.0))
        phase = str(helper.snapshot().get("phase") or "")
        while phase in (tun_helper.PHASE_STARTING, tun_helper.PHASE_STOPPING):
            if loop.time() >= deadline:
                raise RuntimeError(
                    "TUN helper is still %s; refusing to switch the upstream "
                    "while the tunnel is in transition" % phase
                )
            await asyncio.sleep(0.25)
            phase = str(helper.snapshot().get("phase") or "")
        if phase != tun_helper.PHASE_READY:
            # No TUN capture is in place, so a direct dial cannot loop.
            return None

        lock = getattr(self, "_tun_pin_lock", None)
        if lock is None:
            lock = asyncio.Lock()
            self._tun_pin_lock = lock
        async with lock:
            phase = str(helper.snapshot().get("phase") or "")
            if phase != tun_helper.PHASE_READY:
                return None
            ips, targets, unresolved, blocked, host_pins = (
                await self._switch_bypass_ips(candidate, edge_host, alternates)
            )
            if unresolved:
                raise RuntimeError(
                    "cannot resolve the country-switch edge (%s) to pin it "
                    "outside the TUN; refusing to dial through the tunnel"
                    % ", ".join(unresolved)
                )
            if not targets:
                raise RuntimeError(
                    "cannot determine the country-switch edge address to pin "
                    "outside the TUN; refusing to dial through the tunnel"
                )
            missing = [ip for ip in targets if ip not in ips]
            if missing:
                raise RuntimeError(
                    "cannot pin the country-switch edge address outside the "
                    "TUN (missing %s); refusing to dial through the tunnel"
                    % ", ".join(missing)
                )
            persist = self._tun_persistent_ips(self._source_bind_ip or "")
            await helper.update_bypass(ips, persist=persist)
            return ips, persist, host_pins, blocked

    def _install_control_plane_overrides(
        self, resolved: dict[str, list[str]]
    ) -> None:
        """Only dial the verified physical pin for resolved hostnames."""
        from perchvpn import http_client

        guardian = self._endpoint_hostname(self.config.guardian_endpoint).lower()
        proxy_host = self._upstream_proxy_hostname().lower()
        mapping: dict[str, str] = {}
        for host, addresses in (resolved or {}).items():
            host = str(host or "").lower()
            if not host or not addresses:
                continue
            mapping[host] = addresses[0]
            if host == guardian:
                self._control_plane_dial_ips[host] = list(addresses)
            if proxy_host and host == proxy_host:
                self._upstream_proxy_pin = str(addresses[0])
        http_client.set_control_plane_address_overrides(mapping)
        # From activation on, a hostname-shaped upstream proxy may only dial
        # its verified physical pin: never a fresh OS-resolved answer.
        controller_config = getattr(getattr(self, "_controller", None), "config", None)
        if controller_config is not None:
            controller_config.require_pinned_upstream = True
            if proxy_host:
                controller_config.upstream_proxy_host = mapping.get(proxy_host)

    async def _refresh_control_plane_pins(
        self, physical_ip: str, physical_index: int
    ) -> bool:
        """Re-resolve the guardian and pin a changed answer before dialing it.

        A hostname can resolve to a different address after activation; that
        address may not be dialed until the helper proved its /32 leaves via
        the physical NIC.  Ordering is therefore: resolve physically -> pin
        and verify -> only then replace the dial override.  On any failure the
        previous (verified) pin stays in place and the call fails closed
        instead of leaking into the tunnel.
        """
        from perchvpn.doh_resolver import _is_ip

        guardian = self._endpoint_hostname(self.config.guardian_endpoint)
        if not guardian or _is_ip(guardian):
            return False
        addresses = await asyncio.to_thread(
            _physical_ipv4_addresses,
            guardian,
            physical_ip=physical_ip,
            physical_index=physical_index,
        )
        if not addresses:
            return False
        current = self._control_plane_dial_ips.get(guardian.lower()) or []
        if sorted(addresses) == sorted(current):
            return False
        helper = self._tun_helper
        if helper is None:
            return False
        from perchvpn_windows import tun_helper

        lock = getattr(self, "_tun_pin_lock", None)
        if lock is None:
            lock = asyncio.Lock()
            self._tun_pin_lock = lock
        async with lock:
            if str(helper.snapshot().get("phase") or "") != tun_helper.PHASE_READY:
                return False
            keep = self._tun_bypass_ips(physical_ip)
            missing = [address for address in addresses if address not in keep]
            if missing:
                await helper.update_bypass(
                    keep + missing,
                    persist=self._tun_persistent_ips(physical_ip),
                )
                for address in missing:
                    if address not in self._tun_control_plane_ips:
                        self._tun_control_plane_ips.append(address)
            self._control_plane_dial_ips[guardian.lower()] = list(addresses)
            from perchvpn import http_client

            http_client.set_control_plane_address_overrides(
                {guardian.lower(): addresses[0]}
            )
            logger.info(
                "control-plane pin refreshed for %s: %s (verified before dial)",
                guardian,
                ", ".join(addresses),
            )
        return True

    async def _control_plane_refresh_loop(
        self, physical_ip: str, physical_index: int
    ) -> None:
        while True:
            await asyncio.sleep(CONTROL_PLANE_PIN_REFRESH_SECONDS)
            try:
                await self._refresh_control_plane_pins(physical_ip, physical_index)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - keep the verified pin
                logger.warning("control-plane pin refresh failed: %s", exc)

    def _start_control_plane_refresh(
        self, physical_ip: str, physical_index: int
    ) -> None:
        task = self._control_plane_refresh_task
        if task is not None and not task.done():
            return
        self._control_plane_refresh_task = asyncio.ensure_future(
            self._control_plane_refresh_loop(physical_ip, physical_index)
        )

    async def _stop_control_plane_refresh(self) -> None:
        task = self._control_plane_refresh_task
        self._control_plane_refresh_task = None
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        from perchvpn import http_client

        http_client.set_control_plane_address_overrides(None)
        self._control_plane_dial_ips = {}

    def _resolve_tun_executable(self) -> str:
        """Locate the sing-box sidecar next to the app or use the config.

        PyInstaller does not bundle sing-box.exe/wintun.dll (they are runtime
        sidecars); resolving them relative to the frozen executable keeps a
        one-folder deployment self-contained without touching the host.
        """
        return resolve_tun_executable(self.config.tun_executable_path)

    # ------------------------------------------------------------------
    # Country hot-swap: keep SOCKS5 + TUN alive, exchange the upstream pool
    # ------------------------------------------------------------------

    def can_hot_swap(self) -> bool:
        """True when a country change can reuse the running listener/TUN.

        An in-flight switch does not block a newer one: the newest request
        wins and older work is marked stale before it can swap or publish.
        """
        return (
            self._controller is not None
            and self._pool is not None
            and self._frontend is not None
        )

    def switch_payload(self) -> dict:
        """Observable state of the last/ongoing country switch."""
        task = getattr(self, "_switch_task", None)
        return {
            "id": self._switch_id,
            "state": self._switch_state,
            "target": self._switch_target,
            "duration_ms": round(self._switch_duration_ms, 1),
            "phases": list(self._switch_phases),
            "error": self._switch_error,
            "in_progress": bool(task is not None and not task.done()),
        }

    def begin_country_switch(self, country_code: str, countries: Optional[list] = None) -> dict:
        """Start (or supersede) a hot switch and return immediately.

        The caller gets a switch id it can poll through /api/status. A newer
        switch invalidates older in-flight work: only the latest id is
        allowed to swap the pool or publish an exit verdict.
        """
        from perchvpn_windows import diagnostics

        code = (country_code or "").strip().upper()
        self._switch_id += 1
        switch_id = self._switch_id
        self._switch_state = "switching"
        self._notify_status()
        self._switch_target = code
        self._switch_error = ""
        self._switch_phases = []
        self._switch_started_at = asyncio.get_running_loop().time()
        self._switch_duration_ms = 0.0
        diagnostics.emit(
            "INFO", "country", "switch", "requested", outcome="started",
            detail=f"switch_id={switch_id} target={code}",
        )
        self._switch_task = asyncio.ensure_future(
            self._do_country_switch(code, switch_id, countries)
        )
        return {"mode": "hot_swap", "switch_id": switch_id, "target": code}

    def _record_phase(self, name: str, started_at: float) -> None:
        now = asyncio.get_running_loop().time()
        self._switch_phases.append(
            {"phase": name, "duration_ms": round((now - started_at) * 1000.0, 1)}
        )

    async def _do_country_switch(
        self, code: str, switch_id: int, countries: Optional[list] = None
    ) -> None:
        """Build the new upstream, swap it in atomically, verify in background."""
        from perchvpn_windows import diagnostics

        loop = asyncio.get_running_loop()
        t0 = loop.time()
        pin_info: Optional[tuple[list[str], list[str], dict[str, str], list[str]]] = None
        swapped = False
        try:
            if countries is None:
                countries = (
                    [] if self.config.explicit_proxy
                    else await asyncio.to_thread(
                        serverlist.fetch_server_list,
                        self.config.serverlist_cache_path,
                    )
                )
            state_store = ProxyStateStore(self.config.proxy_state_path)
            candidate, _ = resolve_proxy(
                countries,
                explicit_proxy=self.config.explicit_proxy,
                country_code=code,
                state_store=state_store,
            )
            self._record_phase("plan", t0)

            if switch_id != self._switch_id:
                self._switch_state = "stale"
                return

            t1 = loop.time()
            try:
                alternates = (
                    [] if self.config.explicit_proxy
                    else alternate_candidates(countries, candidate)
                )
                edge_host, edge_port = self._parse_edge_address(self.config.edge_address)
                if edge_host is None and self.config.resolver_dns_provider != "system":
                    from perchvpn.doh_resolver import resolve_hostname, ResolverError

                    try:
                        resolved = await resolve_hostname(
                            candidate.host,
                            self.config.resolver_dns_provider,
                            self.config.custom_resolver_ip,
                            timeout=min(self.config.handshake_timeout, 5.0),
                            local_address=self._source_bind_ip,
                        )
                    except ResolverError as exc:
                        raise RuntimeError(f"resolver DNS failed: {exc}") from exc
                    if resolved:
                        edge_host = resolved[0]
                        edge_port = candidate.port
            finally:
                # Always record the phase so a failed switch reports where it
                # stopped instead of looking like it never started.
                self._record_phase("resolve", t1)

            if switch_id != self._switch_id:
                self._switch_state = "stale"
                return

            # TUN stays up through the swap: pin the new edge/upstream before
            # the guardian dials it, or the dial re-enters the tunnel.
            t_pin = loop.time()
            pin_info = await self._pin_upstream_for_switch(
                candidate, edge_host or "", alternates
            )
            self._record_phase("pin_upstream", t_pin)
            if switch_id != self._switch_id:
                self._switch_state = "stale"
                return

            blocked: list[str] = []
            host_pins: dict[str, str] = {}
            if pin_info is not None:
                _ips, _persist, host_pins, blocked = pin_info
            if blocked:
                alternates = [
                    entry
                    for entry in alternates
                    if str(getattr(entry, "host", "") or "") not in blocked
                ]
            if self.config.edge_address:
                # The custom edge applies to every candidate: it must be
                # dialed as its verified answer, and per-candidate pins would
                # wrongly override it.
                custom = self._endpoint_hostname(self.config.edge_address)
                if custom and custom in host_pins:
                    edge_host = host_pins[custom]
                host_pins = {}
            elif edge_host:
                # A DoH-resolved primary must keep winning over a
                # physical-DNS answer; only alternates use ``edge_hosts``.
                host_pins = {
                    host: ip
                    for host, ip in host_pins.items()
                    if host != str(getattr(candidate, "host", "") or "")
                }
            ctrl_config = ControllerConfig(
                guardian_endpoint=self.config.guardian_endpoint,
                candidate=candidate,
                upstream_conns=self.config.upstream_conns,
                handshake_timeout=self.config.handshake_timeout,
                status_file=self.config.status_path,
                upstream_proxy=(
                    self.config.upstream_proxy
                    if self.config.upstream_proxy_enabled else None
                ),
                use_http3=self.config.effective_use_http3,
                alternates=alternates,
                edge_host=edge_host,
                edge_port=edge_port,
                edge_hosts=host_pins,
                source_bind_ip=self._source_bind_ip,
                transport_version=self.config.transport_version,
                utls_fingerprint=self.config.utls_fingerprint,
                tls_fragment_mode=self.config.tls_fragment_mode,
                tls_fragment_fallback_delay_ms=self.config.tls_fragment_fallback_delay_ms,
                multiplex_streams=self.config.multiplex_streams,
                transport_pinned=bool(self.config.strict_transport_pinning),
            )
            old_controller = self._controller
            reused = getattr(old_controller, "proxy_pass", None)
            new_controller = ProxyController(ctrl_config, self._runtime_auth)
            new_controller.on_pool_replaced = self._repoint_frontend_pool
            t2 = loop.time()
            new_pool = await new_controller.start(initial_pass=reused)
            self._record_phase("dial", t2)

            if switch_id != self._switch_id:
                await new_controller.stop()
                self._switch_state = "stale"
                diagnostics.emit(
                    "INFO", "country", "switch", "superseded",
                    detail=f"switch_id={switch_id} dropped before swap",
                )
                return

            # --- Atomic swap: no awaits between these assignments. ---
            swapped = True
            old_pool = self._pool
            self._controller = new_controller
            self._pool = new_pool
            self._candidate = new_controller.current_candidate
            self._exit_verification_state = "pending"
            self._exit_ip = "0.0.0.0"
            self._exit_country = "--"
            self._resolved_edge_host = edge_host
            if self._frontend is not None:
                self._frontend.set_pool(new_pool, new_controller.metrics)
            self._switch_state = "verifying"
            self._notify_status()

            # Persist only the country the new upstream actually serves.
            persisted = getattr(self._candidate, "country_code", "") or code
            try:
                from perchvpn_windows.config import load_config, save_config

                cfg = load_config()
                cfg.country = persisted
                save_config(cfg)
                self.config.country = persisted
            except Exception as exc:  # noqa: BLE001 - swap already succeeded
                logger.warning("country persist failed: %s", exc)
            self._record_phase("swap", t2)
            diagnostics.emit(
                "INFO", "country", "switch", "swapped", outcome="ok",
                detail=f"switch_id={switch_id} -> {self._candidate.authority}",
            )

            # Verify the new exit through the still-running listener, tagged
            # with the switch id so stale results are discarded.
            if self.config.verify_exit and self._candidate.country_code:
                if self._exit_check_task and not self._exit_check_task.done():
                    self._exit_check_task.cancel()
                self._exit_check_task = asyncio.ensure_future(
                    self._run_exit_check(self._local_proxy_url(), switch_id)
                )
            else:
                self._switch_state = "complete"
            self._sync_tun_verification_target()
            self._record_phase("verify_start", loop.time())

            # Drain the previous upstream in the background (grace keeps
            # in-flight streams alive), then prune its now-superseded
            # physical-NIC pins; the listener already serves the new one.
            asyncio.ensure_future(
                self._finalize_switch(old_controller, old_pool, pin_info, switch_id)
            )

            self._switch_duration_ms = (loop.time() - self._switch_started_at) * 1000.0
            diagnostics.emit(
                "INFO", "country", "switch", "handoff_complete",
                outcome="ok", duration_ms=self._switch_duration_ms,
                detail=f"switch_id={switch_id}",
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - never corrupt the live tunnel
            logger.exception("country hot-swap failed: %s", exc)
            if switch_id != self._switch_id:
                # A newer switch already owns the observable state; a stale
                # failure must not overwrite its result.
                self._switch_state = "stale"
                return
            self._switch_state = "failed"
            self._switch_error = str(exc)
            self._notify_status()
            self._switch_duration_ms = (
                asyncio.get_running_loop().time() - self._switch_started_at
            ) * 1000.0
            if pin_info is not None and not swapped:
                # The candidate never became active: keep the previous
                # country's pins and drop only the candidate's temporary ones.
                helper = getattr(self, "_tun_helper", None)
                if helper is not None:
                    try:
                        from perchvpn_windows import tun_helper

                        if (
                            str(helper.snapshot().get("phase") or "")
                            == tun_helper.PHASE_READY
                        ):
                            keep = self._tun_bypass_ips(self._source_bind_ip or "")
                            persist = self._tun_persistent_ips(
                                self._source_bind_ip or ""
                            )
                            await helper.update_bypass(
                                keep, persist=persist, prune=True
                            )
                    except Exception as prune_exc:  # noqa: BLE001
                        logger.warning(
                            "failed-switch pin cleanup failed: %s", prune_exc
                        )
            diagnostics.emit(
                "ERROR", "country", "switch", "failed", outcome="error",
                detail=f"switch_id={switch_id}: {exc}",
            )

    async def _drain_old_upstream(
        self, controller: Optional[ProxyController], pool: Optional[SessionPool],
        grace_seconds: float = 10.0,
    ) -> None:
        """Let in-flight streams finish, then release the replaced upstream."""
        try:
            await asyncio.sleep(grace_seconds)
            if controller is not None:
                await controller.stop()
            elif pool is not None:
                await pool.close()
        except asyncio.CancelledError:
            return
        except Exception as exc:  # noqa: BLE001
            logger.warning("old upstream drain failed: %s", exc)

    async def _finalize_switch(
        self,
        controller: Optional[ProxyController],
        pool: Optional[SessionPool],
        pin_info: Optional[tuple[list[str], list[str], dict[str, str], list[str]]],
        switch_id: int,
    ) -> None:
        """Drain the old upstream, then prune its superseded bypass pins.

        Pruning runs only after the new country is live and the previous
        upstream is drained, and only removes journaled /32 and /128 pins
        that belong to the replaced country; persistent infrastructure pins
        (source IP, static bypasses, DoH/control plane) are never touched.
        """
        await self._drain_old_upstream(controller, pool)
        if not pin_info:
            return
        # Only prune once the new endpoint is active (verification settled);
        # a newer switch owns the pin set from here on.
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 20.0
        while (
            switch_id == self._switch_id
            and self._switch_state == "verifying"
            and loop.time() < deadline
        ):
            await asyncio.sleep(0.25)
        if switch_id != self._switch_id:
            return
        helper = getattr(self, "_tun_helper", None)
        if helper is None:
            return
        from perchvpn_windows import tun_helper

        if str(helper.snapshot().get("phase") or "") != tun_helper.PHASE_READY:
            return
        ips, persist, _host_pins, _blocked = pin_info
        try:
            await helper.update_bypass(ips, persist=persist, prune=True)
            self._switch_prune_error = ""
        except Exception as exc:  # noqa: BLE001 - switch already succeeded
            self._switch_prune_error = str(exc)
            logger.warning("superseded upstream pin prune failed: %s", exc)
            from perchvpn_windows import diagnostics

            diagnostics.emit(
                "WARN", "country", "switch", "prune_failed", detail=str(exc)
            )

    def _local_proxy_url(self) -> str:
        host = self.config.listen_host
        if host in ("0.0.0.0", "::", "*"):
            host = "127.0.0.1"
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        return f"socks5h://{host}:{self.config.listen_port}"

    async def _repoint_frontend_pool(self, pool) -> None:
        """Controller fallback hook: point the SOCKS5 frontend at the
        replacement pool (transport fallback). In-flight client connections
        keep draining on the old pool; every new connection uses it."""
        frontend = self._frontend
        if frontend is not None:
            frontend.set_pool(pool, self._controller.metrics)
            # The exit check ran against the pool that just got replaced; a
            # pre-fallback "failed" (or stale "verified") observation does
            # not describe the new transport. Clear the latch and re-verify
            # through the replacement pool immediately, non-blocking.
            self._schedule_exit_recheck(reason="transport fallback")

    def _schedule_exit_recheck(self, *, reason: str) -> None:
        if not (
            self.config.verify_exit
            and self._candidate
            and self._candidate.country_code
        ):
            return
        logger.info("exit verification re-scheduled after %s", reason)
        self._exit_verification_state = "pending"
        if self._exit_check_task and not self._exit_check_task.done():
            self._exit_check_task.cancel()
        self._exit_check_task = asyncio.ensure_future(
            self._run_exit_check(self._local_proxy_url())
        )

    # ------------------------------------------------------------------
    # Transactional mode switching (proxy <-> TUN)
    # ------------------------------------------------------------------

    def _mode_active(self) -> str:
        if self._tun_helper is not None:
            phase = self._tun_helper.snapshot().get("phase")
            if phase in ("starting", "ready"):
                return "tun"
        tun = self._tun_frontend
        if tun is not None and getattr(tun, "status", "") in (
            "running",
            "starting",
            "traffic_verified",
            "tunnel_operational",
        ):
            return "tun"
        if not self.is_connected():
            return "disconnected"
        return "proxy_only" if self.config.proxy_only_mode else "proxy"

    def mode_payload(self, tunnel: Optional[dict] = None) -> dict:
        """Selected vs actually-active connection mode, for honest UI state."""
        selected = "tun" if self.config.tun_enabled else (
            "proxy_only" if self.config.proxy_only_mode else "proxy"
        )
        active = self._mode_active()
        verified = False
        if active == "tun":
            tun = tunnel if isinstance(tunnel, dict) else self.tun_payload()
            verified = tun.get("state") == tun_status.STATE_TRAFFIC_VERIFIED
        elif active == "proxy":
            controller = self._controller
            verified = (
                getattr(self, "_exit_verification_state", "") == "verified"
                and (
                    controller is not None
                    or self._status_state in ("proxy_active", "connected")
                )
            )
        helper = self._tun_helper.snapshot() if self._tun_helper is not None else None
        failure_reason = ""
        if self._mode_transition is not None and self._mode_transition.get("state") == "failed":
            failure_reason = str(self._mode_transition.get("detail") or "")
        fallback_reason = ""
        if selected == "tun" and active != "tun":
            if self._tun_start_error:
                fallback_reason = (
                    "TUN activation failed; proxy-only path preserved and remains "
                    "active (:error: %s)" % self._tun_start_error
                )
            else:
                fallback_reason = (
                    "TUN activation did not complete; proxy-only path preserved "
                    "and remains active"
                )
        return {
            "selected": selected,
            "active": active,
            "verified": verified,
            "failure_reason": failure_reason,
            "fallback_reason": fallback_reason,
            "transition": dict(self._mode_transition) if self._mode_transition else None,
            "helper": helper,
        }

    def _helper_paths(self) -> tuple[Path, Path, Path]:
        from perchvpn_windows.platform import get_config_dir

        base = Path(get_config_dir()) / "tun-helper"
        return (
            base / "tun-helper-spec.json",
            base / "tun-helper-state.json",
            base / "tun-helper-stop",
        )

    async def _start_tun_helper(self) -> dict:
        """Launch the UAC helper and wait for verified adapter evidence."""
        from perchvpn_windows import tun_helper

        # Proxy mode must never elevate.  Callers already gate this, but
        # keeping the invariant here protects against future call sites and
        # makes the "proxy never spawns a helper" contract explicit.
        if self.config.proxy_only_mode or not self.config.tun_enabled:
            return {"phase": tun_helper.PHASE_STOPPED, "error": ""}
        # Every tunnelled flow egresses through the local SOCKS5 listener.
        # Starting sing-box before that listener is proven would publish a
        # TUN adapter whose default route black-holes all traffic.
        if not await self._ensure_local_socks():
            return {
                "phase": tun_helper.PHASE_FAILED,
                "adapter": tun_helper.ADAPTER_NAME,
                "error": self._tun_start_error,
            }

        from perchvpn_windows.tun_state_capture import detect_physical_egress

        egress = await asyncio.to_thread(detect_physical_egress)
        if egress is None:
            raise RuntimeError(
                "no physical egress IPv4 with a default route could be detected"
            )
        source_ip, physical_index = egress
        if self._source_bind_ip and self._source_bind_ip != source_ip:
            raise RuntimeError(
                "physical egress changed from %s to %s since startup; restart "
                "PerchVPN before activating TUN so upstream dials are bound to "
                "the real physical address" % (self._source_bind_ip, source_ip)
            )
        self._source_bind_ip = source_ip
        self._physical_index = physical_index
        self._bind_control_plane_to_physical(source_ip, physical_index)
        host = self.config.listen_host
        if host in ("0.0.0.0", "::", "*"):
            host = "127.0.0.1"
        controller = getattr(self, "_controller", None)
        controller_config = getattr(controller, "config", None)
        candidate = getattr(controller_config, "candidate", None) or self._candidate
        alternates = list(getattr(controller_config, "alternates", ()) or ())
        pins: dict[str, str] = {}
        pin_ips: list[str] = []
        blocked: list[str] = []

        # These lookups are independent: control-plane/edge DNS, the live
        # remote-endpoint scan, and the pre-TUN egress baseline.  They used
        # to run sequentially before ShellExecuteExW, so a single 1 s DNS
        # timeout or TCP probe added its full latency to every Connect.
        # Run them concurrently and only the slowest one is on the UAC
        # critical path.
        prep_started = time.monotonic()
        pending: list[asyncio.Task] = []
        bypass_task = asyncio.create_task(
            self._control_plane_bypass_ips(source_ip, physical_index)
        )
        pending.append(bypass_task)
        edge_task = None
        if candidate is not None and not self.config.edge_address:
            edge_task = asyncio.create_task(
                self._edge_host_pins(
                    candidate,
                    alternates,
                    physical_ip=source_ip,
                    physical_index=physical_index,
                    allow_os_fallback=True,
                )
            )
            pending.append(edge_task)
        endpoints_task = asyncio.create_task(
            asyncio.to_thread(tun_helper.established_remote_endpoints)
        )
        pending.append(endpoints_task)
        baseline_task = None
        if getattr(self, "_tun_baseline", None) is None:
            baseline_task = asyncio.create_task(
                tun_status.probe_system_egress()
            )
            pending.append(baseline_task)

        try:
            # Resolve control-plane hostnames over the physical adapter's own
            # DNS path (verified to leave via that interface) before the
            # tunnel can capture them, then pin every answer.
            persistent, edge_ips, resolved = await bypass_task
            self._tun_control_plane_ips = persistent
            self._install_control_plane_overrides(resolved)
            if edge_task is not None:
                pins, pin_ips, blocked = await edge_task
                if controller is not None:
                    controller.apply_edge_pins(pins, blocked)
                if blocked:
                    logger.warning(
                        "dropping failover edges that cannot be pinned outside "
                        "the TUN: %s", ", ".join(blocked)
                    )
            elif controller_config is not None and self.config.edge_address:
                # A hostname custom edge applies to every candidate, so it
                # must be dialed as its verified physical answer, never
                # re-resolved.
                custom = self._endpoint_hostname(self.config.edge_address)
                if custom and custom in resolved and resolved[custom]:
                    controller_config.edge_host = resolved[custom][0]
            bypass = self._tun_bypass_ips(source_ip)
            for ip in list(edge_ips) + pin_ips:
                if ip not in bypass:
                    bypass.append(ip)
            # A live TLS session (for example OpenCode's LLM socket) must not
            # be pulled into the new tunnel: its remote /32 is pinned to the
            # same carrier as PerchVPN's own upstream, so new segments keep
            # the path the connection started on.
            endpoints = await endpoints_task
            self._tun_protected_endpoints = [str(v) for v in endpoints]
            for ip in endpoints:
                if ip not in bypass:
                    bypass.append(ip)
            if baseline_task is not None:
                try:
                    self._tun_baseline = await baseline_task
                except Exception as exc:  # noqa: BLE001 - evidence is best effort
                    logger.warning("pre-TUN baseline egress probe failed: %s", exc)
        except BaseException:
            for task in pending:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            raise
        logger.info(
            "TUN pre-UAC prep completed in %.2fs (bypass=%d edge=%d "
            "protected=%d baseline=%s)",
            time.monotonic() - prep_started,
            len(self._tun_control_plane_ips or ()),
            len(pin_ips),
            len(self._tun_protected_endpoints or ()),
            "cached" if baseline_task is None else "fresh",
        )
        spec = tun_helper.TunHelperSpec(
            proxy_host=host,
            proxy_port=self.config.listen_port,
            executable=self._resolve_tun_executable(),
            adapter=tun_helper.ADAPTER_NAME,
            mtu=self.config.tun_mtu,
            bypass=bypass,
            extra_args=list(self.config.tun_extra_args),
            parent_pid=os.getpid(),
            owner_pid=os.getpid(),
        )
        spec_path, state_path, stop_path = self._helper_paths()
        self._tun_helper = tun_helper.TunHelperClient(
            spec=spec,
            state_path=state_path,
            stop_path=stop_path,
            spec_path=spec_path,
        )
        self._start_tun_helper_watch()
        # An elevated helper start is a chain of dozens of console-less
        # PowerShell calls; with on-access AV scanning that routinely takes
        # minutes on a slow host.  A short timeout abandoned a helper that
        # then reached READY and had to be torn down (observed: 3m48s).
        launch_started = time.monotonic()
        state = await self._tun_helper.start(timeout=600.0)
        elapsed = time.monotonic() - launch_started
        launch_info = getattr(self._tun_helper, "launch_info", {}) or {}
        uac_wait = float(launch_info.get("launch_seconds") or 0.0)
        logger.info(
            "TUN helper start returned phase=%s reason=%s error=%s "
            "elapsed=%.2fs uac=%.2fs post_uac=%.2fs",
            state.get("phase"),
            state.get("stop_reason") or "-",
            state.get("error") or "-",
            elapsed,
            uac_wait,
            max(0.0, elapsed - uac_wait),
        )
        timings = state.get("timings") or {}
        if timings:
            logger.info(
                "TUN helper phase timings capture=%.2fs config=%.2fs "
                "spawn=%.2fs sidecar=%.2fs total=%.2fs",
                float(timings.get("capture_seconds") or 0.0),
                float(timings.get("config_seconds") or 0.0),
                float(timings.get("spawn_seconds") or 0.0),
                float(timings.get("sidecar_seconds") or 0.0),
                float(timings.get("total_seconds") or 0.0),
            )
        if str(state.get("phase") or "") == "ready":
            # Verified pins exist and the helper verified every route: from
            # now on the guardian may only dial those addresses, and a
            # rotated answer is pinned before it replaces them.
            self._start_control_plane_refresh(source_ip, physical_index)
        return state

    async def _run_mode_apply(self, target: str) -> None:
        """Background owner for a mode switch; never leaks a task exception."""
        try:
            await self.apply_mode(target, timeout=MODE_STARTUP_TIMEOUT_SECONDS)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.error("mode switch to %s failed: %s", target, exc)

    async def begin_mode_apply(
        self, target: str, *, ack_timeout: float = MODE_APPLY_ACK_SECONDS
    ) -> dict:
        """Start a mode switch without holding the HTTP request open.

        The helper can legitimately need minutes for adapter/route evidence.
        The caller waits at most ``ack_timeout`` (5 s) for an early verdict,
        then returns the honest transition; ``/api/status`` keeps reporting
        progress while the background task finishes.  The task is shielded
        from the wait timeout so a slow engine is never cancelled.
        """
        task = self._mode_task
        if task is None or task.done():
            task = asyncio.create_task(self._run_mode_apply(target))
            self._mode_task = task
        try:
            await asyncio.wait_for(
                asyncio.shield(task), timeout=max(0.0, float(ack_timeout))
            )
        except asyncio.TimeoutError:
            transition = dict(self._mode_transition or {})
            transition.setdefault("target", target)
            transition.setdefault("state", "starting")
            transition["detail"] = (
                "Mode switch is still running; /api/status reports readiness"
            )
            self._mode_transition = transition
            logger.info(
                "mode switch to %s still running after %.1fs; "
                "continuing in the background",
                target,
                ack_timeout,
            )
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - apply_mode records its own failure
            pass
        return self.mode_payload()

    async def apply_mode(self, target: str, *, timeout: float = 660.0) -> dict:
        """Switch proxy/TUN transactionally; the SOCKS5 listener stays up.

        Failure never silently claims success: the previous mode remains
        active, the helper is torn down, and the transition carries the
        real error.  ``/api/status`` reports both selected and active.
        """
        if target not in ("proxy", "tun"):
            raise ValueError("unsupported mode %r" % (target,))
        async with self._mode_lock:
            self._mode_transition_seq += 1
            transition = {
                "id": self._mode_transition_seq,
                "target": target,
                "state": "starting",
                "detail": "",
                "started_at": asyncio.get_running_loop().time(),
                "duration_ms": 0.0,
            }
            self._mode_transition = transition
            try:
                if target == "tun":
                    # The selection is applied immediately (matching
                    # /api/mode, which persisted "tun" before the restart):
                    # a failed activation must not silently revert it.
                    self.config.tun_enabled = True
                    self._mode_transition = dict(transition, state="verifying")
                    try:
                        state = await asyncio.wait_for(
                            self._start_tun_helper(), timeout=timeout
                        )
                    except asyncio.TimeoutError:
                        # Never overwrite the helper's own diagnosis with a
                        # generic timeout: its last published phase/error is
                        # the actionable one.
                        last = (
                            self._tun_helper.snapshot()
                            if self._tun_helper is not None
                            else {}
                        )
                        state = dict(last) or {"phase": "failed"}
                        state["phase"] = "failed"
                        state["error"] = "TUN helper timed out after %.0fs (last phase %s%s)" % (
                            timeout,
                            last.get("phase") or "unknown",
                            (": " + str(last.get("error"))) if last.get("error") else "",
                        )
                    if state.get("phase") != "ready":
                        await self._stop_tun_helper_watch()
                        if self._tun_helper is not None:
                            await self._tun_helper.stop(timeout=240.0)
                        self._tun_helper = None
                        await self._stop_control_plane_refresh()
                        # Deliberate: the selected mode stays "tun". The
                        # proxy tunnel keeps running as the fallback, so
                        # there is no silent reversion to proxy-only here.
                        self._tun_start_error = str(
                            state.get("error") or "TUN helper did not become ready"
                        )
                        failure = dict(
                            transition,
                            state="failed",
                            detail=self._tun_start_error,
                            duration_ms=(
                                asyncio.get_running_loop().time()
                                - transition["started_at"]
                            )
                            * 1000.0,
                        )
                        self._mode_transition = failure
                        return self.mode_payload()
                    self.config.tun_enabled = True
                    self.config.proxy_only_mode = False
                else:
                    self._mode_transition = dict(transition, state="stopping")
                    # Proxy mode must not create or wake an elevated helper.
                    # Only tear down one that is already starting/ready; a
                    # stale client object (e.g. after a failed activation)
                    # has no live process to stop.
                    helper = self._tun_helper
                    running = False
                    if helper is not None:
                        check = getattr(helper, "is_running", None)
                        if callable(check):
                            running = bool(check())
                        else:
                            running = str(
                                helper.snapshot().get("phase") or ""
                            ) in ("starting", "ready", "stopping")
                    if helper is not None and running:
                        stop_state = await helper.stop(timeout=timeout)
                        if stop_state.get("phase") not in ("stopped", "failed"):
                            # Keep the only ownership handle: teardown is not
                            # verified, so the helper (not the GUI) still owns
                            # recovery until it reports clean.
                            detail = str(
                                stop_state.get("error")
                                or "TUN helper did not confirm teardown"
                            )
                            failure = dict(
                                transition,
                                state="failed",
                                detail=detail,
                                duration_ms=(
                                    asyncio.get_running_loop().time()
                                    - transition["started_at"]
                                )
                                * 1000.0,
                            )
                            self._mode_transition = failure
                            return self.mode_payload()
                        self._tun_helper = None
                    elif helper is not None:
                        # Not running: drop the dead handle without writing a
                        # stop request that no process will consume.
                        self._tun_helper = None
                    if self._tun_frontend is not None:
                        await self._tun_frontend.stop()
                        self._tun_frontend = None
                    await self._stop_control_plane_refresh()
                    self.config.tun_enabled = False
                    self.config.proxy_only_mode = False
                    if self._frontend is None:
                        ready = False
                    else:
                        ready = await self._local_socks_ready()
                    if not ready:
                        detail = "Local proxy service not running on %s:%s" % (
                            self.config.listen_host,
                            self.config.listen_port,
                        )
                        if self._frontend is None:
                            detail += (
                                " (SOCKS5 frontend not initialized; sign in "
                                "and reconnect)"
                            )
                        else:
                            detail += " (listener is not accepting connections)"
                        logger.error("Proxy mode failed: %s", detail)
                        self._mode_transition = dict(
                            transition,
                            state="failed",
                            detail=detail,
                            duration_ms=(
                                asyncio.get_running_loop().time()
                                - transition["started_at"]
                            )
                            * 1000.0,
                        )
                        return self.mode_payload()
                try:
                    from perchvpn_windows.config import save_config

                    save_config(self.config)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("mode persisted in memory only: %s", exc)
                self._mode_transition = dict(
                    transition,
                    state="complete",
                    duration_ms=(
                        asyncio.get_running_loop().time() - transition["started_at"]
                    )
                    * 1000.0,
                )
                return self.mode_payload()
            except Exception as exc:  # noqa: BLE001
                self._mode_transition = dict(
                    transition,
                    state="failed",
                    detail=str(exc),
                    duration_ms=(
                        asyncio.get_running_loop().time() - transition["started_at"]
                    )
                    * 1000.0,
                )
                raise

    def tun_helper_payload(self) -> dict:
        """Evidence from the elevated helper, classified by the same rules."""
        if self._tun_helper is None:
            return {"enabled": False}
        state = self._tun_helper.snapshot()
        phase = str(state.get("phase") or "starting")
        if phase in ("stopped", "cancelled"):
            return {"enabled": False}
        evidence = tun_status.AdapterEvidence.from_dict(state.get("evidence") or {})
        verdict = tun_status.classify(
            enabled=True,
            opted_in=True,
            configured=bool(state.get("command")) or bool(state.get("child_pid")),
            elevated=True,
            process_alive=phase in ("starting", "ready"),
            spawn_failed=phase == "failed" and not evidence.present,
            recovery_required=phase == "recovery_required",
            evidence=evidence if evidence.present else None,
            egress=state.get("system_egress"),
            expected_exit_ip=getattr(self, "_exit_ip", ""),
            expected_country=getattr(self, "_exit_country", ""),
            baseline=getattr(self, "_tun_baseline", None),
        )
        detail = verdict["detail"]
        if phase in ("failed", "recovery_required") and state.get("error"):
            detail = str(state["error"])
        return {
            "enabled": True,
            "mode": "tun",
            "state": verdict["state"],
            "detail": detail,
            "adapter": str(state.get("adapter") or ""),
            "process_alive": phase in ("starting", "ready"),
            "elevated": True,
            "helper_phase": phase,
            "child_pid": int(state.get("child_pid") or 0),
            "system_egress": state.get("system_egress"),
            "adapter_evidence": evidence.to_dict() if evidence.present else None,
            "physical": state.get("physical"),
            "dns_policy": str(state.get("dns_policy") or ""),
            "stop_reason": str(state.get("stop_reason") or ""),
            "sidecar_exit_code": state.get("sidecar_exit_code"),
            "residual": list(state.get("residual") or []),
        }

    def tun_payload(self) -> dict:
        """Honest TUN status: mode, evidence-based state and detail.

        This is the only source the API/UI may use to describe TUN readiness;
        it never reports traffic_verified without direct system-egress proof.
        """
        if self._tun_helper is not None:
            helper = self.tun_helper_payload()
            if helper.get("enabled"):
                return helper
        if not self.config.tun_enabled:
            return {
                "enabled": False,
                "mode": "socks5",
                "state": tun_status.STATE_DISABLED,
                "detail": (
                    "TUN is not enabled: system traffic is not routed through "
                    "the VPN; only apps using the local SOCKS5 proxy are tunnelled."
                ),
                "adapter": "",
                "process_alive": False,
                "elevated": False,
                "system_egress": None,
            }
        tun = self._tun_frontend
        if tun is None:
            return {
                "enabled": True,
                "mode": "tun",
                "state": tun_status.STATE_FAILED,
                "detail": getattr(self, "_tun_start_error", "") or "TUN frontend could not be started.",
                "adapter": "",
                "process_alive": False,
                "elevated": False,
                "system_egress": None,
            }
        data = tun.payload()
        data["mode"] = "tun"
        return data

    def _sync_tun_verification_target(self) -> None:
        """Feed the verified SOCKS exit + pre-TUN baseline to the TUN monitor."""
        tun = self._tun_frontend
        if tun is None:
            return
        verified = getattr(self, "_exit_verification_state", "") == "verified"
        tun.set_verification_target(
            getattr(self, "_exit_ip", "") if verified else "",
            getattr(self, "_exit_country", "") if verified else "",
            getattr(self, "_tun_baseline", None),
        )

    async def _local_socks_ready(
        self, timeout: float = 4.0, interval: float = 0.15
    ) -> bool:
        """Prove the local SOCKS5 listener accepts connections.

        sing-box forwards every tunnelled flow to this listener, so spawning
        the TUN first produces a tunnel that black-holes traffic.  A plain
        TCP connect is enough here: it verifies the listener, not upstream
        reachability.  Retries with a short interval to allow the async listener
        to finish binding on initial connect.
        """
        host = str(self.config.listen_host or "127.0.0.1")
        if host in ("0.0.0.0", "*"):
            host = "127.0.0.1"
        elif host == "::":
            host = "::1"
        port = int(self.config.listen_port)
        deadline = asyncio.get_running_loop().time() + max(0.5, float(timeout))
        last_error = None
        while True:
            try:
                remaining = max(0.1, deadline - asyncio.get_running_loop().time())
                _reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=min(1.0, remaining),
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return True
            except (OSError, asyncio.TimeoutError) as exc:
                last_error = exc
            if asyncio.get_running_loop().time() >= deadline:
                break
            await asyncio.sleep(interval)
        logger.error(
            "local SOCKS5 prerequisite failed on %s:%s after %.1fs: %s",
            host,
            port,
            timeout,
            last_error,
        )
        return False

    async def _ensure_local_socks(self) -> bool:
        """Make the local SOCKS5 listener ready before starting sing-box.

        TUN forwards every flow to 127.0.0.1:1080.  If the app is connected but
        the listener died (or was never started), start it here instead of
        launching sing-box against a dead port.  Without an authenticated pool
        there is nothing to proxy, so fail closed rather than bind a useless
        listener.
        """
        if await self._local_socks_ready():
            return True
        if self._pool is None:
            self._tun_start_error = (
                "Local proxy service not running on %s:%s and no authenticated "
                "session is available to start it"
                % (self.config.listen_host, self.config.listen_port)
            )
            logger.error("TUN disabled: %s", self._tun_start_error)
            return False

        if self._frontend is not None:
            try:
                await self._frontend.stop()
            except Exception as exc:  # noqa: BLE001 - replace the dead listener
                logger.warning("stopping unresponsive SOCKS5 frontend failed: %s", exc)
            self._frontend = None

        logger.info(
            "local SOCKS5 listener is not ready; starting it before TUN on %s:%s",
            self.config.listen_host,
            self.config.listen_port,
        )
        frontend = Socks5Frontend(
            pool=self._pool,
            host=self.config.listen_host,
            port=self.config.listen_port,
            max_connections=self.config.max_conns,
            idle_timeout=self.config.idle_timeout,
            upstream_proxy=(
                self.config.upstream_proxy
                if self.config.upstream_proxy_enabled
                else None
            ),
            proxy_only_mode=False,
            metrics=getattr(self._controller, "metrics", None),
            local_proxy_users=self._local_proxy_users(),
        )
        try:
            await frontend.start()
            self._frontend = frontend
        except Exception as exc:  # noqa: BLE001
            self._tun_start_error = (
                "Local proxy service failed to start on %s:%s: %s"
                % (self.config.listen_host, self.config.listen_port, exc)
            )
            logger.error("TUN disabled: %s", self._tun_start_error)
            return False
        if not await self._local_socks_ready():
            self._tun_start_error = (
                "Local proxy service did not accept connections on %s:%s"
                % (self.config.listen_host, self.config.listen_port)
            )
            logger.error("TUN disabled: %s", self._tun_start_error)
            return False
        return True

    async def _require_local_socks(self) -> bool:
        """Fail TUN activation when the local SOCKS5 listener is not bound."""
        if await self._local_socks_ready():
            return True
        self._tun_start_error = (
            "Local proxy service not running on %s:%s"
            % (self.config.listen_host, self.config.listen_port)
        )
        logger.error("TUN disabled: %s", self._tun_start_error)
        return False

    async def _start_tun_frontend(self) -> None:
        if self.config.proxy_only_mode or not self.config.tun_enabled:
            return
        if not await self._ensure_local_socks():
            return
        from perchvpn_windows import tun_helper as _tun_helper

        if (
            sys.platform == "win32"
            and _tun_helper.helper_supported()
            and not _tun_helper.process_elevated()
        ):
            try:
                state = await self._start_tun_helper()
            except Exception as exc:  # noqa: BLE001
                self._tun_start_error = "TUN helper launch failed: %s" % exc
                logger.error("%s", self._tun_start_error)
                return
            if state.get("phase") != "ready":
                self._tun_start_error = str(
                    state.get("error") or "TUN helper did not become ready"
                )
                logger.error("TUN helper failed: %s", self._tun_start_error)
                return
            return
        # Fail closed: without a verified physical egress source address,
        # upstream traffic (guardian auth, DoH, H2/H3 dials, upstream-proxy
        # chain) would race the tunnel's own default route once the TUN
        # device comes up ("tunnel-ception"). Starting one is useless.
        from perchvpn_windows.tun_state_capture import detect_physical_egress

        try:
            egress = await asyncio.to_thread(detect_physical_egress)
        except Exception as exc:  # noqa: BLE001
            self._tun_start_error = "physical egress autodetect failed: %s" % exc
            logger.error("TUN disabled: physical egress autodetect failed: %s", exc)
            return
        if egress is None:
            self._tun_start_error = (
                "no physical egress IPv4 with a default route could be detected"
            )
            logger.error(
                "TUN disabled: no physical egress IPv4 with a default route "
                "could be detected; refusing to start the tunnel without it "
                "because upstream traffic would loop into the TUN device"
            )
            return
        source_ip, physical_index = egress
        if self._source_bind_ip and self._source_bind_ip != source_ip:
            self._tun_start_error = (
                "physical egress changed from %s to %s since startup; restart "
                "PerchVPN before activating TUN" % (self._source_bind_ip, source_ip)
            )
            logger.error("TUN disabled: %s", self._tun_start_error)
            return
        self._source_bind_ip = source_ip
        self._physical_index = physical_index
        self._bind_control_plane_to_physical(source_ip, physical_index)
        host = self.config.listen_host
        if host in ("0.0.0.0", "::", "*"):
            host = "127.0.0.1"
        # See _start_tun_helper: resolve hostname control-plane endpoints on
        # the physical path before the tunnel takes over the default route.
        try:
            persistent, edge_ips, resolved = await self._control_plane_bypass_ips(
                source_ip, physical_index
            )
        except RuntimeError as exc:
            self._tun_start_error = str(exc)
            logger.error("TUN disabled: %s", exc)
            return
        self._tun_control_plane_ips = persistent
        self._install_control_plane_overrides(resolved)
        controller = getattr(self, "_controller", None)
        controller_config = getattr(controller, "config", None)
        candidate = getattr(controller_config, "candidate", None) or self._candidate
        alternates = list(getattr(controller_config, "alternates", ()) or ())
        pin_ips: list[str] = []
        if candidate is not None and not self.config.edge_address:
            pins, pin_ips, blocked = await self._edge_host_pins(
                candidate,
                alternates,
                physical_ip=source_ip,
                physical_index=physical_index,
                allow_os_fallback=True,
            )
            if controller is not None:
                controller.apply_edge_pins(pins, blocked)
        elif controller_config is not None and self.config.edge_address:
            custom = self._endpoint_hostname(self.config.edge_address)
            if custom and custom in resolved and resolved[custom]:
                controller_config.edge_host = resolved[custom][0]
        bypass = self._tun_bypass_ips(source_ip)
        for ip in list(edge_ips) + pin_ips:
            if ip not in bypass:
                bypass.append(ip)
        if getattr(self, "_tun_baseline", None) is None:
            try:
                self._tun_baseline = await tun_status.probe_system_egress()
            except Exception as exc:  # noqa: BLE001 - evidence is best effort
                logger.warning("pre-TUN baseline egress probe failed: %s", exc)
        self._tun_frontend = TunFrontend(
            enabled=self.config.tun_enabled,
            opt_in=self.config.tun_opt_in,
            executable_path=self._resolve_tun_executable(),
            proxy_host=host,
            proxy_port=self.config.listen_port,
            mtu=self.config.tun_mtu,
            extra_args=self.config.tun_extra_args,
            bypass=bypass,
            # Split tunneling: ``excluded_apps`` is the user-facing list of
            # process names that must stay on the physical path.  It was
            # persisted and echoed by the API but never reached the sidecar,
            # so excluded apps were still captured by the TUN.
            bypass_processes=tuple(self.config.excluded_apps),
            ip_mode=self.config.ip_mode,
            bypass_local_network=self.config.bypass_local_network,
            local_proxy_users=(
                {self.config.local_proxy_username: self.config.local_proxy_password}
                if self.config.local_proxy_auth_enabled
                and self.config.local_proxy_username
                and self.config.local_proxy_password
                else None
            ),
            kill_switch=self.config.kill_switch,
            automatic_recovery=self.config.automatic_recovery,
            utls_fingerprint=self.config.utls_fingerprint,
            tunnel_dns_provider=self.config.tunnel_dns_provider,
            custom_tunnel_doh_url=self.config.custom_tunnel_doh_url,
        )
        self._tun_frontend.set_state_listener(self._notify_status)
        self._sync_tun_verification_target()
        await self._tun_frontend.start()
        try:
            import inspect

            probe = self._tun_frontend.reconcile()
            if inspect.isawaitable(probe):
                await probe
        except Exception as exc:  # noqa: BLE001
            logger.warning("initial TUN readiness probe failed: %s", exc)
        if self._tun_frontend.status == RECOVERY_UNVERIFIED:
            logger.error(
                "TUN sidecar not started: recovery state is unverified; "
                "operator action is required before retrying"
            )

    async def shutdown(self) -> None:
        """Gracefully shut down all components.

        Raises RuntimeError if any component failed to stop, chaining the
        original exceptions so the caller has full diagnostic information.
        The TUN frontend reference is retained when its stop is incomplete or
        recovery remains unverified so the caller keeps the only recovery
        owner.  Other successfully stopped component references are cleared.
        """
        # Presentation state follows teardown: nothing is serving anymore, so
        # a prior "proxy_active" state must not outlive its proxy.
        self._status_state = "disconnected"
        errors: list[Exception] = []
        mode_task = self._mode_task
        if mode_task is not None and not mode_task.done():
            mode_task.cancel()
            try:
                await mode_task
            except asyncio.CancelledError:
                pass
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)
        self._mode_task = None
        await self._stop_control_plane_refresh()

        if self._exit_check_task:
            self._exit_check_task.cancel()
            try:
                await self._exit_check_task
            except asyncio.CancelledError:
                pass
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)
            self._exit_check_task = None

        # TUN sidecar teardown leads the sequence: sing-box owns every
        # upstream session, so stopping the controller first would leave the
        # pool draining against a live sidecar for seconds. Kill the sidecar
        # first (instant process death + recovery-gate baseline restore) and
        # the controller's pool drain completes immediately afterwards.
        if self._tun_helper is not None:
            helper = self._tun_helper
            await self._stop_tun_helper_watch()
            try:
                stop_state = await helper.stop()
                if stop_state.get("phase") != "stopped":
                    # Keep the ownership handle when teardown is unverified.
                    errors.append(
                        RuntimeError(
                            "TUN helper did not confirm teardown: %s"
                            % (stop_state.get("error") or stop_state.get("phase"))
                        )
                    )
                else:
                    self._tun_helper = None
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)
                self._tun_helper = None
        if self._tun_frontend is not None:
            tun = self._tun_frontend
            stopped = False
            tun_error: Optional[Exception] = None
            _t = time.monotonic()
            try:
                stopped = await tun.stop()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                tun_error = exc
                errors.append(exc)
            logger.info("shutdown: TUN frontend stopped in %.2fs", time.monotonic() - _t)
            if (
                tun_error is None
                and stopped is True
                and getattr(tun, "recovery_state", RECOVERY_UNVERIFIED)
                != RECOVERY_UNVERIFIED
            ):
                self._tun_frontend = None
            elif tun_error is None:
                errors.append(
                    RuntimeError(
                        "TUN shutdown incomplete; frontend is not proven stopped "
                        "and recovery is unverified"
                    )
                )

        if self._controller:
            _t = time.monotonic()
            try:
                await self._controller.stop()
            except Exception as exc:
                errors.append(exc)
            self._controller = None
            logger.info("shutdown: controller stopped in %.2fs", time.monotonic() - _t)

        if self._frontend:
            _t = time.monotonic()
            try:
                await self._frontend.stop()
            except Exception as exc:
                errors.append(exc)
            self._frontend = None
            logger.info("shutdown: socks5 frontend stopped in %.2fs", time.monotonic() - _t)

        if self._http_proxy:
            try:
                await self._http_proxy.stop()
            except Exception as exc:
                errors.append(exc)
            self._http_proxy = None

        self._pool = None
        self._candidate = None

        if errors:
            raise RuntimeError(
                f"Perch VPN shutdown failed after all cleanup attempts: "
                f"{'; '.join(str(e) for e in errors)}"
            ) from errors[0] if errors else None
    
    def launch_auth_helper(self) -> tuple[bool, str]:
        """Launch the existing terminal authentication helper."""
        process = self._auth_helper_process
        if process is not None and process.poll() is None:
            return False, "already_running"

        import shutil
        import subprocess
        import sys

        wt_path = shutil.which("wt")
        if not wt_path:
            logger.warning("Windows Terminal (wt.exe) not found in PATH; cannot launch interactive auth")
            return False, "windows_terminal_not_found"

        env = os.environ.copy()
        env["PERCHVPN_DASHBOARD_WINDOW"] = "1"
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)

        self._auth_helper_process = subprocess.Popen(
            [wt_path, "-w", "0", "new-tab", "--", *auth_helper_command(sys.executable, env=env)],
            env=env,
            creationflags=creationflags,
        )
        logger.info("Launched authentication helper in Windows Terminal (PID=%d)", self._auth_helper_process.pid)
        return True, "launched"

    async def sign_out(self) -> None:
        """Stop the active VPN/controller, delete cached tokens, and clear
        runtime auth.

        Stopping the controller first is deliberate: it cancels proxy-pass
        renewal, closes the session pool, and prevents further authenticated
        upstream use.  Credentials are invalidated even if shutdown partially
        fails, but that failure is still reported to callers.  Handoff is
        disabled for the duration so logout cannot be undone by a concurrent
        account-status request.
        """
        async with self._auth_handoff_lock:
            self._auth_handoff_disabled = True
            shutdown_error: Optional[BaseException] = None
            controller = self._controller
            try:
                await self.shutdown()
            except BaseException as exc:  # noqa: BLE001
                shutdown_error = exc

            # If shutdown was only partially successful, remove the stale auth
            # reference from the controller object as well.  The app no longer
            # references it, but this avoids retaining usable credentials in a
            # partially stopped controller.
            if controller is not None:
                try:
                    controller.auth = None
                except Exception:  # noqa: BLE001
                    pass

            token_path = get_token_path()
            token_error: Optional[BaseException] = None
            try:
                token_path.unlink()
            except FileNotFoundError:
                pass
            except BaseException as exc:  # noqa: BLE001
                token_error = exc

            # Rebrand guard: consume the stranded legacy token store so a
            # later load_persisted_auth() cannot copy it back after the
            # user explicitly signed out.
            legacy_error: Optional[BaseException] = None
            try:
                discard_legacy_tokens()
            except BaseException as exc:  # noqa: BLE001
                legacy_error = exc

            # Invalidate alternate persisted session-token credentials owned by
            # this configuration.  Only the configured path is touched; unrelated
            # files are never deleted.
            session_token_error: Optional[BaseException] = None
            session_token_path_str = self.config.session_token_path
            if session_token_path_str:
                session_token_path = Path(session_token_path_str)
                if str(session_token_path) != str(token_path):
                    try:
                        session_token_path.unlink()
                    except FileNotFoundError:
                        pass
                    except BaseException as exc:  # noqa: BLE001
                        session_token_error = exc

            # Invalidate in-memory auth even when disk deletion or shutdown
            # fails; callers still receive the failure below.
            self._runtime_auth = None

            errors = [
                exc for exc in (
                    shutdown_error, token_error, legacy_error,
                    session_token_error,
                )
                if exc is not None
            ]
            if errors:
                # Fail closed: keep handoff disabled so surviving credentials
                # cannot be reloaded after an incomplete logout.
                raise RuntimeError(
                    "; ".join(str(exc) for exc in errors)
                ) from errors[0]

            self._auth_handoff_disabled = False
        logger.info("Signed out; cached authentication tokens deleted")

    async def load_persisted_auth(self) -> bool:
        """Validate and load a token persisted by the terminal helper.

        The handoff is serialized so concurrent account-status requests share
        one validation attempt.  Logout can disable handoff while it owns the
        lock, preventing a stale token from being installed afterwards.
        """
        async with self._auth_handoff_lock:
            if self._runtime_auth is not None:
                return True
            if self._auth_handoff_disabled:
                return False

            # Rebrand continuity: a pre-rebuild token store may exist under
            # the old directory; surface it before the load attempt.
            from .platform import migrate_legacy_tokens
            migrate_legacy_tokens()

            token_path = get_token_path()
            saved = tokens_module.load_tokens(token_path)
            if saved is None:
                return False
            # Never attempt an interactive login from the API process.  The helper
            # is the only interactive entry point; here we only accept already
            # persisted credentials.
            if not saved.access_token and not saved.refresh_token:
                return False

            try:
                auth = await self._obtain_auth(False)
            except Exception as exc:  # noqa: BLE001
                logger.warning("could not load persisted authentication: %s", exc)
                return False
            if auth is None:
                return False
            if self._auth_handoff_disabled:
                return False
            self._runtime_auth = auth
            self._auth_handoff_disabled = False
            logger.info("Loaded persisted authentication after helper sign-in")
            return True

    async def _obtain_auth(self, interactive: bool = True) -> auth_module.RuntimeAuth:
        """Obtain authentication, respecting Windows token paths."""
        session_token_path = self.config.session_token_path
        oauth_token_path = get_token_path()

        return auth_module.obtain_auth(
            email=None,
            force_login=False,
            session_token_or_path=session_token_path,
            token_path=oauth_token_path,
            interactive=interactive,
        )
