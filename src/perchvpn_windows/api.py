"""FastAPI-based HTTP API for the PerchVPN Windows dashboard."""

from __future__ import annotations

import asyncio
import contextlib
import functools
import hashlib
import importlib
import ipaddress
import logging
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from typing import Any, Callable, Optional

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator, model_validator

from . import diagnostics
from . import config as config_module

# The OAuth module pulls the full FXA/pkce stack (≈80 ms) but only the four
# /api/auth/oauth/* endpoints need it.  Importing it lazily keeps that cost off
# the boot path, which is what the window waits for before first paint.
class _LazyModule:
    """Import a sibling module on first attribute access."""

    def __init__(self, name: str) -> None:
        self._name = name
        self._module = None
        self._lock = threading.Lock()

    def _load(self):
        if self._module is None:
            with self._lock:
                if self._module is None:
                    self._module = importlib.import_module("." + self._name, __package__)
        return self._module

    def __getattr__(self, item: str):
        return getattr(self._load(), item)


oauth_module = _LazyModule("oauth")

from .app import PerchVPNApp, resolve_tun_executable
from .config import (
    WindowsConfig,
    load_config,
    save_config,
    UpstreamProxyConfig,
    DEFAULT_LATENCY_PROBE_URL,
    DEFAULT_IP_MODE,
    DEFAULT_BOOTSTRAP_DNS_PROVIDER,
    DEFAULT_RELAYER_PROVIDER,
    DEFAULT_TRANSPORT_VERSION,
    DEFAULT_UTLS_FINGERPRINT,
    BOOTSTRAP_DNS_PROVIDERS,
    IP_MODES,
    MULTIPLEX_STREAM_CHOICES,
    RELAYER_PROVIDERS,
    TRANSPORT_VERSIONS,
    UTLS_FINGERPRINTS,
)
from .platform import get_token_path
from .ui import DashboardData
from perchvpn import guardian
from perchvpn import tokens as tokens_module
from perchvpn.auth import InteractiveLoginRequired
import perchvpn.auth as auth_module
from perchvpn.exceptions import (
    FastlyChallengeError,
    GuardianHTTPError,
    QuotaExceededError,
    TokenInvalidError,
)

logger = logging.getLogger("perchvpn_windows.api")

# Shared lock to serialize lifecycle endpoints and prevent concurrent
# shutdown/initialization races.
_api_lock = asyncio.Lock()

# The ASGI web server intentionally runs one event loop because ``_app`` and
# ``_config`` are process-global.  Anything that can block (Remote Settings
# fetch/disk I/O, cache misses) is therefore pushed onto this bounded worker
# pool: /api/status and /api/mode keep being scheduled while a country-list
# refresh is in flight.
_API_WORKERS = 8
# Bound app teardown so uvicorn can always finish its lifespan and release
# 127.0.0.1:1080; a stuck elevated helper must not pin the API thread forever.
_APP_SHUTDOWN_TIMEOUT_SECONDS = 25.0
_API_EXECUTOR = ThreadPoolExecutor(
    max_workers=_API_WORKERS, thread_name_prefix="perchvpn-api"
)
# A single refresher is enough: it deduplicates TTL/startup warmups and keeps
# the Remote Settings endpoint from being hammered by concurrent UI polls.
_SERVERLIST_EXECUTOR = ThreadPoolExecutor(
    max_workers=1, thread_name_prefix="perchvpn-serverlist"
)
# Latency-sweep pass minting runs here, not on the shared API pool: a burst of
# country-row probes (up to four at a time) could otherwise occupy every API
# worker and starve /api/mode or a disconnect teardown of its thread.
_URLTEST_WORKERS = 2
_URLTEST_EXECUTOR = ThreadPoolExecutor(
    max_workers=_URLTEST_WORKERS, thread_name_prefix="perchvpn-urltest"
)
# The disconnect button must answer promptly even when an elevated helper is
# slow to confirm teardown; cleanup then continues in the background.
_DISCONNECT_HTTP_TIMEOUT_SECONDS = 12.0
_bg_shutdown_task: Optional[asyncio.Task] = None


async def _run_in_api_pool(
    func: Callable[..., Any], /, *args: Any, **kwargs: Any
) -> Any:
    """Run blocking cache/disk work on the API thread pool."""
    import functools

    loop = asyncio.get_running_loop()
    call = functools.partial(func, *args, **kwargs)
    return await loop.run_in_executor(_API_EXECUTOR, call)


async def _run_in_urltest_pool(
    func: Callable[..., Any], /, *args: Any, **kwargs: Any
) -> Any:
    """Run latency-sweep pass minting on its own isolated pool."""
    import functools

    loop = asyncio.get_running_loop()
    call = functools.partial(func, *args, **kwargs)
    return await loop.run_in_executor(_URLTEST_EXECUTOR, call)


async def _await_background_shutdown(timeout: float = 30.0) -> None:
    """Wait (bounded) for a disconnect that outlived its HTTP response.

    A lifecycle endpoint must never build a new app on top of a half-torn-down
    old one, but it must also never hang the UI: the wait is bounded and a
    timeout is logged rather than propagated.
    """
    global _bg_shutdown_task
    task = _bg_shutdown_task
    if task is None:
        return
    try:
        await asyncio.wait_for(asyncio.shield(task), timeout=timeout)
    except asyncio.TimeoutError:
        logger.error("background disconnect teardown still running after %.1fs", timeout)
        return
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001 - the verdict was already reported
        logger.warning("background disconnect teardown failed: %s", exc)
    finally:
        if task.done():
            _bg_shutdown_task = None


class NetworkConfig(BaseModel):
    """Network configuration (persisted preferences only)."""
    dns_mode: str = Field(default="auto", pattern="^(auto|cloudflare|google|custom)$")
    dns_custom: str = Field(default="")
    edge_address: str = Field(default="")
    # Upstream proxy chaining (H2 transport-level tunnel).
    # Password is intentionally NOT exposed through the API.
    upstream_proxy_host: str = Field(default="")
    upstream_proxy_port: int = Field(default=0)
    upstream_proxy_type: str = Field(default="socks5")
    upstream_proxy_username: str = Field(default="")
    upstream_proxy_password: str = Field(default="")
    # Proxy-only mode flag.
    proxy_only_mode: bool = Field(default=False)
    # Local proxy / connection settings.
    socks_bind_address: str = Field(default="127.0.0.1")
    socks_port: int = Field(default=1080, ge=1, le=65535)
    http_proxy_enabled: bool = Field(default=False)
    http_proxy_port: int = Field(default=8080, ge=1, le=65535)
    mtu: int = Field(default=1400, ge=576, le=9000)
    # DNS settings.
    tunnel_dns_provider: str = Field(default="default")
    custom_tunnel_doh_url: str = Field(default="")
    resolver_dns_provider: str = Field(default="automatic")
    custom_resolver_ip: str = Field(default="")
    # Advanced settings.
    upstream_proxy_enabled: bool = Field(default=False)
    tls_split_mode: str = Field(default="off")
    excluded_apps: list[str] = Field(default_factory=list)
    custom_edge_address: str = Field(default="")
    # Upstream v2.0.3 parity settings.
    latency_probe_url: str = Field(default=DEFAULT_LATENCY_PROBE_URL)
    ip_mode: str = Field(default=DEFAULT_IP_MODE)
    bootstrap_dns_provider: str = Field(default=DEFAULT_BOOTSTRAP_DNS_PROVIDER)
    custom_bootstrap_doh_url: str = Field(default="")
    relayer_provider: str = Field(default=DEFAULT_RELAYER_PROVIDER)
    custom_relayer_url: str = Field(default="")
    relayed_endpoints: list[str] = Field(default_factory=list)
    bypass_local_network: bool = Field(default=True)
    local_proxy_auth_enabled: bool = Field(default=False)
    local_proxy_username: str = Field(default="")
    local_proxy_password: str = Field(default="")
    transport_version: str = Field(default=DEFAULT_TRANSPORT_VERSION)
    multiplex_streams: int = Field(default=8)
    utls_fingerprint: str = Field(default=DEFAULT_UTLS_FINGERPRINT)
    tls_fragment_mode: str = Field(default="disabled")
    tls_fragment_fallback_delay_ms: int = Field(default=300, ge=0, le=10000)
    always_on: bool = Field(default=False)
    kill_switch: bool = Field(default=False)
    automatic_recovery: bool = Field(default=True)
    update_checks: bool = Field(default=True)

    @field_validator("dns_custom")
    @classmethod
    def validate_dns_custom(cls, v: str) -> str:
        if v:
            parts = [p.strip() for p in v.split(",") if p.strip()]
            for part in parts:
                if not part:
                    raise ValueError("Empty DNS entry")
            return ",".join(parts)
        return v

    @field_validator("edge_address")
    @classmethod
    def validate_edge_address(cls, v: str) -> str:
        if v:
            if ":" not in v:
                raise ValueError("Edge address must be host:port")
            host, port = v.rsplit(":", 1)
            if not host:
                raise ValueError("Empty host")
            try:
                port_num = int(port)
                if not 1 <= port_num <= 65535:
                    raise ValueError("Invalid port")
            except ValueError:
                raise ValueError("Invalid port number")
        return v

    @field_validator("upstream_proxy_type")
    @classmethod
    def validate_upstream_proxy_type(cls, v: str) -> str:
        if v not in ("socks5", "http"):
            raise ValueError("upstream_proxy_type must be 'socks5' or 'http'")
        return v

    @model_validator(mode="after")
    def validate_upstream_proxy(self) -> "NetworkConfig":
        if self.upstream_proxy_enabled and not self.upstream_proxy_host:
            raise ValueError("upstream_proxy_host is required when upstream proxy is enabled")
        if self.upstream_proxy_host and not (1 <= self.upstream_proxy_port <= 65535):
            raise ValueError("upstream_proxy_port must be between 1 and 65535")
        return self

    @field_validator("tunnel_dns_provider")
    @classmethod
    def validate_tunnel_dns_provider(cls, v: str) -> str:
        if v not in ("default", "cloudflare", "google", "quad9", "adguard", "custom"):
            raise ValueError("invalid tunnel_dns_provider")
        return v

    @field_validator("resolver_dns_provider")
    @classmethod
    def validate_resolver_dns_provider(cls, v: str) -> str:
        if v not in ("automatic", "quad9", "cloudflare", "google", "system", "custom"):
            raise ValueError("invalid resolver_dns_provider")
        return v

    @field_validator("tls_split_mode")
    @classmethod
    def validate_tls_split_mode(cls, v: str) -> str:
        if v not in ("off", "first_byte", "sni"):
            raise ValueError("invalid tls_split_mode")
        return v

    @field_validator("custom_tunnel_doh_url")
    @classmethod
    def validate_custom_tunnel_doh_url(cls, v: str) -> str:
        if v and not v.startswith("https://"):
            raise ValueError("custom DoH URL must use HTTPS")
        return v

    @field_validator("ip_mode")
    @classmethod
    def validate_ip_mode(cls, v: str) -> str:
        if v not in IP_MODES:
            raise ValueError("invalid ip_mode")
        return v

    @field_validator("bootstrap_dns_provider")
    @classmethod
    def validate_bootstrap_dns_provider(cls, v: str) -> str:
        if v not in BOOTSTRAP_DNS_PROVIDERS:
            raise ValueError("invalid bootstrap_dns_provider")
        return v

    @field_validator("custom_bootstrap_doh_url")
    @classmethod
    def validate_custom_bootstrap_doh_url(cls, v: str) -> str:
        if v and not v.startswith("https://"):
            raise ValueError("custom bootstrap DoH URL must use HTTPS")
        return v

    @field_validator("relayer_provider")
    @classmethod
    def validate_relayer_provider(cls, v: str) -> str:
        if v not in RELAYER_PROVIDERS:
            raise ValueError("invalid relayer_provider")
        return v

    @field_validator("custom_relayer_url")
    @classmethod
    def validate_custom_relayer_url(cls, v: str) -> str:
        if v and not v.startswith("https://"):
            raise ValueError("custom relayer URL must use HTTPS")
        return v

    @field_validator("transport_version")
    @classmethod
    def validate_transport_version(cls, v: str) -> str:
        if v not in TRANSPORT_VERSIONS:
            raise ValueError("invalid transport_version")
        return v

    @field_validator("multiplex_streams")
    @classmethod
    def validate_multiplex_streams(cls, v: int) -> int:
        if v not in MULTIPLEX_STREAM_CHOICES:
            raise ValueError("multiplex_streams must be one of 8, 16, 32, 64")
        return v

    @field_validator("utls_fingerprint")
    @classmethod
    def validate_utls_fingerprint(cls, v: str) -> str:
        if v not in UTLS_FINGERPRINTS:
            raise ValueError("invalid utls_fingerprint")
        return v

    @field_validator("tls_fragment_mode")
    @classmethod
    def validate_tls_fragment_mode(cls, v: str) -> str:
        if v not in config_module.TLS_FRAGMENT_MODES:
            raise ValueError("invalid tls_fragment_mode")
        return v

    @field_validator("latency_probe_url")
    @classmethod
    def validate_latency_probe_url(cls, v: str) -> str:
        if v and not v.startswith("https://"):
            raise ValueError("latency probe URL must use HTTPS")
        return v

    @field_validator("custom_resolver_ip")
    @classmethod
    def validate_custom_resolver_ip(cls, v: str) -> str:
        if v:
            import ipaddress
            try:
                ipaddress.ip_address(v)
            except ValueError as exc:
                raise ValueError("custom resolver must be an IP address") from exc
        return v

    @field_validator("custom_edge_address")
    @classmethod
    def validate_custom_edge_address(cls, v: str) -> str:
        if v:
            host = v
            port = None
            if ":" in v and not v.startswith("["):
                host, _, port_text = v.rpartition(":")
                try:
                    port = int(port_text)
                except ValueError:
                    raise ValueError("custom edge address must be host or host:port")
            if not host:
                raise ValueError("custom edge address must include a host")
            if port is not None and not (1 <= port <= 65535):
                raise ValueError("custom edge port must be 1-65535")
        return v

    @field_validator("socks_bind_address")
    @classmethod
    def validate_socks_bind_address(cls, v: str) -> str:
        import ipaddress
        try:
            address = ipaddress.ip_address(v)
        except ValueError as exc:
            raise ValueError("SOCKS bind address must be an IP address") from exc
        if not (address.is_loopback or address.is_unspecified):
            raise ValueError(
                "SOCKS bind address must be a loopback IP address "
                "(or 0.0.0.0 with local proxy authentication)"
            )
        return v

    @model_validator(mode="after")
    def validate_socks_bind_auth_gate(self) -> "NetworkConfig":
        import ipaddress

        address = ipaddress.ip_address(self.socks_bind_address)
        if address.is_unspecified and not (
            self.local_proxy_auth_enabled
            and self.local_proxy_username
            and self.local_proxy_password
        ):
            raise ValueError(
                "SOCKS bind address must be a loopback IP address "
                "(0.0.0.0 requires local proxy authentication)"
            )
        return self

    @model_validator(mode="after")
    def validate_http_proxy_bind_address(self) -> "NetworkConfig":
        if self.http_proxy_enabled:
            import ipaddress

            try:
                address = ipaddress.ip_address(self.socks_bind_address)
                if not (address.is_loopback or address.is_unspecified):
                    raise ValueError(
                        "HTTP proxy bind address must be a loopback IP address "
                        "(or 0.0.0.0 with local proxy authentication)"
                    )
            except ValueError as exc:
                raise ValueError("HTTP proxy bind address must be a loopback IP address") from exc
        return self

    @model_validator(mode="after")
    def validate_relayer_pair(self) -> "NetworkConfig":
        if self.relayer_provider == "custom" and not self.custom_relayer_url:
            raise ValueError("relayer_provider='custom' requires custom_relayer_url")
        if self.relayer_provider != "custom" and self.custom_relayer_url:
            raise ValueError("custom_relayer_url requires relayer_provider='custom'")
        return self


class ConnectionModeRequest(BaseModel):
    """Target connection mode.

    ``proxy``      normal SOCKS5 + VPN upstream, no TUN (the default).
    ``proxy_only`` legacy mode with no VPN upstream at all.
    ``tun``        system-wide tunnel through the elevated helper.

    ``apply`` performs the live, transactional switch instead of only
    persisting the choice for the next launch.
    """
    mode: str = Field(..., pattern="^(proxy_only|proxy|tun)$")
    apply: bool = False


class ConnectRequest(BaseModel):
    """Explicit Connect payload: carry the user's selected mode.

    ``proxy`` starts only the SOCKS5 frontend (no TUN helper/sing-box);
    ``tun`` starts it after the SOCKS5 listener is proven ready; absent
    means use the persisted config.
    """
    mode: Optional[str] = Field(default=None, pattern="^(proxy_only|proxy|tun)$")


class UrlPingRequest(BaseModel):
    """One-shot realtime HTTP reachability probe."""
    url: str = Field(..., min_length=1)
    via_proxy: bool = False


class CountrySelection(BaseModel):
    country_code: str = Field(min_length=2, max_length=2)
    city_code: Optional[str] = None


class PrewarmRequest(BaseModel):
    """Ask the resolver to warm its cache for a country's edge hostname."""

    country_code: str = Field(min_length=2, max_length=2)


class ClientPerfRequest(BaseModel):
    """Frame telemetry posted by the WebView (measured, never synthetic)."""

    fps: int = Field(ge=0, le=480)
    frames: int = Field(default=0, ge=0)
    longTasks: int = Field(default=0, ge=0)
    worstFrameMs: float = Field(default=0.0, ge=0.0)
    size: str = ""


class CityResponse(BaseModel):
    name: str
    code: str
    hostname: str = ""
    port: int = 0


class CountryResponse(BaseModel):
    code: str
    name: str
    cities: list[CityResponse]


class StatusResponse(BaseModel):
    status: str
    uptime: float
    socks5_addr: str
    exit_ip: str
    country: str
    transport: str
    downloaded: int
    uploaded: int
    download_speed: float
    upload_speed: float
    active_connections: int
    exit_verification_state: str = "not_applicable"
    webui_debug: str = "0"
    proxy_only_mode: bool = False
    # Verified local component states (object presence only — used by the
    # dashboard radar schematic; each maps to a real backend component).
    tun_frontend: bool = False
    session_pool: bool = False
    http_proxy_enabled_live: bool = False
    # Honest tunnel readiness: mode ("socks5"/"tun"), evidence-based state,
    # detail text and direct system-egress evidence. See
    # perchvpn_windows.tun_status for the state contract.
    tunnel: dict = {}
    switch: dict = {}
    modes: dict = {}


class AccountResponse(BaseModel):
    email: str
    account_status: str
    signin_stage: str = ""
    verification_method: str = ""
    identifier_masked: str = ""


class NetworkConfigResponse(BaseModel):
    dns_mode: str
    dns_custom: str
    edge_address: str
    # Upstream proxy chaining (H2 transport-level tunnel).
    # Password is intentionally NOT included.
    upstream_proxy_host: str
    upstream_proxy_port: int
    upstream_proxy_type: str
    upstream_proxy_username: str
    # Proxy-only mode flag.
    proxy_only_mode: bool
    # Local proxy / connection settings.
    socks_bind_address: str
    socks_port: int
    http_proxy_enabled: bool
    http_proxy_port: int
    mtu: int
    # DNS settings.
    tunnel_dns_provider: str
    custom_tunnel_doh_url: str
    resolver_dns_provider: str
    custom_resolver_ip: str
    # Advanced settings.
    upstream_proxy_enabled: bool
    tls_split_mode: str
    excluded_apps: list[str]
    custom_edge_address: str
    # Upstream v2.0.3 parity settings.
    latency_probe_url: str
    ip_mode: str
    bootstrap_dns_provider: str
    custom_bootstrap_doh_url: str
    relayer_provider: str
    custom_relayer_url: str
    relayed_endpoints: list[str]
    bypass_local_network: bool
    local_proxy_auth_enabled: bool
    local_proxy_username: str
    transport_version: str
    multiplex_streams: int
    utls_fingerprint: str
    tls_fragment_mode: str
    tls_fragment_fallback_delay_ms: int
    always_on: bool
    kill_switch: bool
    automatic_recovery: bool
    update_checks: bool


# Global app instance (set during startup)
_app: Optional[PerchVPNApp] = None
_restart_task: Optional["asyncio.Task[None]"] = None
_init_task: Optional["asyncio.Task[None]"] = None
_config: Optional[WindowsConfig] = None


def _attach_status_notifier(app_inst) -> None:
    """Give the app the event-driven /ws/status push hook (idempotent)."""
    setter = getattr(app_inst, "set_status_notifier", None)
    if callable(setter):
        setter(notify_status_changed)


def _retain_failed_app(app_inst: PerchVPNApp, config: WindowsConfig) -> bool:
    """Keep a failed app when rollback left an unresolved TUN frontend."""
    if getattr(app_inst, "_tun_frontend", None) is None:
        return False
    global _app, _config
    _app = app_inst
    _config = config
    _attach_status_notifier(app_inst)
    return True


def _apply_mode_flags(config: WindowsConfig, mode: str) -> None:
    """Persist one mode without leaving the two flags inconsistent."""
    if mode == "tun":
        config.tun_enabled = True
        config.proxy_only_mode = False
    elif mode == "proxy_only":
        config.tun_enabled = False
        config.proxy_only_mode = True
    else:
        config.tun_enabled = False
        config.proxy_only_mode = False


def _app_can_apply_mode(app_obj) -> bool:
    """Only a live app may apply a mode switch; idle boot just persists."""
    check = getattr(app_obj, "is_connected", None)
    if callable(check):
        try:
            return bool(check())
        except Exception:  # noqa: BLE001 - absent evidence means idle
            return False
    return True


async def _startup() -> None:
    global _app, _config, _init_task
    diagnostics.install_logger_handler()
    _config = load_config()
    # Install the control-plane relayer routing from the persisted config
    # before any control-plane HTTP client is used.
    from perchvpn import relayer as relayer_module

    relayer_module.configure(
        provider=getattr(_config, "relayer_provider", "direct"),
        custom_url=getattr(_config, "custom_relayer_url", ""),
        routed_endpoints=getattr(_config, "relayed_endpoints", ()) or (),
    )
    # Warm the server-list snapshot off the event loop before the WebView
    # asks for countries.  Startup never waits for Remote Settings.
    _schedule_serverlist_refresh()
    if _app is not None:
        _app.config = _config
        return
    new_app = PerchVPNApp(_config)
    _app = new_app
    _attach_status_notifier(new_app)
    # Boot is idle: prepare logging/token migration only.  No auth dial,
    # proxy listener, TUN helper, or mode switch runs until Connect.
    if _init_task is not None and not _init_task.done():
        return
    initialize_idle = getattr(new_app, "initialize_idle", None)
    if callable(initialize_idle):
        _init_task = asyncio.create_task(initialize_idle())
    else:
        # Compatibility for test/legacy app doubles.
        _init_task = asyncio.create_task(new_app.initialize())


async def _shutdown() -> None:
    global _app, _config, _init_task, _restart_task, _bg_shutdown_task
    # Stop the /ws/status monitor before app teardown so it never races
    # _app/_config being torn down to None.
    await _stop_status_monitor()
    # Sequence background work before app teardown: let an in-flight init or
    # a disconnect that outlived its HTTP response finish (success or its own
    # failure handling) rather than cancelling it mid-write.
    for task in (_init_task, _restart_task, _bg_shutdown_task):
        if task is not None and not task.done():
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
    _init_task = None
    _restart_task = None
    _bg_shutdown_task = None
    if _app is not None:
        try:
            await asyncio.wait_for(
                _app.shutdown(), timeout=_APP_SHUTDOWN_TIMEOUT_SECONDS
            )
        except asyncio.TimeoutError:
            logger.error(
                "app shutdown exceeded %.1fs; releasing API ownership so the "
                "process can exit",
                _APP_SHUTDOWN_TIMEOUT_SECONDS,
            )
        except Exception:  # noqa: BLE001 - teardown must not pin the API thread
            logger.exception("app shutdown failed")
    _app = None
    _config = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle: execute, then always shut down.

    Preserves the exact behavior of the former on_event("startup") /
    on_event("shutdown") handlers, in the same order.
    """
    await _startup()
    try:
        yield
    finally:
        await _shutdown()


# FastAPI application instance
app = FastAPI(lifespan=lifespan)


def _tunnel_payload_of(app_obj) -> dict:
    """Best-effort tunnel evidence for apps without the new interface."""
    fn = getattr(app_obj, "tun_payload", None)
    if not callable(fn):
        return {}
    try:
        data = fn()
    except Exception:  # noqa: BLE001 - status must not fail on evidence gaps
        return {}
    return data if isinstance(data, dict) else {}


def _switch_payload_of(app_obj) -> dict:
    fn = getattr(app_obj, "switch_payload", None)
    if not callable(fn):
        return {}
    try:
        data = fn()
    except Exception:  # noqa: BLE001
        return {}
    return data if isinstance(data, dict) else {}


def _modes_payload_of(app_obj, tunnel: Optional[dict] = None) -> dict:
    fn = getattr(app_obj, "mode_payload", None)
    if not callable(fn):
        return {}
    try:
        data = fn(tunnel) if tunnel is not None else fn()
    except TypeError:
        # Older/duck-typed apps accept no argument; keep the status contract
        # working rather than failing the whole frame.
        try:
            data = fn()
        except Exception:  # noqa: BLE001
            return {}
    except Exception:  # noqa: BLE001
        return {}
    return data if isinstance(data, dict) else {}


def _status_payloads_of(app_obj) -> tuple[dict, dict, dict]:
    """Collect the three app payloads together.

    ``tun_payload``/``mode_payload`` read the elevated helper's state file.
    The API calls this through ``asyncio.to_thread`` so those reads never
    block the event loop, and one tunnel payload is reused by modes.
    """
    tunnel = _tunnel_payload_of(app_obj)
    switch = _switch_payload_of(app_obj)
    modes = _modes_payload_of(app_obj, tunnel)
    return tunnel, switch, modes


async def _status_payloads_async(app_obj) -> tuple[dict, dict, dict]:
    if app_obj is None:
        return {}, {}, {}
    return await asyncio.to_thread(_status_payloads_of, app_obj)


def ui_status_from_controller(controller_status: str, tunnel: dict) -> str:
    """Translate controller lifecycle + TUN evidence into the UI status contract.

    "connected" is reserved for a system-wide tunnel with verified system
    egress. Without TUN, the honest label is "proxy_active" (SOCKS5 only).
    """
    base = {"ok": "connected", "starting": "connecting"}.get(
        controller_status, controller_status
    )
    if base != "connected":
        return base
    if not tunnel.get("enabled"):
        return "proxy_active"
    state = str(tunnel.get("state") or "")
    if state == "traffic_verified":
        return "connected"
    if state in (
        "starting",
        "adapter_ready",
        "routes_configured",
        # Adapter and split default routes are up while exit verification is
        # still running (or has not produced a verdict yet): that is normal
        # TUN startup progress, never a failure. Reporting "degraded" here
        # made the UI flash "Connection degraded" on every healthy start.
        "tunnel_operational",
    ):
        return "connecting"
    if state == "degraded":
        # Reserved for a concrete, exhausted failure (for example a verified
        # physical-egress leak), never for mere verification-in-progress.
        return "degraded"
    return "failed"


async def _build_status_response() -> StatusResponse:
    """Build the authoritative /api/status payload.

    Shared by the REST endpoint and the /ws/status real-time push so both
    surfaces can never disagree. Raises HTTPException(503) when the app or
    config is not initialized (callers decide how to degrade).
    """
    get_app()
    config = get_config()
    restart_active = _restart_task is not None and not _restart_task.done()
    if not _app or not _app._controller or restart_active:
        # Proxy-only mode has no controller: report the app's lifecycle state
        # honestly ("proxy_active" while the local SOCKS5 proxy serves,
        # "disconnected" after shutdown, failed initialization, or rollback).
        # An active restart worker outranks stale controller or disconnected
        # states, keeping the UI at "connecting" throughout initialize().
        if restart_active:
            status = "connecting"
        elif _app is not None and config.proxy_only_mode:
            status = _app._status_state
        elif _app is not None and getattr(_app, "_status_state", "") == "disconnected":
            # Idle boot (or a settled disconnect) outranks a pending idle init
            # task: never flash "connecting" before the user presses Connect.
            status = "disconnected"
        elif (
            _app is not None
            and _init_task is not None
            and not _init_task.done()
            and not getattr(_app, "_signed_out_boot", False)
        ):
            # Background init still dialling: honest progress, not a
            # falsely settled "disconnected".
            status = "connecting"
        else:
            status = "disconnected"
        tunnel, switch, modes = await _status_payloads_async(_app)
        return StatusResponse(
            status=status,
            uptime=0.0,
            socks5_addr=f"{config.listen_host}:{config.listen_port}",
            exit_ip="0.0.0.0",
            country="--",
            transport="--",
            downloaded=0,
            uploaded=0,
            download_speed=0.0,
            upload_speed=0.0,
            active_connections=0,
            exit_verification_state="not_applicable",
            webui_debug=_os.environ.get("PERCHVPN_WEBUI_DEBUG", "0"),
            proxy_only_mode=config.proxy_only_mode,
            tun_frontend=False,
            session_pool=False,
            http_proxy_enabled_live=bool(getattr(_app, "_http_proxy", None)),
            tunnel=tunnel,
            switch=switch,
            modes=modes,
        )

    ctrl = _app._controller
    metrics = ctrl.metrics

    # The core controller exposes its lifecycle reason ("starting" while the
    # initial dial is in flight, "ok" once the upstream is up and accepting).
    # Translate to the documented /api/status contract the frontend renders:
    # "connected" | "connecting" | "disconnected". Pass any other value
    # through unchanged so unknown future reasons are never laundered.
    tunnel, switch, modes = await _status_payloads_async(_app)
    controller_status = ui_status_from_controller(ctrl.status, tunnel)

    return StatusResponse(
        status=controller_status,
        uptime=ctrl.uptime,
        socks5_addr=f"{config.listen_host}:{config.listen_port}",
        exit_ip=_app._exit_ip,
        country=_app._exit_country.lower(),
        transport=ctrl.transport,
        downloaded=metrics.downloaded if metrics else 0,
        uploaded=metrics.uploaded if metrics else 0,
        download_speed=metrics.download_speed if metrics else 0.0,
        upload_speed=metrics.upload_speed if metrics else 0.0,
        active_connections=metrics.active_connections if metrics else 0,
        exit_verification_state=_app._exit_verification_state,
        webui_debug=_os.environ.get("PERCHVPN_WEBUI_DEBUG", "0"),
        proxy_only_mode=config.proxy_only_mode,
        tun_frontend=bool(tunnel.get("process_alive")),
        session_pool=bool(getattr(_app, "_pool", None)),
        http_proxy_enabled_live=bool(getattr(_app, "_http_proxy", None)),
        tunnel=tunnel,
        switch=switch,
        modes=modes,
    )


@app.get("/api/status", response_model=StatusResponse)
async def get_status() -> StatusResponse:
    """Get current connection status."""
    return await _build_status_response()


_devwatch_latest: str = ""


@app.get("/api/events")
async def get_events(after: int = 0, limit: int = 50) -> dict:
    """Structured diagnostics events (bounded in-memory buffer)."""
    return {"events": diagnostics.snapshot(after_id=int(after), limit=int(limit))}


@app.post("/api/devwatch")
async def post_devwatch(payload: dict):
    """Env-gated UI diagnostics sink (PERCHVPN_WEBUI_DEBUG=1). Receives UI
    state strings from the frontend for out-of-band verification."""
    global _devwatch_latest
    if _os.environ.get("PERCHVPN_WEBUI_DEBUG") == "1":
        msg = payload.get("msg", "")
        if isinstance(msg, str) and msg:
            _devwatch_latest = msg[:300]
    return {"ok": True}


@app.get("/api/devwatch")
async def get_devwatch():
    """Last UI state string received from the frontend diagnostics."""
    return {"latest": _devwatch_latest}


@app.get("/api/countries", response_model=list[CountryResponse])
async def get_countries() -> list[CountryResponse]:
    """Get available VPN countries from the cached server list.

    Cached snapshots return immediately; a cold snapshot is loaded/fetched on
    the API worker pool so concurrent /api/status or /api/mode requests keep
    running on the event loop.
    """
    return _filter_country_response(await _run_in_api_pool(_cached_countries))


# Country hovers/focus pre-resolve the target edge hostname so the DoH costs
# nothing at click time. Requests are deduplicated per country and never hold
# the API lock; a miss just falls back to the switch's own resolution.
_prewarm_inflight: set = set()


async def _prewarm_country_host(country_code: str) -> None:
    from perchvpn import doh_resolver
    from perchvpn.proxystate import ProxyStateStore, resolve_proxy
    from perchvpn_windows import diagnostics

    config = get_config()
    started = time.monotonic()
    try:
        countries = await _run_in_api_pool(_cached_countries, False)
        candidate, _ = resolve_proxy(
            countries,
            explicit_proxy=config.explicit_proxy,
            country_code=country_code,
            state_store=ProxyStateStore(config.proxy_state_path),
        )
        if not candidate:
            return
        await doh_resolver.resolve_hostname(
            candidate.host,
            config.resolver_dns_provider,
            config.custom_resolver_ip,
            timeout=min(config.handshake_timeout, 5.0),
            local_address=getattr(_app, "_source_bind_ip", None),
        )
        diagnostics.emit(
            "DEBUG", "countries", "prewarm", "resolved",
            outcome="ok",
            duration_ms=round((time.monotonic() - started) * 1000.0, 1),
            detail=country_code,
        )
    except Exception as exc:  # noqa: BLE001 - warming is best effort
        diagnostics.emit(
            "DEBUG", "countries", "prewarm", "skipped",
            outcome="error",
            duration_ms=round((time.monotonic() - started) * 1000.0, 1),
            detail=f"{country_code}: {exc}",
        )
    finally:
        _prewarm_inflight.discard(country_code)


@app.post("/api/prewarm")
async def prewarm_country(request: PrewarmRequest) -> dict:
    """Warm the DoH cache for a country before the user commits to it."""
    config = get_config()
    code = request.country_code.upper()
    if config.resolver_dns_provider == "system":
        return {"success": True, "queued": False, "reason": "system resolver"}
    if code in _prewarm_inflight:
        return {"success": True, "queued": False, "reason": "already warming", "country": code}
    _prewarm_inflight.add(code)
    asyncio.create_task(_prewarm_country_host(code))
    return {"success": True, "queued": True, "country": code}


_client_perf: dict = {}


@app.post("/api/client-perf")
async def post_client_perf(sample: ClientPerfRequest) -> dict:
    """Store the latest frame sample from the WebView for acceptance runs."""
    global _client_perf
    _client_perf = {
        "fps": sample.fps,
        "frames": sample.frames,
        "longTasks": sample.longTasks,
        "worstFrameMs": sample.worstFrameMs,
        "size": sample.size,
        "received_at": time.time(),
    }
    return {"success": True}


@app.get("/api/client-perf")
async def get_client_perf() -> dict:
    return {"success": True, "sample": _client_perf or None}


@app.get("/api/dns-cache")
async def dns_cache_state() -> dict:
    """Resolver cache counters (read-only; used by acceptance measurements)."""
    from perchvpn import doh_resolver

    return {"success": True, **doh_resolver.dns_cache_stats()}


# Shared server-list snapshot for /api/countries and /api/country selection.
# The Remote Settings list changes rarely and fetching it on the request path
# made every country tab/pick wait on the network.  The snapshot is
# stale-while-revalidate: a cached list is returned immediately, and a
# refresh runs on a background worker.  Only a completely cold cache (no
# in-process snapshot and no disk cache) performs one synchronous fetch, and
# endpoints invoke that path in the API worker pool so /api/status and
# /api/mode cannot be starved.
_serverlist_cache: dict = {"countries": None, "at": 0.0}
_serverlist_cache_lock = threading.Lock()
_serverlist_refresh_inflight = False
_SERVERLIST_TTL_SECONDS = 120.0


def _serverlist_cache_path() -> Optional[str]:
    try:
        return get_config().serverlist_cache_path
    except (HTTPException, AttributeError):
        return None


def _publish_serverlist(countries: list, *, at: Optional[float] = None) -> None:
    if not countries:
        return
    global _serverlist_cache
    with _serverlist_cache_lock:
        _serverlist_cache = {
            "countries": countries,
            "at": time.monotonic() if at is None else at,
        }


def _refresh_serverlist_worker() -> None:
    """Fetch Remote Settings and swap the snapshot; never touches the loop."""
    global _serverlist_refresh_inflight
    from perchvpn import serverlist

    started = time.monotonic()
    try:
        countries = serverlist.fetch_server_list(_serverlist_cache_path())
        _publish_serverlist(countries)
        diagnostics.emit(
            "DEBUG", "countries", "server-list", "background_refresh",
            outcome="ok",
            duration_ms=(time.monotonic() - started) * 1000.0,
            detail=f"countries={len(countries)}",
        )
    except Exception as exc:  # noqa: BLE001 - keep last-known-good snapshot
        diagnostics.emit(
            "WARN", "countries", "server-list", "background_refresh",
            outcome="error",
            duration_ms=(time.monotonic() - started) * 1000.0,
            detail=str(exc),
        )
    finally:
        with _serverlist_cache_lock:
            _serverlist_refresh_inflight = False


def _schedule_serverlist_refresh() -> bool:
    """Queue one background refresh; return True if this call queued it."""
    global _serverlist_refresh_inflight
    with _serverlist_cache_lock:
        if _serverlist_refresh_inflight:
            return False
        _serverlist_refresh_inflight = True
    try:
        _SERVERLIST_EXECUTOR.submit(_refresh_serverlist_worker)
    except RuntimeError:
        with _serverlist_cache_lock:
            _serverlist_refresh_inflight = False
        return False
    return True


def _serverlist_snapshot() -> tuple[Optional[list], float]:
    with _serverlist_cache_lock:
        return _serverlist_cache.get("countries"), float(_serverlist_cache.get("at", 0.0))


def _cached_countries(allow_refresh: bool = True) -> list:
    """Return the country snapshot without waiting on a network refresh.

    * fresh snapshot -> return it
    * stale snapshot -> return it immediately and refresh in the background
    * no memory snapshot -> use the disk cache immediately, if present
    * completely cold -> one fetch (callers that serve HTTP do this in a
      worker thread so the event loop stays responsive)
    """
    import time as _time

    from perchvpn import serverlist

    now = _time.monotonic()
    cached, cached_at = _serverlist_snapshot()
    if cached is not None:
        if (now - cached_at) < _SERVERLIST_TTL_SECONDS:
            diagnostics.emit("DEBUG", "countries", "server-list", "cache_hit",
                             outcome="hit", duration_ms=0.0)
            return cached
        if allow_refresh:
            _schedule_serverlist_refresh()
        diagnostics.emit("DEBUG", "countries", "server-list", "stale_hit",
                         outcome="stale", duration_ms=0.0)
        return cached

    cache_path = _serverlist_cache_path()
    if cache_path:
        disk = serverlist.load_cached_server_list(cache_path)
        if disk:
            _publish_serverlist(disk, at=now)
            if allow_refresh:
                _schedule_serverlist_refresh()
            diagnostics.emit("DEBUG", "countries", "server-list", "disk_hit",
                             outcome="hit", duration_ms=0.0)
            return disk

    if not allow_refresh:
        # Hot validation paths must not turn a cold cache into a blocking
        # network call; the startup warmup/refresh will populate it.
        diagnostics.emit("DEBUG", "countries", "server-list", "cold_miss",
                         outcome="miss", duration_ms=0.0)
        return []

    started = now
    countries = serverlist.fetch_server_list(cache_path)
    elapsed_ms = (_time.monotonic() - started) * 1000.0
    _publish_serverlist(countries, at=started)
    diagnostics.emit("DEBUG", "countries", "server-list", "cache_miss",
                     outcome="fetched", duration_ms=elapsed_ms,
                     detail=f"disk_cache={'yes' if cache_path else 'no'}")
    return countries


# The server list carries an "automatically choose" pseudo-country.  It is
# not a location: it has no flag, no cities of its own and resolve_proxy()
# already falls back to it, so listing it as a pickable row is noise (and a
# row whose data-code is empty).  Only the explicit picker drops it.
_AUTO_COUNTRY_CODES = frozenset({"REC"})


def _filter_country_response(countries) -> list[CountryResponse]:
    """Project the server list into the countries API shape, skipping
    countries without a usable first city/server and the auto pseudo-country."""
    result = []
    for c in countries:
        if not c.code or not c.cities:
            continue
        if str(c.code).strip().upper() in _AUTO_COUNTRY_CODES:
            continue
        cities = []
        for city in c.cities:
            if not city.servers:
                continue
            server = city.servers[0]
            cities.append(CityResponse(
                name=city.name,
                code=city.code,
                hostname=server.hostname,
                port=server.port or 2499,
            ))
        if cities:
            result.append(CountryResponse(code=c.code, name=c.name, cities=cities))
    return result


@app.get("/api/account", response_model=AccountResponse)
async def get_account() -> AccountResponse:
    app_inst = get_app()
    # Hand off a token persisted by the terminal auth helper without exposing
    # it through the API.  This is a no-op when runtime auth is already set.
    await app_inst.load_persisted_auth()

    email = ""
    account_status = ""

    if app_inst._runtime_auth and app_inst._runtime_auth.token:
        email = getattr(app_inst._runtime_auth.token, "email", "") or ""
        account_status = "signed in"

    async with _signin_lock:
        stage = _signin_state.get("stage")
        if stage == "signing_in":
            signin_stage = "signing_in"
        elif stage in ("verification_required", "verification_email_link"):
            signin_stage = "verification_required"
        elif stage == "unblock_required":
            signin_stage = "unblock_required"
        else:
            signin_stage = ""
        verification_method = str(_signin_state.get("verification_method") or "")

    return AccountResponse(
        email=email,
        account_status=account_status,
        signin_stage=signin_stage,
        verification_method=verification_method,
        identifier_masked=_mask_email(email) if email else "",
    )
class AccountActionResponse(BaseModel):
    status: str
    message: str = ""


@app.post("/api/account/login", response_model=AccountActionResponse)
async def account_login() -> AccountActionResponse:
    app_inst = get_app()
    launched, status = app_inst.launch_auth_helper()
    if status == "windows_terminal_not_found":
        raise HTTPException(status_code=503, detail="Windows Terminal is required for interactive sign-in")
    if status == "already_running":
        return AccountActionResponse(status=status, message="Authentication helper is already running")
    return AccountActionResponse(status=status, message="Authentication helper launched; complete sign-in in the terminal window")


@app.post("/api/account/logout", response_model=AccountActionResponse)
async def account_logout() -> AccountActionResponse:
    app_inst = get_app()
    try:
        await app_inst.sign_out()
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=f"Sign-out failed: {exc}") from exc
    _income_quota_cache.update(data=None, ok_at=0.0, err_at=0.0, key="")
    return AccountActionResponse(status="signed_out", message="Cached authentication tokens deleted and active VPN session stopped")


# ---------------------------------------------------------------------------
# In-app sign-in (no console): password login through the existing perchvpn
# authentication protocol. The password exists only inside a single request
# body and one executor argument; it is never logged, stored or returned.
# ---------------------------------------------------------------------------

_signin_state: dict[str, Any] = {"stage": "idle"}  # idle | signing_in | verification_required | verification_email_link
_signin_lock = asyncio.Lock()
_SIGNIN_TIMEOUT_SECONDS = 90.0
_VERIFY_TIMEOUT_SECONDS = 60.0
_VERIFICATION_SLOT_TTL_SECONDS = 600.0
_VERIFICATION_MAX_ATTEMPTS = 6


class SigninRequest(BaseModel):
    email: str = Field(default="", max_length=320)
    password: str = Field(default="", min_length=1, max_length=1024)
    # Emailed FxA unblock/authorization code (errno 125 retry).
    unblock_code: str = Field(default="", max_length=64)
    # Fresh attempt: cancel any pending browser/verification state first.
    reset: bool = False


class SessionTokenRequest(BaseModel):
    session_token: str = Field(min_length=1, max_length=512)


class UnblockSendRequest(BaseModel):
    email: str = Field(default="", max_length=320)


class VerifyRequest(BaseModel):
    code: str = Field(default="", max_length=16)


class SigninResponse(BaseModel):
    status: str  # signed_in | verification_required | unblock_required
    verification_method: str = ""
    message: str = ""
    authorization_url: str = ""
    state: str = ""


def _mask_email(email: str) -> str:
    if not email or "@" not in email:
        return "account"
    local, _, domain = email.partition("@")
    hidden_local = f"{local[:1]}\u2022\u2022\u2022" if len(local) >= 2 else "\u2022\u2022\u2022"
    return f"{hidden_local}@{domain}"


def _normalize_verification_method(method: Optional[str]) -> str:
    """Map FxA's verificationMethod values to the two UI branches.

    ``totp-2fa`` -> ``totp``; ``email-otp``/``email-2fa`` -> ``email-2fa``;
    link-based ``email`` stays ``email``.
    """
    value = (method or "").strip().lower()
    if value.startswith("totp"):
        return "totp"
    if value == "email":
        return "email"
    return "email-2fa"


def _classify_fxa_signin_error(exc: Exception) -> tuple[str, str]:
    """Reduce an FxA failure to a sanitized (kind, message) pair.

    Never echoes the raw server body or any credential material.
    """
    if isinstance(exc, auth_module.FxaApiError):
        errno = exc.errno
        text = (str(exc) or "").lower()
        # errno 125 ("The request was blocked for security reasons") means
        # FxA emailed an unblock code; the login must be retried with it.
        if errno == 125:
            return "unblock_required", (
                "Firefox Accounts emailed an authorization code to your account. "
                "Enter it to finish signing in."
            )
        if errno == 127:
            return "invalid_unblock_code", "That authorization code is not correct"
        # A 406 that survives a solved challenge is a Fastly edge rejection.
        # The solver runs with a browser TLS fingerprint: plain
        # httpx/OpenSSL is served an unsolvable captcha challenge, while a
        # browser fingerprint gets the solvable PAT/PoW chain.
        if exc.status_code == 406 and errno is None:
            return "edge_blocked", (
                "Firefox Accounts rejected this network's connection "
                "(HTTP 406). Try again in a moment, or switch networks."
            )
        if errno in (102, 103) or "unknown account" in text:
            return "invalid_credentials", "Incorrect email or password"
        if errno == 55 or "incorrect password" in text or errno == 104:
            return "invalid_credentials", "Incorrect email or password"
        if errno == 201 or "locked" in text:
            return "account_locked", "This Firefox account is currently locked; check for recovery emails"
        if exc.status_code == 429 or errno == 114 or "throttled" in text:
            return "throttled", "Too many sign-in attempts; wait a few minutes and try again"
        if exc.status_code in (400, 401):
            return "invalid_credentials", "Firefox Accounts rejected these credentials"
        return "service_error", "Sign-in is unavailable right now; try again shortly"
    return "service_error", "Sign-in is unavailable right now; try again shortly"


async def _install_signed_in_auth() -> bool:
    app_inst = get_app()
    installed = await app_inst.load_persisted_auth()
    if installed:
        diagnostics.emit(
            "INFO", "auth", "in-app sign-in", "complete", outcome="signed_in"
        )
    return installed


@app.post("/api/account/signin", response_model=SigninResponse)
async def account_signin(request: SigninRequest) -> SigninResponse:
    """Password sign-in entirely in-process: never launches helper/console."""
    email = (request.email or "").strip()
    password = request.password or ""
    unblock_code = (request.unblock_code or "").strip()
    request.password = ""  # clear on the request model as early as possible
    if not email or "@" not in email or " " in email:
        raise HTTPException(status_code=400, detail="Enter a valid email address")
    if not password:
        raise HTTPException(status_code=400, detail="Password is required")

    if request.reset:
        oauth_module.reset_oauth_flow()
        async with _signin_lock:
            _signin_state.update(stage="idle", email="", verification_method="",
                                 session_token=None, expires_at=0.0, attempts=0)
    async with _signin_lock:
        stage = _signin_state.get("stage")
        if stage in ("signing_in", "verification_required", "verification_email_link"):
            raise HTTPException(
                status_code=409, detail="A sign-in attempt is already in progress"
            )
        _signin_state["stage"] = "signing_in"

    diagnostics.emit(
        "INFO", "auth", "in-app sign-in", "start",
        outcome="pending", detail=_mask_email(email),
    )
    loop = asyncio.get_running_loop()
    token_path = get_token_path()
    login_kwargs: dict[str, Any] = {}
    if unblock_code:
        login_kwargs["unblock_code"] = unblock_code
    try:
        token = await asyncio.wait_for(
            loop.run_in_executor(
                None,
                functools.partial(
                    auth_module.login_with_password,
                    email,
                    password,
                    token_path,
                    **login_kwargs,
                ),
            ),
            timeout=_SIGNIN_TIMEOUT_SECONDS,
        )
        if not token or not token.access_token:
            raise GuardianHTTPError("sign-in returned no access token")
        del token
        installed = await _install_signed_in_auth()
        if not installed:
            raise GuardianHTTPError("signed-in session could not be accepted by the app")
        return SigninResponse(status="signed_in", message="Sign-in successful")
    except auth_module.VerificationRequired as pending:
        method = _normalize_verification_method(pending.method)
        async with _signin_lock:
            _signin_state.update(
                stage=(
                    "verification_email_link"
                    if method == "email"
                    else "verification_required"
                ),
                email=email,
                verification_method=method,
                session_token=pending.session_token,
                expires_at=time.monotonic() + _VERIFICATION_SLOT_TTL_SECONDS,
                attempts=0,
            )
        diagnostics.emit(
            "INFO", "auth", "in-app sign-in", "awaiting_confirmation",
            outcome="verification_required", detail=f"method={method}",
        )
        return SigninResponse(
            status="verification_required",
            verification_method=method,
            message=(
                "A confirmation link was emailed to you. Open it, then press "
                "\u201cI opened the link\u201d."
                if method == "email"
                else (
                    "Enter the 6-digit code from your authenticator app."
                    if method == "totp"
                    else "Enter the confirmation code emailed to you."
                )
            ),
        )
    except auth_module.UnblockRequired as blocked:
        async with _signin_lock:
            _signin_state.update(
                stage="unblock_required",
                email=email,
                verification_method=blocked.method,
                session_token=None,
                expires_at=time.monotonic() + _VERIFICATION_SLOT_TTL_SECONDS,
                attempts=0,
            )
        # FxA's errno 125 response implies it emailed an unblock code, but a
        # fresh login attempt does not always trigger the send. Request it
        # explicitly in the background so the inline prompt is never empty.
        sent = False
        try:
            await asyncio.wait_for(
                loop.run_in_executor(
                    None, functools.partial(auth_module.send_unblock_code, email)
                ),
                timeout=_VERIFY_TIMEOUT_SECONDS,
            )
            sent = True
        except Exception as exc:  # noqa: BLE001 - Resend remains available
            diagnostics.emit(
                "WARN", "auth", "in-app sign-in", "unblock_send_failed",
                outcome="failed", detail=diagnostics.redact_exception(exc),
            )
        diagnostics.emit(
            "INFO", "auth", "in-app sign-in", "unblock_required",
            outcome="unblock_required", detail=f"method={blocked.method}",
        )
        return SigninResponse(
            status="unblock_required",
            verification_method=blocked.method,
            message=(
                "Firefox Accounts emailed an authorization code to your "
                "account. Enter it to finish signing in."
                if sent
                else "Firefox Accounts requires an authorization code. "
                "Press Resend code to request one."
            ),
        )
    except FastlyChallengeError as exc:
        diagnostics.emit(
            "WARN", "auth", "in-app sign-in", "failed",
            outcome="edge_blocked", detail="anti-bot challenge unsolved",
        )
        raise HTTPException(
            status_code=503,
            detail=(
                "Firefox Accounts' anti-bot check could not be completed "
                "from this network. Try again in a moment, or switch "
                "networks."
            ),
        ) from exc
    except auth_module.FxaApiError as exc:
        kind, message = _classify_fxa_signin_error(exc)
        diagnostics.emit(
            "WARN", "auth", "in-app sign-in", "failed",
            outcome=kind, detail=message,
        )
        raise HTTPException(
            status_code=(
                401 if kind == "invalid_credentials"
                else 503 if kind in ("edge_blocked", "throttled")
                else 502
            ),
            detail=message,
        )
    except asyncio.TimeoutError:
        diagnostics.emit(
            "WARN", "auth", "in-app sign-in", "failed",
            outcome="timeout", detail="timed out",
        )
        raise HTTPException(
            status_code=504, detail="Sign-in timed out; try again shortly"
        )
    except Exception as exc:  # noqa: BLE001
        diagnostics.emit(
            "ERROR", "auth", "in-app sign-in", "failed",
            outcome="service_error",
            detail=diagnostics.redact_exception(exc),
        )
        raise HTTPException(
            status_code=502,
            detail="Sign-in is unavailable right now; try again shortly",
        ) from exc
    finally:
        password = ""  # noqa: F841 - drop the credential reference
        async with _signin_lock:
            if _signin_state.get("stage") == "signing_in":
                _signin_state.update(stage="idle", email="", verification_method="",
                                     session_token=None, expires_at=0.0, attempts=0)


@app.post("/api/account/verify", response_model=SigninResponse)
async def account_verify(request: VerifyRequest) -> SigninResponse:
    """Complete an awaiting sign-in confirmation (emailed code or link)."""
    async with _signin_lock:
        state = dict(_signin_state)
        stage = state.get("stage")
        if stage not in ("verification_required", "verification_email_link"):
            raise HTTPException(
                status_code=404, detail="No sign-in is currently awaiting confirmation"
            )
        if time.monotonic() > float(state.get("expires_at") or 0.0):
            _signin_state.update(stage="idle", email="", verification_method="",
                                 session_token=None, expires_at=0.0, attempts=0)
            raise HTTPException(
                status_code=410,
                detail="The confirmation window expired; sign in again",
            )
        attempts = int(state.get("attempts") or 0) + 1
        if attempts > _VERIFICATION_MAX_ATTEMPTS:
            _signin_state.update(stage="idle", email="", verification_method="",
                                 session_token=None, expires_at=0.0, attempts=0)
            raise HTTPException(
                status_code=429,
                detail="Too many confirmation attempts; sign in again",
            )
        _signin_state["attempts"] = attempts
        _signin_state["stage"] = "signing_in"  # guard against parallel submits

    session_token = state.get("session_token") or ""
    verification_method = state.get("verification_method") or ""
    code = (request.code or "").strip()
    if verification_method in ("email-2fa", "totp") and not code:
        async with _signin_lock:
            _signin_state["stage"] = "verification_required"
        raise HTTPException(status_code=400, detail="Enter the confirmation code emailed to you")

    loop = asyncio.get_running_loop()
    token_path = get_token_path()
    try:
        if verification_method == "totp":
            await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    functools.partial(
                        auth_module.verify_with_totp, session_token, code, token_path
                    ),
                ),
                timeout=_VERIFY_TIMEOUT_SECONDS,
            )
        elif verification_method == "email-2fa":
            await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    functools.partial(
                        auth_module.verify_with_code, session_token, code, token_path
                    ),
                ),
                timeout=_VERIFY_TIMEOUT_SECONDS,
            )
        else:
            await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    functools.partial(
                        auth_module.complete_link_verification, session_token, token_path
                    ),
                ),
                timeout=_VERIFY_TIMEOUT_SECONDS,
            )
    except auth_module.FxaApiError as exc:
        # Keep the slot so the user can retry with a fresh code/link.
        async with _signin_lock:
            _signin_state["stage"] = stage
        kind, message = _classify_fxa_signin_error(exc)
        if kind == "invalid_credentials" and verification_method == "email-2fa":
            message = "That confirmation code is not correct"
        diagnostics.emit(
            "WARN", "auth", "sign-in confirmation", "failed",
            outcome=kind, detail=message,
        )
        raise HTTPException(
            status_code=(401 if kind == "invalid_credentials" else 502),
            detail=message,
        )
    except asyncio.TimeoutError:
        async with _signin_lock:
            _signin_state["stage"] = stage
        raise HTTPException(status_code=504, detail="Confirmation check timed out; try again")
    except Exception:  # noqa: BLE001
        async with _signin_lock:
            _signin_state["stage"] = stage
        raise HTTPException(status_code=502, detail="Confirmation is unavailable right now; try again")
    else:
        async with _signin_lock:
            _signin_state.update(stage="idle", email="", verification_method="",
                                 session_token=None, expires_at=0.0, attempts=0)
        await _install_signed_in_auth()
        return SigninResponse(
            status="signed_in",
            message="Sign-in complete" if verification_method == "email-2fa"
            else "Email link confirmed; sign-in complete",
        )


@app.post("/api/account/verify/cancel", response_model=SigninResponse)
async def account_verify_cancel() -> SigninResponse:
    """Abandon an awaiting confirmation without state leakage."""
    async with _signin_lock:
        had = _signin_state.get("stage") in (
            "verification_required", "verification_email_link", "unblock_required"
        )
        _signin_state.update(stage="idle", email="", verification_method="",
                             session_token=None, expires_at=0.0, attempts=0)
    diagnostics.emit("INFO", "auth", "sign-in confirmation", "cancelled",
                     outcome="cancelled" if had else "none")
    return SigninResponse(status="cancelled", message="Sign-in attempt cancelled")


@app.post("/api/account/verify/resend", response_model=AccountActionResponse)
async def account_resend_verification() -> AccountActionResponse:
    """(Re)send the code/link for the sign-in awaiting confirmation."""
    async with _signin_lock:
        state = dict(_signin_state)
    stage = state.get("stage")
    if stage not in (
        "verification_required", "verification_email_link", "unblock_required"
    ):
        raise HTTPException(
            status_code=404, detail="No sign-in is currently awaiting confirmation"
        )
    email = str(state.get("email") or "")
    session_token = str(state.get("session_token") or "")
    loop = asyncio.get_running_loop()
    try:
        if stage == "unblock_required":
            await asyncio.wait_for(
                loop.run_in_executor(
                    None, functools.partial(auth_module.send_unblock_code, email)
                ),
                timeout=_VERIFY_TIMEOUT_SECONDS,
            )
        else:
            await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    functools.partial(
                        auth_module.resend_verification_code, session_token
                    ),
                ),
                timeout=_VERIFY_TIMEOUT_SECONDS,
            )
    except auth_module.FxaApiError as exc:
        kind, message = _classify_fxa_signin_error(exc)
        diagnostics.emit(
            "WARN", "auth", "sign-in confirmation", "resend_failed",
            outcome=kind, detail=message,
        )
        raise HTTPException(status_code=502, detail=message) from exc
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=504, detail="Resending the code timed out; try again"
        )
    diagnostics.emit(
        "INFO", "auth", "sign-in confirmation", "resent", outcome="pending",
    )
    return AccountActionResponse(
        status="sent", message="A new code was sent; check your email."
    )


@app.post("/api/account/unblock/send", response_model=AccountActionResponse)
async def account_send_unblock_code(request: UnblockSendRequest) -> AccountActionResponse:
    """(Re)send the FxA authorization/unblock code after errno 125."""
    email = (request.email or "").strip()
    if not email or "@" not in email or " " in email:
        raise HTTPException(status_code=400, detail="Enter a valid email address")
    loop = asyncio.get_running_loop()
    try:
        await asyncio.wait_for(
            loop.run_in_executor(
                None, functools.partial(auth_module.send_unblock_code, email)
            ),
            timeout=_VERIFY_TIMEOUT_SECONDS,
        )
    except auth_module.FxaApiError as exc:
        kind, message = _classify_fxa_signin_error(exc)
        diagnostics.emit(
            "WARN", "auth", "unblock code", "failed", outcome=kind, detail=message,
        )
        raise HTTPException(
            status_code=(429 if kind == "throttled" else 502), detail=message
        ) from exc
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=504, detail="Sending the authorization code timed out; try again"
        )
    diagnostics.emit(
        "INFO", "auth", "unblock code", "sent",
        outcome="pending", detail=_mask_email(email),
    )
    return AccountActionResponse(
        status="unblock_code_sent",
        message="An authorization code was emailed to your account",
    )


@app.post("/api/account/session-token", response_model=SigninResponse)
async def account_session_token(request: SessionTokenRequest) -> SigninResponse:
    """Sign in by importing (pasting) a Firefox Accounts session token.

    The fallback when password auth is anti-bot blocked and browser sign-in
    is unavailable. The token is validated by FxA before being persisted;
    it is never logged or returned.
    """
    session_token = (request.session_token or "").strip()
    if not session_token:
        raise HTTPException(status_code=400, detail="Paste a session token first")
    async with _signin_lock:
        if _signin_state.get("stage") in ("signing_in", "verification_required"):
            raise HTTPException(
                status_code=409, detail="A sign-in attempt is already in progress"
            )
        _signin_state["stage"] = "signing_in"
    loop = asyncio.get_running_loop()
    token_path = get_token_path()
    try:
        token = await asyncio.wait_for(
            loop.run_in_executor(
                None,
                functools.partial(
                    auth_module.login_with_session_token, session_token, token_path
                ),
            ),
            timeout=_SIGNIN_TIMEOUT_SECONDS,
        )
        if not token or not token.access_token:
            raise GuardianHTTPError("session token produced no access token")
        if not await _install_signed_in_auth():
            raise GuardianHTTPError("session token could not be accepted by the app")
    except auth_module.FxaApiError as exc:
        kind, message = _classify_fxa_signin_error(exc)
        if exc.status_code in (400, 401) and kind == "service_error":
            message = "That session token is not valid"
        diagnostics.emit(
            "WARN", "auth", "session token import", "failed",
            outcome=kind, detail=message,
        )
        raise HTTPException(status_code=401, detail=message) from exc
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=504, detail="Session token check timed out; try again"
        )
    except Exception as exc:  # noqa: BLE001
        diagnostics.emit(
            "ERROR", "auth", "session token import", "failed",
            outcome="service_error", detail=diagnostics.redact_exception(exc),
        )
        raise HTTPException(
            status_code=502, detail="Session token sign-in is unavailable right now"
        ) from exc
    finally:
        session_token = ""  # noqa: F841 - drop the credential reference
        async with _signin_lock:
            if _signin_state.get("stage") == "signing_in":
                _signin_state.update(stage="idle", email="", verification_method="",
                                     session_token=None, expires_at=0.0, attempts=0)
    diagnostics.emit(
        "INFO", "auth", "session token import", "complete", outcome="signed_in"
    )
    return SigninResponse(status="signed_in", message="Signed in with the session token")


# ---------------------------------------------------------------------------
# OAuth browser sign-in (Supported first-time path): the FxA HTTP login API
# is hard-blocked for non-browser clients, so the browser handles user
# authentication, and the application only does the PKCE state handling and
# the authorization-code exchange.
# ---------------------------------------------------------------------------

class OAuthStartResponse(BaseModel):
    authorization_url: str
    state: str
    launched: bool = False


async def _install_oauth_tokens() -> bool:
    return await _install_signed_in_auth()


@app.post("/api/auth/oauth/start", response_model=OAuthStartResponse)
async def oauth_start() -> OAuthStartResponse:
    """Allocate state/PKCE and a loopback callback host; return the URL."""
    try:
        flow = await asyncio.get_running_loop().run_in_executor(
            None, oauth_module.start_oauth_flow)
    except Exception as exc:  # noqa: BLE001
        diagnostics.emit(
            "ERROR", "oauth", "authorization", "start",
            outcome="failed", detail=diagnostics.redact_exception(exc),
        )
        raise HTTPException(
            status_code=502, detail="Browser sign-in is unavailable right now; try again shortly"
        ) from exc
    return OAuthStartResponse(authorization_url=flow["authorization_url"], state=flow["state"])


@app.post("/api/auth/oauth/open", response_model=OAuthStartResponse)
async def oauth_open() -> OAuthStartResponse:
    """Start a browser sign-in and hand the authorization page to the
    system browser (the anti-bot-safe path when password login is blocked).

    Uses the OOB redirect the OAuth client actually registers; FxA shows the
    authorization code on its success page and the app finishes the PKCE
    exchange once the user pastes it back."""
    try:
        flow = await asyncio.get_running_loop().run_in_executor(
            None, oauth_module.start_oauth_oob_flow)
    except Exception as exc:  # noqa: BLE001
        diagnostics.emit(
            "ERROR", "oauth", "authorization", "start",
            outcome="failed", detail=diagnostics.redact_exception(exc),
        )
        raise HTTPException(
            status_code=502, detail="Browser sign-in is unavailable right now; try again shortly"
        ) from exc
    launched = await asyncio.get_running_loop().run_in_executor(
        None, oauth_module.open_authorization_url, flow["authorization_url"])
    diagnostics.emit(
        "INFO", "oauth", "authorization", "opened",
        outcome="pending" if launched else "failed",
        detail="" if launched else "no default browser handler",
    )
    return OAuthStartResponse(
        authorization_url=flow["authorization_url"], state=flow["state"], launched=launched
    )


@app.post("/api/auth/guardian/start", response_model=OAuthStartResponse)
async def guardian_start() -> OAuthStartResponse:
    """Start Guardian's native desktop PKCE flow with a loopback listener."""
    try:
        flow = await asyncio.get_running_loop().run_in_executor(
            None, oauth_module.start_guardian_flow
        )
    except Exception as exc:  # noqa: BLE001
        diagnostics.emit(
            "ERROR", "oauth", "guardian", "start",
            outcome="failed", detail=diagnostics.redact_exception(exc),
        )
        raise HTTPException(
            status_code=502, detail="Interactive sign-in is unavailable right now"
        ) from exc
    diagnostics.emit(
        "INFO", "oauth", "guardian", "start", outcome="pending",
        detail=f"port={flow.get('port', 0)}",
    )
    return OAuthStartResponse(
        authorization_url=flow["authorization_url"],
        state=flow["state"],
        launched=False,
    )


@app.get("/api/auth/oauth/status")
async def oauth_status(state: str = "") -> dict:
    """Poll the one-shot browser callback listener (no secrets returned)."""
    if not state:
        raise HTTPException(status_code=400, detail="A sign-in state is required")
    return oauth_module.oauth_flow_status(state)


class OAuthCompleteRequest(BaseModel):
    state: str = Field(min_length=1, max_length=256)
    # Out-of-band flow: the code FxA displayed after browser sign-in.
    code: str = Field(default="", max_length=1024)


@app.post("/api/auth/oauth/complete", response_model=SigninResponse)
async def oauth_complete(request: OAuthCompleteRequest) -> SigninResponse:
    """Exchange the (single-use) callback result and install the session."""
    try:
        if request.code.strip():
            token = await oauth_module.submit_oauth_code_async(
                request.state, request.code)
        else:
            token = await oauth_module.complete_oauth_flow_async(request.state)
    except oauth_module.OAuthError as exc:
        diagnostics.emit(
            "WARN", "oauth", "authorization", "failed",
            outcome=exc.kind, detail=exc.message,
        )
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc
    except Exception as exc:  # noqa: BLE001
        diagnostics.emit(
            "ERROR", "oauth", "authorization", "failed",
            outcome="service_error", detail=diagnostics.redact_exception(exc),
        )
        raise HTTPException(
            status_code=502, detail="Browser sign-in is unavailable right now; try again shortly"
        ) from exc

    if not token or not token.access_token:
        raise HTTPException(status_code=502, detail="Sign-in did not produce a usable session")
    installed = await _install_oauth_tokens()
    if not installed:
        raise HTTPException(status_code=502, detail="Sign-in succeeded but the app could not accept the session")
    return SigninResponse(status="signed_in", message="Signed in through the browser")


@app.post("/api/auth/oauth/cancel", response_model=SigninResponse)
async def oauth_cancel(request: OAuthCompleteRequest) -> SigninResponse:
    cancelled = oauth_module.cancel_oauth_flow(request.state)
    if cancelled:
        diagnostics.emit("INFO", "oauth", "authorization", "cancelled", outcome="cancelled")
    return SigninResponse(status="cancelled", message="Browser sign-in cancelled")


@app.post("/api/auth/oauth/reset", response_model=AccountActionResponse)
async def oauth_reset(request: OAuthCompleteRequest) -> AccountActionResponse:
    """Cancel any pending attempt and clear stale login stage state."""
    oauth_module.reset_oauth_flow(request.state)
    async with _signin_lock:
        if _signin_state.get("stage") != "signed_in":
            _signin_state.update(stage="idle", email="", verification_method="",
                                 session_token=None, expires_at=0.0, attempts=0)
    return AccountActionResponse(status="auth_reset", message="Sign-in state reset")


class OAuthCallbackRequest(BaseModel):
    state: str = Field(min_length=1, max_length=256)
    url: str = Field(default="", max_length=4096)


@app.post("/api/auth/oauth/callback", response_model=AccountActionResponse)
async def oauth_callback(request: OAuthCallbackRequest) -> AccountActionResponse:
    """Feed an intercepted oauth/success navigation into the pending flow."""
    if not oauth_module.record_external_callback(request.state, request.url):
        raise HTTPException(status_code=400, detail="No matching sign-in attempt")
    return AccountActionResponse(status="callback_recorded", message="Sign-in callback accepted")


# ---------------------------------------------------------------------------
# Account + monthly allowance (gauge) state, driven only by Guardian-reported
# data (mirrors the FoxyVPN Android client: /fpn/status payload + X-Quota-*
# pass headers). Never fabricated; parsed headers are the sole source.
# ---------------------------------------------------------------------------

class QuotaResponse(BaseModel):
    account_state: str  # signed_out | signing_in | signed_in | retrieving | no_pass | quota_exhausted | auth_error | service_error
    gauge_state: str  # ok | unlimited | unavailable
    identifier_masked: str = ""
    subscribed: bool = False
    limited_bandwidth: bool = False
    max_bytes: Optional[int] = None
    remaining_bytes: Optional[int] = None
    used_bytes: Optional[int] = None
    used_percent: Optional[float] = None
    remaining_percent: Optional[float] = None
    reset_epoch: Optional[int] = None
    usage_source: str = ""  # "guardian"
    email: str = ""
    message: str = ""
    checked_at: float = 0.0


_income_quota_cache: dict[str, Any] = {"data": None, "ok_at": 0.0, "err_at": 0.0, "key": ""}
_QUOTA_OK_TTL_SECONDS = 120.0
_QUOTA_ERR_TTL_SECONDS = 60.0
_RESET_EPOCH_MIN = 1_600_000_000
_RESET_PLAUSIBLE_WINDOW_SECONDS = int(1.5 * 365.25 * 24 * 3600)


def _mask_identifier(uid: str, email: str) -> str:
    uid = (uid or "").strip()
    if uid:
        if len(uid) > 8:
            return f"{uid[:4]}\u2022{uid[-2:]}"
        return "uid"
    return _mask_email(email)


def _quota_token_key(access_token: str) -> str:
    digest = hashlib.sha256(access_token.encode("utf-8")).hexdigest()
    return f"t:{digest[:12]}"


def _parse_int_bytes(value: Any) -> Optional[int]:
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _parse_reset_epoch(value: Any, now: float) -> Optional[int]:
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    if parsed < _RESET_EPOCH_MIN or parsed > now + _RESET_PLAUSIBLE_WINDOW_SECONDS:
        return None
    return parsed


def _signed_in_token_or_none(app_inst: PerchVPNApp):
    auth = app_inst._runtime_auth
    if not auth or not auth.token or not auth.token.access_token:
        return None
    # A cached token alone is not proof the account is authenticated: the
    # Guardian calls below act as the actual validation step, exactly like
    # the Android client's account-status fetch.
    return auth.token.access_token


def _quota_error_response(account_state: str, gauge_state: str, message: str) -> QuotaResponse:
    return QuotaResponse(
        account_state=account_state,
        gauge_state=gauge_state,
        message=message,
        checked_at=time.time(),
    )


async def _guardian_quota_fetch(access_token: str) -> QuotaResponse:
    """One authoritative quota snapshot from the existing Guardian client."""
    app_inst = get_app()
    endpoint = app_inst.config.guardian_endpoint
    loop = asyncio.get_running_loop()

    entitlement: Optional[guardian.Entitlement] = None
    status_error: Optional[Exception] = None
    try:
        entitlement = await loop.run_in_executor(
            None, functools.partial(guardian.fetch_user_info, endpoint, access_token)
        )
    except (GuardianHTTPError, TokenInvalidError) as exc:
        status_error = exc
    except Exception as exc:  # noqa: BLE001
        status_error = exc

    if entitlement is None:
        if isinstance(status_error, (GuardianHTTPError, TokenInvalidError)):
            status = getattr(status_error, "status_code", None)
            if status in (401, 403):
                return _quota_error_response(
                    "auth_error", "unavailable",
                    "The stored session was rejected by Guardian; sign in again",
                )
            if status == 429:
                return _quota_error_response(
                    "quota_exhausted", "unavailable",
                    "Guardian reports the proxy quota is exhausted for now",
                )
            return _quota_error_response(
                "service_error", "unavailable",
                "Account status could not be read from Guardian; try again later",
            )

    email = getattr(app_inst._runtime_auth and app_inst._runtime_auth.token, "email", "") or ""
    identifier = _mask_identifier(entitlement.uid, email)

    if not entitlement.limited_bandwidth:
        quota = QuotaResponse(
            account_state="signed_in",
            gauge_state="unlimited",
            identifier_masked=identifier,
            subscribed=entitlement.subscribed,
            limited_bandwidth=False,
            usage_source="guardian",
            message="The account is not bandwidth-limited; no monthly cap applies",
            checked_at=time.time(),
        )
        if not entitlement.subscribed:
            quota.account_state = "no_pass"
            quota.message = "The account has no active VPN entitlement"
        return quota

    max_bytes = _parse_int_bytes(entitlement.max_bytes)
    remaining = entitlement.quota_remaining

    # Reset + header-grade max/remaining can only come from a proxy-pass
    # response; honour 401/429 *and* the limited-bandwidth pass retry exactly
    # like the Android client's best-effort fetchUserInfo.
    reset_epoch: Optional[int] = None
    pass_error: Optional[Exception] = None
    try:
        pass_info = await loop.run_in_executor(
            None, functools.partial(guardian.fetch_proxy_pass, endpoint, access_token)
        )
        reset_epoch = _parse_reset_epoch(pass_info.quota_reset, time.time())
        header_max = _parse_int_bytes(pass_info.quota_max)
        header_left = _parse_int_bytes(pass_info.quota_left)
        if header_max is not None:
            max_bytes = header_max
        if remaining is None:
            remaining = header_left
    except (GuardianHTTPError, TokenInvalidError) as exc:
        pass_error = exc
    except Exception as exc:  # noqa: BLE001
        pass_error = exc

    if isinstance(pass_error, (GuardianHTTPError, TokenInvalidError)):
        status = getattr(pass_error, "status_code", None)
        if status in (401, 403):
            return _quota_error_response(
                "auth_error", "unavailable",
                "The stored session was rejected by Guardian; sign in again",
            )
        if status == 429:
            return _quota_error_response(
                "quota_exhausted", "unavailable",
                "Guardian reports the proxy quota is exhausted for now",
            )

    if max_bytes is None or remaining is None:
        return _quota_error_response(
            "service_error", "unavailable",
            "Guardian did not report complete quota information for this account",
        )

    max_bytes = max(max_bytes, 0)
    remaining = max(remaining, 0)
    used = max(max_bytes - remaining, 0)
    used_percent = (used / max_bytes * 100.0) if max_bytes > 0 else None
    remaining_percent = (remaining / max_bytes * 100.0) if max_bytes > 0 else None
    exhausted = max_bytes > 0 and remaining == 0
    return QuotaResponse(
        account_state="quota_exhausted" if exhausted else "signed_in",
        gauge_state="ok",
        identifier_masked=identifier,
        subscribed=entitlement.subscribed,
        limited_bandwidth=True,
        max_bytes=max_bytes,
        remaining_bytes=remaining,
        used_bytes=used,
        used_percent=used_percent,
        remaining_percent=remaining_percent,
        reset_epoch=reset_epoch,
        usage_source="guardian",
        message="Monthly allowance reported by Guardian" if reset_epoch is None
        else "Monthly allowance reported by Guardian; resets at the reported date",
        checked_at=time.time(),
    )


@app.get("/api/account/quota", response_model=QuotaResponse)
async def get_account_quota(refresh: bool = False) -> QuotaResponse:
    """In-process screen: account card + allowance gauge, Guardian-sourced."""
    app_inst = get_app()
    async with _signin_lock:
        stage = _signin_state.get("stage")
        if stage in (
            "signing_in", "verification_required", "verification_email_link",
            "unblock_required",
        ):
            return QuotaResponse(
                account_state="signing_in",
                gauge_state="unavailable",
                message="Signing in\u2026",
                checked_at=time.time(),
            )

    access_token = _signed_in_token_or_none(app_inst)
    if access_token is None:
        return _quota_error_response("signed_out", "unavailable", "")

    token_key = _quota_token_key(access_token)
    cache = _income_quota_cache
    now = time.monotonic()
    if not refresh and cache["data"] is not None and cache["key"] == token_key:
        if cache["data"].gauge_state not in ("unavailable",) and now - cache["ok_at"] < _QUOTA_OK_TTL_SECONDS:
            cached = cache["data"]
            return cached.model_copy(update={"checked_at": time.time()})
        if cache["data"].gauge_state == "unavailable" and now - cache["err_at"] < _QUOTA_ERR_TTL_SECONDS:
            cached = cache["data"]
            return cached.model_copy(update={"checked_at": time.time()})

    result = await _guardian_quota_fetch(access_token)
    if result.gauge_state in ("ok", "unlimited"):
        cache.update(data=result, ok_at=time.monotonic(), err_at=0.0, key=token_key)
    else:
        cache.update(data=result, err_at=time.monotonic(), ok_at=0.0, key=token_key)
    return result


def _network_response(config: WindowsConfig) -> NetworkConfigResponse:
    upstream_proxy = config.upstream_proxy
    return NetworkConfigResponse(
        dns_mode=config.dns_mode if hasattr(config, "dns_mode") else "auto",
        dns_custom=config.dns_custom if hasattr(config, "dns_custom") else "",
        edge_address=config.edge_address if hasattr(config, "edge_address") else "",
        socks_bind_address=config.listen_host,
        socks_port=config.listen_port,
        http_proxy_enabled=config.http_proxy_enabled,
        http_proxy_port=config.http_proxy_port,
        mtu=config.mtu,
        tunnel_dns_provider=config.tunnel_dns_provider,
        custom_tunnel_doh_url=config.custom_tunnel_doh_url,
        resolver_dns_provider=config.resolver_dns_provider,
        custom_resolver_ip=config.custom_resolver_ip,
        upstream_proxy_enabled=config.upstream_proxy_enabled,
        tls_split_mode=config.tls_split_mode,
        excluded_apps=list(config.excluded_apps),
        custom_edge_address=config.edge_address,
        upstream_proxy_host=upstream_proxy.host if upstream_proxy else "",
        upstream_proxy_port=upstream_proxy.port if upstream_proxy else 0,
        upstream_proxy_type=upstream_proxy.type if upstream_proxy else "socks5",
        upstream_proxy_username=upstream_proxy.username if upstream_proxy else "",
        proxy_only_mode=config.proxy_only_mode,
        latency_probe_url=config.latency_probe_url,
        ip_mode=config.ip_mode,
        bootstrap_dns_provider=config.bootstrap_dns_provider,
        custom_bootstrap_doh_url=config.custom_bootstrap_doh_url,
        relayer_provider=config.relayer_provider,
        custom_relayer_url=config.custom_relayer_url,
        relayed_endpoints=list(config.relayed_endpoints),
        bypass_local_network=config.bypass_local_network,
        local_proxy_auth_enabled=config.local_proxy_auth_enabled,
        local_proxy_username=config.local_proxy_username,
        transport_version=config.transport_version,
        multiplex_streams=config.multiplex_streams,
        utls_fingerprint=config.utls_fingerprint,
        tls_fragment_mode=config.tls_fragment_mode,
        tls_fragment_fallback_delay_ms=config.tls_fragment_fallback_delay_ms,
        always_on=config.always_on,
        kill_switch=config.kill_switch,
        automatic_recovery=config.automatic_recovery,
        update_checks=config.update_checks,
    )


@app.get("/api/network", response_model=NetworkConfigResponse)
async def get_network_config() -> NetworkConfigResponse:
    """Get current network configuration (DNS, edge, upstream proxy, proxy-only mode)."""
    return _network_response(get_config())


@app.post("/api/network", response_model=NetworkConfigResponse)
async def set_network_config(config_data: NetworkConfig) -> NetworkConfigResponse:
    """Update network configuration (DNS, edge, upstream proxy, proxy-only mode).

    Note: upstream proxy password cannot be set through the API.
    """
    config = get_config()

    config.dns_mode = config_data.dns_mode
    config.dns_custom = config_data.dns_custom
    config.edge_address = config_data.custom_edge_address or config_data.edge_address
    config.listen_host = config_data.socks_bind_address
    config.listen_port = config_data.socks_port
    config.http_proxy_enabled = config_data.http_proxy_enabled
    config.http_proxy_port = config_data.http_proxy_port
    config.mtu = config_data.mtu
    config.tunnel_dns_provider = config_data.tunnel_dns_provider
    config.custom_tunnel_doh_url = config_data.custom_tunnel_doh_url
    config.resolver_dns_provider = config_data.resolver_dns_provider
    config.custom_resolver_ip = config_data.custom_resolver_ip
    config.upstream_proxy_enabled = config_data.upstream_proxy_enabled
    config.tls_split_mode = config_data.tls_split_mode
    config.excluded_apps = list(config_data.excluded_apps)
    # Upstream v2.0.3 parity settings.
    config.latency_probe_url = config_data.latency_probe_url
    config.ip_mode = config_data.ip_mode
    config.bootstrap_dns_provider = config_data.bootstrap_dns_provider
    config.custom_bootstrap_doh_url = config_data.custom_bootstrap_doh_url
    config.relayer_provider = config_data.relayer_provider
    config.custom_relayer_url = config_data.custom_relayer_url
    config.relayed_endpoints = list(config_data.relayed_endpoints)
    config.bypass_local_network = config_data.bypass_local_network
    config.local_proxy_auth_enabled = config_data.local_proxy_auth_enabled
    if config_data.local_proxy_username:
        config.local_proxy_username = config_data.local_proxy_username
    if config_data.local_proxy_password:
        config.local_proxy_password = config_data.local_proxy_password
    elif not config_data.local_proxy_auth_enabled:
        config.local_proxy_username = ""
        config.local_proxy_password = ""
    config.transport_version = config_data.transport_version
    config.multiplex_streams = config_data.multiplex_streams
    config.utls_fingerprint = config_data.utls_fingerprint
    config.tls_fragment_mode = config_data.tls_fragment_mode
    config.tls_fragment_fallback_delay_ms = config_data.tls_fragment_fallback_delay_ms
    config.always_on = config_data.always_on
    config.kill_switch = config_data.kill_switch
    config.automatic_recovery = config_data.automatic_recovery
    config.update_checks = config_data.update_checks

    if config_data.upstream_proxy_host:
        existing_password = config.upstream_proxy.password if config.upstream_proxy is not None else ""
        password = config_data.upstream_proxy_password or existing_password
        config.upstream_proxy = UpstreamProxyConfig(
            host=config_data.upstream_proxy_host,
            port=config_data.upstream_proxy_port,
            type=config_data.upstream_proxy_type,
            username=config_data.upstream_proxy_username,
            password=password,
        )
    # Disabling upstream proxy chaining preserves the saved endpoint and
    # credentials so they can be re-enabled without re-entering them.

    config.proxy_only_mode = config_data.proxy_only_mode

    save_config(config)

    return _network_response(config)


@app.post("/api/mode")
async def set_connection_mode(request: ConnectionModeRequest) -> dict:
    """Persist — and optionally apply — the connection mode.

    ``proxy`` is the normal SOCKS5 + VPN-upstream mode, ``proxy_only`` is the
    legacy no-upstream mode, and ``tun`` routes the whole system through the
    elevated helper.  Mode changes are transactional: with ``apply`` the
    transition starts immediately, the request waits at most 5 s for an early
    verdict, and /api/status reports readiness while the background switch
    continues.  The SOCKS5 listener never tears down, and a failure leaves the
    previous mode active instead of falsely reporting success.
    """
    global _config
    async with _api_lock:
        await _await_background_shutdown()
        config = load_config()
        mode = request.mode
        opt_in_auto_enabled = False
        if mode == "tun":
            # The UI click is the user's explicit opt-in: it must never be
            # rejected because the config had no prior elevated-terminal
            # opt-in. Record it honestly so the response can say so.
            if not config.tun_opt_in:
                config.tun_opt_in = True
                opt_in_auto_enabled = True
            config.tun_enabled = True
            config.proxy_only_mode = False
            ok, prereq_error = await _run_in_api_pool(
                _check_tun_prerequisites, config
            )
            if not ok:
                raise HTTPException(status_code=400, detail=prereq_error)
        elif mode == "proxy":
            config.tun_enabled = False
            config.proxy_only_mode = False
        else:
            config.tun_enabled = False
            config.proxy_only_mode = True
        save_config(config)
        _config = config
        # Keep the idle app's view in lockstep with the persisted selection.
        # Otherwise /api/mode would answer from the app's pre-selection config
        # (e.g. selected="tun") and the UI would snap back to the old mode.
        app_config = getattr(_app, "config", None)
        if app_config is not None:
            app_config.tun_enabled = config.tun_enabled
            app_config.proxy_only_mode = config.proxy_only_mode
            app_config.tun_opt_in = config.tun_opt_in
    result = {
        "success": True,
        "mode": mode,
        "proxy_only_mode": config.proxy_only_mode,
        "tun_enabled": config.tun_enabled,
        "tun_opt_in": config.tun_opt_in,
        "tun_opt_in_auto_enabled": opt_in_auto_enabled,
        "applied": False,
        "detail": "Connection mode saved; restarting to apply",
    }
    can_apply = (
        _app is not None
        and callable(getattr(_app, "apply_mode", None))
        and _app_can_apply_mode(_app)
    )
    if request.apply and mode in ("proxy", "tun") and not can_apply:
        # Idle boot: persist the selection only.  Applying here would either
        # fail (no SOCKS listener) or start TUN before an explicit Connect.
        result["detail"] = "Connection mode saved; press Connect to apply"
        mode_payload = getattr(_app, "mode_payload", None)
        if callable(mode_payload):
            result["modes"] = mode_payload()
    if request.apply and mode in ("proxy", "tun") and can_apply:
        target = "tun" if mode == "tun" else "proxy"
        begin = getattr(_app, "begin_mode_apply", None)
        if callable(begin):
            # Never hold the HTTP request for the full multi-minute engine
            # startup: wait at most 5 s for an early verdict, then let
            # /api/status report the background transition.
            payload = await begin(target)
        else:
            payload = await _app.apply_mode(target)
        transition = payload.get("transition") or {}
        state = transition.get("state")
        result["applied"] = state == "complete"
        result["started"] = callable(begin) and state not in ("complete", "failed")
        result["modes"] = payload
        result["success"] = state != "failed"
        result["detail"] = transition.get("detail") or (
            "Connection mode applied" if result["applied"] else "Mode switch started"
        )
        result["active"] = payload.get("active")
    # Mode changes (saved or applied) are a state transition: push a fresh
    # frame so a connected UI updates without waiting for its poll.
    await broadcast_status()
    return result


def _check_tun_prerequisites(config: WindowsConfig) -> tuple[bool, str]:
    """Fail-closed read-only sanity gate before applying TUN mode.

    The user's mode click is the opt-in itself, so ``tun_opt_in`` is never
    a refusal reason here (the caller sets it).  This gate only verifies
    that activation is technically possible: the sing-box sidecar
    (resolved from config/PATH), wintun.dll next to it, and an elevation
    path (UAC helper on a non-elevated GUI).
    """
    try:
        from .tun_frontend import TunFrontend

        frontend = TunFrontend(
            enabled=True,
            opt_in=True,
            executable_path=resolve_tun_executable(config.tun_executable_path),
            proxy_host="127.0.0.1",
            proxy_port=config.listen_port,
            mtu=config.tun_mtu,
            extra_args=config.tun_extra_args,
        )
        frontend._resolve_executable()
    except (ValueError, OSError) as exc:
        return False, f"TUN sidecar not ready: {exc}"
    if not frontend.is_elevated():
        from .tun_helper import helper_supported

        if not helper_supported():
            return False, (
                "TUN mode requires an elevated (admin) process; restart the app "
                "elevated after opting in"
            )
        # A non-elevated GUI can still use TUN through the UAC helper; the
        # helper performs the privileged adapter/route work.
    return True, ""


# GitHub release checking (upstream v2.0.3 ``AppUpdater`` parity). The Windows
# client tracks its own release repository for tags.
UPDATE_CHECK_REPO = "daniboylfc/perchvpn-windows"
UPDATE_CHECK_TIMEOUT_SECONDS = 10.0


def _parse_version_parts(value: str) -> Optional[tuple[int, ...]]:
    parts: list[int] = []
    for chunk in str(value).strip().lstrip("v").split("."):
        if not chunk.isdigit():
            return None
        parts.append(int(chunk))
    return tuple(parts) if parts else None


def is_newer_version(tag: str, current_version: str) -> bool:
    """Mirror the Android client's ``isNewerVersion`` compare (x.y.z)."""
    tag_parts = _parse_version_parts(tag)
    current_parts = _parse_version_parts(current_version)
    if tag_parts is None or current_parts is None:
        return False
    width = max(len(tag_parts), len(current_parts))
    tag_parts += (0,) * (width - len(tag_parts))
    current_parts += (0,) * (width - len(current_parts))
    return tag_parts > current_parts


def _fetch_latest_release() -> dict:
    import json as _json
    import urllib.request

    url = f"https://api.github.com/repos/{UPDATE_CHECK_REPO}/releases/latest"
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/vnd.github+json"},
    )
    with urllib.request.urlopen(request, timeout=UPDATE_CHECK_TIMEOUT_SECONDS) as resp:
        payload = _json.loads(resp.read().decode("utf-8"))
    tag = str(payload.get("tag_name", "")).strip()
    if not tag:
        raise ValueError("release payload has no tag_name")
    return {
        "tag": tag,
        "name": payload.get("name", ""),
        "url": payload.get(
            "html_url", f"https://github.com/{UPDATE_CHECK_REPO}/releases/tag/{tag}"
        ),
        "body": payload.get("body", ""),
    }


class RelayerTestRequest(BaseModel):
    """Body of the Network panel's "Test latency" action."""
    provider: str = Field(default="automatic")
    custom_url: str = Field(default="")
    routed_endpoints: list[str] = Field(default_factory=list)

    @field_validator("provider")
    @classmethod
    def validate_provider(cls, v: str) -> str:
        if v not in (RELAYER_PROVIDERS + ("cloudflare", "vercel")):
            raise ValueError("invalid relayer provider")
        return v


@app.post("/api/network/relayer/test")
async def test_relayer_latency(request: RelayerTestRequest) -> dict:
    """Measure real round-trip RTT to the selected relayer endpoint(s)."""
    from perchvpn import relayer as relayer_module

    try:
        results = await _run_in_api_pool(
            relayer_module.measure_relayer_rtt,
            request.provider,
            request.custom_url,
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"relayer test failed: {exc}")
    return {
        "provider": request.provider,
        "custom_url": request.custom_url,
        "routed_endpoints": request.routed_endpoints,
        "results": results,
    }


@app.get("/api/updates/check")
async def check_updates() -> dict:
    """Check GitHub for a newer upstream release (manual or automatic)."""
    from . import __version__ as app_version

    try:
        release = await _run_in_api_pool(_fetch_latest_release)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"update check failed: {exc}")
    return {
        "current_version": app_version,
        "latest_tag": release["tag"],
        "release_name": release["name"],
        "release_url": release["url"],
        "release_notes": release["body"],
        "update_available": is_newer_version(release["tag"], app_version),
    }


@app.get("/api/latency")
async def get_latency(host: str, port: int = 2499) -> dict:
    """Measure a TCP connection to a VPN edge host, like the Android client.

    Security: resolve once, validate every returned address, then connect to
    the validated IP literal (not the hostname). This prevents SSRF through
    private/loopback/link-local/unspecified/multicast/reserved addresses and
    DNS-rebinding / TOCTOU).
    """
    import asyncio
    import ipaddress
    import socket
    from typing import Optional

    loop = asyncio.get_running_loop()

    try:
        infos = await loop.getaddrinfo(
            host,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=504, detail=f"Latency probe failed: {exc}")

    if not infos:
        raise HTTPException(
            status_code=504,
            detail="Latency probe failed: no globally routable address found",
        )

    expected_version = {socket.AF_INET: 4, socket.AF_INET6: 6}
    selected: Optional[tuple[int, str]] = None

    for family, _type, _proto, _canon, sockaddr in infos:
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            continue

        if family not in expected_version or expected_version[family] != ip.version:
            raise HTTPException(
                status_code=504,
                detail=f"Latency probe failed: address family mismatch (got {ip})",
            )

        # Reject anything that is not a globally routable unicast address.
        # One prohibited answer poisons the hostname: a rebinding resolver
        # could otherwise swap in a private target between check and connect.
        if (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
            or ip.is_unspecified
            or ip.is_multicast
            or ip.is_reserved
            or not ip.is_global
        ):
            raise HTTPException(
                status_code=504,
                detail=f"Latency probe failed: no globally routable address found (got {ip})",
            )

        if selected is None:
            selected = (family, str(ip))

    if selected is None:
        raise HTTPException(
            status_code=504,
            detail="Latency probe failed: no globally routable address found",
        )

    family, validated_ip = selected
    target = (
        (validated_ip, port)
        if family == socket.AF_INET
        else (validated_ip, port, 0, 0)
    )

    start = loop.time()
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.setblocking(False)
    try:
        await asyncio.wait_for(loop.sock_connect(sock, target), timeout=2.0)
        elapsed_ms = int((loop.time() - start) * 1000)
        return {"host": host, "port": port, "latency_ms": elapsed_ms}
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=504, detail=f"Latency probe failed: {exc}")
    finally:
        sock.close()


@app.post("/api/url-ping")
async def url_ping(request: UrlPingRequest) -> dict:
    """Measure realtime reachability + time-to-first-byte for one HTTP(S) URL.

    Surgical probe: streamed GET that measures until the response headers
    arrive and then closes — no body download, no state changes.  With
    ``via_proxy=True`` the request is routed through this instance's local
    SOCKS5 proxy (loopback only), so the number reflects the active
    VPN/proxy egress rather than the local network.
    """
    import asyncio
    import httpx
    from urllib.parse import urlsplit

    parsed = urlsplit(request.url)
    if (parsed.scheme or "").lower() not in ("http", "https") or not parsed.hostname:
        raise HTTPException(
            status_code=400,
            detail="URL must be an absolute http(s) URL with a hostname",
        )

    proxy_url = None
    if request.via_proxy:
        if _app is None or _app._frontend is None:
            raise HTTPException(status_code=409, detail="Local proxy is not running")
        config = get_config()
        bind_host = config.listen_host
        if bind_host in ("0.0.0.0", "::", "*"):
            bind_host = "127.0.0.1"
        proxy_url = f"socks5://{bind_host}:{config.listen_port}"

    loop = asyncio.get_running_loop()
    start = loop.time()
    client_kwargs: dict = {
        "timeout": httpx.Timeout(3.0),
        "follow_redirects": False,
    }
    if proxy_url:
        client_kwargs["proxy"] = proxy_url
    try:
        async with httpx.AsyncClient(**client_kwargs) as client:
            async with client.stream("GET", request.url) as resp:
                elapsed_ms = int((loop.time() - start) * 1000)
                return {
                    "url": request.url,
                    "status_code": resp.status_code,
                    "elapsed_ms": elapsed_ms,
                    "via_proxy": request.via_proxy,
                    "success": True,
                }
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=504, detail=f"URL ping failed: {exc}")


# One Guardian proxy pass is enough for every per-city URL test: the H2
# CONNECT carries the account's pass as bearer auth. Cache it briefly so a
# country-list refresh cycle does not hammer the guardian endpoint per city.
# A failed pass fetch is negative-cached briefly as well: without it, every
# signed-out / rejected-token probe (one per country row per cycle) retried
# the Guardian call, slowing the lists and plastering the same error on
# every row.
_urltest_pass_cache: dict = {"token": None, "at": 0.0, "ttl": 0.0}
_URLTEST_PASS_TTL_SECONDS = 60.0
_URLTEST_PASS_EXPIRY_MARGIN_SECONDS = 10.0
_URLTEST_FAIL_TTL_SECONDS = 30.0

# Classic lightweight URL-test targets (HTTP 204/200, tiny response),
# resolved server-side by each relay — the local machine never touches DNS
# for them. The primary target is gstatic; the Cloudflare equivalent is a
# fallback for networks/relays that block it.
_URLTEST_HOST = "www.gstatic.com"
_URLTEST_PORT = 80
_URLTEST_FALLBACK_HOST = "cp.cloudflare.com"
_URLTEST_REQUEST_TEMPLATE = (
    b"GET /generate_204 HTTP/1.1\r\n"
    b"Host: %b\r\n"
    b"User-Agent: perchvpn-urltest\r\n"
    b"Accept: */*\r\n"
    b"Connection: keep-alive\r\n"
    b"\r\n"
)


def _urltest_request_for(host: str) -> bytes:
    """Keep-alive HTTP/1.1 /generate_204 request for one URL-test target.

    ``Connection: keep-alive`` is what makes the two-stage measurement
    possible: the same tunneled TCP connection established during the
    (untimed) warm-up request carries the (timed) surgical RTT request.
    """
    return _URLTEST_REQUEST_TEMPLATE % (host.encode("ascii"),)


def _get_urltest_raw_token() -> str:
    """Surgical diagnostic token for per-city URL tests.

    Reuses the live controller's proxy pass when a tunnel is up — zero extra
    guardian calls — and otherwise fetches one fresh pass for the account,
    cached across the countries-list probe cycle. The cache TTL honours the
    pass's own remaining validity (with a safety margin), so a long-lived
    pass is reused for its whole life while a short-lived pass still
    refreshes on time. A failed fetch is negative-cached for a short TTL so
    a full probe cycle cannot hammer the guardian endpoint with one request
    per country row.
    """
    global _urltest_pass_cache
    now = time.monotonic()
    cached = _urltest_pass_cache.get("token")
    ttl = _urltest_pass_cache.get("ttl") or _URLTEST_PASS_TTL_SECONDS
    if cached and (now - _urltest_pass_cache.get("at", 0.0)) < ttl:
        diagnostics.emit("DEBUG", "guardian", "proxy-pass", "reuse",
                         outcome="cache_hit", detail="pass reused within TTL")
        return cached
    fail_at = _urltest_pass_cache.get("fail_at", 0.0)
    if fail_at and (now - fail_at) < _URLTEST_FAIL_TTL_SECONDS:
        raise HTTPException(
            status_code=_urltest_pass_cache.get("fail_status", 502),
            detail=_urltest_pass_cache.get("fail_detail") or "URL test proxy pass unavailable",
        )
    if _app is not None and _app._controller is not None:
        proxy_pass = getattr(_app._controller, "proxy_pass", None)
        raw = getattr(proxy_pass, "raw_token", None)
        if raw:
            _urltest_pass_cache = {
                "token": raw,
                "at": now,
                "ttl": _pass_ttl_seconds(getattr(proxy_pass, "expires_at", None)),
            }
            return raw
    if _app is None:
        raise HTTPException(status_code=503, detail="Application not initialized")
    runtime_auth = getattr(_app, "_runtime_auth", None)
    if runtime_auth is None or not getattr(runtime_auth, "access_token", None):
        raise HTTPException(status_code=503, detail="Not signed in")

    def _remember_failure(status: int, detail: str) -> None:
        """Negative-cache the failure without discarding any positive cache."""
        global _urltest_pass_cache
        _urltest_pass_cache = dict(_urltest_pass_cache, fail_at=now, fail_status=status, fail_detail=detail)
        diagnostics.emit("WARN", "guardian", "proxy-pass", "fetch_failed",
                         outcome=f"http_{status}", detail=detail)

    from perchvpn import guardian
    from perchvpn.exceptions import TokenInvalidError
    from datetime import datetime, timezone

    def _pass_expiry_seconds() -> float:
        try:
            remaining = pass_info.expires_at() - datetime.now(timezone.utc)
            return max(remaining.total_seconds(), 0.0)
        except Exception:  # noqa: BLE001
            return -1.0

    config = get_config()
    try:
        pass_info = guardian.fetch_proxy_pass(
            config.guardian_endpoint, runtime_auth.access_token
        )
    except TokenInvalidError as exc:
        # Rejected/stale session token: this is an authentication problem,
        # not a missing VPN pass. Reporting it as "Not signed in" (401) keeps
        # the frontend from showing a misleading "No pass" on every row.
        _remember_failure(
            401,
            "Not signed in: the stored access token was rejected by Guardian; sign in again",
        )
        raise HTTPException(
            status_code=401,
            detail=_urltest_pass_cache.get("fail_detail"),
        ) from exc
    except Exception as exc:  # noqa: BLE001
        _remember_failure(
            502,
            f"URL test proxy pass unavailable: {exc}",
        )
        raise HTTPException(
            status_code=502, detail=_urltest_pass_cache.get("fail_detail")
        )
    _urltest_pass_cache = {
        "token": pass_info.raw_token,
        "at": now,
        "ttl": _pass_ttl_seconds(getattr(pass_info, "expires_at", None)),
    }
    diagnostics.emit(
        "INFO", "guardian", "proxy-pass", "acquired",
        outcome="ok",
        detail=f"pass expires in {_pass_expiry_seconds() / 60.0:.0f}m"
        if _pass_expiry_seconds() >= 0 else "pass expiry unknown",
        duration_ms=(time.monotonic() - now) * 1000.0,
    )
    return pass_info.raw_token


def _pass_ttl_seconds(expires_at_fn) -> float:
    """Effective cache TTL for one proxy pass.

    ``expires_at`` is a callable returning an aware datetime (or None when
    the pass carries no usable expiry). Cache for the pass's own remaining
    validity minus a safety margin, clamped to the guard-band TTL; unknown
    expiry falls back to the guard-band TTL.
    """
    from datetime import datetime, timezone

    if not callable(expires_at_fn):
        return _URLTEST_PASS_TTL_SECONDS
    try:
        remaining = expires_at_fn() - datetime.now(timezone.utc)
        seconds = remaining.total_seconds() - _URLTEST_PASS_EXPIRY_MARGIN_SECONDS
    except Exception:  # noqa: BLE001
        return _URLTEST_PASS_TTL_SECONDS
    if seconds <= 0:
        # Essentially expired pass: cache just long enough for one cycle.
        return 2.0
    return min(max(seconds, 2.0), _URLTEST_PASS_TTL_SECONDS)


@app.get("/api/urltest")
async def get_urltest(host: str, port: int, timeout: float = 6.0) -> dict:
    """Unified-delay style per-node URL test: measure the surgical RTT of a
    small test URL fetched *through* one city's edge relay.

    Two-stage handshake-debiased measurement (mihomo ``unified-delay``
    architecture) over a persistent keyed H2 session:

    * **Stage 1 (untimed warm-up):** establish the authenticated H2 session
      to that city's edge, open the CONNECT tunnel to the URL-test target
      (relay-side DNS — no local DNS traffic) and issue one untimed
      ``/generate_204`` request so the end-to-end keep-alive path — proxy
      pass auth, relay acceptance, tunneled TCP handshake, first HTTP
      exchange — is fully established. **Stage 0 (cached):** the Guardian
      proxy pass itself is cached in memory for its valid TTL, so pass
      minting latency never lands inside a country's ping.
    * **Stage 2 (surgical timed RTT):** over the warm keep-alive connection,
      ``t0 = time.perf_counter()`` immediately before the lightweight
      ``/generate_204`` request is written and ``t1`` as soon as the
      ``204``/``200`` status response arrives; the reported delay is
      ``latency_ms = max(1, round((t1 - t0) * 1000))`` — control-plane and
      cold-handshake overhead excluded, cold_ms reported for diagnostics.

    No TUN/adapter/route state is touched and the throwaway session is
    always closed. If the primary target (gstatic) fails end-to-end, the
    Cloudflare ``/generate_204`` equivalent is probed once as a fallback.

    Failure surfaces as HTTP 504; the frontend's existing pinging/country
    order scheduler (bounded in-flight batches, TTL cache, sink
    Unavailable) consumes it.
    """
    host = (host or "").strip()
    if not host or port <= 0 or port > 65535:
        raise HTTPException(status_code=400, detail="host and a valid port are required")

    app_inst = get_app()
    config = get_config()
    # Pass acquisition can make its own Guardian HTTP call.  Keep it off the
    # ASGI event loop so a burst of country-row probes and /api/status polls
    # do not serialize behind pass minting.
    raw_token = await _run_in_urltest_pool(_get_urltest_raw_token)

    from perchvpn.exceptions import ProxyError
    from perchvpn.proxy.session import H2ProxySession

    loop = asyncio.get_event_loop()
    grant = min(max(timeout, 1.0), 8.0)
    connect_started = loop.time()

    async def _read_response_headers(stream) -> int:
        """Read one full HTTP/1.1 response from the tunneled stream.

        Accumulates until the header block is complete (so the keep-alive
        connection stays aligned), validates a 204/200 success status and
        drains any body bytes announced by content-length. Returns the
        status code.
        """
        status = None
        content_length = 0
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = await stream.read()
            if not chunk:
                raise ProxyError("empty test response")
            buf += chunk
            if status is None:
                line = buf.split(b"\r\n", 1)[0]
                parts = line.split()
                if len(parts) >= 2 and parts[0].startswith(b"HTTP/"):
                    status = int(parts[1])
        if status is None:
            raise ProxyError("malformed test response")
        for header in buf.split(b"\r\n\r\n", 1)[0].split(b"\r\n")[1:]:
            name, _, value = header.partition(b":")
            if name.strip().lower() == b"content-length":
                try:
                    content_length = int(value.strip())
                except ValueError:
                    content_length = 0
        remaining = content_length - (len(buf) - buf.index(b"\r\n\r\n") - 4)
        while remaining > 0:
            chunk = await stream.read()
            if not chunk:
                break
            remaining -= len(chunk)
        if status not in (204,):
            if status != 200 or content_length > 0:
                raise ProxyError(f"unexpected test status HTTP {status}")
        return status

    async def _probe(target_host: str) -> tuple[int, int, int]:
        """Warm a fresh session/tunnel for ``target_host`` and time one RTT.

        Returns ``(relay_connect_ms, cold_ms, latency_ms)`` where cold_ms
        covers the full Stage-1 establishment (session handshake, CONNECT
        tunnel and warm-up exchange) and latency_ms is the Stage-2 timed
        round trip on the warm keep-alive connection.
        """
        session = H2ProxySession(
            host,
            port,
            raw_token,
            upstream_proxy=config.upstream_proxy if config.upstream_proxy_enabled else None,
            source_bind_ip=getattr(app_inst, "_source_bind_ip", None),
        )
        try:
            await session.connect(timeout=grant)
            stream = await session.open_stream(target_host, _URLTEST_PORT)
            connect_ms = int((loop.time() - connect_started) * 1000)

            warm_started = time.perf_counter()
            await stream.write(_urltest_request_for(target_host))
            await _read_response_headers(stream)
            cold_ms = max(0, round((time.perf_counter() - warm_started) * 1000))

            t0 = time.perf_counter()
            await stream.write(_urltest_request_for(target_host))
            await _read_response_headers(stream)
            latency_ms = max(1, round((time.perf_counter() - t0) * 1000))
            return connect_ms, cold_ms, latency_ms
        finally:
            await session.close()

    for index, target in enumerate((_URLTEST_HOST, _URLTEST_FALLBACK_HOST)):
        connect_started = loop.time()
        try:
            connect_ms, cold_ms, latency_ms = await asyncio.wait_for(
                _probe(target), grant + 2.0
            )
            diagnostics.emit(
                "DEBUG", "urltest", "probe", "complete",
                outcome="ok", duration_ms=float(latency_ms),
                detail=(
                    f"relay={host}:{port} target={target} "
                    f"cold={cold_ms}ms latency={latency_ms}ms"
                ),
                corr_id=f"probe-{host}:{port}",
            )
            return {
                "host": host,
                "port": port,
                "target": target,
                "connect_ms": connect_ms,
                "cold_ms": cold_ms,
                "latency_ms": latency_ms,
                "elapsed_ms": latency_ms,  # legacy field: same value
                "success": True,
            }
        except asyncio.TimeoutError:
            elapsed_ms = int((loop.time() - connect_started) * 1000)
            diagnostics.emit(
                "WARN", "urltest", "probe", "failed",
                outcome="timeout", duration_ms=float(elapsed_ms),
                detail=f"relay={host}:{port} target={target} timed out",
                corr_id=f"probe-{host}:{port}",
            )
            if index == 1:
                raise HTTPException(
                    status_code=504,
                    detail=f"URL test timed out after {int(elapsed_ms)} ms",
                )
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            diagnostics.emit(
                "WARN", "urltest", "probe", "failed",
                outcome="error", duration_ms=(loop.time() - connect_started) * 1000.0,
                detail=f"relay={host}:{port} target={target}: {exc}",
                corr_id=f"probe-{host}:{port}",
            )
            if index == 1:
                raise HTTPException(status_code=504, detail=f"URL test failed: {exc}")


@app.post("/api/disconnect")
async def disconnect() -> dict:
    """Gracefully disconnect the VPN: stop controller and SOCKS frontend."""
    global _app, _restart_task, _bg_shutdown_task
    if _restart_task is not None and not _restart_task.done():
        _restart_task.cancel()
        # The button must always answer: bound the wait for in-flight
        # initialization teardown instead of letting a slow/cleanup-heavy
        # restart task hold the request until the frontend's 60s abort.
        # A bounded poll rather than wait_for(shield(...)): the task's own
        # CancelledError must never be mistaken for this endpoint's
        # cancellation.
        deadline = asyncio.get_running_loop().time() + 5.0
        while not _restart_task.done() and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.05)
        _restart_task = None
    async with _api_lock:
        await _await_background_shutdown()
        if _app is None:
            return {"success": True, "detail": "Not connected"}
        shutdown_task = asyncio.ensure_future(_app.shutdown())
        try:
            await asyncio.wait_for(
                asyncio.shield(shutdown_task),
                timeout=_DISCONNECT_HTTP_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            # Teardown (elevated helper + recovery verification) can exceed
            # any sensible HTTP budget.  Keep the UI responsive: report the
            # request and let cleanup finish in the background; the next
            # connect/restart waits for it before building a new app.
            _bg_shutdown_task = shutdown_task
            logger.warning(
                "disconnect: teardown exceeded %.1fs; continuing in the background",
                _DISCONNECT_HTTP_TIMEOUT_SECONDS,
            )
            await broadcast_status()
            return {
                "success": True,
                "detail": "Disconnect requested; cleanup is finishing in the background",
            }
        except RuntimeError as exc:
            raise HTTPException(
                status_code=500,
                detail=f"VPN disconnect failed: {exc}",
            ) from exc
        await broadcast_status()
        return {"success": True, "detail": "Disconnected"}


def get_app() -> PerchVPNApp:
    if _app is None:
        raise HTTPException(status_code=503, detail="Application not initialized")
    _attach_status_notifier(_app)
    return _app


@app.post("/api/restart")
async def restart(request: Optional[ConnectRequest] = None) -> dict:
    """Start a VPN restart without blocking the caller (one click, one op).

    The optional payload carries the user's selected ``mode`` so Connect can
    never fall back to a stale TUN flag.  The heavyweight stop/re-init work
    runs in the background while the API stays responsive; ``/api/status``
    reflects progress honestly ("connecting" until initialization finishes).
    Concurrent restarts are refused with 409.
    """
    global _restart_task, _config
    if _restart_task is not None and not _restart_task.done():
        raise HTTPException(
            status_code=409,
            detail="A restart is already in progress; wait for it to finish",
        )
    # Fast synchronous signed-out check before spawning any work (a
    # signed-out boot stays disconnected until the user signs in).
    if (
        _app is not None
        and (
            getattr(_app, "_signed_out_boot", False)
            or getattr(_app, "_boot_idle", False)
        )
        and getattr(_app, "_runtime_auth", None) is None
        and tokens_module.load_tokens(get_token_path()) is None
    ):
        raise HTTPException(
            status_code=409,
            detail="Not signed in: sign in first, then connect",
        )
    mode = request.mode if request is not None else None
    if mode is not None:
        config = load_config()
        if mode == "tun":
            if not config.tun_opt_in:
                config.tun_opt_in = True
            ok, prereq_error = await _run_in_api_pool(
                _check_tun_prerequisites, config
            )
            if not ok:
                raise HTTPException(status_code=400, detail=prereq_error)
        _apply_mode_flags(config, mode)
        save_config(config)
        _config = config
    _restart_task = asyncio.create_task(_restart_worker(mode))
    # Push the "connecting" transition immediately instead of waiting for
    # the monitor tick or the frontend's 2 s poll.
    await broadcast_status()
    return {"success": True, "detail": "Restart started; connection status updates via /api/status"}


async def _restart_worker(mode: Optional[str] = None) -> None:
    """Stop the VPN and re-initialize with current config (background).

    Country changes persisted via /api/country take effect.  ``mode`` is
    re-applied under the lock so the fresh app cannot pick up a stale flag.

    If initialization fails, ``_app`` and ``/api/status`` are left in a
    coherent disconnected state and the API server remains available for
    a subsequent retry. Raises so awaited tests can assert exact failures.
    """
    global _app, _config
    async with _api_lock:
        await _await_background_shutdown()
        if _app is not None:
            # /api/disconnect cancels this task to keep the button
            # responsive, and the cancellation must never land inside a
            # half-finished old-app teardown: an interrupted recovery
            # verification wedges the frontend (ownership record intact,
            # stale tunnel state) so every later disconnect/restart fails.
            # Shield the teardown and honour the cancellation afterwards.
            shutdown_task = asyncio.ensure_future(_app.shutdown())
            try:
                await asyncio.shield(shutdown_task)
            except asyncio.CancelledError:
                try:
                    await shutdown_task
                except RuntimeError as exc:
                    raise HTTPException(
                        status_code=500,
                        detail=f"VPN restart failed; old shutdown error: {exc}",
                    ) from exc
                raise
            except RuntimeError as exc:
                # Old-app shutdown failed — retain it as the recovery owner
                # and do not initialize a replacement, unless the requested
                # mode does not own the tunnel at all.  A proxy-only restart
                # cannot race a residual TUN adapter, so refusing it turned a
                # single unverified TUN teardown into a lockout of *both*
                # modes until the process was killed.
                requested = mode
                if requested is None:
                    try:
                        requested = (
                            "proxy_only" if load_config().proxy_only_mode else None
                        )
                    except Exception:  # noqa: BLE001 - treat as unknown
                        requested = None
                if requested != "proxy_only":
                    raise HTTPException(
                        status_code=500,
                        detail=f"VPN restart failed; old shutdown error: {exc}",
                    ) from exc
                logger.warning(
                    "old TUN shutdown did not complete (%s); continuing with a "
                    "proxy-only restart because that mode does not own the tunnel",
                    exc,
                )
        config = load_config()
        if mode is not None:
            _apply_mode_flags(config, mode)
            save_config(config)
        new_app = PerchVPNApp(config)
        try:
            await new_app.initialize()
        except asyncio.CancelledError:
            _retain_failed_app(new_app, config)
            raise
        except InteractiveLoginRequired:
            # Signed-out user hitting Connect: keep the app disconnected and
            # tell the GUI to sign in first (inventory-safe retry).
            if not _retain_failed_app(new_app, config):
                _app = None
            raise HTTPException(
                status_code=409,
                detail="Not signed in: sign in first, then connect",
            )
        except TokenInvalidError as exc:
            # A persisted session can still be rejected by Guardian after it
            # was accepted locally (revoked account, stale FxA session).  The
            # initialization rollback already left new_app disconnected;
            # retain that clean app so /api/account reports "signed out"
            # instead of leaving the UI on an optimistic "connecting" frame
            # or a generic tunnel failure.
            logger.warning(
                "saved Guardian session was rejected; clearing tokens: %s", exc
            )
            try:
                tokens_module.delete_tokens(get_token_path())
            except OSError as delete_exc:  # noqa: BLE001 - sign-out is best effort
                logger.warning("could not delete rejected tokens: %s", delete_exc)
            new_app._runtime_auth = None
            new_app._signed_out_boot = True
            new_app._status_state = "disconnected"
            if not _retain_failed_app(new_app, config):
                _app = new_app
            _config = config
            _attach_status_notifier(new_app)
            await broadcast_status()
            raise HTTPException(
                status_code=409,
                detail=(
                    "Sign-in expired: Guardian rejected the saved session; "
                    "sign in again"
                ),
            ) from exc
        except Exception:
            if not _retain_failed_app(new_app, config):
                _app = None
            raise HTTPException(status_code=500, detail="VPN restart failed; "
                "state is disconnected and safe to retry")
        _app = new_app
        _config = config
        _attach_status_notifier(new_app)
        # Push the settled (connected/proxy_active) transition immediately.
        await broadcast_status()


@app.post("/api/country")
async def set_country(selection: CountrySelection) -> dict:
    """Set the selected country and persist to config."""
    global _app, _config
    async with _api_lock:
        await _await_background_shutdown()
        # Validate country exists (shared server-list snapshot). When the app
        # can hot-swap, a stale snapshot is enough for validation and the
        # request must not block on a network refresh.
        can_hot = callable(getattr(_app, "can_hot_swap", None)) and _app.can_hot_swap()
        countries = await _run_in_api_pool(
            _cached_countries, allow_refresh=not can_hot
        )
        if not countries:
            # Cold snapshot on the hot path: one worker-pool fetch rather
            # than rejecting a valid country or blocking the event loop.
            countries = await _run_in_api_pool(_cached_countries, True)
        country_codes = {c.code.lower(): c.code for c in countries if c.code}

        if selection.country_code.lower() not in country_codes:
            raise HTTPException(status_code=400, detail=f"Invalid country code: {selection.country_code}")

        # Case 1: No existing app — create fresh with new country
        if _app is None:
            config = load_config()
            config.country = country_codes[selection.country_code.lower()]
            save_config(config)
            new_app = PerchVPNApp(config)
            try:
                await new_app.initialize()
            except asyncio.CancelledError:
                _retain_failed_app(new_app, config)
                raise
            except Exception:
                if not _retain_failed_app(new_app, config):
                    _app = None
                raise HTTPException(status_code=500, detail="VPN country change failed; "
                    "state is disconnected and safe to retry")
            _app = new_app
            _config = config
            _attach_status_notifier(new_app)
            await broadcast_status()
            return {"success": True, "detail": f"Country set to {config.country}"}

        # Case 2: Live components — hot-swap the upstream only. The listener
        # (and TUN forwarding to it) keeps serving throughout, so the call
        # returns immediately with a switch id to poll via /api/status.
        if _app is not None:
            hot_swap = getattr(_app, "can_hot_swap", None)
            if callable(hot_swap) and hot_swap():
                target = country_codes[selection.country_code.lower()]
                result = _app.begin_country_switch(target, countries=countries)
                _config = _app.config
                return {
                    "success": True,
                    "detail": f"Switching to {target}",
                    **result,
                }

        # Idle boot: selecting a country must not dial just because the app
        # object exists.  Persist the choice; Connect applies it.
        connected_check = getattr(_app, "is_connected", None)
        if callable(connected_check) and not connected_check():
            config = load_config()
            config.country = country_codes[selection.country_code.lower()]
            save_config(config)
            _config = config
            _app.config = config
            return {
                "success": True,
                "detail": f"Country set to {config.country}; press Connect to apply",
            }

        # Case 3: Existing app without live components — full restart.
        try:
            await _app.shutdown()
        except RuntimeError as exc:
            # Old-app shutdown failed — retain it as the recovery owner and
            # do not initialize a replacement.
            raise HTTPException(
                status_code=500,
                detail=f"VPN country change failed; old shutdown error: {exc}",
            ) from exc

        # Old-app shutdown succeeded — now save the new country config
        config = load_config()
        config.country = country_codes[selection.country_code.lower()]
        save_config(config)

        # Create and initialize new app with selected country
        new_app = PerchVPNApp(config)
        try:
            await new_app.initialize()
        except asyncio.CancelledError:
            _retain_failed_app(new_app, config)
            raise
        except Exception:
            if not _retain_failed_app(new_app, config):
                _app = None
            raise HTTPException(status_code=500, detail="VPN country change failed; "
                "state is disconnected and safe to retry")
        _app = new_app
        _config = config
        _attach_status_notifier(new_app)
        await broadcast_status()
        return {"success": True, "detail": f"Country set to {config.country}"}


def get_config() -> WindowsConfig:
    if _config is None:
        raise HTTPException(status_code=503, detail="Configuration not initialized")
    return _config


# Log streaming support
_log_websockets: set[WebSocket] = set()


async def broadcast_log(message: str) -> None:
    """Broadcast log message to all connected WebSocket clients."""
    dead: list[WebSocket] = []
    for ws in list(_log_websockets):
        try:
            await ws.send_text(message)
        except Exception:
            dead.append(ws)
    for ws in dead:
        _log_websockets.discard(ws)


@app.websocket("/ws/logs")
async def websocket_logs(websocket: WebSocket):
    """WebSocket endpoint for real-time log streaming."""
    await websocket.accept()
    _log_websockets.add(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        _log_websockets.discard(websocket)


# Real-time status push --------------------------------------------------
# /ws/status pushes the same payload as /api/status the moment a state
# transition happens (connection status, exit verification, tunnel
# readiness, restart/disconnect), instead of waiting for the frontend's
# 2 s poll. A lightweight monitor compares cheap state signatures between
# ticks and sends a full frame only on change (state) or at most 1 Hz
# (traffic counters), so an idle connected dashboard costs near-zero CPU.

_status_websockets: set[WebSocket] = set()
_status_monitor_task: Optional[asyncio.Task] = None
_STATUS_MONITOR_INTERVAL_SECONDS = 1.0
_STATUS_METRICS_PUSH_SECONDS = 1.0
# Last serialized frame. A duplicate transition notification (or a poll
# landing on the same state/metrics) is diffed here and never re-sent to
# every connected client; a fresh client still receives its own snapshot.
_status_last_payload: Optional[str] = None


def _status_state_signature(resp: StatusResponse) -> tuple:
    """Cheap transition fingerprint: everything that must push instantly."""
    tunnel = resp.tunnel if isinstance(resp.tunnel, dict) else {}
    switch = resp.switch if isinstance(resp.switch, dict) else {}
    return (
        resp.status,
        resp.exit_verification_state,
        resp.exit_ip,
        resp.country,
        resp.transport,
        resp.proxy_only_mode,
        resp.tun_frontend,
        resp.session_pool,
        resp.http_proxy_enabled_live,
        tunnel.get("enabled"),
        tunnel.get("state"),
        tunnel.get("detail"),
        tunnel.get("process_alive"),
        switch.get("state"),
    )


def _status_metrics_signature(resp: StatusResponse) -> tuple:
    return (resp.downloaded, resp.uploaded, resp.active_connections)


async def _push_status_frame(resp: StatusResponse, *, force: bool = False) -> None:
    global _status_last_payload
    payload = resp.model_dump_json()
    if not force and payload == _status_last_payload:
        return
    _status_last_payload = payload
    dead: list[WebSocket] = []
    for ws in list(_status_websockets):
        try:
            await ws.send_text(payload)
        except Exception:
            dead.append(ws)
    for ws in dead:
        _status_websockets.discard(ws)


async def broadcast_status() -> None:
    """Push the current status frame to every /ws/status client now.

    Callers invoke this right after they mutate state (restart started,
    disconnect, mode switch) so the UI transitions immediately; the monitor
    loop remains the safety net for transitions detected elsewhere.
    """
    if not _status_websockets:
        return
    try:
        resp = await _build_status_response()
    except Exception:  # noqa: BLE001 - app not ready; poll fallback covers it
        return
    await _push_status_frame(resp)


_status_push_pending = False


def notify_status_changed() -> None:
    """Schedule an immediate /ws/status push from a state-change hook.

    The app calls this from TUN/helper/exit transitions (event-driven)
    instead of waiting up to ``_STATUS_MONITOR_INTERVAL_SECONDS`` for the
    next poll. Coalesces bursts into one frame; the monitor loop stays the
    safety net. Must be called from the API event loop.
    """
    global _status_push_pending
    if _status_push_pending or not _status_websockets:
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    _status_push_pending = True

    async def _push_now() -> None:
        global _status_push_pending
        try:
            await broadcast_status()
        finally:
            _status_push_pending = False

    loop.create_task(_push_now())


async def _status_monitor_loop() -> None:
    """Watch internal state and push /api/status-equivalent frames on change.

    Runs only while at least one /ws/status client is connected; the
    endpoint (re)starts it on the first connection.
    """
    last_state_sig: Optional[tuple] = None
    last_metrics_sig: Optional[tuple] = None
    last_push_at = 0.0
    try:
        while _status_websockets:
            try:
                resp = await _build_status_response()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - app/config not ready yet
                await asyncio.sleep(_STATUS_MONITOR_INTERVAL_SECONDS)
                continue
            state_sig = _status_state_signature(resp)
            metrics_sig = _status_metrics_signature(resp)
            loop = asyncio.get_running_loop()
            now = loop.time()
            state_changed = state_sig != last_state_sig
            metrics_due = (
                metrics_sig != last_metrics_sig
                and (now - last_push_at) >= _STATUS_METRICS_PUSH_SECONDS
            )
            if state_changed or metrics_due:
                await _push_status_frame(resp)
                last_state_sig = state_sig
                last_metrics_sig = metrics_sig
                last_push_at = now
            await asyncio.sleep(_STATUS_MONITOR_INTERVAL_SECONDS)
    except asyncio.CancelledError:
        raise


def _ensure_status_monitor() -> None:
    global _status_monitor_task
    task = _status_monitor_task
    if task is not None and not task.done():
        return
    _status_monitor_task = asyncio.ensure_future(_status_monitor_loop())


async def _stop_status_monitor() -> None:
    global _status_monitor_task
    task = _status_monitor_task
    _status_monitor_task = None
    if task is None or task.done():
        return
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    except Exception:  # noqa: BLE001 - shutdown must never raise through
        pass


@app.websocket("/ws/status")
async def websocket_status(websocket: WebSocket):
    """WebSocket endpoint for immediate status/state frames.

    A new client receives the current snapshot immediately on connect and
    then every transition via the monitor loop; incoming client messages
    are drained and ignored (the stream is server-push only).
    """
    await websocket.accept()
    _status_websockets.add(websocket)
    _ensure_status_monitor()
    try:
        # Immediate snapshot so the UI paints truth before the next tick.
        try:
            resp = await _build_status_response()
            await websocket.send_text(resp.model_dump_json())
        except Exception:  # noqa: BLE001 - app not ready; monitor covers it
            pass
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        _status_websockets.discard(websocket)


# Serve the WebView2 frontend. The web assets live inside the package so
# this works identically in editable checkout, wheel/site-packages
# installation and PyInstaller frozen mode (_MEIPASS).
import os as _os
import sys as _sys

_resolved_dir = getattr(_sys, "_MEIPASS", _os.path.dirname(_os.path.abspath(__file__)))
_web_dir = _os.path.join(_resolved_dir, "web")
_web_dir = _os.path.abspath(_web_dir)
if _os.path.isdir(_web_dir):
    from fastapi.staticfiles import StaticFiles

    class _ImmutableAssets(StaticFiles):
        """Static /assets/* responses with a long-lived immutable cache.

        Country flag SVGs are versioned inside the package build, never
        change at runtime and are re-requested by every country-list
        render. Without cache headers WebView2 revalidates each file on
        every render (round-trip + re-decode), which showed up as slow,
        popping-in flags. Immutable caching lets repeated decodes come
        from the browser's cache with zero network round-trips.
        App pages and scripts (mounted at /) keep the default ETag
        revalidation so updated frontends always replace cache entries.
        """

        async def get_response(self, path: str, scope):  # type: ignore[override]
            response = await super().get_response(path, scope)
            response.headers.setdefault(
                "Cache-Control", "public, max-age=31536000, immutable"
            )
            return response

    _assets_dir = _os.path.join(_web_dir, "assets")
    if _os.path.isdir(_assets_dir):
        app.mount("/assets", _ImmutableAssets(directory=_assets_dir), name="assets")
    app.mount("/", StaticFiles(directory=_web_dir, html=True), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8765, log_level="info")
