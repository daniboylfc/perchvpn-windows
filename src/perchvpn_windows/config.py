"""Windows application configuration model and persistence."""

from __future__ import annotations

import json
import tempfile
import os
import base64
import ctypes
import ctypes.wintypes
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from perchvpn_windows.platform import get_config_dir, get_proxy_state_path, get_status_path, get_token_path, ensure_config_dir


DEFAULT_LISTEN_HOST = "127.0.0.1"
DEFAULT_LISTEN_PORT = 1080
DEFAULT_GUARDIAN_ENDPOINT = "https://vpn.mozilla.org"
DEFAULT_HANDSHAKE_TIMEOUT = 10.0
DEFAULT_UPSTREAM_CONNS = 1
DEFAULT_IDLE_TIMEOUT = 0.0
DEFAULT_MAX_CONNS = 256
DEFAULT_VERIFY_EXIT = True
DEFAULT_MTU = 1400
MIN_MTU = 576
MAX_MTU = 9000
DEFAULT_HTTP_PROXY_PORT = 8080
DEFAULT_LOG_LEVEL = "info"
DEFAULT_LOG_FORMAT = "text"

# Parity constants mirrored from the upstream Android client (v2.0.3).
DEFAULT_LATENCY_PROBE_URL = "https://www.gstatic.com/generate_204"
IP_MODES = (
    "dual_stack",
    "prefer_ipv4",
    "prefer_ipv6",
    "ipv4_only",
    "ipv6_only",
)
DEFAULT_IP_MODE = "dual_stack"
BOOTSTRAP_DNS_PROVIDERS = (
    "automatic",
    "cloudflare",
    "google",
    "quad9",
    "adguard",
    "system",
    "custom",
)
DEFAULT_BOOTSTRAP_DNS_PROVIDER = "automatic"
RELAYER_PROVIDERS = ("automatic", "direct", "cloudflare", "vercel", "custom")
DEFAULT_RELAYER_PROVIDER = "automatic"
DEFAULT_RELAYER_URL = "https://relayer.foxyvpn.workers.dev"
DEFAULT_RELAYED_ENDPOINTS = ("guardian",)
TRANSPORT_VERSIONS = ("h1", "h2", "h3")
DEFAULT_TRANSPORT_VERSION = "h2"
MULTIPLEX_STREAM_CHOICES = (8, 16, 32, 64)
UTLS_FINGERPRINTS = (
    "disabled",
    "chrome",
    "firefox",
    "edge",
    "safari",
    "ios",
    "randomized",
    "random",
)
DEFAULT_UTLS_FINGERPRINT = "disabled"
TLS_FRAGMENT_MODES = ("disabled", "record", "packet", "combined")
DEFAULT_TLS_FRAGMENT_MODE = "disabled"
DEFAULT_TLS_FRAGMENT_FALLBACK_DELAY_MS = 300


@dataclass
class UpstreamProxyConfig:
    """Upstream proxy configuration for H2 transport-level chaining."""
    host: str
    port: int
    type: str = "socks5"  # "socks5" or "http"
    username: str = ""
    password: str = ""

    def __post_init__(self) -> None:
        if self.type not in ("socks5", "http"):
            raise ValueError(f"upstream_proxy.type must be 'socks5' or 'http', got {self.type!r}")
        if not self.host:
            raise ValueError("upstream_proxy.host must not be empty")
        if self.port < 1 or self.port > 65535:
            raise ValueError("upstream_proxy.port must be between 1 and 65535")


@dataclass
class WindowsConfig:
    listen_host: str = DEFAULT_LISTEN_HOST
    listen_port: int = DEFAULT_LISTEN_PORT
    country: Optional[str] = None
    explicit_proxy: Optional[str] = None
    upstream_conns: int = DEFAULT_UPSTREAM_CONNS
    use_http3: bool = False
    handshake_timeout: float = DEFAULT_HANDSHAKE_TIMEOUT
    idle_timeout: float = DEFAULT_IDLE_TIMEOUT
    max_conns: int = DEFAULT_MAX_CONNS
    verify_exit: bool = DEFAULT_VERIFY_EXIT
    mtu: int = DEFAULT_MTU
    tunnel_dns_provider: str = "default"
    custom_tunnel_doh_url: str = ""
    resolver_dns_provider: str = "automatic"
    custom_resolver_ip: str = ""
    http_proxy_enabled: bool = False
    http_proxy_port: int = DEFAULT_HTTP_PROXY_PORT
    upstream_proxy_enabled: bool = False
    tls_split_mode: str = "off"
    excluded_apps: list[str] = field(default_factory=list)
    guardian_endpoint: str = DEFAULT_GUARDIAN_ENDPOINT
    session_token_path: Optional[str] = None
    log_level: str = DEFAULT_LOG_LEVEL
    log_format: str = DEFAULT_LOG_FORMAT
    dashboard: bool = True
    new_window: bool = False
    # Network settings (persisted preferences)
    dns_mode: str = "auto"
    dns_custom: str = ""
    edge_address: str = ""
    # Upstream proxy chaining (H2 transport-level tunnel)
    upstream_proxy: Optional[UpstreamProxyConfig] = None
    # Proxy-only mode: no VPN tunnel, local SOCKS5 only, CONNECT rejected
    proxy_only_mode: bool = False
    # TUN frontend (disabled by default; explicit opt-in required)
    tun_enabled: bool = False
    tun_opt_in: bool = False
    tun_executable_path: str = ""
    tun_mtu: int = DEFAULT_MTU
    tun_extra_args: list[str] = field(default_factory=list)
    # sing-box route_exclude_address entries (IP/CIDR) so upstream server IPs skip the TUN.
    tun_bypass: list[str] = field(default_factory=list)
    # Explicit physical-NIC source address; None = autodetect for TUN, else OS default.
    source_bind_ip: Optional[str] = None

    # Upstream v2.0.3 parity settings.
    latency_probe_url: str = DEFAULT_LATENCY_PROBE_URL
    ip_mode: str = DEFAULT_IP_MODE
    bootstrap_dns_provider: str = DEFAULT_BOOTSTRAP_DNS_PROVIDER
    custom_bootstrap_doh_url: str = ""
    relayer_provider: str = DEFAULT_RELAYER_PROVIDER
    custom_relayer_url: str = ""
    relayed_endpoints: list[str] = field(default_factory=lambda: list(DEFAULT_RELAYED_ENDPOINTS))
    bypass_local_network: bool = True
    local_proxy_auth_enabled: bool = False
    local_proxy_username: str = ""
    local_proxy_password: str = ""
    transport_version: str = DEFAULT_TRANSPORT_VERSION
    # When True the controller never falls back to HTTP/2 on its own: an
    # HTTP/1.1 close storm or an HTTP/3 QUIC timeout surfaces as an error
    # instead of a transport switch (set automatically from the network
    # response's transport_pinned field).
    strict_transport_pinning: bool = False
    multiplex_streams: int = MULTIPLEX_STREAM_CHOICES[0]
    utls_fingerprint: str = DEFAULT_UTLS_FINGERPRINT
    tls_fragment_mode: str = DEFAULT_TLS_FRAGMENT_MODE
    tls_fragment_fallback_delay_ms: int = DEFAULT_TLS_FRAGMENT_FALLBACK_DELAY_MS
    always_on: bool = False
    kill_switch: bool = False
    automatic_recovery: bool = True
    update_checks: bool = True

    def __post_init__(self) -> None:
        if self.upstream_conns < 1:
            raise ValueError("upstream_conns must be >= 1")
        if self.max_conns < 0:
            raise ValueError("max_conns must be >= 0")
        if self.idle_timeout < 0:
            raise ValueError("idle_timeout must not be negative")
        if self.handshake_timeout <= 0:
            raise ValueError("handshake_timeout must be positive")
        if self.dns_mode not in ("auto", "cloudflare", "google", "custom"):
            raise ValueError("dns_mode must be one of: auto, cloudflare, google, custom")
        if self.edge_address:
            if ":" not in self.edge_address:
                raise ValueError("edge_address must be in host:port format")
            host, port = self.edge_address.rsplit(":", 1)
            if not host:
                raise ValueError("edge_address must have a host")
            try:
                port_num = int(port)
                if not 1 <= port_num <= 65535:
                    raise ValueError("edge_address port must be 1-65535")
            except ValueError:
                raise ValueError("edge_address port must be a valid integer")
        if self.dns_custom:
            parts = self.dns_custom.split(",")
            normalized = []
            for part in parts:
                stripped = part.strip()
                if not stripped:
                    raise ValueError("dns_custom contains empty entry")
                normalized.append(stripped)
            self.dns_custom = ",".join(normalized)
        if self.upstream_proxy is not None:
            if self.upstream_proxy.type not in ("socks5", "http"):
                raise ValueError(f"upstream_proxy.type must be 'socks5' or 'http', got {self.upstream_proxy.type!r}")
            if not self.upstream_proxy.host:
                raise ValueError("upstream_proxy.host must not be empty")
            if self.upstream_proxy.port < 1 or self.upstream_proxy.port > 65535:
                raise ValueError("upstream_proxy.port must be between 1 and 65535")
        if not (MIN_MTU <= self.mtu <= MAX_MTU):
            raise ValueError(f"mtu must be between {MIN_MTU} and {MAX_MTU}")
        if not (1 <= self.http_proxy_port <= 65535):
            raise ValueError("http_proxy_port must be between 1 and 65535")
        if self.http_proxy_enabled:
            import ipaddress

            try:
                address = ipaddress.ip_address(self.listen_host)
                if address.is_unspecified and not self._local_proxy_users():
                    raise ValueError(
                        "HTTP proxy bind address must be a loopback IP address "
                        "(0.0.0.0 requires local proxy authentication)"
                    )
                if not (address.is_loopback or address.is_unspecified):
                    raise ValueError(
                        "HTTP proxy bind address must be a loopback IP address "
                        "(or 0.0.0.0 with local proxy authentication)"
                    )
            except ValueError as exc:
                raise ValueError("HTTP proxy bind address must be a loopback IP address") from exc
        if self.tunnel_dns_provider not in ("default", "cloudflare", "google", "quad9", "adguard", "custom"):
            raise ValueError(f"invalid tunnel_dns_provider {self.tunnel_dns_provider!r}")
        if self.custom_tunnel_doh_url:
            if not self.custom_tunnel_doh_url.startswith("https://"):
                raise ValueError("custom_tunnel_doh_url must be an HTTPS DoH endpoint")
        if self.resolver_dns_provider not in ("automatic", "quad9", "cloudflare", "google", "system", "custom"):
            raise ValueError(f"invalid resolver_dns_provider {self.resolver_dns_provider!r}")
        if self.custom_resolver_ip:
            import ipaddress
            try:
                ipaddress.ip_address(self.custom_resolver_ip)
            except ValueError as exc:
                raise ValueError("custom_resolver_ip must be a valid IP address") from exc
        if self.tls_split_mode not in ("off", "first_byte", "sni"):
            raise ValueError(f"invalid tls_split_mode {self.tls_split_mode!r}")
        if self.upstream_proxy_enabled and self.upstream_proxy is None:
            raise ValueError("upstream_proxy_enabled requires upstream_proxy configuration")
        import ipaddress

        try:
            address = ipaddress.ip_address(self.listen_host)
            if address.is_unspecified and not self._local_proxy_users():
                raise ValueError(
                    "SOCKS5 bind address must be a loopback IP address "
                    "(0.0.0.0 requires local proxy authentication)"
                )
            if not (address.is_loopback or address.is_unspecified):
                raise ValueError(
                    "SOCKS5 bind address must be a loopback IP address "
                    "(or 0.0.0.0 with local proxy authentication)"
                )
        except ValueError as exc:
            raise ValueError("SOCKS5 bind address must be a loopback IP address") from exc
        if self.proxy_only_mode and self.upstream_proxy is not None:
            raise ValueError("proxy_only_mode and upstream_proxy are mutually exclusive")
        if self.latency_probe_url and not self.latency_probe_url.startswith("https://"):
            raise ValueError("latency_probe_url must be an HTTPS URL")
        if self.ip_mode not in IP_MODES:
            raise ValueError(f"ip_mode must be one of: {', '.join(IP_MODES)}")
        if self.bootstrap_dns_provider not in BOOTSTRAP_DNS_PROVIDERS:
            raise ValueError(
                f"bootstrap_dns_provider must be one of: {', '.join(BOOTSTRAP_DNS_PROVIDERS)}"
            )
        if self.custom_bootstrap_doh_url:
            if self.bootstrap_dns_provider != "custom":
                raise ValueError("custom_bootstrap_doh_url requires bootstrap_dns_provider='custom'")
            if not self.custom_bootstrap_doh_url.startswith("https://"):
                raise ValueError("custom_bootstrap_doh_url must be an HTTPS DoH endpoint")
        elif self.bootstrap_dns_provider == "custom":
            raise ValueError("bootstrap_dns_provider='custom' requires custom_bootstrap_doh_url")
        if self.relayer_provider not in RELAYER_PROVIDERS:
            raise ValueError(f"relayer_provider must be one of: {', '.join(RELAYER_PROVIDERS)}")
        if self.relayer_provider == "custom":
            if not self.custom_relayer_url:
                raise ValueError("relayer_provider='custom' requires custom_relayer_url")
            if not self.custom_relayer_url.startswith("https://"):
                raise ValueError("custom_relayer_url must be an HTTPS URL")
        elif self.custom_relayer_url:
            raise ValueError("custom_relayer_url requires relayer_provider='custom'")
        self.relayed_endpoints = [
            str(ep).strip() for ep in self.relayed_endpoints if str(ep).strip()
        ]
        if self.local_proxy_auth_enabled:
            if not self.local_proxy_username or not self.local_proxy_password:
                raise ValueError("local proxy auth requires a username and password")
            if ":" in self.local_proxy_username:
                raise ValueError("local proxy username must not contain ':'")
        if self.transport_version not in TRANSPORT_VERSIONS:
            raise ValueError(f"transport_version must be one of: {', '.join(TRANSPORT_VERSIONS)}")
        if self.multiplex_streams not in MULTIPLEX_STREAM_CHOICES:
            raise ValueError(
                f"multiplex_streams must be one of: {', '.join(map(str, MULTIPLEX_STREAM_CHOICES))}"
            )
        if self.utls_fingerprint not in UTLS_FINGERPRINTS:
            raise ValueError(f"utls_fingerprint must be one of: {', '.join(UTLS_FINGERPRINTS)}")
        if self.tls_fragment_mode not in TLS_FRAGMENT_MODES:
            raise ValueError(f"tls_fragment_mode must be one of: {', '.join(TLS_FRAGMENT_MODES)}")
        if not 0 <= int(self.tls_fragment_fallback_delay_ms) <= 10_000:
            raise ValueError("tls_fragment_fallback_delay_ms must be between 0 and 10000")

    @property
    def listen_address(self) -> str:
        return f"{self.listen_host}:{self.listen_port}"

    def _local_proxy_users(self) -> Optional[dict[str, str]]:
        if self.local_proxy_auth_enabled and self.local_proxy_username and self.local_proxy_password:
            return {self.local_proxy_username: self.local_proxy_password}
        return None

    @property
    def effective_use_http3(self) -> bool:
        """HTTP/3 is selected by ``transport_version`` (h1/h2/h3 parity).

        ``use_http3`` remains as a legacy override; explicit ``transport_version``
        wins when the user picks h1/h2/h3 in the UI.
        """
        if self.transport_version == "h3":
            return True
        if self.transport_version == "h2":
            return False
        return self.use_http3

    @property
    def proxy_state_path(self) -> str:
        return str(get_proxy_state_path())

    @property
    def status_path(self) -> str:
        return str(get_status_path())

    @property
    def token_path(self) -> str:
        return str(get_token_path())

    @property
    def serverlist_cache_path(self) -> str:
        return str(get_config_dir() / "serverlist-cache.json")


CONFIG_FILE_NAME = "config.json"


def _config_path() -> Path:
    override = os.environ.get("PERCHVPN_CONFIG_FILE")
    if override:
        return Path(override)
    return get_config_dir() / CONFIG_FILE_NAME


class _CRYPT_INTEGER_BLOB(ctypes.Structure):
    """Win32 DATA_BLOB: byte-count + pointer, not a NUL-terminated string."""

    _fields_ = [
        ("cbData", ctypes.c_ulong),
        ("pbData", ctypes.c_void_p),
    ]


def _local_free(pointer: int) -> None:
    try:
        ctypes.windll.kernel32.LocalFree(ctypes.c_void_p(pointer))
    except Exception:
        pass


def _cryptprotect(data: bytes, protection_type: int = 1) -> bytes:
    """Encrypt ``data`` with Windows DPAPI via CryptProtectData."""
    CryptProtectData = ctypes.windll.crypt32.CryptProtectData
    CryptProtectData.restype = ctypes.c_int
    CryptProtectData.argtypes = [
        ctypes.POINTER(_CRYPT_INTEGER_BLOB),  # pDataIn
        ctypes.c_wchar_p,  # szDataDescr
        ctypes.POINTER(_CRYPT_INTEGER_BLOB),  # pvOptionalEntropy
        ctypes.c_ulong,  # cbOptionalEntropy
        ctypes.c_void_p,  # pvPromptStruct
        ctypes.c_ulong,  # dwFlags
        ctypes.POINTER(_CRYPT_INTEGER_BLOB),  # pDataOut
    ]
    in_blob = _CRYPT_INTEGER_BLOB(
        len(data), ctypes.cast(ctypes.c_char_p(bytes(data)), ctypes.c_void_p)
    )
    entropy = _CRYPT_INTEGER_BLOB(0, None)
    out_blob = _CRYPT_INTEGER_BLOB()
    description = ctypes.c_wchar_p("Perch VPN upstream proxy credential")
    ret = CryptProtectData(
        ctypes.byref(in_blob),
        description,
        ctypes.byref(entropy),
        0,
        None,
        0,
        ctypes.byref(out_blob),
    )
    if ret == 0:
        raise RuntimeError(
            "DPAPI encryption failed (GetLastError=%d)" % ctypes.GetLastError()
        )
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        if out_blob.pbData:
            _local_free(out_blob.pbData)


def _cryptunprotect(data: bytes) -> bytes:
    """Decrypt DPAPI-protected ``data`` via CryptUnprotectData."""
    CryptUnprotectData = ctypes.windll.crypt32.CryptUnprotectData
    CryptUnprotectData.restype = ctypes.c_int
    CryptUnprotectData.argtypes = [
        ctypes.POINTER(_CRYPT_INTEGER_BLOB),  # pDataIn
        ctypes.POINTER(ctypes.c_wchar_p),  # ppszDataDescr (out)
        ctypes.POINTER(_CRYPT_INTEGER_BLOB),  # pvOptionalEntropy
        ctypes.c_ulong,  # cbOptionalEntropy
        ctypes.c_void_p,  # pvPromptStruct
        ctypes.c_ulong,  # dwFlags
        ctypes.POINTER(_CRYPT_INTEGER_BLOB),  # pDataOut
    ]
    in_blob = _CRYPT_INTEGER_BLOB(
        len(data), ctypes.cast(ctypes.c_char_p(bytes(data)), ctypes.c_void_p)
    )
    entropy = _CRYPT_INTEGER_BLOB(0, None)
    out_blob = _CRYPT_INTEGER_BLOB()
    description_out = ctypes.c_wchar_p()
    ret = CryptUnprotectData(
        ctypes.byref(in_blob),
        ctypes.byref(description_out),
        ctypes.byref(entropy),
        0,
        None,
        0,
        ctypes.byref(out_blob),
    )
    if ret == 0:
        raise RuntimeError(
            "DPAPI decryption failed (GetLastError=%d)" % ctypes.GetLastError()
        )
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        if out_blob.pbData:
            _local_free(out_blob.pbData)
        if ctypes.cast(ctypes.byref(description_out), ctypes.POINTER(ctypes.c_void_p)).contents.value:
            _local_free(
                ctypes.cast(
                    ctypes.byref(description_out), ctypes.POINTER(ctypes.c_void_p)
                ).contents.value
            )


def _encrypt_password(password: str) -> str:
    """Encrypt ``password`` with DPAPI and return base64-encoded ciphertext."""
    if not password:
        return ""
    try:
        encrypted = _cryptprotect(password.encode("utf-8"))
        return base64.b64encode(encrypted).decode("ascii")
    except Exception as exc:
        raise RuntimeError(f"DPAPI encryption failed: {exc}") from exc


def _decrypt_password(encrypted: str) -> str:
    """Decrypt DPAPI-protected base64 ciphertext back to plaintext password."""
    if not encrypted:
        return ""
    try:
        ciphertext = base64.b64decode(encrypted, validate=True)
        decrypted = _cryptunprotect(ciphertext)
        return decrypted.decode("utf-8")
    except Exception:
        # Corrupted ciphertext or DPAPI failure: fail safe, return empty.
        return ""


def load_config() -> WindowsConfig:
    """Load configuration from disk, falling back to defaults and decrypting
    DPAPI-encrypted upstream-proxy passwords."""
    path = _config_path()
    if not path.exists():
        return WindowsConfig()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            up = data.get("upstream_proxy")
            if isinstance(up, dict):
                # Decrypt DPAPI-encrypted password
                if up.get("password"):
                    dec = _decrypt_password(up["password"])
                    if dec:
                        up["password"] = dec
                    else:
                        up["password"] = ""
                up = UpstreamProxyConfig(
                    host=up.get("host", ""),
                    port=up.get("port", 0),
                    type=up.get("type", "socks5"),
                    username=up.get("username", ""),
                    password=up.get("password", ""),
                )
                data["upstream_proxy"] = up
        if isinstance(data.get("local_proxy_password"), str) and data["local_proxy_password"]:
            data["local_proxy_password"] = _decrypt_password(data["local_proxy_password"])
        return WindowsConfig(**{k: v for k, v in data.items() if k in WindowsConfig.__dataclass_fields__})
    except (json.JSONDecodeError, TypeError, ValueError):
        return WindowsConfig()


def save_config(config: WindowsConfig) -> None:
    """Persist configuration atomically with DPAPI-encrypted upstream-proxy
    passwords (plaintext password is never written to disk)."""
    ensure_config_dir()
    path = _config_path()
    config_for_serialization = asdict(config)
    if config.upstream_proxy is not None and config.upstream_proxy.password:
        config_for_serialization["upstream_proxy"]["password"] = _encrypt_password(
            config.upstream_proxy.password
        )
    if config.local_proxy_password:
        config_for_serialization["local_proxy_password"] = _encrypt_password(
            config.local_proxy_password
        )
    fd, tmp_path = tempfile.mkstemp(prefix=CONFIG_FILE_NAME + ".tmp-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(config_for_serialization, fh, indent=2)
        os.replace(tmp_path, path)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
