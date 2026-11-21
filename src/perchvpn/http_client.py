"""Shared HTTP client used for control-plane calls (FxA, Guardian, Remote Settings)."""

from __future__ import annotations

import os
import socket
import struct
import sys
import threading
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

import httpx

from .doh_resolver import DoHTransport

CONTROL_PLANE_HTTP_TIMEOUT = 30.0

# Some system-wide proxy tooling (v2ray, Xray, Clash, and similar) exports
# proxy environment variables using a bare "socks://" scheme rather than the
# "socks5://"/"socks5h://" schemes httpx requires. Normalize known aliases so
# a perfectly usable SOCKS5 proxy doesn't hard-crash the process.
_PROXY_SCHEME_ALIASES = {"socks": "socks5"}

# Checked in the same order common CLI tools use: an explicit all-protocols
# override first, then the protocol-specific vars, uppercase before lowercase.
_ENV_PROXY_VARS = ("ALL_PROXY", "all_proxy", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy")

_lock = threading.Lock()
_client: Optional[httpx.Client] = None
_proxy_url: Optional[str] = None
_timeout: float = CONTROL_PLANE_HTTP_TIMEOUT
_use_doh: bool = False


def _normalize_proxy_url(url: str) -> str:
    parts = urlsplit(url)
    scheme = _PROXY_SCHEME_ALIASES.get(parts.scheme.lower(), parts.scheme)
    if scheme == parts.scheme:
        return url
    return urlunsplit((scheme, parts.netloc, parts.path, parts.query, parts.fragment))


def _env_proxy_url() -> Optional[str]:
    for var in _ENV_PROXY_VARS:
        value = os.environ.get(var)
        if value:
            return value
    return None


# When set, control-plane connections are bound to this source address
# (physical-NIC egress pinning under TUN mode).
_local_address: Optional[str] = None

# Windows IPPROTO_IP option used to force IPv4 egress through one interface,
# independent of the route table (and therefore independent of the tunnel).
IP_UNICAST_IF = 31

# When set, every new control-plane socket is pinned to this physical
# interface index.  The pre-TUN guardian bootstrap and the post-activation
# refresh loop both rely on it, so no control-plane request can leave through
# the tunnel's default route even before its per-host /32 pin exists.
_physical_interface: Optional[int] = None


def physical_interface_socket_options(interface_index: Optional[int]) -> list:
    """``IP_UNICAST_IF`` socket options for one Windows interface index.

    Returns an empty list off Windows and for an unset index, so the same
    call site is a no-op in non-Windows test runs.
    """
    if not interface_index or sys.platform != "win32":
        return []
    return [(socket.IPPROTO_IP, IP_UNICAST_IF, struct.pack("!I", int(interface_index)))]


def set_physical_interface(interface_index: Optional[int]) -> None:
    """Pin (or clear) physical-interface egress for control-plane sockets,
    rebuilding the shared client so the binding takes effect immediately."""
    global _client, _physical_interface
    with _lock:
        if _physical_interface == interface_index:
            return
        _physical_interface = interface_index
        _rebuild_shared_client_locked(use_doh=_use_doh)


def physical_interface() -> Optional[int]:
    with _lock:
        return _physical_interface


# Verified hostname -> IPv4 pins for control-plane dials.  With a TUN active
# the system resolver may answer from a different cache/view than the one the
# pins were verified against, so a hostname is only ever dialed after its
# address was pinned to the physical NIC.  The original hostname is preserved
# for SNI and in the Host header, so TLS and routing behave normally.
_address_overrides: dict[str, str] = {}


def set_control_plane_address_overrides(mapping: Optional[dict] = None) -> None:
    """Install (or clear) hostname -> pinned-address overrides."""
    global _address_overrides
    with _lock:
        _address_overrides = {
            str(key).strip().lower(): str(value).strip()
            for key, value in (mapping or {}).items()
            if str(key or "").strip() and str(value or "").strip()
        }


def control_plane_address_overrides() -> dict:
    with _lock:
        return dict(_address_overrides)


def rewrite_control_plane_url(url: str) -> tuple[str, dict, dict]:
    """Dial a pinned address for an overridden hostname.

    Returns ``(dial_url, extra_headers, extensions)``.  The address replaces
    the hostname in the URL, while ``Host`` carries the original authority
    and ``sni_hostname`` keeps the TLS verification name (httpcore honours
    it), so the dial is source-pinned to a verified physical path without
    weakening certificate checks.
    """
    if not _address_overrides:
        return url, {}, {}
    parts = urlsplit(url)
    host = (parts.hostname or "").strip().lower()
    pinned = _address_overrides.get(host)
    if not host or not pinned:
        return url, {}, {}
    netloc = "[%s]" % pinned if ":" in pinned else pinned
    if parts.port:
        netloc = "%s:%d" % (netloc, parts.port)
    dial_url = urlunsplit(
        (parts.scheme, netloc, parts.path, parts.query, parts.fragment)
    )
    authority = host if not parts.port else "%s:%d" % (host, parts.port)
    return dial_url, {"Host": authority}, {"sni_hostname": host.encode("ascii")}


def _local_addr_kwargs() -> dict:
    if _local_address:
        return {"local_address": _local_address}
    return {}


def _transport_kwargs() -> dict:
    """Transport kwargs shared by the sync and async control-plane clients."""
    kwargs = _local_addr_kwargs()
    options = physical_interface_socket_options(_physical_interface)
    if options:
        kwargs["socket_options"] = options
    return kwargs


def set_local_address(address: Optional[str]) -> None:
    """Set (or clear) the source address control-plane HTTP(S) dials bind to,
    rebuilding the shared client so the new binding takes effect."""
    global _client, _local_address
    with _lock:
        if _local_address == address:
            return
        _local_address = address
        _rebuild_shared_client_locked(use_doh=_use_doh)


def control_plane_local_address() -> Optional[str]:
    """Source address control-plane dials bind to (physical-NIC pinning)."""
    with _lock:
        return _local_address


def control_plane_proxy_url() -> Optional[str]:
    """Effective control-plane proxy URL, normalized for httpx/curl."""
    with _lock:
        proxy = _proxy_url or _env_proxy_url()
    return _normalize_proxy_url(proxy) if proxy else None


def _build_client(use_doh: bool = False) -> httpx.Client:
    # Resolve the effective proxy ourselves -- an explicit --api-proxy wins,
    # otherwise fall back to the ambient system proxy env vars -- and turn
    # off httpx's own trust_env-based environment lookup so we get a chance
    # to normalize scheme aliases before httpx ever validates the URL.
    proxy = _proxy_url or _env_proxy_url()
    kwargs = {"timeout": _timeout, "http2": True, "follow_redirects": True, "trust_env": False}
    if proxy:
        kwargs["proxy"] = _normalize_proxy_url(proxy)

    transport_kwargs = _transport_kwargs()
    if use_doh:
        from perchvpn.doh_resolver import DoHTransport
        transport = DoHTransport(fallback_transport=httpx.HTTPTransport(**transport_kwargs))
        kwargs["transport"] = transport
    elif transport_kwargs:
        kwargs["transport"] = httpx.HTTPTransport(**transport_kwargs)

    return _RelayingClient(**kwargs)


class _RelayingClient(httpx.Client):
    """httpx.Client with upstream-v2.0.3 relayer failover.

    When a relayer is configured and the request URL belongs to a routed
    category, a direct failure (failover status or connection error) is
    retried through the configured relayer workers.  With the default
    "direct" state this is a plain pass-through.
    """

    def request(self, method: str, url, **kwargs):  # type: ignore[override]
        from . import relayer

        state = relayer.current_state()
        if not relayer.should_relay(str(url), state):
            return super().request(method, url, **kwargs)
        return relayer.request_with_relayer(self, method, str(url), state=state, **kwargs)

    def _request_direct(self, method: str, url, **kwargs):
        # Explicitly bypass our own request() override so relayer failover
        # attempts never recurse back into the routing hook.
        return super().request(method, url, **kwargs)


def get_client() -> httpx.Client:
    global _client
    with _lock:
        if _client is None:
            _client = _build_client()
        return _client


def get_async_client(use_doh: bool = False) -> httpx.AsyncClient:
    """Create an async client for async control-plane calls."""
    proxy = _proxy_url or _env_proxy_url()
    kwargs = {"timeout": _timeout, "http2": True, "follow_redirects": True, "trust_env": False}
    if proxy:
        kwargs["proxy"] = _normalize_proxy_url(proxy)

    transport_kwargs = _transport_kwargs()
    if use_doh:
        from perchvpn.doh_resolver import DoHTransport
        transport = DoHTransport(fallback_transport=httpx.AsyncHTTPTransport(**transport_kwargs))
        kwargs["transport"] = transport
    elif transport_kwargs:
        kwargs["transport"] = httpx.AsyncHTTPTransport(**transport_kwargs)

    return httpx.AsyncClient(**kwargs)


def _rebuild_shared_client_locked(use_doh: Optional[bool] = None) -> None:
    """Replace the shared client without closing the old one.

    A close here kills any request another thread already started on the
    previous client (observed as httpx's "Cannot send a request, as the
    client has been closed." during initialization, when the startup
    preflight thread rebuilt the client while auth/Guardian dials were in
    flight). The replaced client's sockets are reclaimed by GC; rebuilds
    are a handful per session, so the transient socket cost is negligible.
    Callers hold ``_lock``.
    """
    global _client
    if use_doh is None:
        _client = _build_client()
    else:
        _client = _build_client(use_doh=use_doh)


def set_control_plane_proxy(proxy_url: Optional[str]) -> None:
    """Set (or clear) the proxy URL used for control-plane HTTP calls, rebuilding
    the shared client so the new proxy takes effect immediately."""
    global _client, _proxy_url
    with _lock:
        _proxy_url = proxy_url
        _rebuild_shared_client_locked()


def set_control_plane_timeout(timeout: Optional[float]) -> None:
    """Set the default per-request timeout (seconds) used for control-plane
    HTTP calls (FxA, Guardian, Remote Settings), rebuilding the shared client
    so the new timeout takes effect immediately. Falls back to
    CONTROL_PLANE_HTTP_TIMEOUT when ``timeout`` is None or not positive.
    """
    global _client, _timeout
    with _lock:
        _timeout = timeout if timeout and timeout > 0 else CONTROL_PLANE_HTTP_TIMEOUT
        _rebuild_shared_client_locked()


def set_doh_enabled(enabled: bool) -> None:
    """Enable or disable DNS-over-HTTPS for control-plane connections."""
    global _client, _use_doh
    with _lock:
        _use_doh = enabled
        _rebuild_shared_client_locked(use_doh=enabled)


def read_error_body(response: httpx.Response, limit: int = 2048) -> str:
    try:
        text = response.text
    except Exception:  # noqa: BLE001
        return ""
    return text[:limit]
