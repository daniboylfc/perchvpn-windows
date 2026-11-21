"""Build sing-box JSON configuration for PerchVPN's Windows TUN engine.

PerchVPN keeps its local SOCKS5 proxy as the traffic egress.  sing-box owns
the Wintun adapter, routes and DNS interception, then forwards tunnelled
traffic to that local proxy.  Tunnel DNS uses an IP-literal plain resolver
sent through the direct outbound, so it never depends on the SOCKS tunnel or
on DNS to bootstrap itself.  This module is deliberately free of Windows API
calls so the generated configuration can be unit-tested on any host.
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

from perchvpn.proxy.transport_options import SINGBOX_UTLS_FINGERPRINTS

__all__ = [
    "DEFAULT_ADAPTER",
    "DEFAULT_BYPASS_PROCESSES",
    "DEFAULT_ROUTE_ADDRESS",
    "DEFAULT_TUN_ADDRESS_V4",
    "DEFAULT_DNS_ADDRESS_V4",
    "DEFAULT_MTU",
    "DEFAULT_MIXED_PORT",
    "DEFAULT_PROXY_HOST",
    "DEFAULT_PROXY_PORT",
    "DNS_DIRECT_TAG",
    "DNS_PORT",
    "DNS_SERVER",
    "DNS_TUNNEL_TAG",
    "REMOTE_DNS_HOST",
    "TUNNEL_DNS_PROVIDERS",
    "tunnel_dns_endpoint",
    "REMOTE_DNS_PATH",
    "REMOTE_DNS_PORT",
    "FASTLY_MASQUE_NETWORKS",
    "LOCAL_NETWORKS",
    "TELEGRAM_NETWORKS",
    "available_mixed_port",
    "build_config",
    "dumps_config",
    "validate_config",
    "write_config",
]

DEFAULT_ADAPTER = "PerchVPN"
DEFAULT_MTU = 1400
DEFAULT_MIXED_PORT = 10808
DEFAULT_PROXY_HOST = "127.0.0.1"
DEFAULT_PROXY_PORT = 1080
# DNS address-family selection strategies keyed by the configured IP mode.
# Upstream Android v2.0.3 maps its IpMode enum onto these resolver strategies.
IP_MODE_STRATEGIES = {
    "dual_stack": "prefer_ipv4",
    "prefer_ipv4": "prefer_ipv4",
    "prefer_ipv6": "prefer_ipv6",
    "ipv4_only": "ipv4_only",
    "ipv6_only": "ipv6_only",
}
# IP modes whose resolver must refuse the opposite address family entirely.
IP_MODE_EXCLUSIVE_V4 = "ipv4_only"
IP_MODE_EXCLUSIVE_V6 = "ipv6_only"
# Split default routes sing-box must install instead of the physical default.
# A /0 route would overwrite the underlay; the /1 pair captures all IPv4 while
# leaving LAN/loopback/private prefixes on the physical path.
DEFAULT_ROUTE_ADDRESS = ("0.0.0.0/1", "128.0.0.0/1")
DEFAULT_TUN_ADDRESS_V4 = "172.19.0.1/30"
DEFAULT_TUN_ADDRESS_V6 = "fdfe:dcba:9876::1/126"
DEFAULT_DNS_ADDRESS_V4 = "172.19.0.2"
DEFAULT_DNS_ADDRESS_V6 = "fdfe:dcba:9876::2"

# The tunnel resolver is addressed by IP and uses plain DNS over the physical
# interface.  It cannot depend on DNS to resolve itself, and it never enters
# the SOCKS tunnel, so there is no DNS-over-SOCKS bootstrap deadlock.
DNS_TUNNEL_TAG = "remote-dns"
DNS_DIRECT_TAG = "local-dns"
DNS_SERVER = "1.1.1.1"
DNS_PORT = 53
REMOTE_DNS_PORT = 443
REMOTE_DNS_PATH = "/dns-query"
REMOTE_DNS_HOST = "cloudflare-dns.com"

# Tunnel resolver presets.  The UI has always offered ``tunnel_dns_provider``
# and ``custom_tunnel_doh_url``, but the Windows config generator ignored both
# and always pinned Cloudflare's 1.1.1.1.  That made the setting inert and,
# on networks where 1.1.1.1:443 is blocked or reset (measured in the sandbox
# guest: 10054 on 1.1.1.1/1.0.0.1/8.8.8.8, clean answers from AdGuard), it
# broke every tunnel DNS query.
TUNNEL_DNS_PROVIDERS: Dict[str, Dict[str, Any]] = {
    "default": {
        "servers": ("1.1.1.1",),
        "server_name": REMOTE_DNS_HOST,
        "path": REMOTE_DNS_PATH,
    },
    "cloudflare": {
        "servers": ("1.1.1.1", "1.0.0.1"),
        "server_name": REMOTE_DNS_HOST,
        "path": REMOTE_DNS_PATH,
    },
    "google": {
        "servers": ("8.8.8.8", "8.8.4.4"),
        "server_name": "dns.google",
        "path": REMOTE_DNS_PATH,
    },
    "quad9": {
        "servers": ("9.9.9.9", "149.112.112.112"),
        "server_name": "dns.quad9.net",
        "path": REMOTE_DNS_PATH,
    },
    "adguard": {
        "servers": ("94.140.14.14", "94.140.15.15"),
        "server_name": "dns.adguard-dns.com",
        "path": REMOTE_DNS_PATH,
    },
}


def tunnel_dns_endpoint(
    provider: str = "default", custom_url: str = ""
) -> Dict[str, Any]:
    """Resolve ``(server, server_name, path, port, pin_ips)`` for DoH.

    ``custom_url`` wins when ``provider == "custom"`` and must be an https
    URL whose host is an IP literal (a hostname cannot be resolved before the
    tunnel exists).  Every preset endpoint also contributes a ``/32`` route
    exclusion so the physical bootstrap path is never captured.
    """
    name = str(provider or "default").strip().lower()
    if name == "custom":
        return _custom_doh_endpoint(custom_url)
    preset = TUNNEL_DNS_PROVIDERS.get(name) or TUNNEL_DNS_PROVIDERS["default"]
    servers = tuple(preset["servers"])
    return {
        "server": servers[0],
        "server_name": preset["server_name"],
        "path": preset["path"],
        "port": REMOTE_DNS_PORT,
        "pin_ips": servers,
    }


def _custom_doh_endpoint(custom_url: str) -> Dict[str, Any]:
    from urllib.parse import urlsplit

    text = str(custom_url or "").strip()
    parsed = urlsplit(text)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ValueError("custom_tunnel_doh_url must be an https URL")
    try:
        port = parsed.port or REMOTE_DNS_PORT
    except ValueError as exc:
        raise ValueError("custom_tunnel_doh_url has an invalid port") from exc
    host = parsed.hostname
    try:
        ipaddress.ip_address(host)
    except ValueError as exc:
        # A hostname endpoint would have to be resolved before the tunnel
        # exists (bootstrap deadlock, and validate_config rejects it).
        raise ValueError(
            "custom_tunnel_doh_url host must be an IP literal"
        ) from exc
    return {
        "server": host,
        "server_name": host,
        "path": parsed.path or REMOTE_DNS_PATH,
        "port": port,
        "pin_ips": (host,),
    }

# Telegram data-centre ranges.  They are routed explicitly instead of falling
# through to the generic UDP rejection so TCP sessions reach the proxy without
# waiting on a failed UDP/QUIC path or a stale upstream session.
TELEGRAM_NETWORKS = (
    "91.108.4.0/22",
    "91.108.8.0/22",
    "91.108.12.0/22",
    "91.108.16.0/22",
    "91.108.56.0/22",
    "149.154.160.0/20",
    "149.154.164.0/22",
    "149.154.168.0/22",
    "149.154.172.0/22",
)

# Fastly MASQUE proxy network ranges.  Upstream proxy endpoints
# (e.g. *.m1.fastly-masque.net) live here; excluding this CIDR block from the
# TUN prevents the Wintun adapter from capturing upstream proxy traffic and
# routing it back into perch-socks.
FASTLY_MASQUE_NETWORKS = (
    "23.235.32.0/20",
)

# RFC 6598 shared address space (Tailscale and other CGNAT overlays).
CGNAT_NETWORKS = (
    "100.64.0.0/10",
)

# RFC1918, link-local, loopback and IPv6 ULA/link-local destinations stay
# outside the tunnel.  The exact list mirrors the Android client's
# local-network bypass.
LOCAL_NETWORKS = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "127.0.0.0/8",
    "fc00::/7",
    "fe80::/10",
)

# Process-level bypass is disabled by default: routing PerchVPN.exe to "direct"
# breaks PerchVPN's own egress verification (sending probes out the physical NIC
# instead of the TUN), and sing-box's find_process scans the OS socket table on
# every packet causing high CPU usage.  Upstream MASQUE traffic, physical DNS,
# and private subnets are already excluded at the driver level via route_exclude_address.
DEFAULT_BYPASS_PROCESSES = ()


def _validate_port(name: str, value: int) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("%s must be an integer" % name) from exc
    if not 1 <= port <= 65535:
        raise ValueError("%s must be between 1 and 65535" % name)
    return port


def available_mixed_port(
    listen: str = "127.0.0.1", preferred: int = DEFAULT_MIXED_PORT
) -> Optional[int]:
    """Return the preferred mixed inbound port when this host can bind it.

    The optional mixed inbound is a convenience listener, not a requirement
    for TUN routing.  A separate local proxy (for example p-xray) may already
    own 10808; in that case return ``None`` so sing-box starts without a
    competing listener instead of failing its whole config.
    """
    try:
        port = _validate_port("preferred", preferred)
    except ValueError:
        return None
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((str(listen or "127.0.0.1"), port))
        except OSError:
            return None
    return port


def _normalize_cidr(value: str) -> str:
    """Return a canonical CIDR, preserving a bare host as /32 or /128."""
    text = str(value or "").strip()
    if not text:
        raise ValueError("exclude address must not be empty")
    try:
        return str(ipaddress.ip_network(text, strict=False))
    except ValueError as exc:
        raise ValueError("invalid exclude address %r: %s" % (text, exc)) from exc


def excluded_networks(bypass: Sequence[str] = ()) -> tuple:
    """IPv4 networks excluded from the tunnel's route table.

    The route-coverage classifier must know these: ``route_exclude_address``
    carves /32 holes (for example the DoH resolver pins) into sing-box's
    decomposed default-route table, so a coverage sentinel sitting inside an
    excluded network is an intentional gap, not a missing route.
    """
    return tuple(
        ipaddress.ip_network(normalized)
        for normalized in _exclude_addresses(bypass)
        if ipaddress.ip_network(normalized).version == 4
    )


def _exclude_addresses(
    bypass: Sequence[str], dns_pins: Sequence[str] = (DNS_SERVER,)
) -> List[str]:
    addresses: List[str] = list(LOCAL_NETWORKS)
    # Tailscale and other CGNAT-overlay adapters live in 100.64.0.0/10.  When
    # such an adapter is Up (for example Tailscale with MagicDNS at
    # 100.100.100.100:53), capturing this space into the TUN churns every
    # keepalive and DNS query into the MASQUE upstream as tunneled DoH.  The
    # space is never globally routed, so excluding it unconditionally is
    # always safe: local CGNAT traffic stays on its own adapter.
    for cgnat_net in CGNAT_NETWORKS:
        normalized = _normalize_cidr(cgnat_net)
        if normalized not in addresses:
            addresses.append(normalized)
    for net in FASTLY_MASQUE_NETWORKS:
        normalized = _normalize_cidr(net)
        if normalized not in addresses:
            addresses.append(normalized)
    # The bootstrap resolver must always stay on the physical path.  If it
    # were captured by the TUN route, direct DNS lookups would loop back into
    # the tunnel before the proxy was usable.
    for pin in dns_pins or ():
        dns_endpoint = _normalize_cidr(pin)
        if dns_endpoint not in addresses:
            addresses.append(dns_endpoint)
    for entry in bypass or ():
        if not str(entry or "").strip():
            continue
        normalized = _normalize_cidr(str(entry))
        if normalized not in addresses:
            addresses.append(normalized)
    return addresses


def _wsl2_exclude_addresses() -> List[str]:
    """Host-local WSL virtual adapter subnets for ``route_exclude_address``.

    WSL2 NAT egress (source addresses on ``vEthernet (WSL ...)``) must never
    be black-holed by ``strict_route`` WFP rules: the host-local subnet is
    carved out of the TUN route table so WSL traffic leaves via its NAT even
    when the tunnel owns the default route.  Detection is live (native IP
    Helper enumeration) and returns only the subnets that actually exist;
    a non-Windows host or any failure yields an empty list, leaving the
    existing RFC1918 bypass untouched.
    """
    try:
        from perchvpn_windows import iphelper

        return iphelper.virtual_nat_subnets_native()
    except Exception:  # noqa: BLE001 - bypass is best-effort
        return []


def build_config(
    *,
    proxy_host: str = DEFAULT_PROXY_HOST,
    proxy_port: int = DEFAULT_PROXY_PORT,
    adapter: str = DEFAULT_ADAPTER,
    mtu: int = DEFAULT_MTU,
    bypass: Sequence[str] = (),
    ipv6: bool = False,
    mixed_listen: str = "127.0.0.1",
    mixed_port: Optional[int] = DEFAULT_MIXED_PORT,
    auto_route: bool = True,
    strict_route: bool = True,
    log_level: str = "info",
    log_output: Optional[str] = None,
    bypass_processes: Sequence[str] = DEFAULT_BYPASS_PROCESSES,
    ip_mode: Optional[str] = None,
    bypass_local_network: bool = True,
    local_proxy_users: Optional[Dict[str, str]] = None,
    kill_switch: bool = False,
    utls_fingerprint: str = "disabled",
    tunnel_dns_provider: str = "default",
    custom_tunnel_doh_url: str = "",
    auto_detect_interface: bool = True,
) -> Dict[str, Any]:
    """Return a complete sing-box configuration dictionary.

    ``bypass`` entries are upstream/edge IPs that must stay on the physical
    adapter; they are emitted as ``route_exclude_address`` alongside the
    private/local ranges.
    ``bypass_processes`` entries are process names whose outbound traffic is
    routed directly out the physical interface, preventing upstream proxy loops.
    ``auto_detect_interface`` binds every outbound socket to the detected
    physical interface.  Production keeps it on (the upstream proxy is
    remote), but a local stand-in proxy is unreachable from an
    interface-bound socket, so the e2e harness turns it off.
    ``log_output`` persists the sidecar's own log to a file (WFP/TUN
    forwarding errors are otherwise only visible in the drained in-memory
    stdout/stderr deques, which vanish with the process).
    """
    host = str(proxy_host or "").strip()
    if not host:
        raise ValueError("proxy_host must not be empty")
    dns_endpoint = tunnel_dns_endpoint(tunnel_dns_provider, custom_tunnel_doh_url)
    exclude_addresses = _exclude_addresses(bypass, dns_endpoint["pin_ips"])
    # WSL2 NAT subnets are carved out of the TUN route table explicitly so
    # strict_route never black-holes the vEthernet (WSL) egress path.
    try:
        for subnet in _wsl2_exclude_addresses():
            if subnet not in exclude_addresses:
                exclude_addresses.append(subnet)
    except Exception:  # noqa: BLE001 - bypass is best-effort
        pass
    proxy_port = _validate_port("proxy_port", proxy_port)
    adapter = str(adapter or "").strip()
    if not adapter:
        raise ValueError("adapter must not be empty")
    try:
        mtu = int(mtu)
    except (TypeError, ValueError) as exc:
        raise ValueError("mtu must be an integer") from exc
    if mtu <= 0:
        raise ValueError("mtu must be positive")

    valid_processes = [
        str(p).strip()
        for p in (bypass_processes or ())
        if str(p).strip()
    ]

    # ``ipv6`` is the legacy switch: False keeps the historical IPv4-only
    # address set, True upgrades to dual-stack.  An explicit ``ip_mode``
    # (upstream v2.0.3 parity) takes precedence and enables the exclusive
    # address-family rules.
    explicit_mode = ip_mode is not None and str(ip_mode).strip() != ""
    if explicit_mode:
        effective_mode = str(ip_mode).strip()
        strategy = IP_MODE_STRATEGIES.get(effective_mode)
        if strategy is None:
            raise ValueError(
                "ip_mode must be one of: %s" % ", ".join(IP_MODE_STRATEGIES)
            )
    else:
        effective_mode = "dual_stack" if ipv6 else "ipv4_only"
        strategy = "prefer_ipv4"
    if effective_mode != "ipv4_only" and mtu < 1280:
        raise ValueError("IPv6 requires a tunnel MTU of at least 1280")
    if kill_switch:
        strict_route = True

    users: List[Dict[str, str]] = []
    if local_proxy_users:
        for username, password in sorted(local_proxy_users.items()):
            if not username or not password:
                raise ValueError("local proxy auth requires a username and password")
            users.append({"username": username, "password": password})

    requested_fp = str(utls_fingerprint or "").strip().lower()
    utls = SINGBOX_UTLS_FINGERPRINTS.get(requested_fp) if requested_fp != "disabled" else None
    if requested_fp and utls is None and requested_fp != "disabled":
        raise ValueError("utls_fingerprint must be one of: %s" % ", ".join(SINGBOX_UTLS_FINGERPRINTS))

    if mixed_port is not None:
        mixed_port = _validate_port("mixed_port", mixed_port)
        if mixed_port == proxy_port:
            raise ValueError("mixed_port must differ from proxy_port")

    tun_addresses = [DEFAULT_TUN_ADDRESS_V4]
    dns_addresses = [DEFAULT_DNS_ADDRESS_V4]
    tun_cidrs = [str(ipaddress.ip_network(DEFAULT_TUN_ADDRESS_V4, strict=False))]
    if effective_mode != "ipv4_only":
        # IPv6 stays available unless the mode is IPv4-only.
        tun_addresses.append(DEFAULT_TUN_ADDRESS_V6)
        dns_addresses.append(DEFAULT_DNS_ADDRESS_V6)
        tun_cidrs.append(
            str(ipaddress.ip_network(DEFAULT_TUN_ADDRESS_V6, strict=False))
        )
    if effective_mode == "ipv6_only":
        tun_addresses = [DEFAULT_TUN_ADDRESS_V6]
        dns_addresses = [DEFAULT_DNS_ADDRESS_V6]
        tun_cidrs = [str(ipaddress.ip_network(DEFAULT_TUN_ADDRESS_V6, strict=False))]

    inbounds: List[Dict[str, Any]] = [
        {
            "type": "tun",
            "tag": "tun-in",
            "interface_name": adapter,
            "mtu": mtu,
            "address": tun_addresses,
            "dns_address": dns_addresses,
            "auto_route": bool(auto_route),
            "strict_route": bool(strict_route),
            "route_address": list(DEFAULT_ROUTE_ADDRESS),
            "route_exclude_address": exclude_addresses,
            "stack": "system",
        }
    ]
    if mixed_port is not None:
        inbound: Dict[str, Any] = {
            "type": "mixed",
            "tag": "mixed-in",
            "listen": str(mixed_listen or "127.0.0.1"),
            "listen_port": mixed_port,
            "reuse_addr": True,
        }
        if users:
            inbound["users"] = users
        inbounds.append(inbound)

    perch_socks_outbound: Dict[str, Any] = {
        "type": "socks",
        "tag": "perch-socks",
        "server": host,
        "server_port": proxy_port,
        "version": "5",
        "network": "tcp",
    }
    if local_proxy_users:
        # The app's local listener enforces RFC 1929 when auth is enabled;
        # sing-box must present the first configured credential.
        auth_username, auth_password = sorted(local_proxy_users.items())[0]
        perch_socks_outbound["username"] = auth_username
        perch_socks_outbound["password"] = auth_password

    outbounds: List[Dict[str, Any]] = [
        perch_socks_outbound,
        {"type": "direct", "tag": "direct"},
    ]

    # Loopback is always direct, and an IP-literal proxy endpoint is pinned to
    # the physical adapter for its control port so SOCKS5 setup cannot be
    # captured by the TUN route it is trying to establish.
    proxy_networks = ["127.0.0.0/8"]
    try:
        proxy_endpoint = str(ipaddress.ip_network(host, strict=False))
    except ValueError:
        proxy_endpoint = None
    if proxy_endpoint and proxy_endpoint not in proxy_networks:
        proxy_networks.append(proxy_endpoint)

    # DNS interception must run before the private-network bypass.  Otherwise
    # a query to the TUN DNS peer (172.19.0.2:53) matches 172.16.0.0/12,
    # goes to the direct outbound, and is recaptured by the same TUN.  Reject
    # any remaining traffic to the TUN subnet instead of sending it direct.
    # Local/private destinations and the loopback proxy port are explicitly
    # direct before the final SOCKS detour.
    route_rules: List[Dict[str, Any]] = [
        {"protocol": "dns", "action": "hijack-dns"},
        {"port": DNS_PORT, "action": "hijack-dns"},
        {"ip_cidr": tun_cidrs, "action": "reject"},
    ]
    if valid_processes:
        route_rules.append(
            {
                "action": "route",
                "process_name": valid_processes,
                "outbound": "direct",
            }
        )
    if explicit_mode and effective_mode == "ipv4_only":
        # Exclusive IPv4 mode refuses every IPv6 destination outright.
        route_rules.append({"ip_version": 6, "action": "reject"})
    if explicit_mode and effective_mode == "ipv6_only":
        route_rules.append({"ip_version": 4, "action": "reject"})
    route_rules.extend(
        [
            {
                "ip_cidr": proxy_networks,
                "port": proxy_port,
                "outbound": "direct",
            },
        ]
    )
    if bypass_local_network:
        route_rules.append(
            {
                "ip_cidr": list(LOCAL_NETWORKS),
                "outbound": "direct",
            }
        )
    route_rules.extend(
        [
            {
                "ip_cidr": list(TELEGRAM_NETWORKS),
                "network": "tcp",
                "outbound": "perch-socks",
            },
            {"network": "udp", "action": "reject"},
            {"port": 853, "action": "reject"},
            # Fastly MASQUE upstream edges only accept CONNECT to ports 80/443
            # and refuse every other port with HTTP 502, which also poisons
            # live :443 streams. Reject those TCP ports locally so the OS gets
            # an immediate refusal and no upstream stream is ever opened.
            {
                "port_range": ["0:79", "81:442", "444:65535"],
                "network": "tcp",
                "action": "reject",
            },
        ]
    )

    log_section: Dict[str, Any] = {
        "level": str(log_level or "info"),
        "timestamp": True,
    }
    if log_output:
        log_section["output"] = str(log_output)

    return {
        "log": log_section,
        "dns": {
            "servers": [
                {
                    "type": "https",
                    "tag": DNS_TUNNEL_TAG,
                    "server": dns_endpoint["server"],
                    "server_port": dns_endpoint["port"],
                    "path": dns_endpoint["path"],
                    # Resolver traffic must ride the VPN.  Without an explicit
                    # detour sing-box dials DNS transports directly, so the
                    # query leaves on the physical adapter even while every
                    # other packet is proxied (a DNS leak).  ``perch-socks``
                    # is an IP-literal endpoint, so this cannot recurse into
                    # the resolver it bootstraps.
                    # Fastly MASQUE upstream proxy edges only accept port 443
                    # CONNECT streams; port 53 is rejected with HTTP 502.
                    # HTTPS DoH with TLS SNI satisfies upstream proxy egress.
                    "detour": "perch-socks",
                    "tls": {
                        "enabled": True,
                        "server_name": dns_endpoint["server_name"],
                        **(
                            {"utls": {"enabled": True, "fingerprint": utls}}
                            if utls
                            else {}
                        ),
                    },
                },
                {
                    "type": "local",
                    "tag": DNS_DIRECT_TAG,
                    "detour": "direct",
                },
            ],
            "final": DNS_TUNNEL_TAG,
            "strategy": strategy,
            "independent_cache": True,
            "disable_cache": False,
        },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {
            "rules": route_rules,
            "final": "perch-socks",
            "auto_detect_interface": bool(auto_detect_interface),
            "find_process": bool(valid_processes),
            "default_domain_resolver": DNS_DIRECT_TAG,
        },
    }


def validate_config(config: Dict[str, Any]) -> None:
    """Fail closed on a config that sing-box would reject or misroute."""
    if not isinstance(config, dict):
        raise ValueError("sing-box config must be an object")
    inbounds = config.get("inbounds")
    outbounds = config.get("outbounds")
    route = config.get("route")
    if not isinstance(inbounds, list) or not inbounds:
        raise ValueError("sing-box config has no inbounds")
    if not isinstance(outbounds, list) or not outbounds:
        raise ValueError("sing-box config has no outbounds")
    if not isinstance(route, dict):
        raise ValueError("sing-box config has no route section")

    tun = next((item for item in inbounds if item.get("type") == "tun"), None)
    if not isinstance(tun, dict):
        raise ValueError("sing-box config has no tun inbound")
    if not tun.get("interface_name"):
        raise ValueError("tun inbound has no interface_name")
    if not isinstance(tun.get("address"), list) or not tun["address"]:
        raise ValueError("tun inbound has no address")
    if not isinstance(tun.get("auto_route"), bool):
        raise ValueError("tun inbound must declare auto_route")
    _validate_port("tun.mtu", tun.get("mtu"))

    tags = {item.get("tag") for item in outbounds if isinstance(item, dict)}
    if route.get("final") not in tags:
        raise ValueError("route.final does not reference an outbound tag")

    dns = config.get("dns")
    if not isinstance(dns, dict):
        raise ValueError("sing-box config has no dns section")
    dns_servers = dns.get("servers")
    if not isinstance(dns_servers, list) or not dns_servers:
        raise ValueError("sing-box config has no dns servers")
    dns_tags = {
        item.get("tag") for item in dns_servers if isinstance(item, dict)
    }
    if dns.get("final") not in dns_tags:
        raise ValueError("dns.final does not reference a dns server tag")
    resolver = route.get("default_domain_resolver")
    if resolver is not None and resolver not in dns_tags:
        raise ValueError(
            "route.default_domain_resolver references unknown dns tag"
        )
    for item in dns_servers:
        if not isinstance(item, dict):
            raise ValueError("dns server must be an object")
        detour = item.get("detour")
        if detour is not None and detour not in tags:
            raise ValueError(
                "dns server references unknown outbound %r" % detour
            )
        if item.get("type") in ("tcp", "https", "tls", "quic", "h3"):
            try:
                ipaddress.ip_address(str(item.get("server") or ""))
            except ValueError as exc:
                raise ValueError(
                    "remote dns server must be an IP literal to avoid a "
                    "bootstrap loop"
                ) from exc

    for rule in route.get("rules") or ():
        if not isinstance(rule, dict):
            raise ValueError("route rule must be an object")
        outbound = rule.get("outbound")
        if outbound is not None and outbound not in tags:
            raise ValueError("route rule references unknown outbound %r" % outbound)
        for cidr in rule.get("ip_cidr") or ():
            _normalize_cidr(str(cidr))

    for item in inbounds:
        if not isinstance(item, dict):
            raise ValueError("sing-box inbound must be an object")
        if "listen_host" in item:
            raise ValueError(
                "inbound field 'listen_host' is unsupported; use 'listen'"
            )
        if item.get("type") == "mixed":
            if not item.get("listen"):
                raise ValueError("mixed inbound has no listen address")
            _validate_port("mixed.listen_port", item.get("listen_port"))
    for item in outbounds:
        if item.get("type") == "socks":
            _validate_port("socks.server_port", item.get("server_port"))


def dumps_config(config: Dict[str, Any]) -> str:
    validate_config(config)
    return json.dumps(config, indent=2)


def write_config(path: Union[Path, str], config: Optional[Dict[str, Any]] = None) -> Path:
    """Atomically write ``config`` (or a freshly built one) and return the path."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = config if config is not None else build_config()
    text = dumps_config(payload)
    tmp = target.with_suffix(target.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, target)
    return target
