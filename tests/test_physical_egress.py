"""Tests for physical egress pinning and TUN loop prevention.

Covers: the physical-IPv4 detector (snapshot-driven, never name-only),
tun2proxy ``--bypass`` destination computation on the app, H2/H3/DoH/
upstream-proxy source-address binding, controller wiring, and the
fail-closed TUN startup gate.
"""

from __future__ import annotations

import asyncio
import socket as socket_module
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import perchvpn.controller as controller_module
import perchvpn.http_client as http_client_module
import perchvpn.proxy.h3_session as h3_session_module
import perchvpn.proxy.session as session_module
from perchvpn.controller import ControllerConfig, ProxyController
from perchvpn.exceptions import ProxyError
from perchvpn.proxy.h3_session import H3ProxySession
from perchvpn.proxy.session import H2ProxySession
from perchvpn.proxy.upstream_proxy import UpstreamProxyConfig, connect_through_upstream_proxy
from perchvpn.proxystate import ProxyCandidate
from perchvpn_windows.app import PerchVPNApp
from perchvpn_windows.config import WindowsConfig
from perchvpn_windows.tun_state_capture import (
    CaptureError,
    NetworkSnapshot,
    detect_physical_ipv4,
)


def _snapshot(
    *,
    physical_ifindex: int = 10,
    tunnel_ifindex: int = 29,
    extra_adapters: Optional[list] = None,
) -> NetworkSnapshot:
    adapters = [
        {"Name": "perchvpn-trial0", "InterfaceGuid": "{A}", "InterfaceIndex": tunnel_ifindex,
         "Status": "Up", "InterfaceDescription": "perch vpn Tunnel"},
        {"Name": "Wi-Fi", "InterfaceGuid": "{B}", "InterfaceIndex": physical_ifindex,
         "Status": "Up", "InterfaceDescription": "Intel(R) Wi-Fi 6 AX201 160MHz"},
    ]
    if extra_adapters:
        adapters += extra_adapters
    return NetworkSnapshot(
routes=[
        {"DestinationPrefix": "0.0.0.0/0", "NextHop": "172.18.0.2",
         "InterfaceIndex": tunnel_ifindex, "RouteMetric": 1, "ifMetric": 1, "PolicyStore": "x"},
        {"DestinationPrefix": "0.0.0.0/0", "NextHop": "192.168.1.1",
         "InterfaceIndex": physical_ifindex, "RouteMetric": 0, "ifMetric": 0, "PolicyStore": "y"},
    ],
        adapters=adapters,
        ip_addresses=[
            {"InterfaceIndex": tunnel_ifindex, "IPAddress": "172.18.0.1",
             "PrefixLength": 20, "AddressFamily": "IPv4"},
            {"InterfaceIndex": physical_ifindex, "IPAddress": "192.168.1.2",
             "PrefixLength": 24, "AddressFamily": "IPv4"},
        ],
        interface_config=[
            {"InterfaceIndex": tunnel_ifindex, "InterfaceAlias": "perchvpn-trial0",
             "AddressFamily": "IPv4", "NlMtu": 1400, "InterfaceMetric": 1000,
             "ConnectionState": 1},
            {"InterfaceIndex": physical_ifindex, "InterfaceAlias": "Wi-Fi",
             "AddressFamily": "IPv4", "NlMtu": 1500, "InterfaceMetric": 25,
             "ConnectionState": 2},
        ],
    )


class TestDetectPhysicalIpv4:
    def test_picks_physical_up_adapter_with_default_route(self):
        snap = _snapshot()
        assert detect_physical_ipv4(snap) == "192.168.1.2"

    def test_excludes_tunnel_adapter_despite_default_route(self):
        snap = _snapshot()
        # Only the tunnel owns a default route if we drop the physical one.
        snap.routes = [r for r in snap.routes if r["InterfaceIndex"] == 29]
        assert detect_physical_ipv4(snap) is None

    def test_trust_virtual_nic_knob_is_fail_closed(self, monkeypatch):
        # Default: a Hyper-V-named adapter never qualifies as egress.
        snap = _snapshot()
        snap.adapters = [
            {"Name": "Ethernet", "InterfaceGuid": "{B}", "InterfaceIndex": 10,
             "Status": "Up", "InterfaceDescription": "Microsoft Hyper-V Network Adapter"},
        ]
        assert detect_physical_ipv4(snap) is None
        # Opt-in knob: same adapter qualifies (Up + IPv4 + default route).
        monkeypatch.setenv("PERCH_TRUST_VIRTUAL_NIC", "1")
        assert detect_physical_ipv4(snap) == "192.168.1.2"
        # Any other value stays off.
        monkeypatch.setenv("PERCH_TRUST_VIRTUAL_NIC", "true")
        snap2 = _snapshot()
        snap2.routes = [r for r in snap2.routes if r["InterfaceIndex"] == 10]
        snap2.adapters = [
            {"Name": "Ethernet", "InterfaceGuid": "{B}", "InterfaceIndex": 10,
             "Status": "Up", "InterfaceDescription": "Microsoft Hyper-V Network Adapter"},
        ]
        snap2.ip_addresses = [
            {"InterfaceIndex": 10, "IPAddress": "192.168.1.2",
             "PrefixLength": 24, "AddressFamily": "IPv4"},
        ]
        assert detect_physical_ipv4(snap2) is None

    def test_requires_up_status(self):
        snap = _snapshot()
        for adapter in snap.adapters:
            if adapter["InterfaceIndex"] == 10:
                adapter["Status"] = "Down"
        assert detect_physical_ipv4(snap) is None

    def test_requires_owned_ipv4(self):
        snap = _snapshot()
        snap.ip_addresses = [ip for ip in snap.ip_addresses if ip["InterfaceIndex"] != 10]
        assert detect_physical_ipv4(snap) is None

    def test_lowest_effective_metric_wins_deterministic(self):
        # Two physical candidates; combined route+interface metric decides,
        # then InterfaceIndex breaks ties.
        extra = [
            {"Name": "Ethernet", "InterfaceGuid": "{C}", "InterfaceIndex": 5,
             "Status": "Up", "InterfaceDescription": "Realtek PCIe GbE"},
        ]
        snap = _snapshot(extra_adapters=extra)
        snap.ip_addresses.append(
            {"InterfaceIndex": 5, "IPAddress": "10.0.5.2", "PrefixLength": 24, "AddressFamily": "IPv4"}
        )
        snap.routes.append(
            {"DestinationPrefix": "0.0.0.0/0", "NextHop": "10.0.5.1",
             "InterfaceIndex": 5, "RouteMetric": 0, "ifMetric": 0, "PolicyStore": "z"}
        )
        snap.interface_config.append(
            {"InterfaceIndex": 5, "InterfaceAlias": "Ethernet", "AddressFamily": "IPv4",
             "NlMtu": 1500, "InterfaceMetric": 25, "ConnectionState": 2}
        )
        # Ethernet if5: 0+25=25; Wi-Fi if10: 0+25=25 -> lowest index (5) wins.
        assert detect_physical_ipv4(snap) == "10.0.5.2"

    def test_tunnel_named_candidates_excluded_even_when_named_first(self):
        snap = _snapshot()
        snap.adapters = list(reversed(snap.adapters))
        assert detect_physical_ipv4(snap) == "192.168.1.2"

    def test_live_capture_failure_returns_none(self):
        def boom():
            raise CaptureError("powershell unavailable")

        with patch("perchvpn_windows.tun_state_capture.capture_snapshot", boom):
            assert detect_physical_ipv4() is None


def _app(tun_on: bool = True) -> PerchVPNApp:
    config = WindowsConfig(tun_enabled=tun_on, tun_opt_in=True)
    app = object.__new__(PerchVPNApp)
    app.config = config
    app._candidate = ProxyCandidate("203.0.113.7", 443, "us", "United States")
    app._resolved_edge_host = "198.51.100.9"
    app._source_bind_ip = "192.168.1.2"
    app._tun_frontend = None
    app._tun_control_plane_ips = []
    app._physical_index = None
    app._control_plane_dial_ips = {}
    app._control_plane_refresh_task = None
    app._tun_helper = None
    app._controller = None
    return app


class TestTunBypassIps:
    def test_includes_source_and_upstream_ips(self):
        config = WindowsConfig(tun_enabled=True, tun_opt_in=True, resolver_dns_provider="system")
        config.upstream_proxy = UpstreamProxyConfig(
            type="socks5", host="192.0.2.44", port=1080, username=None, password=None
        )
        app = object.__new__(PerchVPNApp)
        app.config = config
        app._candidate = ProxyCandidate("203.0.113.7", 443, "us", "United States")
        app._resolved_edge_host = "198.51.100.9"
        bypass = app._tun_bypass_ips("192.168.1.2")
        assert "192.168.1.2" in bypass
        assert "203.0.113.7" in bypass
        assert "198.51.100.9" in bypass
        assert "192.0.2.44" in bypass

    def test_doh_endpoint_ips_included_for_provider(self):
        config = WindowsConfig(tun_enabled=True, tun_opt_in=True, resolver_dns_provider="quad9")
        app = _app()
        app.config = config
        bypass = app._tun_bypass_ips("192.168.1.2")
        assert "9.9.9.9" in bypass
        assert "149.112.112.112" in bypass

    def test_doh_automatic_includes_all_providers(self):
        config = WindowsConfig(tun_enabled=True, tun_opt_in=True, resolver_dns_provider="automatic")
        app = _app()
        app.config = config
        bypass = app._tun_bypass_ips("192.168.1.2")
        assert "1.1.1.1" in bypass
        assert "8.8.8.8" in bypass
        assert "9.9.9.9" in bypass

    def test_domains_never_enter_bypass(self):
        app = _app()
        app._candidate = ProxyCandidate("upstream.example", 443, "us", "United States")
        app._resolved_edge_host = None
        bypass = app._tun_bypass_ips("192.168.1.2")
        assert "upstream.example" not in bypass


class TestControlPlaneEndpointPinning:
    """`resolver_dns_provider="system"` leaves hostnames unresolved, so the
    activation must resolve them on the physical path and pin every answer;
    otherwise the guardian/edge dial follows the TUN default route."""

    async def _activation_bypass(self, app, monkeypatch, answers):
        import perchvpn_windows.app as app_module
        import perchvpn_windows.tun_helper as tun_helper_module
        import perchvpn_windows.tun_state_capture as capture_module

        def fake_resolve(name, *, physical_ip, physical_index):
            assert physical_ip == "192.168.1.2"
            assert physical_index == 10
            return list(answers.get(name) or [])

        monkeypatch.setattr(app_module, "_physical_ipv4_addresses", fake_resolve)
        monkeypatch.setattr(
            capture_module,
            "detect_physical_egress",
            lambda snapshot=None: ("192.168.1.2", 10),
        )
        monkeypatch.setattr(tun_helper_module, "established_remote_endpoints", lambda: [])

        async def _socks_ready():
            return True

        monkeypatch.setattr(app, "_local_socks_ready", _socks_ready)
        launched = {}

        class FakeHelper:
            def __init__(self, **kwargs):
                launched["spec"] = kwargs["spec"]

            async def start(self, timeout=None):
                return {"phase": tun_helper_module.PHASE_READY, "physical": {}}

        monkeypatch.setattr(tun_helper_module, "TunHelperClient", FakeHelper)
        state = await app._start_tun_helper()
        assert state["phase"] == tun_helper_module.PHASE_READY
        return launched["spec"].bypass

    @pytest.mark.asyncio
    async def test_activation_pins_resolved_guardian_and_edge(self, monkeypatch):
        app = _app()
        app.config.resolver_dns_provider = "system"
        app.config.guardian_endpoint = "https://guardian.example"
        app._candidate = ProxyCandidate("edge.example", 443, "us", "United States")
        app._resolved_edge_host = None
        app._tun_baseline = {}
        bypass = await self._activation_bypass(
            app,
            monkeypatch,
            {"edge.example": ["198.51.100.7"], "guardian.example": ["192.0.2.53"]},
        )
        assert "198.51.100.7" in bypass
        assert "192.0.2.53" in bypass
        assert all("." in value for value in bypass)
        # The country edge is not infrastructure: it must stay prunable when
        # the next country supersedes it.  The guardian must survive.
        assert "198.51.100.7" not in app._tun_control_plane_ips
        assert "192.0.2.53" in app._tun_control_plane_ips

    @pytest.mark.asyncio
    async def test_custom_edge_ip_is_pinned_without_resolving_the_candidate(
        self, monkeypatch
    ):
        app = _app()
        app.config.resolver_dns_provider = "system"
        app.config.guardian_endpoint = "https://guardian.example"
        app.config.edge_address = "203.0.113.55:443"
        app._candidate = ProxyCandidate("edge.example", 443, "us", "United States")
        app._resolved_edge_host = None
        app._tun_baseline = {}
        bypass = await self._activation_bypass(
            app, monkeypatch, {"guardian.example": ["192.0.2.53"]}
        )
        assert "203.0.113.55" in bypass
        assert "192.0.2.53" in bypass
        assert all("." in value for value in bypass)
        assert "203.0.113.55" in app._tun_control_plane_ips

    @pytest.mark.asyncio
    async def test_activation_never_uses_the_system_resolver(self, monkeypatch):
        import perchvpn_windows.tun_state_capture as capture_module
        import socket as socket_module

        app = _app()
        app.config.resolver_dns_provider = "system"
        app.config.guardian_endpoint = "https://guardian.example"
        app._candidate = ProxyCandidate("edge.example", 443, "us", "United States")
        app._resolved_edge_host = None
        app._tun_baseline = {}
        monkeypatch.setattr(
            socket_module,
            "getaddrinfo",
            lambda *a, **k: (_ for _ in ()).throw(
                AssertionError("system resolver used for control plane")
            ),
        )
        bypass = await self._activation_bypass(
            app,
            monkeypatch,
            {"edge.example": ["198.51.100.7"], "guardian.example": ["192.0.2.53"]},
        )
        assert "198.51.100.7" in bypass
        assert "192.0.2.53" in bypass
        assert app._physical_index == 10

    @pytest.mark.asyncio
    async def test_unresolvable_edge_does_not_block_helper_launch(self, monkeypatch):
        import perchvpn_windows.app as app_module
        import perchvpn_windows.tun_helper as tun_helper_module

        app = _app()
        app.config.resolver_dns_provider = "system"
        app.config.guardian_endpoint = "https://guardian.example"
        app._candidate = ProxyCandidate("edge.example", 443, "us", "United States")
        app._resolved_edge_host = None
        app._tun_baseline = {}
        monkeypatch.setattr(
            app_module,
            "_physical_ipv4_addresses",
            lambda name, **kwargs: [] if name == "edge.example" else ["192.0.2.53"],
        )
        monkeypatch.setattr(
            app_module,
            "_getaddrinfo_ipv4_addresses",
            lambda name: (_ for _ in ()).throw(OSError("no OS answer")),
        )
        import perchvpn_windows.tun_state_capture as capture_module

        monkeypatch.setattr(
            capture_module,
            "detect_physical_egress",
            lambda snapshot=None: ("192.168.1.2", 10),
        )
        monkeypatch.setattr(tun_helper_module, "established_remote_endpoints", lambda: [])

        async def _socks_ready():
            return True

        monkeypatch.setattr(app, "_local_socks_ready", _socks_ready)
        launched = []

        class FakeHelper:
            def __init__(self, **kwargs):
                launched.append(kwargs["spec"])

            async def start(self, timeout=None):
                return {"phase": tun_helper_module.PHASE_READY}

        monkeypatch.setattr(tun_helper_module, "TunHelperClient", FakeHelper)
        await app._start_tun_helper()
        assert len(launched) == 1

    @pytest.mark.asyncio
    async def test_unresolvable_guardian_does_not_block_helper_launch(self, monkeypatch):
        import perchvpn_windows.app as app_module
        import perchvpn_windows.tun_helper as tun_helper_module

        app = _app()
        app.config.resolver_dns_provider = "system"
        app.config.guardian_endpoint = "https://guardian.example"
        app._candidate = ProxyCandidate("edge.example", 443, "us", "United States")
        app._resolved_edge_host = None
        app._tun_baseline = {}
        monkeypatch.setattr(
            app_module,
            "_physical_ipv4_addresses",
            lambda name, **kwargs: [] if name == "guardian.example" else ["198.51.100.7"],
        )
        monkeypatch.setattr(
            app_module,
            "_getaddrinfo_ipv4_addresses",
            lambda name: (_ for _ in ()).throw(OSError("no OS answer")),
        )
        import perchvpn_windows.tun_state_capture as capture_module

        monkeypatch.setattr(
            capture_module,
            "detect_physical_egress",
            lambda snapshot=None: ("192.168.1.2", 10),
        )
        monkeypatch.setattr(tun_helper_module, "established_remote_endpoints", lambda: [])

        async def _socks_ready():
            return True

        monkeypatch.setattr(app, "_local_socks_ready", _socks_ready)
        launched = []

        class FakeHelper:
            def __init__(self, **kwargs):
                launched.append(kwargs["spec"])

            async def start(self, timeout=None):
                return {"phase": tun_helper_module.PHASE_READY}

        monkeypatch.setattr(tun_helper_module, "TunHelperClient", FakeHelper)
        await app._start_tun_helper()
        assert len(launched) == 1


class TestStartupPhysicalPreflight:
    @pytest.mark.asyncio
    async def test_timeout_does_not_hold_startup(self, monkeypatch):
        import time

        import perchvpn_windows.app as app_module

        app = _app()
        monkeypatch.setattr(app_module, "PREFLIGHT_TIMEOUT_SECONDS", 0.05)
        monkeypatch.setattr(
            app, "_bootstrap_physical_path", lambda: time.sleep(0.4)
        )
        started = time.monotonic()
        await app._startup_physical_preflight()
        assert time.monotonic() - started < 0.35

    @pytest.mark.asyncio
    async def test_preflight_failure_is_logged_and_swallowed(self, monkeypatch, caplog):
        app = _app()

        def fail():
            raise RuntimeError("secondary route preempts physical adapter")

        monkeypatch.setattr(app, "_bootstrap_physical_path", fail)
        await app._startup_physical_preflight()
        assert "secondary route preempts physical adapter" in caplog.text


class TestFailClosedTunGate:
    @pytest.mark.asyncio
    async def test_no_source_ip_disables_tun(self, caplog, monkeypatch):
        app = _app()
        app._source_bind_ip = None

        async def _socks_ready():
            return True

        monkeypatch.setattr(app, "_local_socks_ready", _socks_ready)
        with patch(
            "perchvpn_windows.tun_state_capture.detect_physical_egress",
            MagicMock(return_value=None),
        ):
            await app._start_tun_frontend()
        assert app._tun_frontend is None

    @pytest.mark.asyncio
    async def test_configured_source_ip_starts_tun_with_bypass(self, monkeypatch):
        app = _app(tun_on=True)
        app.config.tun_bypass = ["10.9.9.0/24"]

        async def _socks_ready():
            return True

        monkeypatch.setattr(app, "_local_socks_ready", _socks_ready)
        with patch(
            "perchvpn_windows.app._physical_ipv4_addresses",
            return_value=["192.0.2.53"],
        ), patch(
            "perchvpn_windows.tun_state_capture.detect_physical_egress",
            MagicMock(return_value=("192.168.1.2", 10)),
        ), patch("perchvpn_windows.app.TunFrontend") as frontend_cls:
            frontend_cls.return_value.status = "stopped"
            frontend_cls.return_value.start = AsyncMock()
            await app._start_tun_frontend()
        frontend_cls.assert_called_once()
        kwargs = frontend_cls.call_args.kwargs
        assert "192.168.1.2" in kwargs["bypass"]
        assert "203.0.113.7" in kwargs["bypass"]
        assert "192.0.2.53" in kwargs["bypass"]

    @pytest.mark.asyncio
    async def test_excluded_apps_reach_sidecar_bypass_processes(self, monkeypatch):
        app = _app(tun_on=True)
        app.config.excluded_apps = ["Steam.exe", "qbittorrent.exe"]

        async def _socks_ready():
            return True

        monkeypatch.setattr(app, "_local_socks_ready", _socks_ready)
        with patch(
            "perchvpn_windows.app._physical_ipv4_addresses",
            return_value=[],
        ), patch(
            "perchvpn_windows.tun_state_capture.detect_physical_egress",
            MagicMock(return_value=("192.168.1.2", 10)),
        ), patch("perchvpn_windows.app.TunFrontend") as frontend_cls:
            frontend_cls.return_value.status = "stopped"
            frontend_cls.return_value.start = AsyncMock()
            await app._start_tun_frontend()
        kwargs = frontend_cls.call_args.kwargs
        assert kwargs["bypass_processes"] == ("Steam.exe", "qbittorrent.exe")

    @pytest.mark.asyncio
    async def test_detector_exception_fails_closed(self, monkeypatch):
        app = _app()
        app._source_bind_ip = None

        async def _socks_ready():
            return True

        monkeypatch.setattr(app, "_local_socks_ready", _socks_ready)
        with patch(
            "perchvpn_windows.tun_state_capture.detect_physical_egress",
            MagicMock(side_effect=CaptureError("ps failed")),
        ):
            await app._start_tun_frontend()
        assert app._tun_frontend is None


class UpstreamStub:
    raw_token = "raw-token"


def _controller_config(**overrides) -> ControllerConfig:
    candidate = ProxyCandidate("203.0.113.7", 443, "us", "United States")
    defaults = dict(
        guardian_endpoint="https://guardian.example",
        candidate=candidate,
        upstream_conns=2,
        handshake_timeout=5.0,
        source_bind_ip="192.168.1.2",
    )
    defaults.update(overrides)
    return ControllerConfig(**defaults)


class TestControllerWiring:
    @pytest.mark.asyncio
    async def test_h2_session_receives_source_bind_ip(self):
        config = _controller_config()
        controller = object.__new__(ProxyController)
        controller.config = config
        controller.proxy_pass = UpstreamStub()
        with patch.object(controller_module, "H2ProxySession") as session_cls:
            session = MagicMock()
            session.connect = AsyncMock()
            session.close = AsyncMock()
            session_cls.return_value = session
            await controller._connect_candidate(config.candidate)
        assert session_cls.call_args.kwargs["source_bind_ip"] == "192.168.1.2"
        session.connect.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_h3_session_receives_source_bind_ip(self):
        config = _controller_config(use_http3=True)
        controller = object.__new__(ProxyController)
        controller.config = config
        controller.proxy_pass = UpstreamStub()
        with patch.object(controller_module, "H3ProxySession") as session_cls:
            session = MagicMock()
            session.connect = AsyncMock()
            session.close = AsyncMock()
            session_cls.return_value = session
            await controller._connect_candidate(config.candidate)
        assert session_cls.call_args.kwargs["source_bind_ip"] == "192.168.1.2"

    @pytest.mark.asyncio
    async def test_upstream_proxy_receives_source_bind_ip(self):
        config = _controller_config(
            upstream_proxy=UpstreamProxyConfig(
                type="socks5", host="192.0.2.44", port=1080, username=None, password=None
            )
        )
        controller = object.__new__(ProxyController)
        controller.config = config
        controller.proxy_pass = UpstreamStub()
        forward = MagicMock(return_value=MagicMock())
        with patch.object(controller_module, "H2ProxySession") as session_cls, patch(
            "perchvpn.proxy.session.connect_through_upstream_proxy", forward
        ):
            session = MagicMock()
            session.connect = AsyncMock()
            session.close = AsyncMock()
            session_cls.return_value = session
            await controller._connect_candidate(config.candidate)
        session_cls.assert_called_once()
        src = session_cls.call_args.kwargs["source_bind_ip"]
        assert src == "192.168.1.2"
        kwargs = session_cls.call_args.kwargs
        assert kwargs["upstream_proxy"].host == "192.0.2.44"


class _FakeSocket:
    def __init__(self, *args, **kwargs):
        self.family = args[0] if args else socket_module.AF_INET
        self.type = args[1] if len(args) > 1 else socket_module.SOCK_STREAM
        self.binds: list = []
        self.connects: list = []
        self.sent: list = []
        self.closed = False
        self._recv_script: list = []

    def settimeout(self, timeout):
        self._timeout = timeout

    def bind(self, addr):
        self.binds.append(addr)

    def connect(self, addr):
        self.connects.append(addr)

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, size):
        if self._recv_script:
            return self._recv_script.pop(0)
        return b""

    def close(self):
        self.closed = True


class TestSourceBindUpstreamProxy:
    def _run_with_script(
        self,
        config: UpstreamProxyConfig,
        source_ip: Optional[str],
        script: list,
    ) -> Optional[_FakeSocket]:
        fake = _FakeSocket()
        fake._recv_script = script
        with patch.object(socket_module, "socket", MagicMock(side_effect=lambda *a, **k: fake)):
            connect_through_upstream_proxy(
                config, "target.example", 443, source_bind_ip=source_ip
            )
        return fake

    def test_socks5_binds_before_connect(self):
        fake = self._run_with_script(
            UpstreamProxyConfig(type="socks5", host="192.0.2.44", port=1080, username=None, password=None),
            "192.168.1.2",
            [b"\x05\x00", b"\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00"],
        )
        assert fake.binds == [("192.168.1.2", 0)]
        # bind happened before connect
        assert fake.connects == [("192.0.2.44", 1080)]
        assert not fake.closed

    def test_http_binds_before_connect(self):
        fake = self._run_with_script(
            UpstreamProxyConfig(type="http", host="192.0.2.44", port=3128, username=None, password=None),
            "192.168.1.2",
            [b"HTTP/1.1 200 Connection established\r\n\r\n"],
        )
        assert fake.binds == [("192.168.1.2", 0)]
        assert fake.connects == [("192.0.2.44", 3128)]
        assert not fake.closed

    def test_no_bind_when_unpinned_socks5(self):
        fake = self._run_with_script(
            UpstreamProxyConfig(type="socks5", host="192.0.2.44", port=1080, username=None, password=None),
            None,
            [b"\x05\x00", b"\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00"],
        )
        assert fake.binds == []

    def test_bind_failure_propagates_and_closes_socket(self):
        fake = _FakeSocket()

        def failing_bind(addr):
            raise OSError("cannot assign requested address")

        fake.bind = failing_bind
        with patch.object(socket_module, "socket", MagicMock(side_effect=lambda *a, **k: fake)):
            with pytest.raises(Exception, match="SOCKS5 upstream proxy failed"):
                connect_through_upstream_proxy(
                    UpstreamProxyConfig(type="socks5", host="192.0.2.44", port=1080, username=None, password=None),
                    "target.example",
                    443,
                    source_bind_ip="192.168.1.2",
                )
        assert fake.connects == []
        assert fake.closed is True


class TestH2SourceBindDial:
    @pytest.mark.asyncio
    async def test_local_addr_forwarded_when_pinned(self):
        session = H2ProxySession("upstream.example", 443, "token", source_bind_ip="192.168.1.2")
        await self._dial(session, pinned=True)

    @pytest.mark.asyncio
    async def test_no_local_addr_when_unpinned(self):
        session = H2ProxySession("upstream.example", 443, "token")
        await self._dial(session, pinned=False)

    async def _dial(self, session: H2ProxySession, pinned: bool) -> None:
        class FakeReader:
            async def read(self, size):
                await asyncio.Event().wait()

        class FakeWriter:
            def write(self, data):
                pass

            async def drain(self):
                pass

            def close(self):
                pass

            async def wait_closed(self):
                pass

            def get_extra_info(self, name):
                return None

        recorded = {}

        async def fake_open_connection(*args, **kwargs):
            recorded.update(kwargs)
            return FakeReader(), FakeWriter()

        class FakeH2Conn:
            def __init__(self, *args, **kwargs):
                pass

            def initiate_connection(self):
                pass

            def data_to_send(self):
                return b""

            @property
            def max_outbound_frame_size(self):
                return 16384

            def send_headers(self, *a, **k):
                pass

            def reset_stream(self, *a, **k):
                pass

            def close(self):
                pass

            def update_settings(self, *a, **k):
                pass

        with patch.object(
            session_module.asyncio, "open_connection", side_effect=fake_open_connection
        ), patch.object(session_module, "H2Connection", FakeH2Conn):
            try:
                await asyncio.wait_for(session.connect(timeout=2.0), timeout=5.0)
            except asyncio.TimeoutError:
                pass

        if pinned:
            assert recorded.get("local_addr") == ("192.168.1.2", 0)
        else:
            assert "local_addr" not in recorded
        await session.close()


class TestH3SourceBind:
    @pytest.mark.asyncio
    async def test_pinned_uses_pinned_connector_and_filters_ipv4(self):
        session = H3ProxySession("upstream.example", 443, "token", source_bind_ip="192.168.1.2")
        session._resolve = AsyncMock(return_value=["2001:db8::1", "203.0.113.7"])
        pinned = MagicMock()
        pinned.__aenter__ = AsyncMock(return_value=MagicMock())
        with patch.object(h3_session_module, "_PinnedQuicConnect", MagicMock(return_value=pinned)) as cls, \
             patch.object(h3_session_module, "quic_connect") as stock:
            await session.connect(timeout=5.0)
        cls.assert_called_once()
        assert cls.call_args.kwargs["source_bind_ip"] == "192.168.1.2"
        assert cls.call_args.args == ("203.0.113.7", 443)
        stock.assert_not_called()
        await session.close()

    @pytest.mark.asyncio
    async def test_pinned_fails_closed_without_ipv4(self):
        session = H3ProxySession("upstream.example", 443, "token", source_bind_ip="192.168.1.2")
        session._resolve = AsyncMock(return_value=["2001:db8::1"])
        with patch.object(h3_session_module, "_PinnedQuicConnect") as cls, \
             patch.object(h3_session_module, "quic_connect") as stock:
            with pytest.raises(ProxyError, match="no IPv4 address"):
                await session.connect(timeout=5.0)
        cls.assert_not_called()
        stock.assert_not_called()

    @pytest.mark.asyncio
    async def test_unpinned_uses_stock_connector(self):
        session = H3ProxySession("upstream.example", 443, "token")
        session._resolve = AsyncMock(return_value=["203.0.113.7"])
        stock_cm = MagicMock()
        stock_cm.__aenter__ = AsyncMock(return_value=MagicMock())
        with patch.object(h3_session_module, "quic_connect", MagicMock(return_value=stock_cm)) as stock, \
             patch.object(h3_session_module, "_PinnedQuicConnect") as cls:
            await session.connect(timeout=5.0)
        stock.assert_called_once()
        cls.assert_not_called()
        await session.close()


class TestHttpClientPinning:
    @pytest.fixture(autouse=True)
    def _clean_http_client_module(self):
        saved = (
            http_client_module._client,
            http_client_module._local_address,
            http_client_module._use_doh,
        )
        http_client_module._client = None
        http_client_module._local_address = None
        yield
        http_client_module._client, http_client_module._local_address, http_client_module._use_doh = saved

    class _FakeTransport:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.closed = False

        def close(self):
            self.closed = True

    def test_set_local_address_propagates_to_transports(self):
        created = []
        self._patch_transports(created)
        http_client_module.set_local_address("192.168.1.2")
        http_client_module._build_client(use_doh=True)
        assert created[0].kwargs.get("local_address") == "192.168.1.2"

    def test_clear_local_address_yields_plain_transports(self):
        created = []
        self._patch_transports(created)
        http_client_module.set_local_address("192.168.1.2")
        http_client_module.set_local_address(None)
        created.clear()
        http_client_module._build_client(use_doh=True)
        assert created[0].kwargs.get("local_address") is None

    def _patch_transports(self, created):
        class FakeSyncTransport(self._FakeTransport):
            pass

        class FakeAsyncTransport(self._FakeTransport):
            pass

        def sync_factory(**kwargs):
            obj = FakeSyncTransport(**kwargs)
            created.append(obj)
            return obj

        def async_factory(**kwargs):
            obj = FakeAsyncTransport(**kwargs)
            created.append(obj)
            return obj

        self._patches = [
            patch.object(http_client_module.httpx, "HTTPTransport", sync_factory),
            patch.object(http_client_module.httpx, "AsyncHTTPTransport", async_factory),
        ]
        for p in self._patches:
            p.start()


class TestPhysicalResolutionPath:
    def test_only_dns_servers_routed_via_the_physical_nic_are_used(self, monkeypatch):
        import perchvpn_windows.app as app_module
        import perchvpn_windows.physical_dns as physical_dns_module

        monkeypatch.setattr(
            app_module,
            "_physical_dns_servers",
            lambda index: ["192.168.1.1", "8.8.8.8", "fe80::1"],
        )
        monkeypatch.setattr(
            app_module,
            "_route_interface",
            lambda ip: 10 if ip == "192.168.1.1" else 56,
        )
        calls = {}

        def fake_resolve(name, servers, *, source_ip="", **kwargs):
            calls.update(name=name, servers=list(servers), source_ip=source_ip)
            return ["203.0.113.5"]

        monkeypatch.setattr(physical_dns_module, "resolve_ipv4", fake_resolve)
        addresses = app_module._physical_ipv4_addresses(
            "edge.example", physical_ip="192.168.1.2", physical_index=10
        )
        assert addresses == ["203.0.113.5"]
        assert calls["servers"] == ["192.168.1.1"]
        assert calls["source_ip"] == "192.168.1.2"

    def test_no_physical_dns_server_fails_closed(self, monkeypatch):
        import perchvpn_windows.app as app_module

        monkeypatch.setattr(
            app_module, "_physical_dns_servers", lambda index: ["8.8.8.8"]
        )
        monkeypatch.setattr(app_module, "_route_interface", lambda ip: 56)
        with pytest.raises(RuntimeError, match="unverified path"):
            app_module._physical_ipv4_addresses(
                "edge.example", physical_ip="192.168.1.2", physical_index=10
            )


class TestControlPlanePinRefresh:
    @pytest.mark.asyncio
    async def test_changed_answer_is_pinned_before_the_dial_override_changes(
        self, monkeypatch
    ):
        import perchvpn_windows.app as app_module
        from perchvpn import http_client

        app = _app()
        app.config.guardian_endpoint = "https://guardian.example"
        app._control_plane_dial_ips = {"guardian.example": ["192.0.2.53"]}
        http_client.set_control_plane_address_overrides(
            {"guardian.example": "192.0.2.53"}
        )
        observed = {}

        class FakeHelper:
            def snapshot(self):
                return {"phase": "ready"}

            async def update_bypass(self, ips, persist=None):
                observed["override_during_pin"] = (
                    http_client.control_plane_address_overrides()
                )
                observed["pinned"] = list(ips)

        app._tun_helper = FakeHelper()
        monkeypatch.setattr(
            app_module,
            "_physical_ipv4_addresses",
            lambda name, **kwargs: ["198.51.100.77"],
        )
        try:
            changed = await app._refresh_control_plane_pins("192.168.1.2", 10)
            assert changed is True
            # The new answer must never be dialable before the helper pins it.
            assert observed["override_during_pin"] == {
                "guardian.example": "192.0.2.53"
            }
            assert "198.51.100.77" in observed["pinned"]
            assert http_client.control_plane_address_overrides() == {
                "guardian.example": "198.51.100.77"
            }
            assert "198.51.100.77" in app._tun_control_plane_ips
        finally:
            http_client.set_control_plane_address_overrides(None)

    @pytest.mark.asyncio
    async def test_pin_failure_keeps_the_previous_verified_override(
        self, monkeypatch
    ):
        import perchvpn_windows.app as app_module
        from perchvpn import http_client

        app = _app()
        app.config.guardian_endpoint = "https://guardian.example"
        app._control_plane_dial_ips = {"guardian.example": ["192.0.2.53"]}
        http_client.set_control_plane_address_overrides(
            {"guardian.example": "192.0.2.53"}
        )

        class FailingHelper:
            def snapshot(self):
                return {"phase": "ready"}

            async def update_bypass(self, ips, persist=None):
                raise RuntimeError("pin verification failed")

        app._tun_helper = FailingHelper()
        monkeypatch.setattr(
            app_module,
            "_physical_ipv4_addresses",
            lambda name, **kwargs: ["198.51.100.77"],
        )
        try:
            with pytest.raises(RuntimeError, match="pin verification failed"):
                await app._refresh_control_plane_pins("192.168.1.2", 10)
            assert http_client.control_plane_address_overrides() == {
                "guardian.example": "192.0.2.53"
            }
        finally:
            http_client.set_control_plane_address_overrides(None)
        assert "198.51.100.77" not in app._tun_control_plane_ips

    @pytest.mark.asyncio
    async def test_unchanged_answer_does_not_touch_the_helper(self, monkeypatch):
        import perchvpn_windows.app as app_module

        app = _app()
        app.config.guardian_endpoint = "https://guardian.example"
        app._control_plane_dial_ips = {"guardian.example": ["192.0.2.53"]}
        pins = []

        class FakeHelper:
            def snapshot(self):
                return {"phase": "ready"}

            async def update_bypass(self, ips, persist=None):
                pins.append(ips)

        app._tun_helper = FakeHelper()
        monkeypatch.setattr(
            app_module,
            "_physical_ipv4_addresses",
            lambda name, **kwargs: ["192.0.2.53"],
        )
        assert await app._refresh_control_plane_pins("192.168.1.2", 10) is False
        assert pins == []


class TestEdgeHostPins:
    @pytest.mark.asyncio
    async def test_sessions_dial_the_verified_pin_for_each_candidate(self):
        candidate = ProxyCandidate("edge.example", 443, "us", "United States")
        alternate = ProxyCandidate("alt.example", 443, "us", "United States")
        config = _controller_config(
            candidate=candidate,
            alternates=[alternate],
            edge_hosts={"edge.example": "198.51.100.7", "alt.example": "198.51.100.8"},
        )
        controller = object.__new__(ProxyController)
        controller.config = config
        controller.proxy_pass = UpstreamStub()
        with patch.object(controller_module, "H2ProxySession") as session_cls:
            session = MagicMock()
            session.connect = AsyncMock()
            session.close = AsyncMock()
            session_cls.return_value = session
            await controller._connect_candidate(candidate)
            await controller._connect_candidate(alternate)

        assert [
            call.args[0] for call in session_cls.call_args_list
        ] == ["edge.example", "alt.example"]
        assert [
            call.kwargs["edge_host"] for call in session_cls.call_args_list
        ] == ["198.51.100.7", "198.51.100.8"]

    def test_apply_edge_pins_drops_unpinnable_failover_edges(self):
        candidate = ProxyCandidate("edge.example", 443, "us", "United States")
        alternate = ProxyCandidate("alt.example", 443, "us", "United States")
        config = _controller_config(candidate=candidate, alternates=[alternate])
        controller = object.__new__(ProxyController)
        controller.config = config
        controller._candidates = [candidate, alternate]
        controller._candidate_index = 1

        controller.apply_edge_pins({"edge.example": "198.51.100.7"}, ["alt.example"])

        assert [entry.host for entry in controller._candidates] == ["edge.example"]
        assert config.edge_hosts == {"edge.example": "198.51.100.7"}
        assert controller._candidate_index == 0

    @pytest.mark.asyncio
    async def test_h3_dials_the_pin_without_resolving(self):
        from perchvpn.proxy.h3_session import H3ProxySession

        session = H3ProxySession(
            "edge.example", 443, "token", edge_host="198.51.100.7"
        )
        assert await session._resolve(1.0) == ["198.51.100.7"]


class TestCountrySwitchPins:
    @pytest.mark.asyncio
    async def test_switch_resolves_physically_and_blocks_unpinnable_edges(
        self, monkeypatch
    ):
        import perchvpn_windows.app as app_module

        app = _app()
        app._physical_index = 10
        primary = ProxyCandidate("edge.example", 443, "us", "United States")
        alternate = ProxyCandidate("alt.example", 443, "us", "United States")
        broken = ProxyCandidate("broken.example", 443, "se", "Sweden")

        answers = {
            "edge.example": ["198.51.100.7"],
            "alt.example": ["198.51.100.8"],
        }

        def fake(name, *, physical_ip, physical_index):
            if name not in answers:
                raise RuntimeError("no physical DNS answer")
            return answers[name]

        monkeypatch.setattr(app_module, "_physical_ipv4_addresses", fake)
        monkeypatch.setattr(
            app_module,
            "_getaddrinfo_ipv4_addresses",
            lambda name: [],
        )

        ips, targets, unresolved, blocked, pins = await app._switch_bypass_ips(
            primary, "", [alternate, broken]
        )

        assert unresolved == []
        assert blocked == ["broken.example"]
        assert pins == {
            "edge.example": "198.51.100.7",
            "alt.example": "198.51.100.8",
        }
        assert "198.51.100.7" in targets
        assert "198.51.100.8" in ips

    @pytest.mark.asyncio
    async def test_switch_falls_back_to_os_resolver_when_physical_dns_blocked(
        self, monkeypatch
    ):
        import perchvpn_windows.app as app_module

        app = _app()
        app._physical_index = 10
        primary = ProxyCandidate("edge.example", 443, "us", "United States")

        def blocked_physical(name, *, physical_ip, physical_index):
            raise TimeoutError("physical DNS blocked")

        monkeypatch.setattr(
            app_module, "_physical_ipv4_addresses", blocked_physical
        )
        monkeypatch.setattr(
            app_module,
            "_getaddrinfo_ipv4_addresses",
            lambda name: ["198.51.100.7"],
        )

        ips, targets, unresolved, blocked, pins = await app._switch_bypass_ips(
            primary, ""
        )

        assert unresolved == []
        assert blocked == []
        assert pins == {"edge.example": "198.51.100.7"}
        assert "198.51.100.7" in targets
        assert "198.51.100.7" in ips

    @pytest.mark.asyncio
    async def test_switch_waits_for_physical_doh_fallback(self, monkeypatch):
        import time

        import perchvpn_windows.app as app_module

        app = _app()
        app._physical_index = 10
        primary = ProxyCandidate("edge.example", 443, "us", "United States")

        def slow_physical(name, *, physical_ip, physical_index):
            time.sleep(1.5)
            return ["198.51.100.7"]

        monkeypatch.setattr(
            app_module, "_physical_ipv4_addresses", slow_physical
        )

        ips, targets, unresolved, blocked, pins = await app._switch_bypass_ips(
            primary, ""
        )

        assert unresolved == []
        assert blocked == []
        assert pins == {"edge.example": "198.51.100.7"}
        assert "198.51.100.7" in targets
        assert "198.51.100.7" in ips


@pytest.mark.asyncio
async def test_control_plane_bypass_ips_times_out_and_falls_back_to_os(monkeypatch):
    import time
    import perchvpn_windows.app as app_module
    from types import SimpleNamespace

    app = _app()
    app.config = SimpleNamespace(
        guardian_endpoint="https://vpn.mozilla.org",
        edge_address="",
        upstream_proxy_enabled=False,
        upstream_proxy=None,
    )

    def slow_physical(name, *, physical_ip, physical_index):
        time.sleep(3.0)
        return ["203.0.113.99"]

    def fake_getaddrinfo(name):
        return ["198.51.100.55"]

    monkeypatch.setattr(app_module, "_physical_ipv4_addresses", slow_physical)
    monkeypatch.setattr(app_module, "_getaddrinfo_ipv4_addresses", fake_getaddrinfo)

    start = time.monotonic()
    persistent, active_edge, resolved = await app._control_plane_bypass_ips(
        physical_ip="192.168.1.5", physical_index=10
    )
    elapsed = time.monotonic() - start

    assert elapsed < 2.5
    assert "198.51.100.55" in persistent
    assert resolved["vpn.mozilla.org"] == ["198.51.100.55"]


@pytest.mark.asyncio
async def test_control_plane_bypass_ips_falls_back_to_cached_ip(monkeypatch):
    import perchvpn_windows.app as app_module
    from types import SimpleNamespace

    app = _app()
    app.config = SimpleNamespace(
        guardian_endpoint="https://vpn.mozilla.org",
        edge_address="",
        upstream_proxy_enabled=False,
        upstream_proxy=None,
    )

    def failing_physical(name, *, physical_ip, physical_index):
        raise RuntimeError("physical DNS unavailable")

    def failing_getaddrinfo(name):
        raise RuntimeError("OS resolver unavailable")

    app._record_cached_ip("vpn.mozilla.org", ["198.51.100.77"])

    monkeypatch.setattr(app_module, "_physical_ipv4_addresses", failing_physical)
    monkeypatch.setattr(app_module, "_getaddrinfo_ipv4_addresses", failing_getaddrinfo)

    persistent, active_edge, resolved = await app._control_plane_bypass_ips(
        physical_ip="192.168.1.5", physical_index=10
    )

    assert "198.51.100.77" in persistent
    assert resolved["vpn.mozilla.org"] == ["198.51.100.77"]
