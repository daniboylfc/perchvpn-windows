"""Regression tests for the 2026-11-14 01:52 diagnostic fix set:

1. Pre-start gate uses the concurrent pool snapshot again (batched capture
   stays opt-in; its five CIM cmdlets measured ~12 s serial in one process).
2. sing-box config persists the sidecar log to ``sing-box.log``.
3. A post-pin tunnel that never carries traffic fast-fails to ``degraded``
   with the probe error and a competing-default-route hint instead of
   keeping the UI on ``connecting`` forever.
4. ``/api/disconnect`` answers within a bounded wait even when the restart
   task is mid-teardown.
5. Tailscale/CGNAT 100.64.0.0/10 stays outside the TUN and the physical-DNS
   refusal names the competing ifIndex.
"""

from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace

import pytest

from perchvpn_windows import singbox_config, tun_status
from perchvpn_windows.tun_frontend import (
    _EGRESS_STALL_DEGRADED_SECONDS,
    _RECONCILE_INTERVAL_STEADY_SECONDS,
    TunFrontend,
)
from perchvpn_windows.tun_status import AdapterEvidence

import src.perchvpn_windows.api as api_module


class TestPreStartGateUsesFastSnapshot:
    def test_recovery_gate_defaults_to_native_preferred_capture(self, monkeypatch):
        from perchvpn_windows import tun_recovery
        from perchvpn_windows.tun_state_capture import (
            capture_snapshot_preferred as preferred,
        )

        gate = tun_recovery.TunRecoveryGate(enabled=True)
        assert gate._snapshot_capture is preferred

    def test_native_capture_fails_closed_to_batched_capture(self, monkeypatch):
        from perchvpn_windows import tun_state_capture as cap

        def native_boom():
            raise cap.CaptureError("native unavailable")

        fallback = cap.NetworkSnapshot(routes=[{"DestinationPrefix": "0.0.0.0/0"}])
        monkeypatch.setattr(cap, "capture_snapshot_native", native_boom)
        monkeypatch.setattr(cap, "capture_snapshot_batched", lambda: fallback)
        assert cap.capture_snapshot_preferred() is fallback

    def test_batched_capture_still_available_as_opt_in(self, monkeypatch):
        from perchvpn_windows.tun_state_capture import (
            capture_snapshot_batched,
            capture_snapshot_preferred,
        )

        payload = {
            "routes": [
                {
                    "DestinationPrefix": "0.0.0.0/0",
                    "NextHop": "192.168.1.1",
                    "InterfaceIndex": 10,
                    "RouteMetric": 0,
                    "ifMetric": None,
                    "PolicyStore": "ActiveStore",
                }
            ],
            "dns": [
                {
                    "InterfaceIndex": 10,
                    "AddressFamily": 2,
                    "ServerAddresses": ["192.168.1.1"],
                }
            ],
            "adapters": [
                {
                    "Name": "Ethernet",
                    "InterfaceGuid": "{11111111-1111-1111-1111-111111111111}",
                    "InterfaceIndex": 10,
                    "Status": "Up",
                }
            ],
            "ip_addresses": [
                {
                    "InterfaceIndex": 10,
                    "IPAddress": "192.168.1.2",
                    "PrefixLength": 24,
                    "AddressFamily": 2,
                }
            ],
            "interface_config": [
                {
                    "InterfaceIndex": 10,
                    "AddressFamily": 2,
                    "NlMtu": 1500,
                    "InterfaceMetric": 25,
                    "ConnectionState": 2,
                }
            ],
            "winhttp_proxy": "Direct access (no proxy server).",
            "errors": {},
        }
        monkeypatch.setattr(
            "perchvpn_windows.tun_state_capture._run_ps",
            lambda script, timeout=30.0: __import__("json").dumps(payload),
        )
        assert isinstance(capture_snapshot_batched(), object)
        assert isinstance(capture_snapshot_preferred(), object)


class TestSingBoxLogOutput:
    def test_log_output_configured_when_provided(self):
        cfg = singbox_config.build_config(log_output=r"C:\x\PerchVPN\sing-box.log")
        log = cfg["log"]
        assert log["level"] == "info"
        assert log["timestamp"] is True
        assert log["output"] == r"C:\x\PerchVPN\sing-box.log"

    def test_log_output_absent_by_default(self):
        cfg = singbox_config.build_config()
        assert "output" not in cfg["log"]

    def test_build_command_persists_sidecar_log_next_to_config(self, monkeypatch):
        import src.perchvpn_windows.tun_frontend as tf_module

        t = TunFrontend(
            enabled=True,
            opt_in=True,
            is_elevated=lambda: True,
            executable_path="/opt/fake/sing-box",
        )
        t._configured = True
        monkeypatch.setattr(
            t, "_resolve_executable", lambda: "/opt/fake/sing-box"
        )
        monkeypatch.setattr(
            tf_module.singbox_config,
            "available_mixed_port",
            lambda: None,
        )
        captured = {}

        def fake_write_config(path, config):
            captured["config"] = config
            return str(path)

        monkeypatch.setattr(
            tf_module.singbox_config, "write_config", fake_write_config
        )
        monkeypatch.setattr(
            t, "_singbox_extra_args", lambda: []
        )
        t.build_command()
        log = captured["config"]["log"]
        assert log["output"].endswith("sing-box.log")


class TestCgnatExclusion:
    def test_cgnat_space_is_excluded_from_the_tun(self):
        cfg = singbox_config.build_config()
        excluded = cfg["inbounds"][0]["route_exclude_address"]
        for expected in singbox_config.CGNAT_NETWORKS:
            assert expected in excluded

    def test_cgnat_helper_never_overlaps_local_networks(self):
        import ipaddress

        local = [ipaddress.ip_network(n) for n in singbox_config.LOCAL_NETWORKS]
        for net in singbox_config.CGNAT_NETWORKS:
            parsed = ipaddress.ip_network(net)
            for other in local:
                assert not parsed.overlaps(other)


class TestDnsRefusalNamesCompetingIfIndex:
    def test_rejection_diagnostics_returned(self, monkeypatch):
        import perchvpn_windows.app as app_module

        monkeypatch.setattr(
            app_module, "_physical_dns_servers", lambda index: ["1.1.1.1", "9.9.9.9"]
        )
        monkeypatch.setattr(
            app_module,
            "_route_interface",
            lambda ip: 56,
        )
        selected, rejected = app_module._select_physical_dns_servers(
            9, ["1.1.1.1", "9.9.9.9"], route_lookup=lambda ip: 56
        )
        assert selected == []
        assert sorted(rejected) == [("1.1.1.1", 56), ("9.9.9.9", 56)]

    def test_refusal_warning_includes_competing_ifindex(self, monkeypatch):
        import perchvpn_windows.app as app_module

        monkeypatch.setattr(
            app_module, "_physical_dns_servers", lambda index: ["1.1.1.1"]
        )
        monkeypatch.setattr(app_module, "_route_interface", lambda ip: 56)
        with pytest.raises(RuntimeError) as exc:
            app_module._physical_ipv4_addresses(
                "edge.example", physical_ip="192.168.1.2", physical_index=10
            )
        message = str(exc.value)
        assert "unverified path" in message
        assert "ifIndex 56" in message


class TestPostPinEgressStallFastFail:
    def _frontend(self) -> TunFrontend:
        t = TunFrontend(enabled=True, opt_in=True, is_elevated=lambda: True)
        evidence = AdapterEvidence()
        evidence.present = True
        evidence.up = True
        evidence.ipv4 = ["172.19.0.1"]
        evidence.routes = [
            {"destination_prefix": "0.0.0.0/1"},
            {"destination_prefix": "128.0.0.0/1"},
        ]
        t._evidence = evidence
        t._configured = True
        t._process = SimpleNamespace(returncode=None)  # process_alive = True
        return t

    @pytest.mark.asyncio
    async def test_stall_under_threshold_keeps_connecting(self):
        t = self._frontend()
        t._metric_pinned = True
        t._pinned_at = time.monotonic() - (_EGRESS_STALL_DEGRADED_SECONDS - 5)
        t._egress = {"ok": False, "error": "connect timeout"}
        await t._track_egress_stall(time.monotonic())
        assert t._stall_degraded is False
        state = t._update_classification()
        assert state != tun_status.STATE_DEGRADED

    @pytest.mark.asyncio
    async def test_stall_over_threshold_degrades_with_hint(self, monkeypatch):
        t = self._frontend()
        t._metric_pinned = True
        t._pinned_at = time.monotonic() - (_EGRESS_STALL_DEGRADED_SECONDS + 1)
        t._egress = {"ok": False, "error": "connect timeout"}

        async def fake_foreign(name, *, timeout=5.0):
            return "singbox_tun"

        monkeypatch.setattr(tun_status, "detect_foreign_default_tunnel", fake_foreign)
        await t._track_egress_stall(time.monotonic())
        assert t._stall_degraded is True
        state = t._update_classification()
        assert state == tun_status.STATE_DEGRADED
        assert "no traffic through TUN" in t._state_detail
        assert "connect timeout" in t._state_detail
        assert "singbox_tun" in t._state_detail
        # Settled failure backs off instead of spinning the 3 s poller.
        assert t._steady_state_now() is True
        assert t._reconcile_interval_for_state() == _RECONCILE_INTERVAL_STEADY_SECONDS

    @pytest.mark.asyncio
    async def test_stall_recovers_when_egress_ok(self, monkeypatch):
        t = self._frontend()
        t._metric_pinned = True
        t._pinned_at = time.monotonic() - (_EGRESS_STALL_DEGRADED_SECONDS + 1)
        t._egress = {"ok": False, "error": "connect timeout"}

        async def fake_foreign(name, *, timeout=5.0):
            return None

        monkeypatch.setattr(tun_status, "detect_foreign_default_tunnel", fake_foreign)
        await t._track_egress_stall(time.monotonic())
        assert t._stall_degraded is True

        t._egress = {"ok": True, "error": None}
        await t._track_egress_stall(time.monotonic())
        assert t._stall_degraded is False
        assert t._state_detail == "" or "no traffic" not in t._state_detail

    def test_detect_foreign_default_tunnel_parses_aliases(self, monkeypatch):
        monkeypatch.setattr(tun_status.sys, "platform", "win32")
        monkeypatch.setattr(
            tun_status, "_run_ps", lambda script, timeout=30.0: "singbox_tun\r\n"
        )
        result = asyncio.run(
            tun_status.detect_foreign_default_tunnel("PerchVPN")
        )
        assert result == "singbox_tun"

    def test_detect_foreign_default_tunnel_none_when_only_own(self, monkeypatch):
        monkeypatch.setattr(tun_status.sys, "platform", "win32")
        monkeypatch.setattr(tun_status, "_run_ps", lambda script, timeout=30.0: "")
        result = asyncio.run(
            tun_status.detect_foreign_default_tunnel("PerchVPN")
        )
        assert result is None

    def test_state_transitions_are_logged(self, caplog):
        import logging

        t = TunFrontend(enabled=True, opt_in=True, is_elevated=lambda: True)
        with caplog.at_level(logging.INFO, logger="perchvpn_windows.tun_frontend"):
            t._update_classification()
        t._evidence = None
        messages = [r.getMessage() for r in caplog.records]
        assert any("TUN state transition" in m for m in messages)


class TestBoundedDisconnect:
    @pytest.fixture(autouse=True)
    def _reset_globals(self):
        original_app = api_module._app
        original_restart = api_module._restart_task
        yield
        api_module._app = original_app
        api_module._restart_task = original_restart

    @pytest.mark.asyncio
    async def test_disconnect_answers_within_bounded_wait(self):
        started = asyncio.Event()
        release = asyncio.Event()

        async def stuck_restart():
            started.set()
            try:
                await asyncio.sleep(60)
            except asyncio.CancelledError:
                release.set()
                raise

        api_module._restart_task = asyncio.create_task(stuck_restart())
        task_ref = api_module._restart_task  # keep alive: no premature GC
        api_module._app = None  # disconnect returns "Not connected" after the wait
        await started.wait()  # the task must run so cancellation is delivered

        loop = asyncio.get_running_loop()
        start = loop.time()
        result = await asyncio.wait_for(api_module.disconnect(), timeout=10.0)
        elapsed = loop.time() - start

        assert result == {"success": True, "detail": "Not connected"}
        assert elapsed < 7.0  # bounded wait (5 s) + scheduler slack
        assert api_module._restart_task is None
        await asyncio.wait_for(release.wait(), timeout=1.0)
        assert task_ref.cancelled()


class TestRouteCoverageVsExcludedSentinels:
    """Regression for the 12:19 run: route_exclude_address carves /32 holes
    (1.0.0.1/32, 8.8.8.8/32 DoH pins) into sing-box's decomposed /1 table,
    so the coverage sentinels sat inside intentional gaps and the
    classifier rejected a perfectly routed tunnel, parking the UI in
    "Setting up tunnel..." for the whole session."""

    @staticmethod
    def _evidence(excluded=()):
        evidence = AdapterEvidence()
        evidence.present = True
        evidence.up = True
        evidence.ipv4 = ["172.19.0.1"]
        evidence.routes = [
            {"destination_prefix": "0.0.0.0/1"},
            {"destination_prefix": "128.0.0.0/1"},
        ]
        evidence.excluded_networks = tuple(excluded)
        return evidence

    def test_excluded_resolver_pins_do_not_break_coverage(self):
        import ipaddress

        excluded = (
            ipaddress.ip_network("1.0.0.1/32"),
            ipaddress.ip_network("8.8.8.8/32"),
        )
        assert self._evidence(excluded).default_route_effective is True

    def test_without_exclusion_context_still_false_for_carved_holes(self):
        # Documents the original false negative: sing-box's real table has
        # no literal /1s — route_exclude_address decomposes 0.0.0.0/1 into
        # sub-/1 prefixes, leaving a hole exactly at the excluded sentinel
        # (here: 8.0.0.0/5 ... 15.255.255.255 uncovered, where 8.8.8.8 lives).
        evidence = self._evidence()
        evidence.routes = [
            {"destination_prefix": "0.0.0.0/5"},   # 0-7
            {"destination_prefix": "16.0.0.0/4"},  # 16-31
            {"destination_prefix": "32.0.0.0/4"},  # 32-47
            {"destination_prefix": "48.0.0.0/4"},  # 48-63
            {"destination_prefix": "128.0.0.0/2"},
            {"destination_prefix": "192.0.0.0/2"},
        ]
        assert evidence.default_route_effective is False

    def test_excluded_context_recovers_the_same_decomposed_table(self):
        import ipaddress

        evidence = self._evidence(
            (
                ipaddress.ip_network("1.0.0.1/32"),
                ipaddress.ip_network("8.8.8.8/32"),
            )
        )
        evidence.routes = [
            {"destination_prefix": "0.0.0.0/5"},
            {"destination_prefix": "16.0.0.0/4"},
            {"destination_prefix": "32.0.0.0/4"},
            {"destination_prefix": "48.0.0.0/4"},
            {"destination_prefix": "128.0.0.0/2"},
            {"destination_prefix": "192.0.0.0/2"},
        ]
        assert evidence.default_route_effective is True

    def test_host_routes_never_satisfy_coverage(self):
        import ipaddress

        evidence = self._evidence(
            (ipaddress.ip_network("1.0.0.1/32"), ipaddress.ip_network("8.8.8.8/32"))
        )
        evidence.routes = [
            {"destination_prefix": "1.0.0.1/32"},
            {"destination_prefix": "8.8.8.8/32"},
        ]
        assert evidence.default_route_effective is False

    def test_excluded_networks_helper_is_ipv4_and_includes_pins(self):
        import ipaddress

        networks = singbox_config.excluded_networks()
        assert ipaddress.ip_network("100.64.0.0/10") in networks
        assert ipaddress.ip_network("1.1.1.1/32") in networks
        assert all(n.version == 4 for n in networks)

    @pytest.mark.asyncio
    async def test_egress_verified_outranks_missing_coverage(self):
        import ipaddress

        t = TunFrontend(enabled=True, opt_in=True, is_elevated=lambda: True)
        evidence = self._evidence(
            (ipaddress.ip_network("1.0.0.1/32"), ipaddress.ip_network("8.8.8.8/32"))
        )
        evidence.routes = [
            {"destination_prefix": "1.0.0.1/32"},
            {"destination_prefix": "8.8.8.8/32"},
        ]
        t._evidence = evidence
        t._configured = True
        t._process = SimpleNamespace(returncode=None)
        t._egress = {
            "ok": True,
            "ipv4": {"ok": True, "ip": "198.51.100.7", "country": "GB"},
        }
        state = t._update_classification()
        # Observed system egress beats the coverage heuristic: the run must
        # not park in adapter_ready while traffic demonstrably flows.
        assert state != tun_status.STATE_ADAPTER_READY

    @pytest.mark.asyncio
    async def test_adapter_ready_stall_reaches_degraded_after_20s(self, monkeypatch):
        t = TunFrontend(enabled=True, opt_in=True, is_elevated=lambda: True)
        evidence = AdapterEvidence()
        evidence.present = True
        evidence.up = True
        evidence.ipv4 = ["172.19.0.1"]
        evidence.routes = []  # coverage never confirmed -> adapter_ready
        t._evidence = evidence
        t._configured = True
        t._process = SimpleNamespace(returncode=None)
        t._metric_pinned = True
        t._pinned_at = time.monotonic() - (_EGRESS_STALL_DEGRADED_SECONDS + 1)
        t._egress = {"ok": False, "error": "connect timeout"}

        async def fake_foreign(name, *, timeout=5.0):
            return "singbox_tun"

        monkeypatch.setattr(tun_status, "detect_foreign_default_tunnel", fake_foreign)
        await t._track_egress_stall(time.monotonic())
        assert t._stall_degraded is True
        state = t._update_classification()
        assert state == tun_status.STATE_DEGRADED
        assert "no traffic through TUN" in t._state_detail
        # adapter_ready stall also counts as steady for cadence backoff.
        assert t._steady_state_now() is True
        assert t._reconcile_interval_for_state() == _RECONCILE_INTERVAL_STEADY_SECONDS


class TestNativeFastPath:
    """The hot path must be iphlpapi, not PowerShell.

    Measured on the production host: batch PowerShell probe 6.3-7.6 s vs
    0.05-0.08 s native; competing/foreign default-route checks 2.9 s vs
    ~0.05 s.  These tests pin the delegation so a future refactor cannot
    silently reintroduce the PowerShell call on the readiness loop.
    """

    def _adapters(self):
        return [
            {
                "Name": "singbox_tun",
                "InterfaceDescription": "Wintun Userspace Tunnel",
                "InterfaceIndex": 70,
                "Status": "Up",
                "unicast": [
                    {"IPAddress": "172.18.0.1", "AddressFamily": 2, "PrefixLength": 30},
                    {"IPAddress": "fe80::1", "AddressFamily": 23, "PrefixLength": 64},
                ],
                "dns": [{"IPAddress": "172.18.0.2", "AddressFamily": 2}],
            },
            {
                "Name": "Wi-Fi",
                "InterfaceDescription": "Intel Wi-Fi 6 AX201",
                "InterfaceIndex": 9,
                "Status": "Up",
                "unicast": [
                    {"IPAddress": "192.168.1.5", "AddressFamily": 2, "PrefixLength": 24}
                ],
                "dns": [],
            },
        ]

    def _routes(self, family):
        return [
            {
                "DestinationPrefix": "0.0.0.0/0",
                "NextHop": "172.18.0.2",
                "InterfaceIndex": 70,
                "RouteMetric": 0,
                "ifMetric": 0,
            },
            {
                "DestinationPrefix": "0.0.0.0/0",
                "NextHop": "192.168.1.1",
                "InterfaceIndex": 9,
                "RouteMetric": 0,
                "ifMetric": 35,
            },
        ]

    def _wire(self, monkeypatch):
        from perchvpn_windows import iphelper

        monkeypatch.setattr(tun_status.sys, "platform", "win32")
        monkeypatch.setattr(iphelper, "available", lambda: True)
        monkeypatch.setattr(iphelper, "adapters_native", self._adapters)
        monkeypatch.setattr(iphelper, "routes_native", self._routes)
        monkeypatch.setattr(
            iphelper, "interface_entry_native", lambda idx: {"InterfaceMetric": 35}
        )
        monkeypatch.setattr(
            tun_status,
            "_run_ps",
            lambda *a, **k: pytest.fail("PowerShell must not run on the hot path"),
        )

    def test_probe_adapter_uses_native_evidence(self, monkeypatch):
        self._wire(monkeypatch)
        evidence = asyncio.run(tun_status.probe_adapter("singbox_tun"))
        assert evidence.present and evidence.up
        assert evidence.if_index == 70
        assert evidence.ipv4 == ["172.18.0.1"]
        assert evidence.ipv6 == []
        assert evidence.dns_servers == ["172.18.0.2"]
        assert {r["destination_prefix"] for r in evidence.routes} == {"0.0.0.0/0"}
        assert {r["interface_metric"] for r in evidence.routes} == {0}

    def test_probe_adapter_native_absence_is_authoritative(self, monkeypatch):
        self._wire(monkeypatch)
        evidence = asyncio.run(tun_status.probe_adapter("PerchVPN"))
        assert evidence.present is False
        assert "not present" in evidence.error

    def test_probe_adapter_falls_back_when_native_incomplete(self, monkeypatch):
        from perchvpn_windows import iphelper

        self._wire(monkeypatch)
        monkeypatch.setattr(iphelper, "routes_native", lambda family: [])
        monkeypatch.setattr(
            tun_status, "_run_ps", lambda script, timeout=30.0: "present=0"
        )
        evidence = asyncio.run(tun_status.probe_adapter("PerchVPN"))
        assert evidence.present is False

    def test_detect_competing_tunnel_native(self, monkeypatch):
        self._wire(monkeypatch)
        assert asyncio.run(tun_status.detect_competing_tunnel("PerchVPN")) == "singbox_tun"

    def test_detect_foreign_default_tunnel_prefers_tunnel_like(self, monkeypatch):
        self._wire(monkeypatch)
        assert asyncio.run(tun_status.detect_foreign_default_tunnel("PerchVPN")) == "singbox_tun"

    def test_detect_foreign_default_tunnel_ignores_own_alias(self, monkeypatch):
        self._wire(monkeypatch)
        from perchvpn_windows import iphelper

        monkeypatch.setattr(
            iphelper, "adapters_native", lambda: [self._adapters()[0]]
        )
        assert asyncio.run(tun_status.detect_foreign_default_tunnel("singbox_tun")) is None


class TestCompetingTunnelPreflight:
    def test_detect_competing_tunnel_matches_tun_descriptions(self, monkeypatch):
        monkeypatch.setattr(tun_status.sys, "platform", "win32")
        monkeypatch.setattr(
            tun_status,
            "_run_ps",
            lambda script, timeout=30.0: "singbox_tun|Wintun Userspace Tunnel\r\n",
        )
        result = asyncio.run(tun_status.detect_competing_tunnel("PerchVPN"))
        assert result == "singbox_tun"

    def test_detect_competing_tunnel_ignores_physical_default_route(self, monkeypatch):
        monkeypatch.setattr(tun_status.sys, "platform", "win32")
        monkeypatch.setattr(
            tun_status,
            "_run_ps",
            lambda script, timeout=30.0: "Wi-Fi|Intel(R) Wi-Fi 6 AX201 160MHz\r\n",
        )
        result = asyncio.run(tun_status.detect_competing_tunnel("PerchVPN"))
        assert result is None

    def test_detect_competing_tunnel_non_windows_is_none(self, monkeypatch):
        monkeypatch.setattr(tun_status.sys, "platform", "linux")
        assert asyncio.run(tun_status.detect_competing_tunnel("PerchVPN")) is None

    @pytest.mark.asyncio
    async def test_start_surfaces_competing_tunnel_immediately(self, monkeypatch, caplog):
        """Preflight detection surfaces the conflict (log + state detail)
        without blocking the start: a foreign singbox_tun coexists with
        PerchVPN TUN in practice, so the message must be actionable, not a
        hard refusal.  The hint clears once egress proves coexistence."""
        import logging

        t = TunFrontend(
            enabled=True,
            opt_in=True,
            is_elevated=lambda: True,
            executable_path="/opt/fake/sing-box",
        )
        monkeypatch.setattr(t, "_resolve_executable", lambda: "/opt/fake/sing-box")

        async def fake_competing(name, *, timeout=5.0):
            return "singbox_tun"

        monkeypatch.setattr(tun_status, "detect_competing_tunnel", fake_competing)

        from perchvpn_windows.tun_recovery import RecoveryUnverified

        def fake_pre_start(exe, adapter, operator_trial=True):
            raise RecoveryUnverified("unverified latch")

        monkeypatch.setattr(t._recovery_gate, "pre_start", fake_pre_start)
        with caplog.at_level(logging.WARNING, logger="perchvpn_windows.tun_frontend"):
            await t.start()
        messages = [r.getMessage() for r in caplog.records]
        assert any(
            "Another VPN tunnel (singbox_tun) is active" in m for m in messages
        )
        assert t._competing_hint == "singbox_tun"
        # Transitional classification carries the actionable message: move
        # past the fail-closed recovery state the stubbed gate left behind.
        from perchvpn_windows.tun_recovery import CLEAN

        t._recovery_state = CLEAN
        evidence = AdapterEvidence()
        evidence.present = True
        evidence.up = True
        evidence.ipv4 = ["172.19.0.1"]
        evidence.routes = [
            {"destination_prefix": "0.0.0.0/1"},
            {"destination_prefix": "128.0.0.0/1"},
        ]
        t._evidence = evidence
        t._configured = True
        t._process = SimpleNamespace(returncode=None)
        t._egress = None
        t._update_classification()
        assert (
            "Another VPN tunnel (singbox_tun) is active; disconnect it "
            "before starting PerchVPN TUN"
        ) == t._state_detail
        # Once egress flows, coexistence is proven and the hint clears.
        t._egress = {"ok": True, "ipv4": {"ok": True, "ip": "198.51.100.7"}}
        t._update_classification()
        assert t._competing_hint == ""
