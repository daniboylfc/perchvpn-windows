"""Performance-behavior regression tests for the two startup/runtime hot paths:

1. Adaptive reconcile cadence: verified-steady tunnels back the heavy
   PowerShell evidence loop off (30 s reconcile / 60 s full evidence) while
   regressions wake the loop immediately.
2. Startup fan-out: control-plane/edge hostname pins resolve concurrently and
   the pre-start network snapshot is captured in ONE PowerShell spawn.
"""

from __future__ import annotations

import asyncio
import json
import time
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import perchvpn_windows.app as app_module
from perchvpn_windows import tun_status
from perchvpn_windows.tun_state_capture import (
    CaptureError,
    NetworkSnapshot,
    _BATCHED_SNAPSHOT_SCRIPT,
    capture_snapshot_batched,
    capture_snapshot_preferred,
)
from perchvpn_windows.tun_frontend import TunFrontend
from src.perchvpn_windows.tun_frontend import (
    _EGRESS_INTERVAL_STEADY_SECONDS,
    _EGRESS_INTERVAL_TRANSITION_SECONDS,
    _FULL_EVIDENCE_INTERVAL_SECONDS,
    _FULL_EVIDENCE_INTERVAL_STEADY_SECONDS,
    _RECONCILE_INTERVAL_STEADY_SECONDS,
)


def _batched_payload(**overrides):
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
    payload.update(overrides)
    return payload


def _run_batched_with(monkeypatch, payload_text):
    monkeypatch.setattr(
        "perchvpn_windows.tun_state_capture._run_ps",
        lambda script, timeout=30.0: payload_text,
    )


class TestBatchedSnapshotCapture:
    def test_batched_script_spawns_once_and_queries_everything(self):
        # A single ConvertTo-Json at the end: one powershell.exe spawn.
        assert _BATCHED_SNAPSHOT_SCRIPT.count("ConvertTo-Json") == 1
        for query in (
            "Get-NetRoute",
            "Get-DnsClientServerAddress",
            "Get-NetAdapter",
            "Get-NetIPAddress",
            "Get-NetIPInterface",
        ):
            assert query in _BATCHED_SNAPSHOT_SCRIPT
        assert "netsh winhttp show proxy" in _BATCHED_SNAPSHOT_SCRIPT

    def test_batched_capture_returns_snapshot(self, monkeypatch):
        _run_batched_with(monkeypatch, json.dumps(_batched_payload()))
        snap = capture_snapshot_batched()
        assert isinstance(snap, NetworkSnapshot)
        assert snap.routes[0]["DestinationPrefix"] == "0.0.0.0/0"
        assert snap.winhttp_proxy == "Direct access (no proxy server)."

    def test_batched_capture_reports_every_failed_section(self, monkeypatch):
        payload = _batched_payload(
            routes=None,
            winhttp_proxy="",
            errors={"routes": "Get-NetRoute failed", "winhttp_proxy": "boom"},
        )
        _run_batched_with(monkeypatch, json.dumps(payload))
        with pytest.raises(CaptureError) as exc:
            capture_snapshot_batched()
        message = str(exc.value)
        assert "routes" in message and "winhttp_proxy" in message

    def test_batched_capture_rejects_malformed_json(self, monkeypatch):
        _run_batched_with(monkeypatch, "not json at all")
        with pytest.raises(CaptureError):
            capture_snapshot_batched()

    def test_preferred_falls_back_to_pool_capture_on_batched_failure(self, monkeypatch):
        _run_batched_with(monkeypatch, "not json at all")

        class _FakePool:
            def __init__(self):
                self.calls = 0

            def __call__(self):
                self.calls += 1
                return NetworkSnapshot(
                    routes=_batched_payload()["routes"],
                    dns=_batched_payload()["dns"],
                    adapters=_batched_payload()["adapters"],
                    ip_addresses=_batched_payload()["ip_addresses"],
                    interface_config=_batched_payload()["interface_config"],
                    winhttp_proxy="Direct access (no proxy server).",
                )

        fake = _FakePool()
        with patch("perchvpn_windows.tun_state_capture.capture_snapshot", fake):
            snap = capture_snapshot_preferred()
        assert fake.calls == 1
        assert isinstance(snap, NetworkSnapshot)

    def test_preferred_uses_batched_when_it_succeeds(self, monkeypatch):
        _run_batched_with(monkeypatch, json.dumps(_batched_payload()))
        with patch(
            "perchvpn_windows.tun_state_capture.capture_snapshot",
            side_effect=AssertionError("pool capture must not run"),
        ):
            assert isinstance(capture_snapshot_preferred(), NetworkSnapshot)


class TestAdaptiveReconcileCadence:
    def test_intervals_switch_on_stability(self):
        t = TunFrontend(enabled=True, opt_in=True, is_elevated=lambda: True)
        t._state = tun_status.STATE_TRAFFIC_VERIFIED
        assert t._reconcile_interval_for_state() == _RECONCILE_INTERVAL_STEADY_SECONDS
        assert t._full_evidence_interval() == _FULL_EVIDENCE_INTERVAL_STEADY_SECONDS
        t._state = tun_status.STATE_DEGRADED
        assert t._reconcile_interval_for_state() == t._reconcile_interval
        assert t._full_evidence_interval() == _FULL_EVIDENCE_INTERVAL_SECONDS

    def test_wake_is_noop_without_loop(self):
        t = TunFrontend(enabled=True, opt_in=True, is_elevated=lambda: True)
        assert t._reconcile_wake is None
        t._wake_reconcile()  # must not raise

    def test_egress_interval_relaxes_when_verified(self):
        t = TunFrontend(enabled=True, opt_in=True, is_elevated=lambda: True)
        t._reconcile_wake = asyncio.Event()
        t._state = tun_status.STATE_STARTING

        steady = {"state": tun_status.STATE_TRAFFIC_VERIFIED, "detail": "verified"}
        with patch.object(tun_status, "classify", return_value=steady):
            t._update_classification()
        assert t._egress_interval == _EGRESS_INTERVAL_STEADY_SECONDS

        degraded = {"state": tun_status.STATE_DEGRADED, "detail": "adapter gone"}
        with patch.object(tun_status, "classify", return_value=degraded):
            t._update_classification()
        assert t._egress_interval == _EGRESS_INTERVAL_TRANSITION_SECONDS

    def test_classification_regression_sets_wake(self):
        t = TunFrontend(enabled=True, opt_in=True, is_elevated=lambda: True)
        t._reconcile_wake = asyncio.Event()
        t._state = tun_status.STATE_TRAFFIC_VERIFIED

        steady = {"state": tun_status.STATE_TRAFFIC_VERIFIED, "detail": "verified"}
        with patch.object(tun_status, "classify", return_value=steady):
            t._update_classification()
        assert not t._reconcile_wake.is_set()  # steady -> steady: no wake

        degraded = {"state": tun_status.STATE_DEGRADED, "detail": "adapter gone"}
        with patch.object(tun_status, "classify", return_value=degraded):
            t._update_classification()
        assert t._reconcile_wake.is_set()  # regression: wake immediately

    @pytest.mark.asyncio
    async def test_wake_cuts_steady_sleep_short(self):
        t = TunFrontend(enabled=True, opt_in=True, is_elevated=lambda: True)
        t._reconcile_interval = 5.0
        t._reconcile_wake = asyncio.Event()
        calls: list[float] = []

        async def fake_reconcile():
            calls.append(time.monotonic())

        t.reconcile = fake_reconcile  # type: ignore[method-assign]
        runner = asyncio.ensure_future(t._reconcile_loop())
        while not calls:
            await asyncio.sleep(0.05)
        # First tick done; the loop is now sleeping ~5 s.  Wake it.
        t._wake_reconcile()
        deadline = time.monotonic() + 2.0
        while len(calls) < 2 and time.monotonic() < deadline:
            await asyncio.sleep(0.05)
        assert len(calls) == 2
        assert calls[1] - calls[0] < 2.0  # wake cut the 5 s sleep short
        runner.cancel()
        try:
            await runner
        except asyncio.CancelledError:
            pass


def _pins_app():
    app = object.__new__(app_module.PerchVPNApp)
    app.config = SimpleNamespace(
        guardian_endpoint="https://vpn.mozilla.org",
        edge_address="",
        upstream_proxy_enabled=False,
        upstream_proxy=None,
    )
    app._candidate = SimpleNamespace(host="cloudflare-dns.com")
    app._resolved_edge_host = None
    app._control_plane_dial_ips = {}
    return app


class TestParallelControlPlanePins:
    @pytest.mark.asyncio
    async def test_control_plane_bypass_ips_resolves_concurrently(self, monkeypatch):
        app = _pins_app()
        sleeps: list[float] = []

        def slow_physical(name, *, physical_ip, physical_index):
            start = time.monotonic()
            time.sleep(0.3)
            sleeps.append(start)
            return ["198.51.100.%d" % len(sleeps)]

        monkeypatch.setattr(
            app_module, "_physical_ipv4_addresses", slow_physical
        )

        start = time.monotonic()
        persistent, active_edge, resolved = await app._control_plane_bypass_ips(
            physical_ip="192.168.1.5", physical_index=10
        )
        elapsed = time.monotonic() - start

        # guardian + edge resolve concurrently: ~0.3 s, not ~0.6 s.
        assert elapsed < 0.6
        assert len(sleeps) == 2
        assert persistent and active_edge
        assert set(resolved) == {"vpn.mozilla.org", "cloudflare-dns.com"}

    @pytest.mark.asyncio
    async def test_edge_host_pins_resolve_concurrently(self, monkeypatch):
        app = _pins_app()
        sleeps: list[float] = []

        def slow_physical(name, *, physical_ip, physical_index):
            start = time.monotonic()
            time.sleep(0.3)
            sleeps.append(start)
            return ["203.0.113.%d" % (len(sleeps) + 1)]

        monkeypatch.setattr(
            app_module, "_physical_ipv4_addresses", slow_physical
        )

        candidate = SimpleNamespace(host="edge-a.example")
        alternates = [SimpleNamespace(host="edge-b.example"), SimpleNamespace(host="edge-c.example")]

        start = time.monotonic()
        pins, ips, blocked = await app._edge_host_pins(
            candidate,
            alternates,
            physical_ip="192.168.1.5",
            physical_index=10,
        )
        elapsed = time.monotonic() - start

        assert elapsed < 0.9  # ~0.3 s concurrent, not ~0.9 s sequential
        assert len(sleeps) == 3
        assert blocked == []
        assert set(pins) == {"edge-a.example", "edge-b.example", "edge-c.example"}
        assert len(ips) == 3

    @pytest.mark.asyncio
    async def test_control_plane_bypass_ips_unresolvable_host_stays_in_tunnel(
        self, monkeypatch
    ):
        app = _pins_app()
        app_module._GLOBAL_DNS_CACHE.clear()

        def failing(name, **kwargs):
            raise RuntimeError("no DNS")

        monkeypatch.setattr(app_module, "_physical_ipv4_addresses", failing)
        monkeypatch.setattr(app_module, "_getaddrinfo_ipv4_addresses", failing)

        persistent, active_edge, resolved = await app._control_plane_bypass_ips(
            physical_ip="192.168.1.5", physical_index=10
        )

        assert persistent == []
        assert active_edge == []
        assert resolved == {}
