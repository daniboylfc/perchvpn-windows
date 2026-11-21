"""Evidence-based TUN readiness classification.

These tests exercise the classification contract directly: no OS calls, no
mocked networking results pretending to prove a tunnel. Every state is
derived from explicit evidence flags, and traffic_verified is impossible
without a direct system-egress observation.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from src.perchvpn_windows import tun_status
from src.perchvpn_windows.api import ui_status_from_controller


class TestEgressProbe:
    class _FakeSocket:
        def __init__(self, fail_until=0):
            self.fail_until = fail_until
            self.attempts = 0
            self.addresses = []
            self.closed = False

        def settimeout(self, _timeout):
            pass

        def connect(self, addr):
            self.addresses.append(addr)
            self.attempts += 1
            if self.attempts <= self.fail_until:
                raise OSError("refused")

        def close(self):
            self.closed = True

    def test_direct_tcp_probe_uses_ip_literals(self, monkeypatch):
        calls = []
        fake = self._FakeSocket()

        def make_socket(*_args, **_kwargs):
            calls.append(True)
            return fake

        monkeypatch.setattr(tun_status.socket, "socket", make_socket)
        result = tun_status._direct_tcp_probe(3.0)
        assert result == {"ok": True, "error": None}
        assert fake.closed
        assert fake.addresses == [("104.16.123.96", 443)]
        assert len(calls) == 1

    def test_direct_tcp_probe_falls_back_to_second_target(self, monkeypatch):
        fake = self._FakeSocket(fail_until=1)
        monkeypatch.setattr(tun_status.socket, "socket", lambda *_a, **_k: fake)
        result = tun_status._direct_tcp_probe(3.0)
        assert result == {"ok": True, "error": None}
        assert fake.addresses == [("104.16.123.96", 443), ("104.16.124.96", 443)]
        assert fake.attempts == 2

    def test_egress_tcp_targets_do_not_overlap_with_route_exclusions(self):
        excluded_ips = {"1.1.1.1", "8.8.8.8"}
        for target_ip, _port in tun_status._EGRESS_TCP_TARGETS:
            assert target_ip not in excluded_ips

    def test_direct_tcp_probe_returns_last_error(self, monkeypatch):
        fake = self._FakeSocket(fail_until=99)
        monkeypatch.setattr(tun_status.socket, "socket", lambda *_a, **_k: fake)
        result = tun_status._direct_tcp_probe(3.0)
        assert result == {"ok": False, "error": "refused"}
        assert fake.attempts == len(tun_status._EGRESS_TCP_TARGETS)

    def test_probe_system_egress_does_not_call_getaddrinfo(self, monkeypatch):
        def fail_lookup(*_args, **_kwargs):
            raise AssertionError("getaddrinfo must not be used")

        monkeypatch.setattr(tun_status.socket, "getaddrinfo", fail_lookup)
        monkeypatch.setattr(
            tun_status, "_direct_https_trace",
            lambda family, timeout: {"ok": False, "family": family, "error": "trace failed"},
        )
        monkeypatch.setattr(
            tun_status, "_direct_tcp_probe",
            lambda timeout: {"ok": True, "error": None},
        )
        result = asyncio.run(tun_status.probe_system_egress(timeout=0.1))
        assert result["ok"] is True
        assert result["error"] is None

    def test_probe_system_egress_reports_failure(self, monkeypatch):
        monkeypatch.setattr(
            tun_status, "_direct_https_trace",
            lambda family, timeout: {"ok": False, "family": family, "error": "trace failed"},
        )
        monkeypatch.setattr(
            tun_status, "_direct_tcp_probe",
            lambda timeout: {"ok": False, "error": "refused"},
        )
        result = asyncio.run(tun_status.probe_system_egress(timeout=0.1))
        assert result["ok"] is False
        assert result["error"] == "refused"

    def test_tcp_success_skips_slow_identity_traces(self, monkeypatch):
        traces = []
        monkeypatch.setattr(
            tun_status, "_direct_tcp_probe",
            lambda timeout: {"ok": True, "error": None},
        )
        monkeypatch.setattr(
            tun_status, "_direct_https_trace",
            lambda family, timeout: traces.append(family) or {"ok": False},
        )
        result = asyncio.run(tun_status.probe_system_egress(timeout=0.1))
        assert result["ok"] is True
        assert result["error"] is None
        assert traces == []

    def test_wait_for_system_egress_polls_at_settling_cadence(self, monkeypatch):
        answers = iter([{"ok": False}, {"ok": False}, {"ok": True}])
        sleeps = []

        async def fake_probe(*, timeout):
            return next(answers)

        async def fake_sleep(seconds):
            sleeps.append(seconds)

        monkeypatch.setattr(tun_status, "probe_system_egress", fake_probe)
        monkeypatch.setattr(tun_status.asyncio, "sleep", fake_sleep)
        result = asyncio.run(
            tun_status.wait_for_system_egress(timeout=5.0, interval=0.25)
        )
        assert result["ok"] is True
        assert sleeps == [0.25, 0.25]


class TestAdapterParsing:
    def _payload(self, adapter=None, addresses=None, routes=None, dns=None):
        return json.dumps({
            "adapter": adapter,
            "addresses": addresses or [],
            "routes": routes or [],
            "dns": dns or [],
        })

    def test_adapter_up_with_split_routes_and_dns(self):
        raw = self._payload(
            adapter={"Name": "PerchVPN", "Status": "Up", "ifIndex": 71},
            addresses=[{"IPAddress": "198.18.0.1", "AddressFamily": 2}],
            routes=[
                {"DestinationPrefix": "0.0.0.0/1", "NextHop": "0.0.0.0",
                 "RouteMetric": 0, "InterfaceMetric": 1},
                {"DestinationPrefix": "128.0.0.0/1", "NextHop": "0.0.0.0",
                 "RouteMetric": 0, "InterfaceMetric": 1},
            ],
            dns=[{"ServerAddresses": ["198.18.0.2"], "AddressFamily": 2}],
        )
        ev = tun_status._parse_probe(raw, "PerchVPN")

        assert ev.present and ev.up and ev.if_index == 71
        assert ev.ipv4 == ["198.18.0.1"]
        assert ev.has_ipv4
        assert ev.split_routes_present and ev.default_route_effective
        assert ev.dns_servers == ["198.18.0.2"]

    def test_tun2proxy_setup_default_route_counts_as_coverage(self):
        """--setup installs 0.0.0.0/0 before the helper re-metrics /1s."""
        raw = self._payload(
            adapter={"Name": "PerchVPN", "Status": "Up", "ifIndex": 71},
            addresses=[{"IPAddress": "10.0.0.1", "AddressFamily": 2}],
            routes=[
                {"DestinationPrefix": "0.0.0.0/0", "NextHop": "0.0.0.0",
                 "RouteMetric": 0, "InterfaceMetric": 1},
            ],
        )
        ev = tun_status._parse_probe(raw, "PerchVPN")
        assert ev.default_route_effective
        assert not ev.split_routes_present

    def test_partial_half_routes_are_not_coverage(self):
        raw = self._payload(
            adapter={"Name": "PerchVPN", "Status": "Up", "ifIndex": 71},
            addresses=[{"IPAddress": "10.0.0.1", "AddressFamily": 2}],
            routes=[
                {"DestinationPrefix": "0.0.0.0/1", "NextHop": "0.0.0.0",
                 "RouteMetric": 0, "InterfaceMetric": 1},
            ],
        )
        ev = tun_status._parse_probe(raw, "PerchVPN")
        assert not ev.default_route_effective
        assert not ev.split_routes_present

    def test_sing_box_decomposed_public_coverage_is_effective(self):
        """Windows auto_route publishes 80+ prefixes instead of the /1 pair."""
        prefixes = [
            "0.0.0.0/8",
            "1.0.0.0/16",
            "1.1.0.0/24",
            "1.1.1.0/32",
            "8.0.0.0/7",
            "172.0.0.0/12",
            "172.19.0.0/30",
            "172.19.0.1/32",
            "196.0.0.0/6",
            "200.0.0.0/5",
            "224.0.0.0/3",
        ]
        raw = self._payload(
            adapter={"Name": "PerchVPN_e20655", "Status": "Up", "ifIndex": 81},
            addresses=[{"IPAddress": "172.19.0.1", "AddressFamily": 2}],
            routes=[
                {"DestinationPrefix": prefix, "NextHop": "0.0.0.0",
                 "RouteMetric": 256, "InterfaceMetric": 1}
                for prefix in prefixes
            ],
        )
        ev = tun_status._parse_probe(raw, "PerchVPN_e20655")
        assert ev.has_ipv4
        assert ev.default_route_effective
        assert not ev.split_routes_present

    def test_narrow_host_routes_do_not_prove_default_coverage(self):
        raw = self._payload(
            adapter={"Name": "PerchVPN", "Status": "Up", "ifIndex": 71},
            addresses=[{"IPAddress": "10.0.0.1", "AddressFamily": 2}],
            routes=[
                {"DestinationPrefix": sentinel + "/32", "NextHop": "0.0.0.0",
                 "RouteMetric": 0, "InterfaceMetric": 1}
                for sentinel in tun_status.DEFAULT_ROUTE_COVERAGE_SENTINELS
            ],
        )
        ev = tun_status._parse_probe(raw, "PerchVPN")
        assert not ev.default_route_effective

    def test_missing_adapter_is_not_present(self):
        ev = tun_status._parse_probe(self._payload(), "PerchVPN")
        assert not ev.present
        assert "not present" in ev.error

    def test_adapter_up_without_routes_has_no_default_coverage(self):
        raw = self._payload(
            adapter={"Name": "PerchVPN", "Status": "Up", "ifIndex": 71},
            addresses=[{"IPAddress": "198.18.0.1", "AddressFamily": 2}],
        )
        ev = tun_status._parse_probe(raw, "PerchVPN")
        assert ev.up and ev.has_ipv4
        assert not ev.default_route_effective

    def test_link_local_ipv6_is_ignored(self):
        raw = self._payload(
            adapter={"Name": "PerchVPN", "Status": "Up", "ifIndex": 71},
            addresses=[
                {"IPAddress": "fe80::1", "AddressFamily": 23},
                {"IPAddress": "2001:db8::5", "AddressFamily": 23},
            ],
        )
        ev = tun_status._parse_probe(raw, "PerchVPN")
        assert ev.ipv6 == ["2001:db8::5"]


class TestClassification:
    BASE = dict(
        enabled=True,
        opted_in=True,
        configured=True,
        elevated=True,
        process_alive=True,
        spawn_failed=False,
        recovery_required=False,
        expected_exit_ip="2a00:8c40::1",
        expected_country="FI",
    )

    def _evidence(self, up=True, ipv4=("198.18.0.1",), routes=True, present=True):
        return tun_status.AdapterEvidence(
            present=present,
            up=up,
            if_index=71 if present else None,
            ipv4=list(ipv4),
            routes=[
                {"destination_prefix": "0.0.0.0/1"},
                {"destination_prefix": "128.0.0.0/1"},
            ] if routes else [],
        )

    def test_disabled_is_not_connected(self):
        r = tun_status.classify(**{**self.BASE, "enabled": False}, evidence=None, egress=None)
        assert r["state"] == tun_status.STATE_DISABLED

    def test_proxy_only_requires_opt_in(self):
        r = tun_status.classify(**{**self.BASE, "opted_in": False}, evidence=None, egress=None)
        assert r["state"] == tun_status.STATE_NOT_OPTED_IN

    def test_not_elevated_is_explicit(self):
        r = tun_status.classify(**{**self.BASE, "elevated": False}, evidence=None, egress=None)
        assert r["state"] == tun_status.STATE_NOT_ELEVATED
        assert "Administrator" in r["detail"]

    def test_missing_executable_is_not_configured(self):
        r = tun_status.classify(**{**self.BASE, "configured": False}, evidence=None, egress=None)
        assert r["state"] == tun_status.STATE_NOT_CONFIGURED

    def test_dead_process_is_failed(self):
        r = tun_status.classify(**{**self.BASE, "process_alive": False}, evidence=None, egress=None)
        assert r["state"] == tun_status.STATE_FAILED

    def test_adapter_up_without_routes(self):
        r = tun_status.classify(
            **self.BASE, evidence=self._evidence(routes=False), egress=None
        )
        assert r["state"] == tun_status.STATE_ADAPTER_READY

    def test_routes_without_egress_proof_is_not_connected(self):
        r = tun_status.classify(**self.BASE, evidence=self._evidence(), egress=None)
        assert r["state"] == tun_status.STATE_ROUTES_CONFIGURED
        assert r["state"] != tun_status.STATE_TRAFFIC_VERIFIED

    def test_matching_system_egress_verifies_traffic(self):
        egress = {
            "ipv4": {"ok": True, "ip": "2a00:8c40::1", "country": "FI"},
            "ipv6": {"ok": False},
        }
        r = tun_status.classify(**self.BASE, evidence=self._evidence(), egress=egress)
        assert r["state"] == tun_status.STATE_TRAFFIC_VERIFIED

    def test_country_match_also_verifies(self):
        egress = {
            "ipv4": {"ok": True, "ip": "203.0.113.9", "country": "FI"},
            "ipv6": {"ok": False},
        }
        r = tun_status.classify(**self.BASE, evidence=self._evidence(), egress=egress)
        assert r["state"] == tun_status.STATE_TRAFFIC_VERIFIED

    def test_physical_egress_leak_is_degraded(self):
        baseline = {"ipv4": {"ok": True, "ip": "192.0.2.44"}, "ipv6": {"ok": False}}
        egress = {
            "ipv4": {"ok": True, "ip": "192.0.2.44", "country": "US"},
            "ipv6": {"ok": False},
        }
        r = tun_status.classify(
            **self.BASE, evidence=self._evidence(), egress=egress, baseline=baseline
        )
        assert r["state"] == tun_status.STATE_DEGRADED
        assert "physical" in r["detail"].lower()

    def test_unknown_exit_is_operational_not_verified(self):
        egress = {
            "ipv4": {"ok": True, "ip": "203.0.113.9", "country": "US"},
            "ipv6": {"ok": False},
        }
        r = tun_status.classify(**self.BASE, evidence=self._evidence(), egress=egress)
        assert r["state"] == tun_status.STATE_TUNNEL_OPERATIONAL

    def test_tcp_egress_without_identity_verifies_traffic(self):
        egress = {
            "ok": True,
            "ipv4": {"ok": True, "source": "tcp"},
            "ipv6": {"ok": False},
        }
        r = tun_status.classify(**self.BASE, evidence=self._evidence(), egress=egress)
        assert r["state"] == tun_status.STATE_TRAFFIC_VERIFIED
        assert "verified" in r["detail"]

    def test_no_exit_expectation_with_observed_ip_verifies_traffic(self):
        base = {**self.BASE, "expected_exit_ip": "", "expected_country": ""}
        egress = {
            "ipv4": {"ok": True, "ip": "85.9.100.160", "country": "BE"},
            "ipv6": {"ok": False},
        }
        r = tun_status.classify(**base, evidence=self._evidence(), egress=egress)
        assert r["state"] == tun_status.STATE_TRAFFIC_VERIFIED
        assert "85.9.100.160" in r["detail"]


class TestUiStatusContract:
    """The top-level status must never claim "connected" without TUN proof."""

    def test_no_tun_is_proxy_active(self):
        assert ui_status_from_controller(
            "ok", {"enabled": False, "state": "disabled"}
        ) == "proxy_active"

    def test_tun_not_elevated_is_failed(self):
        assert ui_status_from_controller(
            "ok", {"enabled": True, "state": "not_elevated"}
        ) == "failed"

    def test_tun_routes_configured_is_connecting(self):
        assert ui_status_from_controller(
            "ok", {"enabled": True, "state": "routes_configured"}
        ) == "connecting"

    def test_tun_operational_but_unverified_is_connecting(self):
        # Normal TUN startup (adapter + split routes up, exit check still
        # pending) is progress, not a degraded connection.
        assert ui_status_from_controller(
            "ok", {"enabled": True, "state": "tunnel_operational"}
        ) == "connecting"

    def test_explicit_verification_failure_is_degraded(self):
        assert ui_status_from_controller(
            "ok", {"enabled": True, "state": "degraded"}
        ) == "degraded"

    def test_tun_traffic_verified_is_connected(self):
        assert ui_status_from_controller(
            "ok", {"enabled": True, "state": "traffic_verified"}
        ) == "connected"

    def test_controller_failure_wins(self):
        assert ui_status_from_controller(
            "starting", {"enabled": True, "state": "traffic_verified"}
        ) == "connecting"
