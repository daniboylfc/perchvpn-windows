"""Regression tests for the parallel, error-ordering capture_snapshot.

The six captures are independent read-only PowerShell queries that used to
run serialized, costing ~15 s on the TUN launch critical path.
"""

from __future__ import annotations

import pytest

from perchvpn_windows import tun_state_capture as cap


def _patch_captures(monkeypatch, behaviors):
    """Patch every capture_* function with the given per-key behavior."""
    for key, fn in behaviors.items():
        monkeypatch.setattr(cap, "capture_%s" % key if key != "ip_addresses" else "capture_ip_addresses", fn)


def test_capture_snapshot_runs_all_captures_and_assembles(monkeypatch):
    calls = []

    def fake(name, value):
        def fn():
            calls.append(name)
            return value

        return fn

    monkeypatch.setattr(cap, "capture_routes", fake("routes", [{"DestinationPrefix": "0.0.0.0/0"}]))
    monkeypatch.setattr(cap, "capture_dns", fake("dns", [{"InterfaceIndex": 1}]))
    monkeypatch.setattr(cap, "capture_adapters", fake("adapters", [{"Name": "PerchVPN"}]))
    monkeypatch.setattr(
        cap, "capture_ip_addresses", fake("ip_addresses", [{"IPAddress": "172.19.0.1"}])
    )
    monkeypatch.setattr(
        cap, "capture_interface_config", fake("interface_config", [{"InterfaceIndex": 1}])
    )
    monkeypatch.setattr(cap, "capture_winhttp_proxy", fake("winhttp_proxy", "Direct access"))

    snap = cap.capture_snapshot()

    assert sorted(calls) == [
        "adapters",
        "dns",
        "interface_config",
        "ip_addresses",
        "routes",
        "winhttp_proxy",
    ]
    assert snap.routes == [{"DestinationPrefix": "0.0.0.0/0"}]
    assert snap.dns == [{"InterfaceIndex": 1}]
    assert snap.adapters == [{"Name": "PerchVPN"}]
    assert snap.ip_addresses == [{"IPAddress": "172.19.0.1"}]
    assert snap.interface_config == [{"InterfaceIndex": 1}]
    assert snap.winhttp_proxy == "Direct access"
    assert snap.captured_at > 0


def test_capture_snapshot_preserves_capture_error_message(monkeypatch):
    def boom():
        raise cap.CaptureError("PowerShell returned 1: boom-details")

    monkeypatch.setattr(cap, "capture_routes", boom)
    monkeypatch.setattr(
        cap, "capture_dns", lambda: [{"InterfaceIndex": 1, "AddressFamily": 2, "ServerAddresses": []}]
    )
    monkeypatch.setattr(cap, "capture_adapters", lambda: [{"Name": "x"}])
    monkeypatch.setattr(cap, "capture_ip_addresses", lambda: [{"IPAddress": "1.2.3.4"}])
    monkeypatch.setattr(cap, "capture_interface_config", lambda: [{"InterfaceIndex": 1}])
    monkeypatch.setattr(cap, "capture_winhttp_proxy", lambda: "Direct access")

    with pytest.raises(cap.CaptureError) as excinfo:
        cap.capture_snapshot()
    assert "boom-details" in str(excinfo.value)


def test_capture_snapshot_native_skips_adapters_without_ip_interface(monkeypatch):
    """Filter/miniport sub-adapters answer ERROR_NOT_FOUND on
    GetIpInterfaceEntry; they must not fail the whole native capture (that
    forced the 12 s PowerShell fallback and starved the TUN launch gate)."""
    from perchvpn_windows import iphelper

    adapters = [
        {
            "Name": "Wi-Fi",
            "InterfaceGuid": "GUID-WIFI",
            "InterfaceIndex": 9,
            "Status": "Up",
            "InterfaceDescription": "Intel Wi-Fi",
            "unicast": [
                {"IPAddress": "192.168.1.5", "AddressFamily": 2, "PrefixLength": 24}
            ],
            "dns": [{"IPAddress": "1.1.1.1", "AddressFamily": 2}],
        },
        {
            "Name": "Ethernet",
            "InterfaceGuid": "GUID-FILTER",
            "InterfaceIndex": 21,
            "Status": "Down",
            "InterfaceDescription": "Filter",
            "unicast": [],
            "dns": [],
        },
    ]
    route = {
        "DestinationPrefix": "0.0.0.0/0",
        "NextHop": "192.168.1.1",
        "InterfaceIndex": 9,
        "RouteMetric": 0,
        "PolicyStore": "ActiveStore",
        "ifMetric": None,
    }
    entry = {
        "InterfaceIndex": 9,
        "AddressFamily": 2,
        "InterfaceMetric": 55,
        "NlMtu": 1500,
        "Connected": True,
    }

    monkeypatch.setattr(iphelper, "available", lambda: True)
    monkeypatch.setattr(iphelper, "adapters_native", lambda: adapters)
    monkeypatch.setattr(iphelper, "routes_native", lambda family=2: [route])
    monkeypatch.setattr(
        iphelper,
        "unicast_native",
        lambda family=0: [
            {
                "InterfaceIndex": 9,
                "IPAddress": "192.168.1.5",
                "PrefixLength": 24,
                "AddressFamily": 2,
            }
        ],
    )
    monkeypatch.setattr(
        iphelper,
        "interface_entry_native",
        lambda ifindex, family=2: entry if ifindex == 9 else None,
    )
    monkeypatch.setattr(cap, "capture_winhttp_proxy", lambda: "Direct access")

    snap = cap.capture_snapshot_native()
    snap.validate()
    assert [row["InterfaceIndex"] for row in snap.interface_config] == [9]
    assert snap.dns == [
        {"InterfaceIndex": 9, "AddressFamily": 2, "ServerAddresses": ["1.1.1.1"]}
    ]
