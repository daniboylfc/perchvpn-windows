"""Regression tests for the native IP Helper capture/pinning fast path.

Covers the parse layer (pure, platform-independent), the PowerShell fallback
contract at each call site, the bounded DNS deadline, and the WSL2 virtual
subnet carve-out in the sing-box route exclusions.
"""

from __future__ import annotations

import struct
from unittest.mock import patch

import pytest

from perchvpn_windows import iphelper
from perchvpn_windows import physical_dns
from perchvpn_windows.physical_dns import PhysicalDnsError


def _utf16(s: str) -> bytes:
    return s.encode("utf-16-le") + b"\x00\x00"


def _adapter_rows(
    friendly: str = "Wi-Fi",
    description: str = "Intel Wi-Fi 6 AX201",
    if_index: int = 9,
    oper_status: int = 1,
    unicast: list = (),
    dns: list = (),
):
    """Build a synthetic adapter row in a REAL ctypes buffer.

    ``unicast`` entries are ``(sockaddr_blob, prefix_len)``; ``dns`` entries
    are ``(sockaddr_blob,)``.  Layout order: adapter row (176 bytes),
    strings, then one chain after another where each node is followed
    immediately by the sockaddr it points at.  All pointers are patched to
    true addresses inside the buffer, so the parser's ``string_at``
    dereferences are valid.  Returns ``(buffer, rows)`` — keep the first
    element alive while the rows are in use.
    """
    import ctypes as _ct

    buf = _ct.create_string_buffer(4096)
    base = _ct.addressof(buf)
    cursor = 176
    buf[0:4] = struct.pack("<I", 176)
    buf[4:8] = struct.pack("<I", if_index)
    buf[104:108] = struct.pack("<I", oper_status)

    def _write_string(field_offset: int, text: bytes) -> int:
        nonlocal cursor
        ptr = base + cursor
        buf[cursor : cursor + len(text)] = text
        struct.pack_into("<Q", buf, field_offset, ptr)
        cursor += len(text)
        return ptr

    _write_string(72, _utf16(friendly))
    _write_string(64, _utf16(description))
    _write_string(16, b"{9B4C3D1E-1111-2222-3333-444455556666}\x00")

    def _write_chain(head_offset: int, entries, node_size: int, with_prefix: bool):
        nonlocal cursor
        if not entries:
            return
        first = base + cursor
        struct.pack_into("<Q", buf, head_offset, first)
        for i, entry in enumerate(entries):
            node = base + cursor
            next_ptr = base + cursor + node_size + 16 if i + 1 < len(entries) else 0
            struct.pack_into("<I", buf, cursor, node_size)
            struct.pack_into("<Q", buf, cursor + 8, next_ptr)
            struct.pack_into("<i", buf, cursor + 24, len(entry[0]))
            if with_prefix and entry[1] is not None:
                buf[cursor + 56] = entry[1]
            sa_ptr = base + cursor + node_size
            struct.pack_into("<Q", buf, cursor + 16, sa_ptr)
            buf[cursor + node_size : cursor + node_size + len(entry[0])] = entry[0]
            cursor += node_size + 16

    _write_chain(24, unicast, 72, True)
    _write_chain(48, dns, 32, False)
    return buf, iphelper.parse_adapter_buffer(buf.raw)


def test_set_interface_metric_uses_zero_site_prefix_length():
    """SetIpInterfaceEntry rejects SitePrefixLength=0xFF (read-only value);
    the fallback then cost two PowerShell calls (8 s on the sandbox guest)."""

    import ctypes as _ctypes

    class _Row(_ctypes.Structure):
        _fields_ = [
            ("Family", _ctypes.c_int),
            ("InterfaceIndex", _ctypes.c_uint),
            ("InterfaceLuid", _ctypes.c_uint64),
            ("SitePrefixLength", _ctypes.c_ubyte),
            ("Metric", _ctypes.c_ulong),
            ("UseAutomaticMetric", _ctypes.c_ubyte),
        ]

    captured = {}

    class _Dll:
        def GetIpInterfaceEntry(self, row):
            return 0

        def SetIpInterfaceEntry(self, row):
            row = row._obj
            captured["spl"] = row.SitePrefixLength
            captured["metric"] = row.Metric
            captured["auto"] = row.UseAutomaticMetric
            return 0

    with patch.object(iphelper, "_dll", lambda: _Dll()), patch.object(
        iphelper, "MIB_IPINTERFACE_ROW", _Row
    ):
        assert iphelper.set_interface_metric_native(7, 2, 3) is True
    assert captured == {"spl": 0, "metric": 3, "auto": 0}


def test_dll_sentinel_initialised_at_module_level():
    """_dll() touches the module-global lazily; if the sentinel is missing the
    NameError only fires on Windows first use (masked on Linux by the early
    _IS_WINDOWS return). Frozen preflight regressed exactly this way."""
    assert hasattr(iphelper, "_iphlpapi")
    if not iphelper._IS_WINDOWS:
        assert iphelper.available() is False


def _sockaddr_v4(address: str) -> bytes:
    import socket as _socket

    return struct.pack("<H", 2) + b"\x00\x00" + _socket.inet_aton(address) + b"\x00" * 8


def test_parse_adapter_buffer_reads_onlink_prefix_length():
    """OnLinkPrefixLength is at offset 56 (after both lifetimes).  Reading 48
    yielded 0xFF from PreferredLifetime, so unicast_native() zeroed every
    prefix and the WSL2 subnet carve-out silently found nothing."""
    buf, rows = _adapter_rows(
        unicast=[(_sockaddr_v4("192.168.1.5"), 24), (_sockaddr_v4("172.27.208.1"), 20)]
    )
    assert [e["PrefixLength"] for e in rows[0]["unicast"]] == [24, 20]
    assert iphelper._OFF_UNICAST_PREFIX_LEN == 56


def test_unicast_native_preserves_prefix_lengths():
    from unittest.mock import patch as _patch

    rows = [{
        "Name": "Wi-Fi",
        "InterfaceIndex": 9,
        "unicast": [
            {"IPAddress": "192.168.1.5", "AddressFamily": 2, "PrefixLength": 24},
            {"IPAddress": "10.0.0.0", "AddressFamily": 2, "PrefixLength": 255},
        ],
        "dns": [],
    }]
    with _patch.object(iphelper, "adapters_native", lambda: rows):
        result = iphelper.unicast_native(2)
    assert [r["PrefixLength"] for r in result] == [24, 0]


def test_parse_adapter_buffer_basic_fields():
    _buf, rows = _adapter_rows()
    assert len(rows) == 1
    row = rows[0]
    assert row["Name"] == "Wi-Fi"
    assert row["InterfaceDescription"] == "Intel Wi-Fi 6 AX201"
    assert row["InterfaceIndex"] == 9
    assert row["Status"] == "Up"
    assert row["InterfaceGuid"] == "9B4C3D1E-1111-2222-3333-444455556666"


def test_parse_adapter_buffer_down_status_text():
    _buf, rows = _adapter_rows(oper_status=6)
    assert rows[0]["Status"] == "Not Present"


def test_parse_adapter_buffer_stops_on_zero_length():
    buf, _rows = _adapter_rows()
    rows = iphelper.parse_adapter_buffer(buf.raw + b"\x00" * 16)
    assert len(rows) == 1


def test_walk_adapter_rows_follows_next_not_length():
    """Live adapter rows are not contiguous; walking by Length truncated the
    list after the first packet-scheduler row (2026-11-18 regression: Wi-Fi's
    DNS servers vanished and PerchVPN itself looked absent, freezing TUN
    readiness at ``starting``/``connecting``)."""
    import ctypes as _ct

    buf = _ct.create_string_buffer(2048)
    base = _ct.addressof(buf)
    first, second = base, base + 1024
    for addr, if_index, next_addr in (
        (first, 21, second),
        (second, 70, 0),
    ):
        offset = addr - base
        struct.pack_into("<I", buf, offset, 176)
        struct.pack_into("<I", buf, offset + 4, if_index)
        struct.pack_into("<Q", buf, offset + 8, next_addr)

    rows = iphelper._walk_adapter_rows(base, len(buf))
    assert [row["InterfaceIndex"] for row in rows] == [21, 70]
    # The contiguous parser cannot reach the second row: this is the bug shape.
    assert len(iphelper.parse_adapter_buffer(buf.raw)) == 1


def test_adapters_native_resizes_from_needed_value():
    """ERROR_BUFFER_OVERFLOW reports the exact required size; doubling a 15 KiB
    guess three times could never reach the ~105 KiB real capture."""

    class FakeDll:
        def __init__(self):
            self.sizes = []

        def GetAdaptersAddresses(self, _family, _flags, _reserved, buf, needed):
            self.sizes.append(len(buf))
            if len(self.sizes) == 1:
                needed._obj.value = 105680
                return iphelper.ERROR_BUFFER_OVERFLOW
            needed._obj.value = len(buf)
            return iphelper.ERROR_SUCCESS

    fake = FakeDll()
    with patch.object(iphelper, "_dll", lambda: fake), patch.object(
        iphelper, "_walk_adapter_rows", lambda base, size: [{"InterfaceIndex": 9}]
    ):
        rows = iphelper.adapters_native()

    assert rows == [{"InterfaceIndex": 9}]
    assert fake.sizes[0] == 64 * 1024
    assert fake.sizes[1] >= 105680


def test_adapter_present_native_matches_guid_and_name():
    buf, rows = _adapter_rows()

    def fake_rows():
        return rows

    with patch.object(iphelper, "adapters_native", fake_rows):
        assert (
            iphelper.adapter_present_native(
                "9b4c3d1e-1111-2222-3333-444455556666", "other"
            )
            is True
        )
        assert iphelper.adapter_present_native(None, "Wi-Fi") is True
        assert iphelper.adapter_present_native(None, "PerchVPN") is False


def test_adapter_present_native_require_up_ignores_down_rows():
    rows = [
        {"InterfaceGuid": "aaaa", "Name": "PerchVPN", "Status": "Down"},
        {"InterfaceGuid": "bbbb", "Name": "Wi-Fi", "Status": "Up"},
    ]
    with patch.object(iphelper, "adapters_native", lambda: rows):
        assert iphelper.adapter_present_native(None, "PerchVPN") is True
        assert iphelper.adapter_present_native(None, "PerchVPN", require_up=True) is False
        assert iphelper.adapter_present_native("BBBB", "x", require_up=True) is True
        rows[0]["Status"] = "Up"
        assert iphelper.adapter_present_native(None, "PerchVPN", require_up=True) is True


def test_adapter_present_native_unknown_without_rows():
    with patch.object(iphelper, "adapters_native", lambda: []):
        assert iphelper.adapter_present_native(None, "PerchVPN") is None


def test_set_interface_metric_rejects_bad_metric():
    assert iphelper.set_interface_metric_native(9, 2, 0) is False
    assert iphelper.set_interface_metric_native(9, 2, 99999) is False


def test_set_interface_metric_false_without_dll():
    assert iphelper.set_interface_metric_native(9, 2, 1) is False


def test_interface_entry_false_values_rejected():
    class FakeDll:
        def GetIpInterfaceEntry(self, row):
            ref = getattr(row, "_obj", None)
            if ref is None:
                return 116
            ref.Metric = 900000
            ref.NlMtu = 1500
            return 0

    with patch.object(iphelper, "_dll", lambda: FakeDll()), patch.object(
        iphelper, "_IS_WINDOWS", True
    ):
        assert iphelper.interface_entry_native(9, 2) is None


def test_dns_servers_native_groups_by_family():
    sa4 = struct.pack("<H2x4s8x", 2, socket_inet_pton("192.168.1.1"))
    sa6 = struct.pack("<H6x16s4x", 23, socket_inet_pton6("fe80::1"))
    buf, rows = _adapter_rows(dns=[(sa4, None), (sa6, None)])
    with patch.object(iphelper, "adapters_native", lambda: rows):
        assert iphelper.dns_servers_native(9, "IPv4") == ["192.168.1.1"]
        assert iphelper.dns_servers_native(9, "IPv6") == ["fe80::1"]


def socket_inet_pton(text: str) -> bytes:
    import socket as _s

    return _s.inet_pton(_s.AF_INET, text)


def socket_inet_pton6(text: str) -> bytes:
    import socket as _s

    return _s.inet_pton(_s.AF_INET6, text)


def test_best_route_interface_rejects_non_ip():
    assert iphelper.best_route_interface("not-an-ip") is None


class TestResolveDeadline:
    def test_deadline_stops_after_two_slow_servers(self):
        import time as _t

        calls = []

        def slow_query(server, name, **kwargs):
            calls.append(server)
            _t.sleep(0.6)
            raise TimeoutError("blocked")

        with pytest.raises(PhysicalDnsError) as excinfo:
            physical_dns.resolve_ipv4(
                "example.com",
                ["10.9.9.9", "10.9.9.10", "10.9.9.11"],
                timeout=2.0,
                deadline=1.0,
                query=slow_query,
                doh_query=lambda *a, **k: [],
            )
        assert len(calls) == 2
        assert "deadline reached" in str(excinfo.value)

    def test_deadline_not_exceeded_tries_doh(self):
        def udp_query(server, name, **kwargs):
            raise TimeoutError("blocked")

        result = physical_dns.resolve_ipv4(
            "example.com",
            ["10.9.9.9"],
            timeout=0.05,
            deadline=5.0,
            query=udp_query,
            doh_query=lambda *a, **k: ["203.0.113.5"],
        )
        assert result == ["203.0.113.5"]


class TestWsl2CarveOut:
    def test_build_config_includes_detected_wsl_subnet(self, monkeypatch):
        from perchvpn_windows import singbox_config

        monkeypatch.setattr(
            singbox_config,
            "_wsl2_exclude_addresses",
            lambda: ["172.27.208.0/20"],
        )
        config = singbox_config.build_config(proxy_host="203.0.113.7", proxy_port=443)
        excluded = config["inbounds"][0]["route_exclude_address"]
        assert "172.27.208.0/20" in excluded

    def test_wsl2_detection_failure_leaves_baseline_unchanged(self, monkeypatch):
        from perchvpn_windows import singbox_config

        def boom():
            raise RuntimeError("native unavailable")

        monkeypatch.setattr(singbox_config, "_wsl2_exclude_addresses", boom)
        config = singbox_config.build_config(proxy_host="203.0.113.7", proxy_port=443)
        baseline = singbox_config._exclude_addresses(())
        excluded = config["inbounds"][0]["route_exclude_address"]
        assert excluded == baseline

    def test_detection_targets_wsl_adapters_only(self):
        rows = [
            {
                "Name": "vEthernet (WSL (Hyper-V firewall))",
                "InterfaceIndex": 42,
                "unicast": [
                    {"IPAddress": "172.27.208.1", "AddressFamily": 2, "PrefixLength": 20}
                ],
                "dns": [],
            },
            {
                "Name": "Wi-Fi",
                "InterfaceIndex": 9,
                "unicast": [
                    {"IPAddress": "192.168.1.5", "AddressFamily": 2, "PrefixLength": 24}
                ],
                "dns": [],
            },
        ]
        with patch.object(iphelper, "adapters_native", lambda: rows):
            assert iphelper.virtual_nat_subnets_native() == ["172.27.208.0/20"]


class TestTunHelperNativeStubs:
    def test_capture_adapter_dns_delegates_to_native(self, monkeypatch):
        from perchvpn_windows import tun_helper

        with patch(
            "perchvpn_windows.iphelper.dns_servers_native",
            lambda idx, family: ["9.9.9.9"] if idx == 9 else [],
        ):
            assert tun_helper.capture_adapter_dns(9) == ["9.9.9.9"]
            assert tun_helper.capture_adapter_dns(3) == []

    def test_find_route_interface_delegates_to_native(self, monkeypatch):
        from perchvpn_windows import tun_helper

        with patch(
            "perchvpn_windows.iphelper.best_route_interface",
            lambda dest: 9 if dest == "1.1.1.1" else None,
        ):
            assert tun_helper.find_route_interface("1.1.1.1") == 9
            assert tun_helper.find_route_interface("bad") is None

    def test_native_failure_fails_closed(self, monkeypatch):
        from perchvpn_windows import tun_helper

        def boom(dest):
            raise RuntimeError("no iphlpapi")

        with patch("perchvpn_windows.iphelper.best_route_interface", boom):
            assert tun_helper.find_route_interface("1.1.1.1") is None


class TestRecoveryProbeFallback:
    def test_native_probe_result_used_directly(self, monkeypatch):
        from perchvpn_windows import tun_recovery

        with patch("perchvpn_windows.iphelper.available", lambda: True), patch(
            "perchvpn_windows.iphelper.adapter_present_native",
            lambda g, n, **kw: False,
        ):
            assert tun_recovery._default_adapter_probe("guid", "PerchVPN") is False
            assert (
                tun_recovery._default_adapter_probe(
                    "guid", "PerchVPN", require_up=True
                )
                is False
            )

    def test_native_unknown_falls_back_to_powershell(self, monkeypatch):
        import sys

        from perchvpn_windows import tun_recovery

        monkeypatch.setattr(sys, "platform", "win32")

        with patch("perchvpn_windows.iphelper.available", lambda: True), patch(
            "perchvpn_windows.iphelper.adapter_present_native",
            lambda g, n, **kw: None,
        ), patch(
            "perchvpn_windows.tun_recovery._powershell_adapter_probe",
            return_value=True,
        ) as ps_probe:
            assert tun_recovery._default_adapter_probe("guid", "PerchVPN") is True
            ps_probe.assert_called_once()

    def test_native_unavailable_returns_none_on_non_windows(self, monkeypatch):
        from perchvpn_windows import tun_recovery

        with patch("perchvpn_windows.iphelper.available", lambda: False):
            assert tun_recovery._default_adapter_probe("guid", "PerchVPN") is None
