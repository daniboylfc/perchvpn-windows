"""Focused tests for TUN trial journal and state capture (no live TUN)."""
from __future__ import annotations

import json
from unittest.mock import patch

import os
import tempfile
from pathlib import Path

import pytest

from perchvpn_windows.tun_trial_journal import (
    JournalError,
    TrialJournal,
    clear_journal,
    compute_file_identity,
    load_journal,
    save_journal,
)


class TestTrialJournalValidation:
    def test_roundtrip(self, tmp_path):
        from perchvpn_windows.tun_state_capture import NetworkSnapshot
        # Create a minimal valid snapshot for prepared state
        snapshot = NetworkSnapshot(
            routes=[{"DestinationPrefix": "0.0.0.0/0", "NextHop": "1.2.3.4", "InterfaceIndex": 1, "RouteMetric": 25, "PolicyStore": "ActiveStore", "ifMetric": None}],
            dns=[{"InterfaceIndex": 1, "AddressFamily": 2, "ServerAddresses": ["8.8.8.8"]}],
            adapters=[{"Name": "eth0", "InterfaceGuid": "guid", "InterfaceIndex": 1, "Status": "Up"}],
            ip_addresses=[{"InterfaceIndex": 1, "IPAddress": "10.0.0.1", "PrefixLength": 24, "AddressFamily": 2}],
            interface_config=[{"InterfaceIndex": 1, "AddressFamily": 2, "NlMtu": 1500, "InterfaceMetric": 5, "ConnectionState": 1}],
            winhttp_proxy="Direct access",
        )
        j = TrialJournal(adapter_name="perchvpn-trial", config_hash="abc123", network_snapshot=snapshot.to_dict())
        save_journal(j, path=tmp_path / "journal.json")
        loaded = load_journal(tmp_path / "journal.json")
        assert loaded is not None
        assert loaded.trial_id == j.trial_id
        assert loaded.adapter_name == "perchvpn-trial"
        assert loaded.state == "prepared"

    def test_malformed_json_rejected(self, tmp_path):
        (tmp_path / "journal.json").write_text("{not json", encoding="utf-8")
        with pytest.raises(JournalError):
            load_journal(tmp_path / "journal.json")

    def test_missing_trial_id_rejected(self, tmp_path):
        (tmp_path / "journal.json").write_text(
            json.dumps({"version": 1, "state": "prepared", "adapter_name": "wintun"}),
            encoding="utf-8",
        )
        with pytest.raises(JournalError):
            load_journal(tmp_path / "journal.json")

    def test_invalid_state_rejected(self, tmp_path):
        (tmp_path / "journal.json").write_text(
            json.dumps({
                "version": 1, "trial_id": "abc", "state": "bogus",
                "adapter_name": "wintun",
            }),
            encoding="utf-8",
        )
        with pytest.raises(JournalError):
            load_journal(tmp_path / "journal.json")

    def test_missing_adapter_name_rejected(self, tmp_path):
        (tmp_path / "journal.json").write_text(
            json.dumps({"version": 1, "trial_id": "abc", "state": "prepared"}),
            encoding="utf-8",
        )
        with pytest.raises(JournalError):
            load_journal(tmp_path / "journal.json")

    def test_executable_identity_incomplete_rejected(self, tmp_path):
        (tmp_path / "journal.json").write_text(
            json.dumps({
                "version": 1, "trial_id": "abc", "state": "prepared",
                "adapter_name": "wintun",
                "executable_identity": {"path": "/fake"},
            }),
            encoding="utf-8",
        )
        with pytest.raises(JournalError):
            load_journal(tmp_path / "journal.json")

    def test_network_snapshot_wrong_type_rejected(self, tmp_path):
        (tmp_path / "journal.json").write_text(
            json.dumps({
                "version": 1, "trial_id": "abc", "state": "prepared",
                "adapter_name": "wintun",
                "network_snapshot": "not a dict",
            }),
            encoding="utf-8",
        )
        with pytest.raises(JournalError):
            load_journal(tmp_path / "journal.json")

    def test_absent_journal_returns_none(self, tmp_path):
        assert load_journal(tmp_path / "nonexistent.json") is None

    def test_clear_unresolved_journal_rejected(self, tmp_path):
        j = TrialJournal(adapter_name="perchvpn-trial", state="running")
        save_journal(j, path=tmp_path / "journal.json")
        with pytest.raises(JournalError):
            clear_journal(tmp_path / "journal.json")

    def test_clear_stopped_journal_succeeds(self, tmp_path):
        j = TrialJournal(adapter_name="perchvpn-trial", state="stopped")
        save_journal(j, path=tmp_path / "journal.json")
        clear_journal(tmp_path / "journal.json")
        assert load_journal(tmp_path / "journal.json") is None

    def test_overwrite_unresolved_journal_rejected(self, tmp_path):
        j1 = TrialJournal(adapter_name="perchvpn-trial", state="prepared")
        save_journal(j1, path=tmp_path / "journal.json")
        j2 = TrialJournal(adapter_name="perchvpn-trial", state="prepared")
        with pytest.raises(JournalError):
            save_journal(j2, path=tmp_path / "journal.json")

    def test_overwrite_same_trial_id_allowed(self, tmp_path):
        from perchvpn_windows.tun_state_capture import NetworkSnapshot
        snapshot = NetworkSnapshot(
            routes=[{"DestinationPrefix": "0.0.0.0/0", "NextHop": "1.2.3.4", "InterfaceIndex": 1, "RouteMetric": 25, "PolicyStore": "ActiveStore", "ifMetric": None}],
            dns=[{"InterfaceIndex": 1, "AddressFamily": 2, "ServerAddresses": ["8.8.8.8"]}],
            adapters=[{"Name": "eth0", "InterfaceGuid": "guid", "InterfaceIndex": 1, "Status": "Up"}],
            ip_addresses=[{"InterfaceIndex": 1, "IPAddress": "10.0.0.1", "PrefixLength": 24, "AddressFamily": 2}],
            interface_config=[{"InterfaceIndex": 1, "AddressFamily": 2, "NlMtu": 1500, "InterfaceMetric": 5, "ConnectionState": 1}],
            winhttp_proxy="Direct access",
        )
        j1 = TrialJournal(adapter_name="perchvpn-trial", state="prepared", network_snapshot=snapshot.to_dict())
        save_journal(j1, path=tmp_path / "journal.json")
        j1.state = "running"
        save_journal(j1, path=tmp_path / "journal.json")
        loaded = load_journal(tmp_path / "journal.json")
        assert loaded.state == "running"

    def test_atomic_write_failure_leaves_no_tmp(self, tmp_path):
        j = TrialJournal(adapter_name="perchvpn-trial")
        target_dir = tmp_path / "readonly"
        target_dir.mkdir()
        target_dir.chmod(0o444)
        try:
            with pytest.raises(JournalError):
                save_journal(j, path=target_dir / "journal.json")
            tmp_files = list(target_dir.glob("*.tmp-*"))
            assert tmp_files == []
        finally:
            target_dir.chmod(0o755)

    def test_compute_file_identity(self, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(b"hello world")
        from perchvpn_windows.tun_trial_journal import compute_file_identity
        ident = compute_file_identity(str(f))
        assert ident["size"] == 11
        assert "sha256" in ident
        assert ident["path"] == str(f.resolve())


class TestStateCapture:
    def _minimal_snapshot(self, **overrides):
        """Create a minimal complete snapshot."""
        from perchvpn_windows.tun_state_capture import NetworkSnapshot
        base = {
            "routes": [{"DestinationPrefix": "0.0.0.0/0", "NextHop": "1.2.3.4", "InterfaceIndex": 1, "RouteMetric": 25, "PolicyStore": "ActiveStore", "ifMetric": None}],
            "dns": [{"InterfaceIndex": 1, "AddressFamily": 2, "ServerAddresses": ["8.8.8.8"]}],
            "adapters": [{"Name": "eth0", "InterfaceGuid": "guid", "InterfaceIndex": 1, "Status": "Up"}],
            "ip_addresses": [{"InterfaceIndex": 1, "IPAddress": "10.0.0.1", "PrefixLength": 24, "AddressFamily": 2}],
            "interface_config": [{"InterfaceIndex": 1, "AddressFamily": 2, "NlMtu": 1500, "InterfaceMetric": 5, "ConnectionState": 1}],
            "winhttp_proxy": "Direct access",
        }
        base.update(overrides)
        return NetworkSnapshot(**base)

    def test_compare_identical_snapshots(self):
        from perchvpn_windows.tun_state_capture import (
            NetworkSnapshot,
            compare_snapshots,
        )
        a = self._minimal_snapshot()
        b = self._minimal_snapshot()
        diffs = compare_snapshots(a, b)
        assert diffs == []

    def test_compare_route_added(self):
        from perchvpn_windows.tun_state_capture import (
            NetworkSnapshot,
            compare_snapshots,
        )
        a = self._minimal_snapshot()
        b = self._minimal_snapshot(
            routes=[
                {"DestinationPrefix": "0.0.0.0/0", "NextHop": "1.2.3.4", "InterfaceIndex": 1, "RouteMetric": 25, "PolicyStore": "ActiveStore", "ifMetric": None},
                {"DestinationPrefix": "0.0.0.0/0", "NextHop": "10.0.0.1", "InterfaceIndex": 5, "RouteMetric": 10, "PolicyStore": "ActiveStore", "ifMetric": None},
            ]
        )
        diffs = compare_snapshots(a, b)
        assert len(diffs) == 1
        assert diffs[0].category == "route"
        assert "added" in diffs[0].description.lower()

    def test_compare_route_removed(self):
        from perchvpn_windows.tun_state_capture import (
            NetworkSnapshot,
            compare_snapshots,
        )
        a = self._minimal_snapshot(
            routes=[
                {"DestinationPrefix": "0.0.0.0/0", "NextHop": "1.2.3.4", "InterfaceIndex": 1, "RouteMetric": 25, "PolicyStore": "ActiveStore", "ifMetric": None},
                {"DestinationPrefix": "10.0.0.0/8", "NextHop": "10.0.0.1", "InterfaceIndex": 1, "RouteMetric": 10, "PolicyStore": "ActiveStore", "ifMetric": None},
            ]
        )
        b = self._minimal_snapshot()
        diffs = compare_snapshots(a, b)
        assert len(diffs) == 1
        assert diffs[0].category == "route"
        assert "removed" in diffs[0].description.lower()

    def test_compare_dns_changed(self):
        from perchvpn_windows.tun_state_capture import (
            NetworkSnapshot,
            compare_snapshots,
        )
        a = self._minimal_snapshot()
        b = self._minimal_snapshot(
            dns=[{"InterfaceIndex": 1, "AddressFamily": 2, "ServerAddresses": ["10.0.0.1"]}]
        )
        diffs = compare_snapshots(a, b)
        assert len(diffs) == 1
        assert diffs[0].category == "dns"
        assert "changed" in diffs[0].description.lower()

    def test_compare_adapter_added(self):
        from perchvpn_windows.tun_state_capture import (
            NetworkSnapshot,
            compare_snapshots,
        )
        a = self._minimal_snapshot()
        b = self._minimal_snapshot(
            adapters=[
                {"Name": "eth0", "InterfaceGuid": "guid", "InterfaceIndex": 1, "Status": "Up"},
                {"Name": "perchvpn-trial", "InterfaceGuid": "guid2", "InterfaceIndex": 99, "Status": "Up"},
            ]
        )
        diffs = compare_snapshots(a, b)
        assert len(diffs) == 1
        assert diffs[0].category == "adapter"
        assert "added" in diffs[0].description.lower()

    def test_compare_mtu_changed(self):
        from perchvpn_windows.tun_state_capture import (
            NetworkSnapshot,
            compare_snapshots,
        )
        a = self._minimal_snapshot()
        b = self._minimal_snapshot(
            interface_config=[{"InterfaceIndex": 1, "AddressFamily": 2, "NlMtu": 1400, "InterfaceMetric": 5, "ConnectionState": 1}]
        )
        diffs = compare_snapshots(a, b)
        assert len(diffs) == 1
        assert diffs[0].category == "interface"
        assert "mtu" in diffs[0].description.lower()

    def test_compare_metric_changed(self):
        from perchvpn_windows.tun_state_capture import (
            NetworkSnapshot,
            compare_snapshots,
        )
        a = self._minimal_snapshot()
        b = self._minimal_snapshot(
            interface_config=[{"InterfaceIndex": 1, "AddressFamily": 2, "NlMtu": 1500, "InterfaceMetric": 10, "ConnectionState": 1}]
        )
        diffs = compare_snapshots(a, b)
        assert len(diffs) == 1
        assert diffs[0].category == "interface"
        assert "metric" in diffs[0].description.lower()

    def test_compare_proxy_changed(self):
        from perchvpn_windows.tun_state_capture import (
            NetworkSnapshot,
            compare_snapshots,
        )
        a = self._minimal_snapshot()
        b = self._minimal_snapshot(winhttp_proxy="Proxy: 127.0.0.1:8080")
        diffs = compare_snapshots(a, b)
        assert len(diffs) == 1
        assert diffs[0].category == "proxy"

    def test_snapshot_roundtrip(self):
        from perchvpn_windows.tun_state_capture import NetworkSnapshot
        s = NetworkSnapshot(
            routes=[{"DestinationPrefix": "0.0.0.0/0", "NextHop": "1.2.3.4", "InterfaceIndex": 1, "RouteMetric": 25, "PolicyStore": "ActiveStore", "ifMetric": None}],
            dns=[{"InterfaceIndex": 1, "AddressFamily": 2, "ServerAddresses": ["8.8.8.8"]}],
            adapters=[{"Name": "eth0", "InterfaceGuid": "guid", "InterfaceIndex": 1, "Status": "Up"}],
            ip_addresses=[{"InterfaceIndex": 1, "IPAddress": "10.0.0.1", "PrefixLength": 24, "AddressFamily": 2}],
            interface_config=[{"InterfaceIndex": 1, "AddressFamily": 2, "NlMtu": 1500, "InterfaceMetric": 5, "ConnectionState": 1}],
            winhttp_proxy="direct",
        )
        d = s.to_dict()
        s2 = NetworkSnapshot.from_dict(d)
        assert s2.routes == s.routes
        assert s2.winhttp_proxy == s.winhttp_proxy


class TestCaptureFailure:
    def test_capture_error_on_ps_failure(self):
        from perchvpn_windows.tun_state_capture import (
            CaptureError,
            capture_routes,
        )
        with patch(
            "perchvpn_windows.tun_state_capture.subprocess.run",
            side_effect=OSError("no powershell"),
        ):
            with pytest.raises(CaptureError):
                capture_routes()

    def test_capture_error_on_empty_output(self):
        from perchvpn_windows.tun_state_capture import (
            CaptureError,
            capture_routes,
        )
        mock_result = type("R", (), {"stdout": "", "stderr": "", "returncode": 0})()
        with patch(
            "perchvpn_windows.tun_state_capture.subprocess.run",
            return_value=mock_result,
        ):
            with pytest.raises(CaptureError):
                capture_routes()

    def test_capture_error_on_invalid_json(self):
        from perchvpn_windows.tun_state_capture import (
            CaptureError,
            capture_routes,
        )
        mock_result = type("R", (), {"stdout": "not json", "stderr": "", "returncode": 0})()
        with patch(
            "perchvpn_windows.tun_state_capture.subprocess.run",
            return_value=mock_result,
        ):
            with pytest.raises(CaptureError):
                capture_routes()

    def test_capture_error_on_ps_nonzero(self):
        from perchvpn_windows.tun_state_capture import (
            CaptureError,
            capture_routes,
        )
        mock_result = type("R", (), {"stdout": "", "stderr": "error", "returncode": 1})()
        with patch(
            "perchvpn_windows.tun_state_capture.subprocess.run",
            return_value=mock_result,
        ):
            with pytest.raises(CaptureError):
                capture_routes()

    def test_capture_snapshot_propagates_error(self):
        from perchvpn_windows.tun_state_capture import (
            CaptureError,
            capture_snapshot,
        )
        with patch(
            "perchvpn_windows.tun_state_capture.capture_routes",
            side_effect=CaptureError("boom"),
        ):
            with pytest.raises(CaptureError):
                capture_snapshot()

    def test_incomplete_snapshot_not_clean(self):
        from perchvpn_windows.tun_state_capture import (
            CaptureError,
            NetworkSnapshot,
            compare_snapshots,
        )
        # Two complete snapshots with different routes should produce differences
        a = NetworkSnapshot(
            routes=[{"DestinationPrefix": "0.0.0.0/0", "NextHop": "1.2.3.4", "InterfaceIndex": 1, "RouteMetric": 25, "PolicyStore": "ActiveStore", "ifMetric": None}],
            dns=[{"InterfaceIndex": 1, "AddressFamily": 2, "ServerAddresses": ["8.8.8.8"]}],
            adapters=[{"Name": "eth0", "InterfaceGuid": "guid", "InterfaceIndex": 1, "Status": "Up"}],
            ip_addresses=[{"InterfaceIndex": 1, "IPAddress": "10.0.0.1", "PrefixLength": 24, "AddressFamily": 2}],
            interface_config=[{"InterfaceIndex": 1, "AddressFamily": 2, "NlMtu": 1500, "InterfaceMetric": 5, "ConnectionState": 1}],
            winhttp_proxy="Direct access",
        )
        b = NetworkSnapshot(
            routes=[],
            dns=[{"InterfaceIndex": 1, "AddressFamily": 2, "ServerAddresses": ["8.8.8.8"]}],
            adapters=[{"Name": "eth0", "InterfaceGuid": "guid", "InterfaceIndex": 1, "Status": "Up"}],
            ip_addresses=[{"InterfaceIndex": 1, "IPAddress": "10.0.0.1", "PrefixLength": 24, "AddressFamily": 2}],
            interface_config=[{"InterfaceIndex": 1, "AddressFamily": 2, "NlMtu": 1500, "InterfaceMetric": 5, "ConnectionState": 1}],
            winhttp_proxy="Direct access",
        )
        with pytest.raises(CaptureError):
            compare_snapshots(a, b)


class TestValidateRecords:
    def test_empty_dict_list_raises(self):
        from perchvpn_windows.tun_state_capture import CaptureError, capture_routes
        with patch("perchvpn_windows.tun_state_capture.subprocess.run") as mock_run:
            mock_result = type("R", (), {"stdout": "[{}]", "stderr": "", "returncode": 0})()
            mock_run.return_value = mock_result
            with pytest.raises(CaptureError):
                capture_routes()

    def test_empty_list_raises(self):
        from perchvpn_windows.tun_state_capture import CaptureError, capture_routes
        with patch("perchvpn_windows.tun_state_capture.subprocess.run") as mock_run:
            mock_result = type("R", (), {"stdout": "[]", "stderr": "", "returncode": 0})()
            mock_run.return_value = mock_result
            with pytest.raises(CaptureError):
                capture_routes()

    def test_missing_required_keys_raises(self):
        from perchvpn_windows.tun_state_capture import CaptureError, capture_routes
        with patch("perchvpn_windows.tun_state_capture.subprocess.run") as mock_run:
            # Missing PolicyStore
            mock_result = type(
                "R",
                (),
                {
                    "stdout": '[{"DestinationPrefix": "0.0.0.0/0", "NextHop": "1.2.3.4", "InterfaceIndex": 1, "RouteMetric": 25}]',
                    "stderr": "",
                    "returncode": 0,
                },
            )()
            mock_run.return_value = mock_result
            with pytest.raises(CaptureError):
                capture_routes()

    def test_capture_routes_allows_nullable_ifmetric(self):
        from perchvpn_windows.tun_state_capture import CaptureError, capture_routes
        with patch("perchvpn_windows.tun_state_capture.subprocess.run") as mock_run:
            # ifMetric is None (nullable) - this is valid Windows CIM output
            mock_result = type(
                "R",
                (),
                {
                    "stdout": '[{"DestinationPrefix": "0.0.0.0/0", "NextHop": "1.2.3.4", "InterfaceIndex": 1, "RouteMetric": 25, "ifMetric": null, "PolicyStore": "ActiveStore"}]',
                    "stderr": "",
                    "returncode": 0,
                },
            )()
            mock_run.return_value = mock_result
            # Should NOT raise
            result = capture_routes()
            assert len(result) == 1
            assert result[0]["ifMetric"] is None

    def test_capture_interface_config_allows_nullable_interface_metric(self):
        from perchvpn_windows.tun_state_capture import CaptureError, capture_interface_config
        with patch("perchvpn_windows.tun_state_capture.subprocess.run") as mock_run:
            # InterfaceMetric is None (nullable) - valid for automatic metric
            mock_result = type(
                "R",
                (),
                {
                    "stdout": '[{"InterfaceIndex": 1, "AddressFamily": 2, "NlMtu": 1500, "InterfaceMetric": null, "ConnectionState": 1}]',
                    "stderr": "",
                    "returncode": 0,
                },
            )()
            mock_run.return_value = mock_result
            # Should NOT raise
            result = capture_interface_config()
            assert len(result) == 1
            assert result[0]["InterfaceMetric"] is None


class TestJournalSnapshotValidation:
    def test_journal_rejects_empty_snapshot_dict(self):
        from perchvpn_windows.tun_trial_journal import JournalError, TrialJournal
        with pytest.raises(JournalError, match="invalid network_snapshot"):
            TrialJournal.from_dict({
                "version": 1,
                "trial_id": "abc",
                "state": "prepared",
                "adapter_name": "wintun",
                "network_snapshot": {},
            })

    def test_journal_rejects_prepared_without_snapshot(self):
        from perchvpn_windows.tun_trial_journal import JournalError, TrialJournal
        with pytest.raises(JournalError, match="network_snapshot is required for state 'prepared'"):
            TrialJournal.from_dict({
                "version": 1,
                "trial_id": "abc",
                "state": "prepared",
                "adapter_name": "wintun",
                "network_snapshot": None,
            })

    def test_journal_rejects_running_without_snapshot(self):
        from perchvpn_windows.tun_trial_journal import JournalError, TrialJournal
        with pytest.raises(JournalError, match="network_snapshot is required for state 'running'"):
            TrialJournal.from_dict({
                "version": 1,
                "trial_id": "abc",
                "state": "running",
                "adapter_name": "wintun",
                "network_snapshot": None,
            })

    def test_journal_allows_stopped_without_snapshot(self):
        from perchvpn_windows.tun_trial_journal import TrialJournal
        # Should NOT raise for stopped state
        j = TrialJournal.from_dict({
            "version": 1,
            "trial_id": "abc",
            "state": "stopped",
            "adapter_name": "wintun",
            "network_snapshot": None,
        })
        assert j.state == "stopped"
        assert j.network_snapshot is None


class TestCompareSnapshotsValidation:
    def test_empty_snapshot_raises(self):
        from perchvpn_windows.tun_state_capture import CaptureError, NetworkSnapshot, compare_snapshots
        a = NetworkSnapshot(
            routes=[{"DestinationPrefix": "0.0.0.0/0", "NextHop": "1.2.3.4", "InterfaceIndex": 1, "RouteMetric": 25, "PolicyStore": "ActiveStore", "ifMetric": None}],
            dns=[{"InterfaceIndex": 1, "AddressFamily": 2, "ServerAddresses": ["8.8.8.8"]}],
            adapters=[{"Name": "eth0", "InterfaceGuid": "guid", "InterfaceIndex": 1, "Status": "Up"}],
            ip_addresses=[{"InterfaceIndex": 1, "IPAddress": "10.0.0.1", "PrefixLength": 24, "AddressFamily": 2}],
            interface_config=[{"InterfaceIndex": 1, "AddressFamily": 2, "NlMtu": 1500, "InterfaceMetric": 5, "ConnectionState": 1}],
            winhttp_proxy="Direct access",
        )
        b = NetworkSnapshot(
            routes=[],
            dns=[{"InterfaceIndex": 1, "AddressFamily": 2, "ServerAddresses": ["8.8.8.8"]}],
            adapters=[{"Name": "eth0", "InterfaceGuid": "guid", "InterfaceIndex": 1, "Status": "Up"}],
            ip_addresses=[{"InterfaceIndex": 1, "IPAddress": "10.0.0.1", "PrefixLength": 24, "AddressFamily": 2}],
            interface_config=[{"InterfaceIndex": 1, "AddressFamily": 2, "NlMtu": 1500, "InterfaceMetric": 5, "ConnectionState": 1}],
            winhttp_proxy="Direct access",
        )
        with pytest.raises(CaptureError):
            compare_snapshots(a, b)

    def test_both_empty_snapshots_raises(self):
        from perchvpn_windows.tun_state_capture import CaptureError, NetworkSnapshot, compare_snapshots
        a = NetworkSnapshot(
            routes=[],
            dns=[],
            adapters=[],
            ip_addresses=[],
            interface_config=[],
            winhttp_proxy="",
        )
        b = NetworkSnapshot(
            routes=[],
            dns=[],
            adapters=[],
            ip_addresses=[],
            interface_config=[],
            winhttp_proxy="",
        )
        with pytest.raises(CaptureError):
            compare_snapshots(a, b)

    def test_route_metric_change_detected(self):
        from perchvpn_windows.tun_state_capture import NetworkSnapshot, compare_snapshots
        a = NetworkSnapshot(
            routes=[{"DestinationPrefix": "0.0.0.0/0", "NextHop": "1.2.3.4", "InterfaceIndex": 1, "RouteMetric": 25, "PolicyStore": "ActiveStore", "ifMetric": None}],
            dns=[{"InterfaceIndex": 1, "AddressFamily": 2, "ServerAddresses": ["8.8.8.8"]}],
            adapters=[{"Name": "eth0", "InterfaceGuid": "guid", "InterfaceIndex": 1, "Status": "Up"}],
            ip_addresses=[{"InterfaceIndex": 1, "IPAddress": "10.0.0.1", "PrefixLength": 24, "AddressFamily": 2}],
            interface_config=[{"InterfaceIndex": 1, "AddressFamily": 2, "NlMtu": 1500, "InterfaceMetric": 5, "ConnectionState": 1}],
            winhttp_proxy="Direct access",
        )
        b = NetworkSnapshot(
            routes=[{"DestinationPrefix": "0.0.0.0/0", "NextHop": "1.2.3.4", "InterfaceIndex": 1, "RouteMetric": 200, "PolicyStore": "ActiveStore", "ifMetric": None}],
            dns=[{"InterfaceIndex": 1, "AddressFamily": 2, "ServerAddresses": ["8.8.8.8"]}],
            adapters=[{"Name": "eth0", "InterfaceGuid": "guid", "InterfaceIndex": 1, "Status": "Up"}],
            ip_addresses=[{"InterfaceIndex": 1, "IPAddress": "10.0.0.1", "PrefixLength": 24, "AddressFamily": 2}],
            interface_config=[{"InterfaceIndex": 1, "AddressFamily": 2, "NlMtu": 1500, "InterfaceMetric": 5, "ConnectionState": 1}],
            winhttp_proxy="Direct access",
        )
        diffs = compare_snapshots(a, b)
        assert any(d.category == "route" and "RouteMetric" in d.description for d in diffs)

    def test_persistent_store_route_detected(self):
        from perchvpn_windows.tun_state_capture import NetworkSnapshot, compare_snapshots
        a = NetworkSnapshot(
            routes=[
                {"DestinationPrefix": "0.0.0.0/0", "NextHop": "1.2.3.4", "InterfaceIndex": 1, "RouteMetric": 25, "PolicyStore": "ActiveStore", "ifMetric": None},
                {"DestinationPrefix": "10.0.0.0/8", "NextHop": "10.0.0.1", "InterfaceIndex": 1, "RouteMetric": 10, "PolicyStore": "PersistentStore", "ifMetric": None},
            ],
            dns=[{"InterfaceIndex": 1, "AddressFamily": 2, "ServerAddresses": ["8.8.8.8"]}],
            adapters=[{"Name": "eth0", "InterfaceGuid": "guid", "InterfaceIndex": 1, "Status": "Up"}],
            ip_addresses=[{"InterfaceIndex": 1, "IPAddress": "10.0.0.1", "PrefixLength": 24, "AddressFamily": 2}],
            interface_config=[{"InterfaceIndex": 1, "AddressFamily": 2, "NlMtu": 1500, "InterfaceMetric": 5, "ConnectionState": 1}],
            winhttp_proxy="Direct access",
        )
        b = NetworkSnapshot(
            routes=[
                {"DestinationPrefix": "0.0.0.0/0", "NextHop": "1.2.3.4", "InterfaceIndex": 1, "RouteMetric": 25, "PolicyStore": "ActiveStore", "ifMetric": None},
            ],
            dns=[{"InterfaceIndex": 1, "AddressFamily": 2, "ServerAddresses": ["8.8.8.8"]}],
            adapters=[{"Name": "eth0", "InterfaceGuid": "guid", "InterfaceIndex": 1, "Status": "Up"}],
            ip_addresses=[{"InterfaceIndex": 1, "IPAddress": "10.0.0.1", "PrefixLength": 24, "AddressFamily": 2}],
            interface_config=[{"InterfaceIndex": 1, "AddressFamily": 2, "NlMtu": 1500, "InterfaceMetric": 5, "ConnectionState": 1}],
            winhttp_proxy="Direct access",
        )
        diffs = compare_snapshots(a, b)
        assert any(d.category == "route" and "PersistentStore" in d.description for d in diffs)

    def test_ipv4_dns_change_with_ipv6_present(self):
        from perchvpn_windows.tun_state_capture import NetworkSnapshot, compare_snapshots
        a = NetworkSnapshot(
            routes=[{"DestinationPrefix": "0.0.0.0/0", "NextHop": "1.2.3.4", "InterfaceIndex": 1, "RouteMetric": 25, "PolicyStore": "ActiveStore", "ifMetric": None}],
            dns=[
                {"InterfaceIndex": 1, "AddressFamily": 2, "ServerAddresses": ["8.8.8.8"]},
                {"InterfaceIndex": 1, "AddressFamily": 23, "ServerAddresses": ["::1"]},
            ],
            adapters=[{"Name": "eth0", "InterfaceGuid": "guid", "InterfaceIndex": 1, "Status": "Up"}],
            ip_addresses=[{"InterfaceIndex": 1, "IPAddress": "10.0.0.1", "PrefixLength": 24, "AddressFamily": 2}],
            interface_config=[{"InterfaceIndex": 1, "AddressFamily": 2, "NlMtu": 1500, "InterfaceMetric": 5, "ConnectionState": 1}],
            winhttp_proxy="Direct access",
        )
        b = NetworkSnapshot(
            routes=[{"DestinationPrefix": "0.0.0.0/0", "NextHop": "1.2.3.4", "InterfaceIndex": 1, "RouteMetric": 25, "PolicyStore": "ActiveStore", "ifMetric": None}],
            dns=[
                {"InterfaceIndex": 1, "AddressFamily": 2, "ServerAddresses": ["10.0.0.1"]},
                {"InterfaceIndex": 1, "AddressFamily": 23, "ServerAddresses": ["::1"]},
            ],
            adapters=[{"Name": "eth0", "InterfaceGuid": "guid", "InterfaceIndex": 1, "Status": "Up"}],
            ip_addresses=[{"InterfaceIndex": 1, "IPAddress": "10.0.0.1", "PrefixLength": 24, "AddressFamily": 2}],
            interface_config=[{"InterfaceIndex": 1, "AddressFamily": 2, "NlMtu": 1500, "InterfaceMetric": 5, "ConnectionState": 1}],
            winhttp_proxy="Direct access",
        )
        diffs = compare_snapshots(a, b)
        assert any(d.category == "dns" and d.description.startswith("DNS changed") for d in diffs)

    def test_ip_address_and_mtu_change(self):
        from perchvpn_windows.tun_state_capture import NetworkSnapshot, compare_snapshots
        a = NetworkSnapshot(
            routes=[{"DestinationPrefix": "0.0.0.0/0", "NextHop": "1.2.3.4", "InterfaceIndex": 1, "RouteMetric": 25, "PolicyStore": "ActiveStore", "ifMetric": None}],
            dns=[{"InterfaceIndex": 1, "AddressFamily": 2, "ServerAddresses": ["8.8.8.8"]}],
            adapters=[{"Name": "eth0", "InterfaceGuid": "guid", "InterfaceIndex": 1, "Status": "Up"}],
            ip_addresses=[
                {"InterfaceIndex": 1, "IPAddress": "10.0.0.1", "PrefixLength": 24, "AddressFamily": 2},
                {"InterfaceIndex": 1, "IPAddress": "::1", "PrefixLength": 128, "AddressFamily": 23},
            ],
            interface_config=[
                {"InterfaceIndex": 1, "AddressFamily": 2, "NlMtu": 1500, "InterfaceMetric": 5, "ConnectionState": 1},
                {"InterfaceIndex": 1, "AddressFamily": 23, "NlMtu": 1500, "InterfaceMetric": 5, "ConnectionState": 1},
            ],
            winhttp_proxy="Direct access",
        )
        b = NetworkSnapshot(
            routes=[{"DestinationPrefix": "0.0.0.0/0", "NextHop": "1.2.3.4", "InterfaceIndex": 1, "RouteMetric": 25, "PolicyStore": "ActiveStore", "ifMetric": None}],
            dns=[{"InterfaceIndex": 1, "AddressFamily": 2, "ServerAddresses": ["8.8.8.8"]}],
            adapters=[{"Name": "eth0", "InterfaceGuid": "guid", "InterfaceIndex": 1, "Status": "Up"}],
            ip_addresses=[
                {"InterfaceIndex": 1, "IPAddress": "10.0.0.1", "PrefixLength": 16, "AddressFamily": 2},
                {"InterfaceIndex": 1, "IPAddress": "::1", "PrefixLength": 128, "AddressFamily": 23},
                {"InterfaceIndex": 1, "IPAddress": "192.168.1.1", "PrefixLength": 24, "AddressFamily": 2},
            ],
            interface_config=[
                {"InterfaceIndex": 1, "AddressFamily": 2, "NlMtu": 1400, "InterfaceMetric": 5, "ConnectionState": 1},
                {"InterfaceIndex": 1, "AddressFamily": 23, "NlMtu": 1500, "InterfaceMetric": 5, "ConnectionState": 1},
            ],
            winhttp_proxy="Direct access",
        )
        diffs = compare_snapshots(a, b)
        # Should detect IP prefix change, IP added, and IPv4 MTU change
        assert any(d.category == "ip_address" and "PrefixLength" in d.description for d in diffs)
        assert any(d.category == "ip_address" and "added" in d.description.lower() for d in diffs)
        assert any(d.category == "interface" and "NlMtu" in d.description for d in diffs)


class TestRollbackCommandSafety:
    """Regression tests for verified PowerShell rollback generation."""

    def test_partition_diffs_scopes_trial_from_ambient(self):
        from perchvpn_windows.tun_state_capture import (
            NetworkSnapshot,
            StateDifference,
            partition_diffs,
        )

        current = NetworkSnapshot(
            routes=[
                {"DestinationPrefix": "0.0.0.0/0", "NextHop": "1.2.3.4", "InterfaceIndex": 1, "RouteMetric": 25, "PolicyStore": "ActiveStore", "ifMetric": None},
            ],
            dns=[{"InterfaceIndex": 2, "AddressFamily": 2, "ServerAddresses": ["8.8.8.8"]}],
            adapters=[{"Name": "eth0", "InterfaceGuid": "g1", "InterfaceIndex": 1, "Status": "Up"},
                      {"Name": "perchvpn-trial0", "InterfaceGuid": "g2", "InterfaceIndex": 72, "Status": "Up"}],
            ip_addresses=[{"InterfaceIndex": 1, "IPAddress": "10.0.0.1", "PrefixLength": 24, "AddressFamily": 2}],
            interface_config=[{"InterfaceIndex": 1, "AddressFamily": 2, "NlMtu": 1500, "InterfaceMetric": 5, "ConnectionState": 1}],
            winhttp_proxy="Direct access",
        )
        diffs = [
            StateDifference(category="route", description="Route removed: ('ff00::/8', '::', 29, 'ActiveStore')", baseline_value={"DestinationPrefix": "ff00::/8", "NextHop": "::", "InterfaceIndex": 29, "RouteMetric": 1, "PolicyStore": "ActiveStore"}, current_value=None),
            StateDifference(category="route", description="Route added", baseline_value=None, current_value={"DestinationPrefix": "0.0.0.0/0", "NextHop": "10.0.0.1", "InterfaceIndex": 72, "RouteMetric": 1, "PolicyStore": "ActiveStore"}),
            StateDifference(category="ip_address", description="IP added", baseline_value=None, current_value={"InterfaceIndex": 72, "IPAddress": "10.0.0.33", "PrefixLength": 24, "AddressFamily": 2}),
            StateDifference(category="dns", description="DNS added for interface 2", baseline_value=None, current_value={"InterfaceIndex": 2, "AddressFamily": 2, "ServerAddresses": ["9.9.9.9"]}),
            StateDifference(category="adapter", description="Adapter added: perchvpn-trial0", baseline_value=None, current_value={"Name": "perchvpn-trial0", "Status": "Up"}),
            StateDifference(category="adapter", description="Adapter added: UserNIC", baseline_value=None, current_value={"Name": "UserNIC", "Status": "Up"}),
            StateDifference(category="interface", description="InterfaceMetric changed", baseline_value={"InterfaceIndex": 1, "AddressFamily": 2, "InterfaceMetric": 5}, current_value={"InterfaceIndex": 1, "AddressFamily": 2, "InterfaceMetric": 50}),
        ]
        owned, ambient = partition_diffs(
            diffs, adapter_name="perchvpn-trial0", current_snapshot=current,
        )
        assert [d.description for d in owned] == [
            "Route added",
            "IP added",
            "DNS added for interface 2",
            "Adapter added: perchvpn-trial0",
        ]
        assert [d.description for d in ambient] == [
            "Route removed: ('ff00::/8', '::', 29, 'ActiveStore')",
            "Adapter added: UserNIC",
            "InterfaceMetric changed",
        ]

    def test_partition_diffs_trial_adapter_absent(self):
        from perchvpn_windows.tun_state_capture import (
            NetworkSnapshot,
            StateDifference,
            partition_diffs,
        )

        current = NetworkSnapshot(
            routes=[],
            dns=[],
            adapters=[{"Name": "eth0", "InterfaceGuid": "g1", "InterfaceIndex": 1, "Status": "Up"}],
            ip_addresses=[],
            interface_config=[],
            winhttp_proxy="Direct access",
        )
        diffs = [StateDifference(
            category="route", description="Route added", baseline_value=None,
            current_value={"DestinationPrefix": "198.18.0.0/15", "NextHop": "0.0.0.0", "InterfaceIndex": 72, "RouteMetric": 1, "PolicyStore": "ActiveStore"},
        )]
        owned, ambient = partition_diffs(
            diffs, adapter_name="perchvpn-trial0", current_snapshot=current,
        )
        assert owned == []
        assert len(ambient) == 1

    def test_destructive_cmdlets_suppress_confirmation(self):
        from perchvpn_windows.tun_state_capture import StateDifference, generate_rollback_commands

        diffs = [
            StateDifference(
                category="route",
                description="Route added",
                baseline_value=None,
                current_value={"DestinationPrefix": "198.51.100.254/32",
                               "NextHop": "0.0.0.0", "InterfaceIndex": 1,
                               "RouteMetric": 999, "PolicyStore": "ActiveStore"},
            ),
            StateDifference(
                category="ip_address",
                description="IP added for interface 1",
                baseline_value=None,
                current_value={"InterfaceIndex": 1, "IPAddress": "192.0.2.9",
                               "PrefixLength": 24, "AddressFamily": 2},
            ),
        ]
        commands = generate_rollback_commands(diffs)
        assert len(commands) == 2
        assert commands[0].startswith("Remove-NetRoute")
        assert "-Confirm:$false" in commands[0]
        assert commands[1].startswith("Remove-NetIPAddress")
        assert "-Confirm:$false" in commands[1]

    def _dns_baseline(self):
        return {"InterfaceIndex": 1, "AddressFamily": 2, "ServerAddresses": ["8.8.8.8"]}

    def test_dns_changed_empty_baseline_servers_resets(self):
        from perchvpn_windows.tun_state_capture import StateDifference, _rollback_dns

        commands = _rollback_dns(
            "DNS changed for interface 2",
            {"InterfaceIndex": 1, "AddressFamily": 2, "ServerAddresses": []},
            {"InterfaceIndex": 1, "AddressFamily": 2, "ServerAddresses": ["9.9.9.9"]},
        )
        assert len(commands) == 1
        assert "-ResetServerAddresses" in commands[0]
        assert "-ServerAddresses" not in commands[0]
        assert "-AddressFamily" not in commands[0]

    def test_dns_changed_ipv6_restores_servers_without_address_family(self):
        from perchvpn_windows.tun_state_capture import _rollback_dns

        commands = _rollback_dns(
            "DNS changed for interface 52",
            {
                "InterfaceIndex": 52,
                "AddressFamily": 23,
                "ServerAddresses": [
                    "fec0:0:0:ffff::1",
                    "fec0:0:0:ffff::2",
                ],
            },
            {
                "InterfaceIndex": 52,
                "AddressFamily": 23,
                "ServerAddresses": ["2001:db8::53"],
            },
        )
        assert len(commands) == 1
        assert "-AddressFamily" not in commands[0]
        assert "-ServerAddresses ('fec0:0:0:ffff::1', 'fec0:0:0:ffff::2')" in commands[0]
        assert "{" not in commands[0] and "}" not in commands[0]

    def test_dns_added_and_removed_reset_without_address_family(self):
        from perchvpn_windows.tun_state_capture import _rollback_dns

        added = _rollback_dns(
            "DNS added for interface 2",
            None,
            {"InterfaceIndex": 2, "AddressFamily": 2, "ServerAddresses": ["9.9.9.9"]},
        )
        removed = _rollback_dns(
            "DNS removed for interface 2",
            {"InterfaceIndex": 2, "AddressFamily": 23, "ServerAddresses": []},
            None,
        )
        assert len(added) == len(removed) == 1
        assert "-ResetServerAddresses" in added[0]
        assert "-ResetServerAddresses" in removed[0]
        assert "-AddressFamily" not in added[0]
        assert "-AddressFamily" not in removed[0]

    def test_prefixlength_commands_are_fully_interpolated(self):
        from perchvpn_windows.tun_state_capture import StateDifference, generate_rollback_commands

        diffs = [StateDifference(
            category="ip_address",
            description="PrefixLength changed for IP 10.0.0.1: 24 -> 25",
            baseline_value={"InterfaceIndex": 1, "IPAddress": "10.0.0.1",
                            "PrefixLength": 24, "AddressFamily": 2},
            current_value=None,
        )]
        commands = generate_rollback_commands(diffs)
        assert len(commands) == 2
        assert "{" not in " ".join(commands) and "}" not in " ".join(commands)
        assert "Remove-NetIPAddress" in commands[0]
        assert "-PrefixLength 24" in commands[1]

    def test_route_removed_preserves_policystore_and_metric(self):
        from perchvpn_windows.tun_state_capture import StateDifference, generate_rollback_commands

        diffs = [StateDifference(
            category="route",
            description="Route removed",
            baseline_value={"DestinationPrefix": "10.0.0.0/8", "NextHop": "10.0.0.1",
                            "InterfaceIndex": 5, "RouteMetric": 10,
                            "PolicyStore": "PersistentStore"},
            current_value=None,
        )]
        commands = generate_rollback_commands(diffs)
        assert len(commands) == 1
        cmd = commands[0]
        assert cmd.startswith("New-NetRoute")
        assert "-PolicyStore PersistentStore" in cmd
        assert "-RouteMetric 10" in cmd
        assert "-ifMetric" not in cmd

    def test_route_metric_change_uses_set_netroute_and_no_ifmetric(self):
        from perchvpn_windows.tun_state_capture import StateDifference, generate_rollback_commands

        diffs = [StateDifference(
            category="route",
            description="RouteMetric changed for route: 25 -> 200",
            baseline_value={"DestinationPrefix": "0.0.0.0/0", "NextHop": "1.2.3.4",
                            "InterfaceIndex": 1, "RouteMetric": 25,
                            "PolicyStore": "ActiveStore"},
            current_value=200,
        )]
        commands = generate_rollback_commands(diffs)
        assert len(commands) == 1
        cmd = commands[0]
        assert cmd.startswith("Set-NetRoute")
        assert "-RouteMetric 25" in cmd
        assert "-PolicyStore ActiveStore" in cmd
        assert "-ifMetric" not in cmd

    def test_interface_mtu_uses_nlmtubytes_and_family_name(self):
        from perchvpn_windows.tun_state_capture import StateDifference, generate_rollback_commands

        diffs = [StateDifference(
            category="interface",
            description="NlMtu changed for interface 2: 1500 -> 1400",
            baseline_value={"InterfaceIndex": 1, "AddressFamily": 2,
                            "NlMtu": 1500, "InterfaceMetric": None,
                            "ConnectionState": 1},
            current_value=None,
        )]
        commands = generate_rollback_commands(diffs)
        assert len(commands) == 1
        cmd = commands[0]
        assert cmd.startswith("Set-NetIPInterface")
        assert "-NlMtuBytes 1500" in cmd
        assert "-AddressFamily IPv4" in cmd
        assert "-ConnectionState" not in cmd

    def test_interface_metric_none_restores_automatic_metric(self):
        from perchvpn_windows.tun_state_capture import StateDifference, generate_rollback_commands

        diffs = [StateDifference(
            category="interface",
            description="InterfaceMetric changed for interface 2: None -> 5",
            baseline_value={"InterfaceIndex": 1, "AddressFamily": 23,
                            "NlMtu": 1500, "InterfaceMetric": None,
                            "ConnectionState": 1},
            current_value=5,
        )]
        commands = generate_rollback_commands(diffs)
        assert len(commands) == 1
        cmd = commands[0]
        assert "-AutomaticMetric Enabled" in cmd
        assert "-AddressFamily IPv6" in cmd
        assert "-InterfaceMetric" not in cmd

    def test_compare_ignores_connectionstate_and_ifmetric(self):
        from perchvpn_windows.tun_state_capture import (
            NetworkSnapshot,
            compare_snapshots,
        )

        base = NetworkSnapshot(
            routes=[{"DestinationPrefix": "0.0.0.0/0", "NextHop": "1.2.3.4", "InterfaceIndex": 1, "RouteMetric": 25, "PolicyStore": "ActiveStore", "ifMetric": None}],
            dns=[{"InterfaceIndex": 1, "AddressFamily": 2, "ServerAddresses": ["8.8.8.8"]}],
            adapters=[{"Name": "eth0", "InterfaceGuid": "guid", "InterfaceIndex": 1, "Status": "Up"}],
            ip_addresses=[{"InterfaceIndex": 1, "IPAddress": "10.0.0.1", "PrefixLength": 24, "AddressFamily": 2}],
            interface_config=[{"InterfaceIndex": 1, "AddressFamily": 2, "NlMtu": 1500, "InterfaceMetric": 5, "ConnectionState": 1}],
            winhttp_proxy="Direct access",
        )
        # Only ConnectionState and ifMetric (read-only projections) change.
        other = NetworkSnapshot.from_dict({
            **base.to_dict(),
            "interface_config": [{"InterfaceIndex": 1, "AddressFamily": 2, "NlMtu": 1500, "InterfaceMetric": 5, "ConnectionState": 2}],
        })
        assert compare_snapshots(base, other) == []

    def test_unexpected_added_adapter_is_refused_not_disabled(self):
        from perchvpn_windows.tun_state_capture import (
            RollbackError,
            StateDifference,
            generate_rollback_commands,
        )

        diffs = [StateDifference(
            category="adapter",
            description="Adapter added: UserNIC",
            baseline_value=None,
            current_value={"Name": "UserNIC", "Status": "Up"},
        )]
        with pytest.raises(RollbackError, match="refusing to disable"):
            generate_rollback_commands(diffs)
        # And nothing was generated that could disable it.
        from perchvpn_windows.tun_state_capture import _rollback_adapter
        try:
            _rollback_adapter("Adapter added: UserNIC", None, {"Name": "UserNIC"})
        except RollbackError:
            pass

    def test_proxy_reset_only_when_baseline_was_direct(self):
        from perchvpn_windows.tun_state_capture import (
            RollbackError,
            StateDifference,
            generate_rollback_commands,
        )

        direct = generate_rollback_commands([StateDifference(
            category="proxy", description="WinHTTP proxy changed",
            baseline_value="Direct access", current_value="evil.proxy:1080",
        )])
        assert direct == ["netsh winhttp reset proxy -ErrorAction Stop"]

        with pytest.raises(RollbackError, match="refusing reset-to-direct"):
            generate_rollback_commands([StateDifference(
                category="proxy", description="WinHTTP proxy changed",
                baseline_value="Import settings from IE", current_value="Direct access",
            )])


class TestPartitionDiffsTproxyOwnership:
    """Ownership classification for tproxy-config host-route mutations and
    residual records bound to a vanished trial adapter's ifIndex."""

    ADAPTER = "perchvpn-trial"

    def _baseline(self):
        from perchvpn_windows.tun_state_capture import NetworkSnapshot
        return NetworkSnapshot(
            routes=[
                {"DestinationPrefix": "0.0.0.0/0", "NextHop": "192.168.1.1", "InterfaceIndex": 10, "RouteMetric": 0, "PolicyStore": "ActiveStore", "ifMetric": None},
                {"DestinationPrefix": "192.168.1.0/24", "NextHop": "0.0.0.0", "InterfaceIndex": 10, "RouteMetric": 0, "PolicyStore": "ActiveStore", "ifMetric": None},
                {"DestinationPrefix": "ff00::/8", "NextHop": "::", "InterfaceIndex": 29, "RouteMetric": 1, "PolicyStore": "ActiveStore", "ifMetric": None},
            ],
            dns=[{"InterfaceIndex": 10, "AddressFamily": 2, "ServerAddresses": ["8.8.8.8"]}],
            adapters=[
                {"Name": "Wi-Fi", "InterfaceGuid": "wifi", "InterfaceIndex": 10, "Status": "Up"},
                {"Name": "singbox_tun", "InterfaceGuid": "sb", "InterfaceIndex": 29, "Status": "Up"},
            ],
            ip_addresses=[
                {"InterfaceIndex": 10, "IPAddress": "192.168.1.42", "PrefixLength": 24, "AddressFamily": 2},
                {"InterfaceIndex": 29, "IPAddress": "fd00::1", "PrefixLength": 64, "AddressFamily": 23},
            ],
            interface_config=[
                {"InterfaceIndex": 10, "AddressFamily": 2, "NlMtu": 1500, "InterfaceMetric": 25, "ConnectionState": 2},
                {"InterfaceIndex": 29, "AddressFamily": 23, "NlMtu": 1500, "InterfaceMetric": 5, "ConnectionState": 2},
            ],
            winhttp_proxy="Direct access",
        )

    def _current(self, routes):
        # The trial adapter was already destroyed by Wintun: only the
        # pre-existing baseline adapters remain.
        from perchvpn_windows.tun_state_capture import NetworkSnapshot
        base = self._baseline()
        return NetworkSnapshot(
            routes=routes, dns=base.dns, adapters=base.adapters,
            ip_addresses=base.ip_addresses, interface_config=base.interface_config,
            winhttp_proxy=base.winhttp_proxy,
        )

    def test_default_route_metric_change_is_owned_and_restored(self):
        from perchvpn_windows.tun_state_capture import (
            compare_snapshots,
            generate_rollback_commands,
            partition_diffs,
        )

        baseline = self._baseline()
        current = self._current([
            {"DestinationPrefix": "0.0.0.0/0", "NextHop": "192.168.1.1", "InterfaceIndex": 10, "RouteMetric": 200, "PolicyStore": "ActiveStore", "ifMetric": None},
            {"DestinationPrefix": "192.168.1.0/24", "NextHop": "0.0.0.0", "InterfaceIndex": 10, "RouteMetric": 0, "PolicyStore": "ActiveStore", "ifMetric": None},
            {"DestinationPrefix": "ff00::/8", "NextHop": "::", "InterfaceIndex": 29, "RouteMetric": 1, "PolicyStore": "ActiveStore", "ifMetric": None},
        ])

        diffs = compare_snapshots(baseline, current)
        assert len(diffs) == 1
        assert diffs[0].category == "route"
        assert "RouteMetric" in diffs[0].description

        owned, ambient = partition_diffs(
            diffs, adapter_name=self.ADAPTER,
            current_snapshot=current, baseline_snapshot=baseline,
        )
        assert owned == diffs, "default-route metric change must be owned"
        assert ambient == []

        commands = generate_rollback_commands(owned)
        assert commands == [
            "Set-NetRoute -DestinationPrefix '0.0.0.0/0' -NextHop '192.168.1.1' "
            "-InterfaceIndex 10 -PolicyStore ActiveStore -RouteMetric 0 -ErrorAction Stop"
        ]

    def test_persistent_store_route_on_vanished_ifindex_is_owned(self):
        from perchvpn_windows.tun_state_capture import (
            compare_snapshots,
            generate_rollback_commands,
            partition_diffs,
        )

        baseline = self._baseline()
        residual = {
            "DestinationPrefix": "0.0.0.0/0", "NextHop": "10.0.0.1",
            "InterfaceIndex": 64, "RouteMetric": 10,
            "PolicyStore": "PersistentStore", "ifMetric": None,
        }
        current = self._current(baseline.routes + [residual])

        diffs = compare_snapshots(baseline, current)
        assert len(diffs) == 1
        assert diffs[0].description.startswith("Route added")

        # ifIndex 64 is in neither baseline.adapters nor current.adapters,
        # and it is not the named trial adapter: still owned.
        owned, ambient = partition_diffs(
            diffs, adapter_name=self.ADAPTER,
            current_snapshot=current, baseline_snapshot=baseline,
        )
        assert owned == diffs
        assert ambient == []

        commands = generate_rollback_commands(owned)
        assert commands == [
            "Remove-NetRoute -DestinationPrefix '0.0.0.0/0' -NextHop '10.0.0.1' "
            "-InterfaceIndex 64 -PolicyStore PersistentStore -Confirm:$false -ErrorAction SilentlyContinue"
        ]

    def test_foreign_multicast_route_removal_stays_ambient(self):
        from perchvpn_windows.tun_state_capture import (
            compare_snapshots,
            partition_diffs,
        )

        baseline = self._baseline()
        current = self._current([
            r for r in baseline.routes if r["DestinationPrefix"] != "ff00::/8"
        ])

        diffs = compare_snapshots(baseline, current)
        assert [d.description for d in diffs] == [
            "Route removed: ('ff00::/8', '::', 29, 'ActiveStore')"
        ]

        owned, ambient = partition_diffs(
            diffs, adapter_name=self.ADAPTER,
            current_snapshot=current, baseline_snapshot=baseline,
        )
        assert owned == []
        assert len(ambient) == 1


class TestRunPsWriteSemantics:
    """Exit-code-only success semantics for mutating PowerShell calls."""

    def _run(
        self,
        returncode=0,
        stdout="",
        stderr="",
        side_effect=None,
        script="Set-NetRoute ...",
    ):
        from perchvpn_windows import tun_state_capture as cap

        completed = __import__("types").SimpleNamespace(
            returncode=returncode, stdout=stdout, stderr=stderr
        )
        with patch.object(cap.subprocess, "run", side_effect=side_effect,
                          return_value=completed) as run:
            result = cap._run_ps_write(script)
            if run.call_args is not None:
                self.last_command = run.call_args.args[0][-1]
            return result

    def test_empty_stdout_success_is_accepted(self):
        assert self._run(returncode=0, stdout="") == ""

    def test_nonzero_exit_raises_rollback_error(self):
        from perchvpn_windows.tun_state_capture import RollbackError

        with pytest.raises(RollbackError, match="PowerShell returned 3"):
            self._run(returncode=3, stdout="", stderr="boom")

    def test_silently_continue_command_is_wrapped_to_exit_zero(self):
        script = "Remove-NetRoute -DestinationPrefix '0.0.0.0/1' " \
                 "-Confirm:$false -ErrorAction SilentlyContinue"
        assert self._run(returncode=0, script=script) == ""
        assert self.last_command.startswith(
            "$ErrorActionPreference='SilentlyContinue';"
        )
        assert self.last_command.endswith("; exit 0")

    def test_silently_continue_exit_one_missing_object_is_tolerated(self):
        script = "Remove-NetRoute -DestinationPrefix '0.0.0.0/1' " \
                 "-Confirm:$false -ErrorAction SilentlyContinue"
        assert self._run(
            returncode=1,
            stderr=(
                "Remove-NetRoute : No matching MSFT_NetRoute objects found by "
                "CIM query CmdletizationQuery_NotFound,Remove-NetRoute"
            ),
            script=script,
        ) == ""

    def test_silently_continue_stdout_missing_object_is_tolerated(self):
        script = "Remove-NetRoute -DestinationPrefix '0.0.0.0/1' " \
                 "-Confirm:$false -ErrorAction SilentlyContinue"
        assert self._run(
            returncode=1,
            stdout="No matching MSFT_NetRoute objects found",
            script=script,
        ) == "No matching MSFT_NetRoute objects found"

    def test_silently_continue_non_missing_error_still_fails(self):
        from perchvpn_windows.tun_state_capture import RollbackError

        script = "Remove-NetRoute -DestinationPrefix '0.0.0.0/1' " \
                 "-Confirm:$false -ErrorAction SilentlyContinue"
        with pytest.raises(RollbackError, match="PowerShell returned 1"):
            self._run(returncode=1, stderr="Access is denied", script=script)

    def test_timeout_raises_rollback_error(self):
        from perchvpn_windows.tun_state_capture import RollbackError
        import subprocess

        with pytest.raises(RollbackError, match="PowerShell execution failed"):
            self._run(side_effect=subprocess.TimeoutExpired(cmd="ps", timeout=30.0))

    def test_os_error_raises_rollback_error(self):
        from perchvpn_windows.tun_state_capture import RollbackError

        with pytest.raises(RollbackError, match="PowerShell execution failed"):
            self._run(side_effect=OSError("no powershell"))

    def test_partial_rollback_aborts_command_list(self):
        from perchvpn_windows.tun_state_capture import RollbackError

        executed: list[str] = []

        def executor(script: str) -> str:
            executed.append(script)
            if len(executed) == 2:
                raise RollbackError("PowerShell returned 4: access denied")
            return "ok"

        commands = ["cmd1", "cmd2", "cmd3"]
        for command in commands:
            try:
                executor(command)
            except RollbackError:
                break
        assert executed == ["cmd1", "cmd2"], "must stop at first failure, not skip ahead"

    def test_crash_site_rollback_aborting_leaves_record_durable(
        self, tmp_path
    ):
        """Mid-rollback failure must retain state and evidence (durable)."""
        from perchvpn_windows.tun_state_capture import NetworkSnapshot, RollbackError
        from src.perchvpn_windows.tun_recovery import TunRecoveryGate

        snapshot = NetworkSnapshot(
            routes=[{"DestinationPrefix": "0.0.0.0/0", "NextHop": "1.2.3.4", "InterfaceIndex": 1, "RouteMetric": 25, "PolicyStore": "ActiveStore", "ifMetric": None}],
            dns=[{"InterfaceIndex": 1, "AddressFamily": 2, "ServerAddresses": ["8.8.8.8"]}],
            adapters=[{"Name": "eth0", "InterfaceGuid": "guid", "InterfaceIndex": 1, "Status": "Up"}],
            ip_addresses=[{"InterfaceIndex": 1, "IPAddress": "10.0.0.1", "PrefixLength": 24, "AddressFamily": 2}],
            interface_config=[{"InterfaceIndex": 1, "AddressFamily": 2, "NlMtu": 1500, "InterfaceMetric": 5, "ConnectionState": 1}],
            winhttp_proxy="Direct access",
        )
        drifted = NetworkSnapshot(
            routes=snapshot.routes, dns=snapshot.dns,
            adapters=snapshot.adapters, ip_addresses=snapshot.ip_addresses,
            interface_config=snapshot.interface_config,
            winhttp_proxy=snapshot.winhttp_proxy,
        )
        drifted.dns = [{"InterfaceIndex": 1, "AddressFamily": 2, "ServerAddresses": ["9.9.9.9"]}]
        _identity = {"path": "/fake/tun2proxy.exe", "size": 11,
                     "mtime_ns": 22, "sha256": "sha-current"}
        record = {
            "version": 2, "state": "running",
            "adapter_guid": None, "adapter_name": "wintun",
            "executable": _identity, "network_baseline": snapshot.to_dict(),
            "pid": 123, "create_time": 100.0,
            "pre_start_present": False, "updated_at": 0.0,
        }
        (tmp_path / "tun-ownership.json").write_text(json.dumps(record), encoding="utf-8")

        def executor(script: str) -> str:
            raise RollbackError("access denied")

        gate = TunRecoveryGate(
            enabled=True,
            state_path=tmp_path / "tun-ownership.json",
            adapter_probe=lambda guid, name: False,
            creation_time_probe=lambda pid: 200.0,
            identity_probe=lambda path: _identity,
            snapshot_capture=lambda: drifted,
            rollback_executor=executor,
        )
        with pytest.raises(Exception):
            gate.pre_start("/fake/tun2proxy.exe")

        record_after = json.loads(
            (tmp_path / "tun-ownership.json").read_text()
        )
        assert record_after["state"] == "running"
        assert record_after.get("network_baseline") == snapshot.to_dict()
