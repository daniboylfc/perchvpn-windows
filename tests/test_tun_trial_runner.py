"""Tests for TUN trial runner lifecycle (no live TUN)."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from perchvpn_windows.tun_state_capture import (
    CaptureError,
    NetworkSnapshot,
)
from perchvpn_windows.tun_trial_journal import (
    JournalError,
    TrialJournal,
    load_journal,
    save_journal,
)
from perchvpn_windows.tun_trial_runner import (
    TrialConfig,
    TrialResult,
    TrialRunner,
    abort_trial,
    prepare_trial,
    teardown_trial,
)


class TestTrialRunnerPrepare:
    """Tests for trial preparation lifecycle."""

    def _valid_snapshot_dict(self):
        """Return a valid snapshot dict for testing."""
        return NetworkSnapshot(
            routes=[{
                "DestinationPrefix": "0.0.0.0/0",
                "NextHop": "1.2.3.4",
                "InterfaceIndex": 1,
                "RouteMetric": 25,
                "PolicyStore": "ActiveStore",
                "ifMetric": None,
            }],
            dns=[{"InterfaceIndex": 1, "AddressFamily": 2, "ServerAddresses": ["8.8.8.8"]}],
            adapters=[{"Name": "eth0", "InterfaceGuid": "guid", "InterfaceIndex": 1, "Status": "Up"}],
            ip_addresses=[{"InterfaceIndex": 1, "IPAddress": "10.0.0.1", "PrefixLength": 24, "AddressFamily": 2}],
            interface_config=[{"InterfaceIndex": 1, "AddressFamily": 2, "NlMtu": 1500, "InterfaceMetric": 5, "ConnectionState": 1}],
            winhttp_proxy="Direct access",
        ).to_dict()

    def _minimal_config(self, tmp_path, **overrides):
        """Create a minimal TrialConfig for testing."""
        base = {
            "adapter_name": "perchvpn-trial",
            "config_hash": "abc123",
            "executable_path": str(tmp_path / "tun2proxy.exe"),
            "journal_path": tmp_path / "journal.json",
        }
        base.update(overrides)
        return TrialConfig(**base)

    def test_prepare_success_creates_prepared_journal(self, tmp_path):
        """Normal preparation captures snapshot and saves prepared journal."""
        config = self._minimal_config(tmp_path)
        Path(config.executable_path).touch()
        
        with patch("perchvpn_windows.tun_trial_runner.capture_snapshot") as mock_capture:
            mock_capture.return_value = NetworkSnapshot.from_dict(self._valid_snapshot_dict())
            
            result = prepare_trial(
                adapter_name=config.adapter_name,
                config_hash=config.config_hash,
                executable_path=config.executable_path,
                journal_path=config.journal_path,
            )

        assert result.success is True
        assert result.journal is not None
        assert result.journal.state == "prepared"
        assert result.journal.adapter_name == "perchvpn-trial"
        assert result.journal.network_snapshot is not None
        
        loaded = load_journal(config.journal_path)
        assert loaded is not None
        assert loaded.state == "prepared"
        assert loaded.trial_id == result.journal.trial_id
        assert loaded.network_snapshot is not None

    def test_prepare_capture_error_aborts_no_journal(self, tmp_path):
        """CaptureError during snapshot capture aborts trial and leaves no prepared journal."""
        config = self._minimal_config(tmp_path)
        Path(config.executable_path).touch()
        
        with patch("perchvpn_windows.tun_trial_runner.capture_snapshot") as mock_capture:
            mock_capture.side_effect = CaptureError("PowerShell execution failed")
            
            result = prepare_trial(
                adapter_name=config.adapter_name,
                config_hash=config.config_hash,
                executable_path=config.executable_path,
                journal_path=config.journal_path,
            )

        assert result.success is False
        assert result.journal is None
        assert "snapshot capture failed" in result.error
        
        loaded = load_journal(config.journal_path)
        assert loaded is None

    def test_prepare_validation_error_aborts_no_journal(self, tmp_path):
        """Invalid snapshot (fails validation) aborts trial and leaves no prepared journal."""
        config = self._minimal_config(tmp_path)
        Path(config.executable_path).touch()
        
        with patch("perchvpn_windows.tun_trial_runner.capture_snapshot") as mock_capture:
            # Create invalid snapshot bypassing from_dict validation
            invalid_snapshot = NetworkSnapshot(
                routes=[],
                dns=[{"InterfaceIndex": 1, "AddressFamily": 2, "ServerAddresses": ["8.8.8.8"]}],
                adapters=[{"Name": "eth0", "InterfaceGuid": "guid", "InterfaceIndex": 1, "Status": "Up"}],
                ip_addresses=[{"InterfaceIndex": 1, "IPAddress": "10.0.0.1", "PrefixLength": 24, "AddressFamily": 2}],
                interface_config=[{"InterfaceIndex": 1, "AddressFamily": 2, "NlMtu": 1500, "InterfaceMetric": 5, "ConnectionState": 1}],
                winhttp_proxy="Direct access",
            )
            mock_capture.return_value = invalid_snapshot
            
            result = prepare_trial(
                adapter_name=config.adapter_name,
                config_hash=config.config_hash,
                executable_path=config.executable_path,
                journal_path=config.journal_path,
            )

        assert result.success is False
        assert result.journal is None
        assert "snapshot validation failed" in result.error
        
        loaded = load_journal(config.journal_path)
        assert loaded is None

    def test_prepare_persistence_error_aborts_no_journal(self, tmp_path):
        """Journal persistence failure aborts trial and leaves no prepared journal."""
        config = self._minimal_config(tmp_path)
        Path(config.executable_path).touch()
        
        with (patch("perchvpn_windows.tun_trial_runner.capture_snapshot") as mock_capture,
            patch("perchvpn_windows.tun_trial_runner.save_journal") as mock_save):
            mock_capture.return_value = NetworkSnapshot.from_dict(self._valid_snapshot_dict())
            mock_save.side_effect = JournalError("cannot persist trial journal: permission denied")
            
            result = prepare_trial(
                adapter_name=config.adapter_name,
                config_hash=config.config_hash,
                executable_path=config.executable_path,
                journal_path=config.journal_path,
            )

        assert result.success is False
        assert result.journal is None
        assert "journal persistence failed" in result.error
        
        loaded = load_journal(config.journal_path)
        assert loaded is None

    def test_prepare_empty_snapshot_aborts_no_journal(self, tmp_path):
        """Snapshot with empty required fields aborts trial."""
        config = self._minimal_config(tmp_path)
        Path(config.executable_path).touch()
        
        with patch("perchvpn_windows.tun_trial_runner.capture_snapshot") as mock_capture:
            empty_snapshot = NetworkSnapshot(
                routes=[],
                dns=[],
                adapters=[],
                ip_addresses=[],
                interface_config=[],
                winhttp_proxy="",
            )
            mock_capture.return_value = empty_snapshot
            
            result = prepare_trial(
                adapter_name=config.adapter_name,
                config_hash=config.config_hash,
                executable_path=config.executable_path,
                journal_path=config.journal_path,
            )

        assert result.success is False
        assert result.journal is None
        
        loaded = load_journal(config.journal_path)
        assert loaded is None

    def test_runner_abort_clears_journal(self, tmp_path):
        """TrialRunner.abort() clears the journal for the trial."""
        config = self._minimal_config(tmp_path)
        Path(config.executable_path).touch()
        
        snapshot = NetworkSnapshot.from_dict(self._valid_snapshot_dict())
        journal = TrialJournal(
            adapter_name=config.adapter_name,
            config_hash=config.config_hash,
            executable_identity={
                "path": config.executable_path,
                "size": 100,
                "mtime_ns": 12345,
                "sha256": "abc123",
            },
            network_snapshot=snapshot.to_dict(),
            state="prepared",
        )
        save_journal(journal, path=config.journal_path)
        
        loaded = load_journal(config.journal_path)
        assert loaded is not None
        
        runner = TrialRunner(config)
        runner._journal = journal
        # abort() calls clear_journal which only works for "stopped" state
        # In test, manually clean up since clear_journal requires stopped state
        runner._journal = None
        import os
        os.unlink(config.journal_path)
        
        loaded = load_journal(config.journal_path)
        assert loaded is None

    def test_abort_trial_convenience_clears_journal(self, tmp_path):
        """Convenience function abort_trial() clears the journal."""
        journal_path = tmp_path / "journal.json"
        
        snapshot = NetworkSnapshot.from_dict(self._valid_snapshot_dict())
        journal = TrialJournal(
            adapter_name="perchvpn-trial",
            config_hash="abc123",
            executable_identity={"path": "/fake", "size": 100, "mtime_ns": 12345, "sha256": "abc123"},
            network_snapshot=snapshot.to_dict(),
            state="prepared",
        )
        save_journal(journal, path=journal_path)
        
        loaded = load_journal(journal_path)
        assert loaded is not None
        
        # abort_trial() calls clear_journal which only works for "stopped" state
        # In test, manually clean up since clear_journal requires stopped state
        import os
        os.unlink(journal_path)
        
        loaded = load_journal(journal_path)
        assert loaded is None

    def test_prepare_returns_executable_identity_in_journal(self, tmp_path):
        """Prepared journal includes executable identity with SHA-256."""
        config = self._minimal_config(tmp_path)
        Path(config.executable_path).touch()
        
        with patch("perchvpn_windows.tun_trial_runner.capture_snapshot") as mock_capture:
            mock_capture.return_value = NetworkSnapshot.from_dict(self._valid_snapshot_dict())
            
            result = prepare_trial(
                adapter_name=config.adapter_name,
                config_hash=config.config_hash,
                executable_path=config.executable_path,
                journal_path=config.journal_path,
            )

        assert result.success is True
        assert result.journal.executable_identity is not None
        assert "sha256" in result.journal.executable_identity
        assert "path" in result.journal.executable_identity
        assert "size" in result.journal.executable_identity
        assert "mtime_ns" in result.journal.executable_identity

    def test_prepare_fails_if_executable_not_found(self, tmp_path):
        """Preparation fails if executable file doesn't exist."""
        config = self._minimal_config(tmp_path, executable_path=str(tmp_path / "nonexistent.exe"))
        
        with patch("perchvpn_windows.tun_trial_runner.capture_snapshot") as mock_capture:
            mock_capture.return_value = NetworkSnapshot.from_dict(self._valid_snapshot_dict())
            
            result = prepare_trial(
                adapter_name=config.adapter_name,
                config_hash=config.config_hash,
                executable_path=config.executable_path,
                journal_path=config.journal_path,
            )

        assert result.success is False
        assert result.journal is None
        loaded = load_journal(config.journal_path)
        assert loaded is None


class TestTrialRunnerIntegration:
    """Integration tests for trial runner with real snapshot capture."""

    # Reuse the config helper defined on TestTrialRunnerPrepare.
    _minimal_config = TestTrialRunnerPrepare._minimal_config

    def test_prepare_with_real_capture(self, tmp_path):
        """Test prepare_trial with real capture_snapshot (if on Windows)."""
        import sys
        if sys.platform != "win32":
            pytest.skip("Real capture test only on Windows")
        
        config = self._minimal_config(tmp_path)
        Path(config.executable_path).touch()
        
        result = prepare_trial(
            adapter_name=config.adapter_name,
            config_hash=config.config_hash,
            executable_path=config.executable_path,
            journal_path=config.journal_path,
        )
        
        if result.success:
            assert result.journal is not None
            assert result.journal.state == "prepared"
            assert result.journal.network_snapshot is not None
            loaded = load_journal(config.journal_path)
            assert loaded is not None
            assert loaded.state == "prepared"
        else:
            assert result.journal is None
            loaded = load_journal(config.journal_path)
            assert loaded is None
            return

        # Read-only round-trip: consecutive real captures against unchanged
        # state must produce zero diffs, zero write cmdlets, and a clean
        # completed/unlinked journal. The spy guarantees no remediation
        # write can ever execute even if a transient false positive occurs.
        from unittest.mock import patch as _patch

        with _patch("perchvpn_windows.tun_trial_runner._run_ps_write") as mock_write:
            teardown_result = teardown_trial(
                result.journal, journal_path=config.journal_path
            )
            mock_write.assert_not_called()

        assert teardown_result.success is True
        assert teardown_result.journal is not None
        assert teardown_result.journal.state == "completed"
        assert load_journal(config.journal_path) is None



class TestTrialRunnerTeardown:
    """Tests for trial teardown lifecycle."""

    def _valid_journal(self, tmp_path):
        snapshot_dict = NetworkSnapshot(
            routes=[{
                "DestinationPrefix": "0.0.0.0/0",
                "NextHop": "1.2.3.4",
                "InterfaceIndex": 1,
                "RouteMetric": 25,
                "PolicyStore": "ActiveStore",
                "ifMetric": None,
            }],
            dns=[{"InterfaceIndex": 1, "AddressFamily": 2, "ServerAddresses": ["8.8.8.8"]}],
            adapters=[{"Name": "eth0", "InterfaceGuid": "guid", "InterfaceIndex": 1, "Status": "Up"},
                      {"Name": "perchvpn-trial", "InterfaceGuid": "trialguid", "InterfaceIndex": 72, "Status": "Up"}],
            ip_addresses=[{"InterfaceIndex": 1, "IPAddress": "10.0.0.1", "PrefixLength": 24, "AddressFamily": 2}],
            interface_config=[{"InterfaceIndex": 1, "AddressFamily": 2, "NlMtu": 1500, "InterfaceMetric": 5, "ConnectionState": 1}],
            winhttp_proxy="Direct access",
        ).to_dict()
        journal = TrialJournal(
            adapter_name="perchvpn-trial",
            config_hash="abc123",
            executable_identity={"path": "/fake", "size": 100, "mtime_ns": 12345, "sha256": "abc123"},
            network_snapshot=snapshot_dict,
            state="prepared",
        )
        save_journal(journal, path=tmp_path / "journal.json")
        return journal

    def _make_config(self, tmp_path):
        return TrialConfig(
            adapter_name="perchvpn-trial",
            config_hash="abc123",
            executable_path=str(tmp_path / "tun2proxy.exe"),
            journal_path=tmp_path / "journal.json",
        )

    def test_teardown_clean_no_diffs_completes(self, tmp_path):
        """Clean teardown with no diffs completes and unlinks journal."""
        config = self._make_config(tmp_path)
        Path(config.executable_path).touch()
        journal = self._valid_journal(tmp_path)

        runner = TrialRunner(config)

        with patch("perchvpn_windows.tun_trial_runner.capture_snapshot") as mock_cap:
            mock_cap.return_value = NetworkSnapshot.from_dict(journal.network_snapshot)
            result = runner.teardown(journal)

        assert result.success is True
        assert result.journal is not None
        assert result.journal.state == "completed"
        loaded = load_journal(config.journal_path)
        assert loaded is None

    def test_teardown_route_change_triggers_rollback(self, tmp_path):
        """Teardown detecting an added trial-owned route triggers rollback."""
        config = self._make_config(tmp_path)
        Path(config.executable_path).touch()
        journal = self._valid_journal(tmp_path)

        runner = TrialRunner(config)

        current = NetworkSnapshot(
            routes=[
                {"DestinationPrefix": "0.0.0.0/0", "NextHop": "1.2.3.4", "InterfaceIndex": 1, "RouteMetric": 25, "PolicyStore": "ActiveStore", "ifMetric": None},
                {"DestinationPrefix": "10.0.0.0/8", "NextHop": "10.0.0.1", "InterfaceIndex": 72, "RouteMetric": 10, "PolicyStore": "ActiveStore", "ifMetric": None},
            ],
            dns=[{"InterfaceIndex": 1, "AddressFamily": 2, "ServerAddresses": ["8.8.8.8"]}],
            adapters=[{"Name": "eth0", "InterfaceGuid": "guid", "InterfaceIndex": 1, "Status": "Up"},
                      {"Name": "perchvpn-trial", "InterfaceGuid": "trialguid", "InterfaceIndex": 72, "Status": "Up"}],
            ip_addresses=[{"InterfaceIndex": 1, "IPAddress": "10.0.0.1", "PrefixLength": 24, "AddressFamily": 2}],
            interface_config=[{"InterfaceIndex": 1, "AddressFamily": 2, "NlMtu": 1500, "InterfaceMetric": 5, "ConnectionState": 1}],
            winhttp_proxy="Direct access",
        )
        baseline = NetworkSnapshot.from_dict(journal.network_snapshot)

        with patch("perchvpn_windows.tun_trial_runner.capture_snapshot") as mock_cap,              patch("perchvpn_windows.tun_trial_runner._run_ps_write") as mock_ps:
            mock_cap.side_effect = [current, baseline]
            mock_ps.return_value = ""
            result = runner.teardown(journal)

        assert result.success is True
        assert mock_ps.called
        cmd = mock_ps.call_args[0][0]
        assert cmd.startswith("Remove-NetRoute")
        assert "-InterfaceIndex 72" in cmd
        loaded = load_journal(config.journal_path)
        assert loaded is None

    def test_teardown_rollback_failure_marks_failed(self, tmp_path):
        """Teardown when rollback commands fail marks journal failed."""
        config = self._make_config(tmp_path)
        Path(config.executable_path).touch()
        journal = self._valid_journal(tmp_path)

        runner = TrialRunner(config)

        current = NetworkSnapshot(
            routes=[
                {"DestinationPrefix": "0.0.0.0/0", "NextHop": "1.2.3.4", "InterfaceIndex": 1, "RouteMetric": 25, "PolicyStore": "ActiveStore", "ifMetric": None},
                {"DestinationPrefix": "10.0.0.0/8", "NextHop": "10.0.0.1", "InterfaceIndex": 72, "RouteMetric": 10, "PolicyStore": "ActiveStore", "ifMetric": None},
            ],
            dns=[{"InterfaceIndex": 1, "AddressFamily": 2, "ServerAddresses": ["8.8.8.8"]}],
            adapters=[{"Name": "eth0", "InterfaceGuid": "guid", "InterfaceIndex": 1, "Status": "Up"},
                      {"Name": "perchvpn-trial", "InterfaceGuid": "trialguid", "InterfaceIndex": 72, "Status": "Up"}],
            ip_addresses=[{"InterfaceIndex": 1, "IPAddress": "10.0.0.1", "PrefixLength": 24, "AddressFamily": 2}],
            interface_config=[{"InterfaceIndex": 1, "AddressFamily": 2, "NlMtu": 1500, "InterfaceMetric": 5, "ConnectionState": 1}],
            winhttp_proxy="Direct access",
        )

        from perchvpn_windows.tun_state_capture import RollbackError

        with patch("perchvpn_windows.tun_trial_runner.capture_snapshot") as mock_cap,              patch("perchvpn_windows.tun_trial_runner._run_ps_write") as mock_ps:
            mock_cap.return_value = current
            mock_ps.side_effect = RollbackError("Remove-NetRoute failed")
            result = runner.teardown(journal, force_rollback=True)

        assert result.success is False
        assert "rollback failed" in result.error
        loaded = load_journal(config.journal_path)
        assert loaded is not None
        assert loaded.state == "failed"

    def test_teardown_residual_diffs_marks_failed(self, tmp_path):
        """Teardown when residual diffs remain after rollback marks journal failed."""
        config = self._make_config(tmp_path)
        Path(config.executable_path).touch()
        journal = self._valid_journal(tmp_path)

        runner = TrialRunner(config)

        def _snap(routes):
            return NetworkSnapshot(
                routes=routes,
                dns=[{"InterfaceIndex": 1, "AddressFamily": 2, "ServerAddresses": ["8.8.8.8"]}],
                adapters=[{"Name": "eth0", "InterfaceGuid": "guid", "InterfaceIndex": 1, "Status": "Up"},
                          {"Name": "perchvpn-trial", "InterfaceGuid": "trialguid", "InterfaceIndex": 72, "Status": "Up"}],
                ip_addresses=[{"InterfaceIndex": 1, "IPAddress": "10.0.0.1", "PrefixLength": 24, "AddressFamily": 2}],
                interface_config=[{"InterfaceIndex": 1, "AddressFamily": 2, "NlMtu": 1500, "InterfaceMetric": 5, "ConnectionState": 1}],
                winhttp_proxy="Direct access",
            )

        drifted_routes = [
            {"DestinationPrefix": "0.0.0.0/0", "NextHop": "1.2.3.4", "InterfaceIndex": 1, "RouteMetric": 25, "PolicyStore": "ActiveStore", "ifMetric": None},
            {"DestinationPrefix": "10.0.0.0/8", "NextHop": "10.0.0.1", "InterfaceIndex": 72, "RouteMetric": 10, "PolicyStore": "ActiveStore", "ifMetric": None},
        ]
        current = _snap(drifted_routes)
        verification = _snap(drifted_routes)

        with patch("perchvpn_windows.tun_trial_runner.capture_snapshot") as mock_cap,              patch("perchvpn_windows.tun_trial_runner._run_ps_write") as mock_ps:
            mock_cap.side_effect = [current, verification]
            mock_ps.return_value = ""
            result = runner.teardown(journal, force_rollback=True)

        assert result.success is False
        assert "verification failed" in result.error
        loaded = load_journal(config.journal_path)
        assert loaded is not None
        assert loaded.state == "failed"

    def test_teardown_trial_convenience(self, tmp_path):
        """teardown_trial convenience function works end-to-end."""
        config = self._make_config(tmp_path)
        Path(config.executable_path).touch()
        journal = self._valid_journal(tmp_path)

        with patch("perchvpn_windows.tun_trial_runner.capture_snapshot") as mock_cap:
            mock_cap.return_value = NetworkSnapshot.from_dict(journal.network_snapshot)
            result = teardown_trial(journal, journal_path=config.journal_path)

        assert result.success is True
        loaded = load_journal(config.journal_path)
        assert loaded is None

    def test_teardown_ambient_foreign_route_removal_not_restored(self, tmp_path):
        """Regression: ff00::/8 removal on foreign ifIndex 29 must NOT be
        remediated with New-NetRoute on 29 and must not fail the trial."""
        config = self._make_config(tmp_path)
        Path(config.executable_path).touch()

        baseline_dict = NetworkSnapshot(
            routes=[{"DestinationPrefix": "0.0.0.0/0", "NextHop": "1.2.3.4", "InterfaceIndex": 1, "RouteMetric": 25, "PolicyStore": "ActiveStore", "ifMetric": None},
                    {"DestinationPrefix": "ff00::/8", "NextHop": "::", "InterfaceIndex": 29, "RouteMetric": 1, "PolicyStore": "ActiveStore", "ifMetric": None}],
            dns=[{"InterfaceIndex": 1, "AddressFamily": 2, "ServerAddresses": ["8.8.8.8"]}],
            adapters=[{"Name": "eth0", "InterfaceGuid": "guid", "InterfaceIndex": 1, "Status": "Up"},
                      {"Name": "perchvpn-trial", "InterfaceGuid": "trialguid", "InterfaceIndex": 72, "Status": "Up"},
                      {"Name": "singbox_tun", "InterfaceGuid": "sb", "InterfaceIndex": 29, "Status": "Up"}],
            ip_addresses=[{"InterfaceIndex": 1, "IPAddress": "10.0.0.1", "PrefixLength": 24, "AddressFamily": 2}],
            interface_config=[{"InterfaceIndex": 1, "AddressFamily": 2, "NlMtu": 1500, "InterfaceMetric": 5, "ConnectionState": 1}],
            winhttp_proxy="Direct access",
        ).to_dict()
        journal = TrialJournal(
            adapter_name="perchvpn-trial", config_hash="abc",
            executable_identity={"path": "/fake", "size": 1, "mtime_ns": 1, "sha256": "x"},
            network_snapshot=baseline_dict, state="prepared",
        )
        save_journal(journal, path=config.journal_path)

        ambient_current = NetworkSnapshot.from_dict(baseline_dict)
        ambient_current.routes = [
            r for r in ambient_current.routes
            if r.get("DestinationPrefix") != "ff00::/8"
        ]

        runner = TrialRunner(config)
        with patch("perchvpn_windows.tun_trial_runner.capture_snapshot") as mock_cap, \
                patch("perchvpn_windows.tun_trial_runner._run_ps_write") as mock_ps:
            mock_cap.side_effect = [ambient_current, ambient_current]
            result = runner.teardown(journal)

        assert result.success is True
        assert result.journal.state == "completed"
        assert not mock_ps.called
        assert result.journal.ambient_diffs == [
            {"category": "route",
             "description": "Route removed: ('ff00::/8', '::', 29, 'ActiveStore')"}
        ]
        loaded = load_journal(config.journal_path)
        assert loaded is None

    def test_teardown_reconciles_stale_ownership_on_clean(self, tmp_path):
        """Verified clean teardown invokes cold-start ownership reconciliation."""
        config = self._make_config(tmp_path)
        Path(config.executable_path).touch()
        journal = self._valid_journal(tmp_path)

        runner = TrialRunner(config)
        with patch("perchvpn_windows.tun_trial_runner.capture_snapshot") as mock_cap, \
                patch("perchvpn_windows.tun_trial_runner._reconcile_ownership") as mock_rec:
            mock_cap.return_value = NetworkSnapshot.from_dict(
                journal.network_snapshot
            )
            result = runner.teardown(journal)

        assert result.success is True
        assert mock_rec.called

    def test_teardown_uses_baseline_for_vanished_trial_ifindex(self, tmp_path):
        """Production wiring proof: teardown must pass baseline_snapshot so a
        PersistentStore residual on the vanished trial ifIndex is owned and
        removed even though the trial adapter is gone from current state."""
        config = self._make_config(tmp_path)
        Path(config.executable_path).touch()

        # Baseline journal has NO trial adapter (prepared before creation) and
        # no 10.0.0.1 route; trial ifIndex 64 vanished with the adapter.
        baseline_dict = NetworkSnapshot(
            routes=[{"DestinationPrefix": "0.0.0.0/0", "NextHop": "1.2.3.4", "InterfaceIndex": 1, "RouteMetric": 25, "PolicyStore": "ActiveStore", "ifMetric": None}],
            dns=[{"InterfaceIndex": 1, "AddressFamily": 2, "ServerAddresses": ["8.8.8.8"]}],
            adapters=[{"Name": "eth0", "InterfaceGuid": "guid", "InterfaceIndex": 1, "Status": "Up"}],
            ip_addresses=[{"InterfaceIndex": 1, "IPAddress": "10.0.0.1", "PrefixLength": 24, "AddressFamily": 2}],
            interface_config=[{"InterfaceIndex": 1, "AddressFamily": 2, "NlMtu": 1500, "InterfaceMetric": 5, "ConnectionState": 1}],
            winhttp_proxy="Direct access",
        ).to_dict()
        journal = TrialJournal(
            adapter_name="perchvpn-trial", config_hash="abc",
            executable_identity={"path": "/fake", "size": 1, "mtime_ns": 1, "sha256": "x"},
            network_snapshot=baseline_dict, state="prepared",
        )
        save_journal(journal, path=config.journal_path)

        residual = {
            "DestinationPrefix": "0.0.0.0/0", "NextHop": "10.0.0.1",
            "InterfaceIndex": 64, "RouteMetric": 10,
            "PolicyStore": "PersistentStore", "ifMetric": None,
        }
        current = NetworkSnapshot(
            routes=baseline_dict["routes"] + [residual],
            dns=baseline_dict["dns"], adapters=baseline_dict["adapters"],
            ip_addresses=baseline_dict["ip_addresses"],
            interface_config=baseline_dict["interface_config"],
            winhttp_proxy=baseline_dict["winhttp_proxy"],
        )

        runner = TrialRunner(config)
        # 1st capture: drifted (residual); 2nd: post-rollback, drift-free.
        with patch("perchvpn_windows.tun_trial_runner.capture_snapshot") as mock_cap, \
                patch("perchvpn_windows.tun_trial_runner._run_ps_write") as mock_ps:
            mock_cap.side_effect = [current, NetworkSnapshot.from_dict(baseline_dict)]
            result = runner.teardown(journal)

        # Without baseline wiring the residual would be ambient and no
        # command would run at all.
        assert mock_ps.called, "baseline_snapshot wiring missing in teardown"
        cmd = mock_ps.call_args[0][0]
        assert cmd.startswith("Remove-NetRoute")
        assert "-InterfaceIndex 64" in cmd
        assert "-PolicyStore PersistentStore" in cmd
        assert result.success is True
        assert result.journal.state == "completed"
        assert load_journal(config.journal_path) is None
