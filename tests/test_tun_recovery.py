"""Focused fail-closed TUN recovery gate tests (mocked; no live TUN)."""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.perchvpn_windows.tun_frontend import TunFrontend
from src.perchvpn_windows.tun_recovery import (
    CLEAN,
    _DOWN_ROW_RELEASE_GRACE_SECONDS,
    DEFAULT_ADAPTER_GUID,
    DEFAULT_ADAPTER_NAME,
    RECOVERY_UNVERIFIED,
    RecoveryRun,
    RecoveryUnverified,
    TunRecoveryGate,
)
from perchvpn_windows.tun_state_capture import (
    NetworkSnapshot,
    RollbackError,
)


def _identity(sha: str = "sha-current") -> dict:
    return {
        "path": "/fake/tun2proxy.exe",
        "size": 11,
        "mtime_ns": 22,
        "sha256": sha,
    }


def _snapshot_dict() -> dict:
    """Return a valid network snapshot dict (same content each call)."""
    return {
        "routes": [{
            "DestinationPrefix": "0.0.0.0/0",
            "NextHop": "1.2.3.4",
            "InterfaceIndex": 1,
            "RouteMetric": 25,
            "PolicyStore": "ActiveStore",
            "ifMetric": None,
        }],
        "dns": [{"InterfaceIndex": 1, "AddressFamily": 2, "ServerAddresses": ["8.8.8.8"]}],
        "adapters": [{"Name": "eth0", "InterfaceGuid": "guid", "InterfaceIndex": 1, "Status": "Up"}],
        "ip_addresses": [{"InterfaceIndex": 1, "IPAddress": "10.0.0.1", "PrefixLength": 24, "AddressFamily": 2}],
        "interface_config": [{"InterfaceIndex": 1, "AddressFamily": 2, "NlMtu": 1500, "InterfaceMetric": 5, "ConnectionState": 1}],
        "winhttp_proxy": "Direct access",
    }


def _drifted_snapshot_dict() -> dict:
    """Snapshot dict with DNS drift vs _snapshot_dict() baseline."""
    drifted = _snapshot_dict()
    drifted["dns"] = [{"InterfaceIndex": 1, "AddressFamily": 2, "ServerAddresses": ["9.9.9.9"]}]
    return drifted


def _virtual_adapter_snapshot_dict() -> dict:
    """Snapshot with churn on an unrelated Hyper-V/WSL virtual adapter."""
    drifted = _snapshot_dict()
    drifted["adapters"] = drifted["adapters"] + [{
        "Name": "vEthernet (WSL)",
        "InterfaceDescription": "Hyper-V Virtual Ethernet Adapter",
        "InterfaceGuid": "virtual-guid",
        "InterfaceIndex": 50,
        "Status": "Up",
    }]
    drifted["routes"] = drifted["routes"] + [{
        "DestinationPrefix": "172.20.0.0/16",
        "NextHop": "0.0.0.0",
        "InterfaceIndex": 50,
        "RouteMetric": 0,
        "PolicyStore": "ActiveStore",
        "ifMetric": 5,
    }]
    drifted["dns"] = drifted["dns"] + [{
        "InterfaceIndex": 50,
        "AddressFamily": 2,
        "ServerAddresses": ["172.20.0.1"],
    }]
    drifted["ip_addresses"] = drifted["ip_addresses"] + [{
        "InterfaceIndex": 50,
        "IPAddress": "172.20.0.1",
        "PrefixLength": 20,
        "AddressFamily": 2,
    }]
    drifted["interface_config"] = drifted["interface_config"] + [{
        "InterfaceIndex": 50,
        "AddressFamily": 2,
        "NlMtu": 1500,
        "InterfaceMetric": 5,
        "ConnectionState": 1,
    }]
    return drifted


def _record(
    *,
    identity: dict | None = None,
    pid: int | None = 123,
    create_time: float | None = 100.0,
    state: str = "running",
    name: str = DEFAULT_ADAPTER_NAME,
    version: int = 2,
    baseline: dict | None = None,
) -> dict:
    record = {
        "version": version,
        "state": state,
        "adapter_guid": DEFAULT_ADAPTER_GUID,
        "adapter_name": name,
        "executable": identity or _identity(),
        "pid": pid,
        "create_time": create_time,
        "pre_start_present": False,
        "updated_at": 0.0,
    }
    if version >= 2:
        record["network_baseline"] = baseline if baseline is not None else _snapshot_dict()
    return record


def _capture_of(snapshot_dict: dict):
    return lambda: NetworkSnapshot.from_dict(snapshot_dict)


def _sequence_capture(sequence):
    """Return a snapshot capture failing after the sequence is exhausted."""
    events = list(sequence)

    def _capture():
        if not events:
            raise AssertionError("unexpected extra snapshot_capture call")
        return NetworkSnapshot.from_dict(events.pop(0))

    return _capture


def _gate(
    tmp_path,
    *,
    probe,
    creation: float | None = 100.0,
    identity: dict | None = None,
    current_snapshot: dict | None = None,
    capture_sequence: list | None = None,
    rollback_executor=None,
    window: float = 5.0,
    clock=None,
    sleep=None,
) -> TunRecoveryGate:
    snapshot_capture = (
        _sequence_capture(capture_sequence)
        if capture_sequence is not None
        else _capture_of(current_snapshot or _snapshot_dict())
    )
    return TunRecoveryGate(
        enabled=True,
        state_path=tmp_path / "tun-ownership.json",
        adapter_probe=probe,
        creation_time_probe=lambda pid: creation,
        identity_probe=lambda path: identity or _identity(),
        snapshot_capture=snapshot_capture,
        rollback_executor=rollback_executor,
        clock=clock,
        sleep=sleep,
        window_seconds=window,
    )


@pytest.fixture(autouse=True)
def _fake_frontend_ps(monkeypatch):
    """The frontend no longer executes PowerShell directly; baseline
    restoration (+ verification) lives in TunRecoveryGate, which is
    injected per-test."""
    return


class TestGatePreStart:
    def test_adapter_without_record_fails_closed(self, tmp_path):
        gate = _gate(tmp_path, probe=lambda guid, name: True)
        with pytest.raises(RecoveryUnverified):
            gate.pre_start("/fake/tun2proxy.exe")

    def test_inconclusive_probe_fails_closed(self, tmp_path):
        gate = _gate(tmp_path, probe=lambda guid, name: None)
        with pytest.raises(RecoveryUnverified):
            gate.pre_start("/fake/tun2proxy.exe")

    def test_corrupt_record_fails_closed(self, tmp_path):
        (tmp_path / "tun-ownership.json").write_text("{not json", encoding="utf-8")
        gate = _gate(tmp_path, probe=lambda guid, name: False)
        with pytest.raises(RecoveryUnverified):
            gate.pre_start("/fake/tun2proxy.exe")

    def test_identity_mismatch_fails_closed(self, tmp_path):
        (tmp_path / "tun-ownership.json").write_text(
            json.dumps(_record(identity=_identity("old"))), encoding="utf-8"
        )
        gate = _gate(
            tmp_path,
            probe=lambda guid, name: False,
            identity=_identity("new"),
        )
        with pytest.raises(RecoveryUnverified, match="executable identity"):
            gate.pre_start("/fake/tun2proxy.exe")

    def test_live_recorded_process_fails_closed_without_kill(
        self, tmp_path, monkeypatch
    ):
        (tmp_path / "tun-ownership.json").write_text(
            json.dumps(_record()), encoding="utf-8"
        )
        gate = _gate(tmp_path, probe=lambda guid, name: False, creation=100.0)
        killed: list[tuple[int, int]] = []
        monkeypatch.setattr(os, "kill", lambda pid, sig: killed.append((pid, sig)))

        with pytest.raises(RecoveryUnverified, match="still running"):
            gate.pre_start("/fake/tun2proxy.exe")

        assert killed == []

    def test_pid_reuse_is_treated_as_stale(self, tmp_path):
        (tmp_path / "tun-ownership.json").write_text(
            json.dumps(_record(create_time=100.0)), encoding="utf-8"
        )
        gate = _gate(tmp_path, probe=lambda guid, name: False, creation=200.0)

        run = gate.pre_start("/fake/tun2proxy.exe")

        assert run.enabled
        record = json.loads((tmp_path / "tun-ownership.json").read_text())
        assert record["state"] == "prepared"
        assert record["pid"] is None

    @pytest.mark.parametrize("state", ["prepared", "unverified"])
    def test_ambiguous_record_blocks_restart(self, tmp_path, state):
        (tmp_path / "tun-ownership.json").write_text(
            json.dumps(
                _record(state=state, pid=None, create_time=None)
            ),
            encoding="utf-8",
        )
        gate = _gate(tmp_path, probe=lambda guid, name: False)

        with pytest.raises(RecoveryUnverified, match=state):
            gate.pre_start("/fake/tun2proxy.exe")


class TestPreStartParallelStep:
    """Identity hashing, the baseline capture and the adapter probe are
    independent read-only steps: they must run in one parallel step instead
    of serializing PowerShell spawns behind the capture."""

    def _capture_of_dict(self, snapshot_dict):
        return lambda: NetworkSnapshot.from_dict(snapshot_dict)

    def test_capture_and_probe_run_concurrently(self, tmp_path):
        import threading

        barrier = threading.Barrier(2, timeout=5.0)
        participants: list[str] = []

        def capture():
            participants.append("capture")
            barrier.wait()
            return NetworkSnapshot.from_dict(_snapshot_dict())

        def probe(guid, name):
            participants.append("probe")
            barrier.wait()
            return False

        gate = TunRecoveryGate(
            enabled=True,
            state_path=tmp_path / "tun-ownership.json",
            adapter_probe=probe,
            creation_time_probe=lambda pid: 100.0,
            identity_probe=lambda path: _identity(),
            snapshot_capture=capture,
        )
        run = gate.pre_start("/fake/tun2proxy.exe")
        assert run.enabled and run.record["state"] == "prepared"
        assert set(participants) == {"capture", "probe"}

    def test_owned_record_skips_speculative_probe(self, tmp_path):
        """An owned record validates via _validate_existing's own presence
        check; the speculative pre-lock probe must not be launched on top
        (peek saw the record, so exactly one probe runs in total)."""
        (tmp_path / "tun-ownership.json").write_text(
            json.dumps(_record(create_time=100.0)), encoding="utf-8"
        )
        probe_calls: list[int] = []

        def probe(guid, name):
            probe_calls.append(1)
            return False

        gate = TunRecoveryGate(
            enabled=True,
            state_path=tmp_path / "tun-ownership.json",
            adapter_probe=probe,
            creation_time_probe=lambda pid: 200.0,  # PID reuse: stale record
            identity_probe=lambda path: _identity(),
            snapshot_capture=self._capture_of_dict(_snapshot_dict()),
        )
        run = gate.pre_start("/fake/tun2proxy.exe")
        assert run.enabled
        record = json.loads((tmp_path / "tun-ownership.json").read_text())
        assert record["state"] == "prepared"
        assert record["pid"] is None
        assert len(probe_calls) == 1

    def test_record_appearing_between_peek_and_lock_still_probes(self, tmp_path):
        """Record vanished between the cheap peek and the locked re-read:
        the fallback must still run the adapter probe (fail-closed kept)."""
        calls: list[str] = []

        def probe(guid, name):
            calls.append("probe")
            return True  # adapter present without a record -> fail closed

        gate = TunRecoveryGate(
            enabled=True,
            state_path=tmp_path / "tun-ownership.json",
            adapter_probe=probe,
            creation_time_probe=lambda pid: 100.0,
            identity_probe=lambda path: _identity(),
            snapshot_capture=self._capture_of_dict(_snapshot_dict()),
        )
        # Corrupt the record only after the peek happened is not possible
        # from outside; instead simulate the race directly: peek sees a
        # record, the locked re-read sees none. Patch _load_record.
        original_load = gate._load_record
        states = iter([_record(), None])

        def flaky_load():
            value = next(states)
            return value

        gate._load_record = flaky_load  # type: ignore[method-assign]
        with pytest.raises(RecoveryUnverified, match="already present"):
            gate.pre_start("/fake/tun2proxy.exe")
        assert calls == ["probe"]
        assert original_load is not None

    def test_probe_failure_without_record_fails_closed(self, tmp_path):
        gate = TunRecoveryGate(
            enabled=True,
            state_path=tmp_path / "tun-ownership.json",
            adapter_probe=lambda guid, name: None,  # inconclusive
            creation_time_probe=lambda pid: 100.0,
            identity_probe=lambda path: _identity(),
            snapshot_capture=self._capture_of_dict(_snapshot_dict()),
        )
        with pytest.raises(RecoveryUnverified, match="inconclusive"):
            gate.pre_start("/fake/tun2proxy.exe")


class TestGateVerification:
    @pytest.mark.asyncio
    async def test_baseline_restore_overlaps_adapter_removal_poll(self, tmp_path):
        """The baseline restoration must run while the zombie adapter is still
        present instead of waiting for its removal first."""
        events: list[str] = []
        state = {"armed": False, "commands_ran": False, "absent": False}

        def probe(guid, name):
            if not state["armed"]:
                return False
            if state["commands_ran"]:
                state["absent"] = True
            events.append("probe=" + ("absent" if state["absent"] else "present"))
            return not state["absent"]

        def executor(cmd: str) -> str:
            state["commands_ran"] = True
            events.append("rollback")
            return "ok"

        gate = _gate(
            tmp_path,
            probe=probe,
            capture_sequence=[
                _snapshot_dict(),
                _drifted_snapshot_dict(),
                _snapshot_dict(),
            ],
            rollback_executor=executor,
            window=5.0,
        )
        run = gate.pre_start("/fake/tun2proxy.exe")
        gate.mark_running(run, 123, 100.0)
        state["armed"] = True

        assert await gate.verify_after_exit(run) == CLEAN

        # The rollback provably ran while the adapter was still reported
        # present, and the poll only observed absence afterwards.
        assert events.index("rollback") < events.index("probe=absent")
        assert events[0] == "probe=present"
        assert not (tmp_path / "tun-ownership.json").exists()

    @pytest.mark.asyncio
    async def test_restore_failure_during_overlap_fails_closed(self, tmp_path):
        state = {"armed": False, "commands_ran": False, "absent": False}

        def probe(guid, name):
            if not state["armed"]:
                return False
            if state["commands_ran"]:
                state["absent"] = True
            return not state["absent"]

        def executor(cmd: str) -> str:
            state["commands_ran"] = True
            raise RecoveryUnverified("rollback command failed")

        gate = _gate(
            tmp_path,
            probe=probe,
            capture_sequence=[
                _snapshot_dict(),
                _drifted_snapshot_dict(),
                _snapshot_dict(),
            ],
            rollback_executor=executor,
            window=5.0,
        )
        run = gate.pre_start("/fake/tun2proxy.exe")
        gate.mark_running(run, 123, 100.0)
        state["armed"] = True

        assert await gate.verify_after_exit(run) == RECOVERY_UNVERIFIED
        record = json.loads((tmp_path / "tun-ownership.json").read_text())
        assert record["state"] == "unverified"

    @pytest.mark.asyncio
    async def test_trial_adapter_still_listed_during_rollback_is_not_fatal(
        self, tmp_path
    ):
        """Wintun can linger in the adapter table after terminate.

        The trial's own adapter must be ignored by the rollback plan instead
        of tripping the "unexpected adapter appears" refusal, which used to
        turn a clean teardown into RECOVERY_UNVERIFIED (and a 500 on
        /api/disconnect).
        """
        lingering = _drifted_snapshot_dict()
        lingering["adapters"] = lingering["adapters"] + [{
            "Name": "PerchVPN",
            "InterfaceDescription": "sing-tun Tunnel",
            "InterfaceGuid": "trial-guid",
            "InterfaceIndex": 70,
            "Status": "Up",
        }]
        lingering["routes"] = lingering["routes"] + [{
            "DestinationPrefix": "10.0.0.0/24",
            "NextHop": "10.0.0.1",
            "InterfaceIndex": 70,
            "RouteMetric": 0,
            "PolicyStore": "ActiveStore",
            "ifMetric": 1,
        }]

        executed: list[str] = []

        def executor(cmd: str) -> str:
            executed.append(cmd)
            return "ok"

        gate = _gate(
            tmp_path,
            probe=lambda guid, name: False,
            capture_sequence=[_snapshot_dict(), lingering, _snapshot_dict()],
            rollback_executor=executor,
            window=5.0,
        )
        run = gate.pre_start("/fake/tun2proxy.exe")
        gate.mark_running(run, 123, 100.0)

        assert await gate.verify_after_exit(run) == CLEAN
        assert any("Set-DnsClientServerAddress" in cmd for cmd in executed)
        assert not (tmp_path / "tun-ownership.json").exists()

    @pytest.mark.asyncio
    async def test_clean_exit_clears_record(self, tmp_path):
        gate = _gate(tmp_path, probe=lambda guid, name: False)
        run = gate.pre_start("/fake/tun2proxy.exe")
        gate.mark_running(run, 123, 100.0)
        assert (tmp_path / "tun-ownership.json").exists()

        assert await gate.verify_after_exit(run) == CLEAN
        assert not (tmp_path / "tun-ownership.json").exists()

    @pytest.mark.asyncio
    async def test_surviving_adapter_fails_closed(self, tmp_path):
        present = {"value": False}
        gate = _gate(
            tmp_path,
            probe=lambda guid, name: present["value"],
            window=1.0,
        )
        run = gate.pre_start("/fake/tun2proxy.exe")
        gate.mark_running(run, 123, 100.0)
        present["value"] = True

        assert await gate.verify_after_exit(run) == RECOVERY_UNVERIFIED
        record = json.loads((tmp_path / "tun-ownership.json").read_text())
        assert record["state"] == "unverified"

    @pytest.mark.asyncio
    async def test_timeout_is_bounded_and_fails_closed(self, tmp_path):
        now = [0.0]
        present = {"value": False}

        async def sleep(seconds: float) -> None:
            now[0] += seconds

        gate = _gate(
            tmp_path,
            probe=lambda guid, name: present["value"],
            window=5.0,
            clock=lambda: now[0],
            sleep=sleep,
        )
        run = gate.pre_start("/fake/tun2proxy.exe")
        gate.mark_running(run, 123, 100.0)
        present["value"] = True

        assert await gate.verify_after_exit(run) == RECOVERY_UNVERIFIED
        assert now[0] >= 5.0

    @pytest.mark.asyncio
    async def test_missing_record_at_verification_fails_closed(self, tmp_path):
        gate = _gate(tmp_path, probe=lambda guid, name: False)
        run = gate.pre_start("/fake/tun2proxy.exe")
        (tmp_path / "tun-ownership.json").unlink()

        assert await gate.verify_after_exit(run) == RECOVERY_UNVERIFIED

    def test_mark_running_requires_creation_time(self, tmp_path):
        gate = _gate(tmp_path, probe=lambda guid, name: False)
        run = gate.pre_start("/fake/tun2proxy.exe")
        with pytest.raises(RecoveryUnverified):
            gate.mark_running(run, 123, None)

    @pytest.mark.asyncio
    async def test_inconclusive_probe_retries_until_window_then_fails_closed(self, tmp_path):
        now = [0.0]
        probes = {"count": 0}
        state = {"value": False}

        async def sleep(seconds: float) -> None:
            now[0] += seconds

        def probe(guid, name):
            probes["count"] += 1
            return state["value"]

        gate = _gate(
            tmp_path,
            probe=probe,
            window=5.0,
            clock=lambda: now[0],
            sleep=sleep,
        )
        run = gate.pre_start("/fake/tun2proxy.exe")
        gate.mark_running(run, 123, 100.0)
        state["value"] = None

        assert await gate.verify_after_exit(run) == RECOVERY_UNVERIFIED
        assert now[0] >= 5.0
        assert probes["count"] > 1
        record = json.loads((tmp_path / "tun-ownership.json").read_text())
        assert record["state"] == "unverified"

    @pytest.mark.asyncio
    async def test_inconclusive_probe_then_absence_is_clean(self, tmp_path):
        now = [0.0]
        state = {"value": False}

        async def sleep(seconds: float) -> None:
            now[0] += seconds
            state["value"] = False

        gate = _gate(
            tmp_path,
            probe=lambda guid, name: state["value"],
            window=5.0,
            clock=lambda: now[0],
            sleep=sleep,
        )
        run = gate.pre_start("/fake/tun2proxy.exe")
        gate.mark_running(run, 123, 100.0)
        state["value"] = None

        assert await gate.verify_after_exit(run) == CLEAN
        assert not (tmp_path / "tun-ownership.json").exists()


class TestNetworkBaseline:
    def test_pre_start_persists_network_baseline(self, tmp_path):
        gate = _gate(tmp_path, probe=lambda guid, name: False)
        gate.pre_start("/fake/tun2proxy.exe")

        record = json.loads((tmp_path / "tun-ownership.json").read_text())
        assert record["version"] == 2
        baseline = record["network_baseline"]
        expected = _snapshot_dict()
        assert baseline["routes"] == expected["routes"]
        assert baseline["dns"] == expected["dns"]
        assert baseline["interface_config"] == expected["interface_config"]
        assert baseline["winhttp_proxy"] == expected["winhttp_proxy"]

    def test_baseline_capture_failure_fails_closed(self, tmp_path):
        from perchvpn_windows.tun_state_capture import CaptureError

        def failing_capture():
            raise CaptureError("PowerShell execution failed")

        gate = TunRecoveryGate(
            enabled=True,
            state_path=tmp_path / "tun-ownership.json",
            adapter_probe=lambda guid, name: False,
            creation_time_probe=lambda pid: 100.0,
            identity_probe=lambda path: _identity(),
            snapshot_capture=failing_capture,
        )
        with pytest.raises(RecoveryUnverified, match="network baseline"):
            gate.pre_start("/fake/tun2proxy.exe")

    def test_legacy_version_1_record_fails_closed(self, tmp_path):
        (tmp_path / "tun-ownership.json").write_text(
            json.dumps(_record(version=1)), encoding="utf-8"
        )
        gate = _gate(tmp_path, probe=lambda guid, name: False)
        with pytest.raises(RecoveryUnverified, match="version is unsupported"):
            gate.pre_start("/fake/tun2proxy.exe")

    def test_missing_baseline_fails_closed(self, tmp_path):
        record = _record()
        del record["network_baseline"]
        (tmp_path / "tun-ownership.json").write_text(
            json.dumps(record), encoding="utf-8"
        )
        gate = _gate(tmp_path, probe=lambda guid, name: False)
        with pytest.raises(RecoveryUnverified, match="network baseline"):
            gate.pre_start("/fake/tun2proxy.exe")

    def test_invalid_baseline_fails_closed(self, tmp_path):
        (tmp_path / "tun-ownership.json").write_text(
            json.dumps(_record(baseline={})), encoding="utf-8"
        )
        gate = _gate(tmp_path, probe=lambda guid, name: False)
        with pytest.raises(RecoveryUnverified, match="invalid network baseline"):
            gate.pre_start("/fake/tun2proxy.exe")

    def test_crash_drift_restores_baseline_before_restart(self, tmp_path):
        executed: list[str] = []

        def executor(cmd: str) -> str:
            executed.append(cmd)
            return "ok"

        # Crash record baseline differs from current state (DNS drift), and
        # the post-restore verification capture is drift-free.
        gate = _gate(
            tmp_path,
            probe=lambda guid, name: False,
            creation=200.0,
            capture_sequence=[_snapshot_dict(), _drifted_snapshot_dict(), _snapshot_dict()],
            rollback_executor=executor,
        )
        (tmp_path / "tun-ownership.json").write_text(
            json.dumps(_record(pid=123, create_time=100.0)), encoding="utf-8"
        )

        run = gate.pre_start("/fake/tun2proxy.exe")

        assert run.enabled
        assert executed and any(
            "Set-DnsClientServerAddress" in cmd for cmd in executed
        )
        record = json.loads((tmp_path / "tun-ownership.json").read_text())
        assert record["state"] == "prepared"

    def test_virtual_adapter_churn_does_not_trigger_rollback(self, tmp_path):
        executed: list[str] = []

        def executor(cmd: str) -> str:
            executed.append(cmd)
            return "ok"

        gate = _gate(
            tmp_path,
            probe=lambda guid, name: False,
            creation=200.0,
            capture_sequence=[
                _virtual_adapter_snapshot_dict(),
                _virtual_adapter_snapshot_dict(),
                _virtual_adapter_snapshot_dict(),
            ],
            rollback_executor=executor,
        )
        (tmp_path / "tun-ownership.json").write_text(
            json.dumps(_record(pid=123, create_time=100.0)), encoding="utf-8"
        )

        run = gate.pre_start("/fake/tun2proxy.exe")

        assert run.enabled
        assert executed == []
        record = json.loads((tmp_path / "tun-ownership.json").read_text())
        assert record["state"] == "prepared"

    def test_virtual_churn_does_not_mask_owned_drift(self, tmp_path):
        executed: list[str] = []

        def executor(cmd: str) -> str:
            executed.append(cmd)
            return "ok"

        current = _virtual_adapter_snapshot_dict()
        current["dns"] = [
            {"InterfaceIndex": 1, "AddressFamily": 2, "ServerAddresses": ["9.9.9.9"]},
        ] + current["dns"][1:]

        gate = _gate(
            tmp_path,
            probe=lambda guid, name: False,
            creation=200.0,
            capture_sequence=[current, current, current],
            rollback_executor=executor,
        )
        (tmp_path / "tun-ownership.json").write_text(
            json.dumps(_record(pid=123, create_time=100.0)), encoding="utf-8"
        )

        with pytest.raises(
            RecoveryUnverified, match="post-rollback verification"
        ):
            gate.pre_start("/fake/tun2proxy.exe")

        assert executed and any(
            "Set-DnsClientServerAddress" in cmd for cmd in executed
        )

    def test_operator_trial_clears_stale_unverified_after_clean_capture(
        self, tmp_path
    ):
        (tmp_path / "tun-ownership.json").write_text(
            json.dumps(
                _record(state="unverified", pid=123, create_time=100.0)
            ),
            encoding="utf-8",
        )
        gate = _gate(tmp_path, probe=lambda guid, name: False, creation=200.0)

        run = gate.pre_start("/fake/tun2proxy.exe", operator_trial=True)

        assert run.enabled
        record = json.loads((tmp_path / "tun-ownership.json").read_text())
        assert record["state"] == "prepared"

    def test_operator_trial_clears_latch_for_down_only_adapter(
        self, tmp_path
    ):
        """A torn-down Wintun device can linger with Status=Down.

        Recovery must not latch that as a surviving tunnel: the down row
        cannot carry traffic and would otherwise block every later Connect.
        """
        (tmp_path / "tun-ownership.json").write_text(
            json.dumps(
                _record(state="unverified", pid=123, create_time=100.0)
            ),
            encoding="utf-8",
        )

        def probe(guid, name, require_up=False):
            return False

        gate = _gate(tmp_path, probe=probe, creation=200.0)

        run = gate.pre_start("/fake/tun2proxy.exe", operator_trial=True)

        assert run.enabled
        record = json.loads((tmp_path / "tun-ownership.json").read_text())
        assert record["state"] == "prepared"

    def test_operator_trial_ignores_lingering_adapter_row(
        self, tmp_path
    ):
        """A torn-down row still listed by the capture must not block the reset.

        When the probe proves the adapter is not operational but the snapshot
        still contains its row, the reset used to count it as owned drift and
        refuse, leaving the operator lockout in place.
        """
        (tmp_path / "tun-ownership.json").write_text(
            json.dumps(
                _record(state="unverified", pid=123, create_time=100.0)
            ),
            encoding="utf-8",
        )
        lingering = _snapshot_dict()
        lingering["adapters"] = lingering["adapters"] + [{
            "Name": "PerchVPN",
            "InterfaceGuid": "trial-guid",
            "InterfaceIndex": 70,
            "Status": "Down",
        }]

        def probe(guid, name, require_up=False):
            return False if require_up else True

        gate = _gate(
            tmp_path,
            probe=probe,
            creation=200.0,
            current_snapshot=lingering,
        )

        run = gate.pre_start("/fake/tun2proxy.exe", operator_trial=True)

        assert run.enabled

    def test_operator_trial_refuses_when_up_adapter_survives(
        self, tmp_path
    ):
        (tmp_path / "tun-ownership.json").write_text(
            json.dumps(
                _record(state="unverified", pid=123, create_time=100.0)
            ),
            encoding="utf-8",
        )

        def probe(guid, name, require_up=False):
            return True if require_up else False

        gate = _gate(tmp_path, probe=probe, creation=200.0)

        with pytest.raises(RecoveryUnverified, match="survives"):
            gate.pre_start("/fake/tun2proxy.exe", operator_trial=True)

    def test_operator_trial_ignores_virtual_churn_when_clearing(
        self, tmp_path
    ):
        (tmp_path / "tun-ownership.json").write_text(
            json.dumps(
                _record(state="unverified", pid=123, create_time=100.0)
            ),
            encoding="utf-8",
        )
        gate = _gate(
            tmp_path,
            probe=lambda guid, name: False,
            creation=200.0,
            current_snapshot=_virtual_adapter_snapshot_dict(),
        )

        run = gate.pre_start("/fake/tun2proxy.exe", operator_trial=True)

        assert run.enabled
        record = json.loads((tmp_path / "tun-ownership.json").read_text())
        assert record["state"] == "prepared"

    def test_operator_trial_refuses_unverified_with_owned_drift(self, tmp_path):
        (tmp_path / "tun-ownership.json").write_text(
            json.dumps(
                _record(state="unverified", pid=123, create_time=100.0)
            ),
            encoding="utf-8",
        )
        gate = _gate(
            tmp_path,
            probe=lambda guid, name: False,
            creation=200.0,
            current_snapshot=_drifted_snapshot_dict(),
        )

        with pytest.raises(RecoveryUnverified, match="refusing operator reset"):
            gate.pre_start("/fake/tun2proxy.exe", operator_trial=True)

        record = json.loads((tmp_path / "tun-ownership.json").read_text())
        assert record["state"] == "unverified"

    def test_operator_trial_refuses_when_recorded_process_still_live(
        self, tmp_path
    ):
        (tmp_path / "tun-ownership.json").write_text(
            json.dumps(
                _record(state="unverified", pid=123, create_time=100.0)
            ),
            encoding="utf-8",
        )
        gate = _gate(tmp_path, probe=lambda guid, name: False, creation=100.0)

        with pytest.raises(RecoveryUnverified, match="still running"):
            gate.pre_start("/fake/tun2proxy.exe", operator_trial=True)

    def test_crash_drift_post_verification_failure_fails_closed(
        self, tmp_path
    ):
        executed: list[str] = []

        def executor(cmd: str) -> str:
            executed.append(cmd)
            return "ok"

        # Commands run but drift persists at the post-restore capture.
        gate = _gate(
            tmp_path,
            probe=lambda guid, name: False,
            creation=200.0,
            capture_sequence=[
                _snapshot_dict(),
                _drifted_snapshot_dict(),
                _drifted_snapshot_dict(),
            ],
            rollback_executor=executor,
        )
        (tmp_path / "tun-ownership.json").write_text(
            json.dumps(_record(pid=123, create_time=100.0)), encoding="utf-8"
        )

        with pytest.raises(RecoveryUnverified, match="post-rollback verification"):
            gate.pre_start("/fake/tun2proxy.exe")

        # Durable record retained as evidence.
        record = json.loads((tmp_path / "tun-ownership.json").read_text())
        assert record["state"] == "running"

    def test_crash_rollback_failure_fails_closed(self, tmp_path):
        def failing_executor(cmd: str) -> str:
            raise RollbackError("Set-DnsClientServerAddress failed")

        gate = _gate(
            tmp_path,
            probe=lambda guid, name: False,
            creation=200.0,
            capture_sequence=[_snapshot_dict(), _drifted_snapshot_dict()],
            rollback_executor=failing_executor,
        )
        (tmp_path / "tun-ownership.json").write_text(
            json.dumps(_record(pid=123, create_time=100.0)), encoding="utf-8"
        )

        with pytest.raises(RecoveryUnverified, match="rollback command failed"):
            gate.pre_start("/fake/tun2proxy.exe")

        # Ownership record stays intact (fail closed, no blind clearing).
        record = json.loads((tmp_path / "tun-ownership.json").read_text())
        assert record["state"] == "running"

    def test_crash_rollback_object_not_found_is_tolerated(self, tmp_path):
        def not_found_executor(cmd: str) -> str:
            raise RollbackError(
                "Remove-NetRoute : No matching MSFT_NetRoute objects found by CIM query "
                "CmdletizationQuery_NotFound,Remove-NetRoute"
            )

        gate = _gate(
            tmp_path,
            probe=lambda guid, name: False,
            creation=200.0,
            capture_sequence=[_snapshot_dict(), _snapshot_dict()],
            rollback_executor=not_found_executor,
        )
        (tmp_path / "tun-ownership.json").write_text(
            json.dumps(_record(pid=123, create_time=100.0)), encoding="utf-8"
        )

        run = gate.pre_start("/fake/sing-box.exe")
        assert run.enabled
        record = json.loads((tmp_path / "tun-ownership.json").read_text())
        assert record["state"] == "prepared"


class _FakeProcess:
    def __init__(self, pid: int = 4242) -> None:
        self.pid = pid
        self.returncode = None
        self.stdout = None
        self.stderr = None
        self.terminated = False
        self.killed = False
        self._done = asyncio.Event()

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = -15
        self._done.set()

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9
        self._done.set()

    async def wait(self):
        await self._done.wait()
        return self.returncode


def _frontend(gate, *, extra_args=None) -> TunFrontend:
    return TunFrontend(
        enabled=True,
        opt_in=True,
        executable_path=sys.executable,
        proxy_host="127.0.0.1",
        proxy_port=1080,
        extra_args=list(extra_args or []),
        is_elevated=lambda: True,
        recovery_gate=gate,
    )


class TestFrontendGate:
    @pytest.fixture(autouse=True)
    def _fake_resolved_executable(self, monkeypatch):
        monkeypatch.setattr(
            TunFrontend, "_resolve_executable", lambda self: sys.executable
        )

    @pytest.mark.asyncio
    async def test_clean_stop_verifies_and_clears(self, tmp_path):
        gate = _gate(tmp_path, probe=lambda guid, name: False)
        frontend = _frontend(gate)
        proc = _FakeProcess()

        with patch(
            "src.perchvpn_windows.tun_frontend.asyncio.create_subprocess_exec",
            AsyncMock(return_value=proc),
        ):
            await frontend.start()
            assert frontend.status == "running"
            await frontend.stop()

        assert frontend.status == "stopped"
        assert frontend.recovery_state == CLEAN
        assert not (tmp_path / "tun-ownership.json").exists()
        assert proc.terminated

    @pytest.mark.asyncio
    async def test_dead_unverified_record_does_not_block_start(self, tmp_path):
        gate = _gate(
            tmp_path,
            probe=lambda guid, name: False,
            creation=200.0,
        )
        path = tmp_path / "tun-ownership.json"
        path.write_text(
            json.dumps(
                _record(state="unverified", pid=123, create_time=100.0)
            ),
            encoding="utf-8",
        )
        frontend = _frontend(gate)
        proc = _FakeProcess()

        with patch(
            "src.perchvpn_windows.tun_frontend.asyncio.create_subprocess_exec",
            AsyncMock(return_value=proc),
        ):
            await frontend.start()
            assert frontend.status == "running"
            await frontend.stop()

        assert frontend.recovery_state == CLEAN
        assert not path.exists()

    @pytest.mark.asyncio
    async def test_stale_wintun_cleanup_runs_before_spawn_and_after_stop(
        self, tmp_path, monkeypatch
    ):
        calls = []

        async def cleanup(frontend):
            calls.append(frontend._adapter_name())

        monkeypatch.setattr(TunFrontend, "_cleanup_stale_wintun", cleanup)
        gate = _gate(tmp_path, probe=lambda guid, name: False)
        frontend = _frontend(gate)
        proc = _FakeProcess()

        with patch(
            "src.perchvpn_windows.tun_frontend.asyncio.create_subprocess_exec",
            AsyncMock(return_value=proc),
        ):
            await frontend.start()
            await frontend.stop()

        assert calls == [DEFAULT_ADAPTER_NAME, DEFAULT_ADAPTER_NAME]

    @pytest.mark.asyncio
    async def test_surviving_adapter_sets_unverified(self, tmp_path):
        now = [0.0]
        present = {"value": False}

        async def sleep(seconds: float) -> None:
            now[0] += seconds

        gate = _gate(
            tmp_path,
            probe=lambda guid, name: present["value"],
            window=1.0,
            clock=lambda: now[0],
            sleep=sleep,
        )
        frontend = _frontend(gate)
        proc = _FakeProcess()

        with patch(
            "src.perchvpn_windows.tun_frontend.asyncio.create_subprocess_exec",
            AsyncMock(return_value=proc),
        ):
            await frontend.start()
            present["value"] = True
            await frontend.stop()

        assert frontend.status == RECOVERY_UNVERIFIED
        assert frontend.recovery_state == RECOVERY_UNVERIFIED
        record = json.loads((tmp_path / "tun-ownership.json").read_text())
        assert record["state"] == "unverified"

    @pytest.mark.asyncio
    async def test_corrupt_record_blocks_spawn(self, tmp_path):
        (tmp_path / "tun-ownership.json").write_text("{", encoding="utf-8")
        gate = _gate(tmp_path, probe=lambda guid, name: False)
        frontend = _frontend(gate)
        spawn = AsyncMock()

        with patch(
            "src.perchvpn_windows.tun_frontend.asyncio.create_subprocess_exec",
            spawn,
        ):
            await frontend.start()

        assert frontend.status == RECOVERY_UNVERIFIED
        assert frontend.recovery_state == RECOVERY_UNVERIFIED
        assert frontend._process is None
        spawn.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_spawn_failure_clears_prepared_record(self, tmp_path):
        gate = _gate(tmp_path, probe=lambda guid, name: False)
        frontend = _frontend(gate)

        with patch(
            "src.perchvpn_windows.tun_frontend.asyncio.create_subprocess_exec",
            AsyncMock(side_effect=OSError("no spawn")),
        ):
            await frontend.start()

        assert frontend.status == "failed"
        assert frontend._process is None
        assert not (tmp_path / "tun-ownership.json").exists()

    @pytest.mark.asyncio
    async def test_creation_time_failure_terminates_child_and_fails_closed(
        self, tmp_path
    ):
        gate = TunRecoveryGate(
            enabled=True,
            state_path=tmp_path / "tun-ownership.json",
            adapter_probe=lambda guid, name: False,
            creation_time_probe=lambda pid: None,
            identity_probe=lambda path: _identity(),
            snapshot_capture=_capture_of(_snapshot_dict()),
        )
        frontend = _frontend(gate)
        proc = _FakeProcess()

        with patch(
            "src.perchvpn_windows.tun_frontend.asyncio.create_subprocess_exec",
            AsyncMock(return_value=proc),
        ):
            await frontend.start()

        assert proc.terminated
        assert frontend.status == RECOVERY_UNVERIFIED
        assert frontend._process is None
        assert not (tmp_path / "tun-ownership.json").exists()

    @pytest.mark.asyncio
    async def test_ownership_write_failure_terminates_owned_child(self, tmp_path):
        gate = _gate(tmp_path, probe=lambda guid, name: False)
        write_record = gate._write_record

        def failing_write(record):
            if record.get("state") == "running":
                raise RecoveryUnverified("disk full")
            write_record(record)

        gate._write_record = failing_write
        frontend = _frontend(gate)
        proc = _FakeProcess()

        with patch(
            "src.perchvpn_windows.tun_frontend.asyncio.create_subprocess_exec",
            AsyncMock(return_value=proc),
        ):
            await frontend.start()

        assert proc.terminated
        assert frontend._process is None
        assert frontend.status == RECOVERY_UNVERIFIED
        assert not (tmp_path / "tun-ownership.json").exists()

    @pytest.mark.asyncio
    async def test_cancelled_spawn_fails_closed_and_blocks_restart(self, tmp_path):
        gate = _gate(tmp_path, probe=lambda guid, name: False)
        frontend = _frontend(gate)

        with patch(
            "src.perchvpn_windows.tun_frontend.asyncio.create_subprocess_exec",
            AsyncMock(side_effect=asyncio.CancelledError),
        ):
            with pytest.raises(asyncio.CancelledError):
                await frontend.start()

        record_path = tmp_path / "tun-ownership.json"
        assert json.loads(record_path.read_text())["state"] == "prepared"

        await frontend.stop()
        assert frontend.status == RECOVERY_UNVERIFIED
        assert frontend.recovery_state == RECOVERY_UNVERIFIED
        assert record_path.exists()
        assert json.loads(record_path.read_text())["state"] == "prepared"

        spawn = AsyncMock()
        restarted = _frontend(gate)
        with patch(
            "src.perchvpn_windows.tun_frontend.asyncio.create_subprocess_exec",
            spawn,
        ):
            await restarted.start()

        assert restarted.status == RECOVERY_UNVERIFIED
        spawn.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_tun_name_is_forwarded_to_gate(self, tmp_path):
        gate = MagicMock()
        gate.pre_start.return_value = RecoveryRun(record={}, enabled=True)
        gate.creation_time.return_value = 1.0
        gate.verify_after_exit = AsyncMock(return_value=CLEAN)
        frontend = _frontend(gate, extra_args=["--tun", "mytun"])
        proc = _FakeProcess()

        with patch(
            "src.perchvpn_windows.tun_frontend.asyncio.create_subprocess_exec",
            AsyncMock(return_value=proc),
        ):
            await frontend.start()
            await frontend.stop()

        assert gate.pre_start.call_args[0][1] == "mytun"
        gate.mark_running.assert_called_once()
        gate.verify_after_exit.assert_awaited_once()


class TestBaselineRestoration:
    """Frontend flows delegate restoration to the gate; the durable record
    must survive until restoration + post-verification succeed."""

    @pytest.fixture(autouse=True)
    def _fake_resolved_executable(self, monkeypatch):
        monkeypatch.setattr(
            TunFrontend, "_resolve_executable", lambda self: sys.executable
        )

    def _run_flow(self, frontend, proc):
        return patch(
            "src.perchvpn_windows.tun_frontend.asyncio.create_subprocess_exec",
            AsyncMock(return_value=proc),
        )

    def _swap_capture(self, gate, sequence):
        gate._snapshot_capture = _sequence_capture(sequence)

    @pytest.mark.asyncio
    async def test_clean_exit_restores_dns_drift(self, tmp_path):
        executed: list[str] = []

        def executor(cmd: str) -> str:
            executed.append(cmd)
            return "ok"

        gate = _gate(tmp_path, probe=lambda guid, name: False, rollback_executor=executor)
        frontend = _frontend(gate)
        proc = _FakeProcess()

        with self._run_flow(frontend, proc):
            await frontend.start()
            # Drift "during the trial": current capture differs from the
            # baseline; post-restore verification capture is drift-free.
            self._swap_capture(
                gate, [_drifted_snapshot_dict(), _snapshot_dict()]
            )
            await frontend.stop()

        assert frontend.recovery_state == CLEAN
        assert frontend.status == "stopped"
        assert any("Set-DnsClientServerAddress" in cmd for cmd in executed)
        assert not (tmp_path / "tun-ownership.json").exists()

    @pytest.mark.asyncio
    async def test_post_restore_verification_failure_is_durable_unverified(
        self, tmp_path
    ):
        executed: list[str] = []

        def executor(cmd: str) -> str:
            executed.append(cmd)
            return "ok"

        gate = _gate(tmp_path, probe=lambda guid, name: False, rollback_executor=executor)
        frontend = _frontend(gate)
        proc = _FakeProcess()

        with self._run_flow(frontend, proc):
            await frontend.start()
            # Rollback commands run but drift persists after them.
            self._swap_capture(
                gate, [_drifted_snapshot_dict(), _drifted_snapshot_dict()]
            )
            await frontend.stop()

        assert frontend.recovery_state == RECOVERY_UNVERIFIED
        assert frontend.status == RECOVERY_UNVERIFIED
        assert executed, "commands attempted before verification"
        record = json.loads((tmp_path / "tun-ownership.json").read_text())
        assert record["state"] == "unverified"
        assert record.get("network_baseline"), "baseline must survive"

    @pytest.mark.asyncio
    async def test_unverified_exit_skips_rollback(self, tmp_path):
        gate = _gate(tmp_path, probe=lambda guid, name: True, window=1.0)
        frontend = _frontend(gate)
        proc = _FakeProcess()
        commands: list[str] = []

        def executor(cmd: str) -> str:
            commands.append(cmd)
            return "ok"

        gate._rollback_executor = executor

        with self._run_flow(frontend, proc):
            await frontend.start()
            await frontend.stop()

        assert frontend.recovery_state == RECOVERY_UNVERIFIED
        assert frontend.status == RECOVERY_UNVERIFIED
        assert commands == [], "no blind rollback when recovery is unverified"

    @pytest.mark.asyncio
    async def test_later_stop_rederives_an_unverified_verdict(self, tmp_path):
        """A latched UNVERIFIED used to block every later disconnect/restart.

        Once the in-process run is consumed, the next stop re-derives the
        verdict from the durable ownership record instead of returning early
        with the stale failure.
        """
        executed: list[str] = []

        def executor(cmd: str) -> str:
            executed.append(cmd)
            return "ok"

        gate = _gate(tmp_path, probe=lambda guid, name: False, rollback_executor=executor)
        frontend = _frontend(gate)
        proc = _FakeProcess()

        with self._run_flow(frontend, proc):
            await frontend.start()
            self._swap_capture(
                gate, [_drifted_snapshot_dict(), _drifted_snapshot_dict()]
            )
            await frontend.stop()
            assert frontend.recovery_state == RECOVERY_UNVERIFIED

            # Next teardown: the sidecar is dead, the adapter is gone and the
            # table is clean, so the durable record reconciles and the verdict
            # must not stay latched.
            gate._creation_time_probe = lambda pid: None
            self._swap_capture(gate, [_snapshot_dict()])
            assert await frontend.stop() is True

        assert frontend.recovery_state == CLEAN
        assert frontend.status == "stopped"


class _FakeApp:
    def __init__(self) -> None:
        self.initialized = False
        self.shutdown_called = False
        self.cancelled = False

    async def initialize(self) -> None:
        self.initialized = True

    async def run(self) -> None:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled = True
            raise

    async def shutdown(self) -> None:
        self.shutdown_called = True


class TestCliInterruption:
    @pytest.mark.asyncio
    async def test_stop_event_cancels_run_and_shuts_down(self):
        from src.perchvpn_windows import cli

        app = _FakeApp()
        stop_event = asyncio.Event()

        async def trigger() -> None:
            await asyncio.sleep(0.05)
            stop_event.set()

        asyncio.create_task(trigger())

        await cli._run_app_with_shutdown(app, stop_event=stop_event)

        assert app.initialized
        assert app.cancelled
        assert app.shutdown_called

    @pytest.mark.asyncio
    async def test_run_failure_still_shuts_down(self):
        from src.perchvpn_windows import cli

        app = _FakeApp()

        async def fail() -> None:
            raise RuntimeError("boom")

        app.run = fail  # type: ignore[assignment]

        with pytest.raises(RuntimeError):
            await cli._run_app_with_shutdown(app, stop_event=asyncio.Event())

        assert app.shutdown_called


class TestInitializationRollback:
    def _patched_app(self, monkeypatch, fake_tun):
        from src.perchvpn_windows.app import PerchVPNApp
        from src.perchvpn_windows.config import WindowsConfig

        controller = MagicMock()
        controller.start = AsyncMock(return_value=MagicMock())
        controller.stop = AsyncMock()
        controller.metrics = MagicMock()
        frontend = MagicMock()
        frontend.start = AsyncMock()
        frontend.stop = AsyncMock()

        app = PerchVPNApp(
            WindowsConfig(
                explicit_proxy="1.2.3.4:1080",
                verify_exit=False,
                tun_enabled=True,
            )
        )

        async def fake_start_tun():
            app._tun_frontend = fake_tun
            raise RuntimeError("tun boom")

        monkeypatch.setattr(app, "_start_tun_frontend", fake_start_tun)

        patches = [
            patch.object(
                PerchVPNApp, "_obtain_auth", AsyncMock(return_value=MagicMock())
            ),
            patch("src.perchvpn_windows.app.ProxyController", return_value=controller),
            patch("src.perchvpn_windows.app.Socks5Frontend", return_value=frontend),
        ]
        return app, frontend, patches

    @pytest.mark.asyncio
    async def test_tun_frontend_stopped_when_later_step_fails(self, monkeypatch):
        fake_tun = MagicMock()
        fake_tun.stop = AsyncMock(return_value=True)
        fake_tun.recovery_state = CLEAN
        app, frontend, patches = self._patched_app(monkeypatch, fake_tun)

        with patches[0], patches[1], patches[2]:
            with pytest.raises(RuntimeError):
                await app.initialize()

        frontend.stop.assert_awaited_once()
        fake_tun.stop.assert_awaited_once()
        assert app._frontend is None
        assert app._tun_frontend is None

    @pytest.mark.asyncio
    async def test_tun_frontend_stopped_on_cancellation(self, monkeypatch):
        fake_tun = MagicMock()
        fake_tun.stop = AsyncMock(return_value=True)
        fake_tun.recovery_state = CLEAN
        app, frontend, patches = self._patched_app(monkeypatch, fake_tun)

        async def cancel_start():
            app._tun_frontend = fake_tun
            raise asyncio.CancelledError()

        monkeypatch.setattr(app, "_start_tun_frontend", cancel_start)

        with patches[0], patches[1], patches[2]:
            with pytest.raises(asyncio.CancelledError):
                await app.initialize()

        frontend.stop.assert_awaited_once()
        fake_tun.stop.assert_awaited_once()
        assert app._frontend is None
        assert app._tun_frontend is None

    @pytest.mark.asyncio
    async def test_tun_frontend_retained_when_rollback_stop_unverified(self, monkeypatch):
        fake_tun = MagicMock()
        fake_tun.stop = AsyncMock(return_value=False)
        fake_tun.recovery_state = RECOVERY_UNVERIFIED
        app, frontend, patches = self._patched_app(monkeypatch, fake_tun)

        with patches[0], patches[1], patches[2]:
            with pytest.raises(RuntimeError):
                await app.initialize()

        fake_tun.stop.assert_awaited_once()
        assert app._frontend is None
        assert app._tun_frontend is fake_tun

    @pytest.mark.asyncio
    async def test_tun_frontend_retained_when_rollback_stop_raises(self, monkeypatch):
        fake_tun = MagicMock()
        fake_tun.stop = AsyncMock(side_effect=RuntimeError("rollback stop failed"))
        app, frontend, patches = self._patched_app(monkeypatch, fake_tun)

        with patches[0], patches[1], patches[2]:
            with pytest.raises(RuntimeError, match="tun boom"):
                await app.initialize()

        fake_tun.stop.assert_awaited_once()
        assert app._frontend is None
        assert app._tun_frontend is fake_tun

    @pytest.mark.asyncio
    async def test_tun_frontend_retained_when_rollback_stop_cancelled(self, monkeypatch):
        fake_tun = MagicMock()
        fake_tun.stop = AsyncMock(side_effect=asyncio.CancelledError)
        app, frontend, patches = self._patched_app(monkeypatch, fake_tun)

        with patches[0], patches[1], patches[2]:
            with pytest.raises(asyncio.CancelledError):
                await app.initialize()

        fake_tun.stop.assert_awaited_once()
        assert app._tun_frontend is fake_tun


class TestStaleOwnershipReconciliation:
    """Cold-start reconciliation: stale running record, absent adapter."""

    def test_no_record_returns_clean(self, tmp_path):
        gate = _gate(tmp_path, probe=lambda g, n: False)
        assert gate.reconcile_stale_ownership() == CLEAN
        assert not (tmp_path / "tun-ownership.json").exists()

    def test_stale_running_record_cleared_after_verified_restore(self, tmp_path):
        commands = []

        def executor(cmd):
            commands.append(cmd)
            return ""

        drift = _drifted_snapshot_dict()
        gate = _gate(
            tmp_path,
            probe=lambda g, n: False,
            capture_sequence=[drift, _snapshot_dict()],
            rollback_executor=executor,
        )
        (tmp_path / "tun-ownership.json").write_text(
            json.dumps(_record()), encoding="utf-8"
        )
        assert gate.reconcile_stale_ownership() == CLEAN
        assert not (tmp_path / "tun-ownership.json").exists()
        assert len(commands) == 1
        assert "-ServerAddresses" in commands[0]

    def test_dead_unverified_record_cleared_after_verified_restore(
        self, tmp_path
    ):
        commands = []

        def executor(cmd):
            commands.append(cmd)
            return ""

        gate = _gate(
            tmp_path,
            probe=lambda g, n: False,
            creation=200.0,
            capture_sequence=[_drifted_snapshot_dict(), _snapshot_dict()],
            rollback_executor=executor,
        )
        path = tmp_path / "tun-ownership.json"
        path.write_text(
            json.dumps(
                _record(state="unverified", pid=123, create_time=100.0)
            ),
            encoding="utf-8",
        )

        assert gate.reconcile_stale_ownership() == CLEAN
        assert not path.exists()
        assert len(commands) == 1
        assert "-ServerAddresses" in commands[0]

    def test_live_unverified_record_is_kept(self, tmp_path):
        gate = _gate(
            tmp_path,
            probe=lambda g, n: False,
            creation=100.0,
        )
        path = tmp_path / "tun-ownership.json"
        path.write_text(
            json.dumps(
                _record(state="unverified", pid=123, create_time=100.0)
            ),
            encoding="utf-8",
        )

        assert gate.reconcile_stale_ownership() == RECOVERY_UNVERIFIED
        assert json.loads(path.read_text())["state"] == "unverified"

    def test_reconciliation_is_idempotent(self, tmp_path):
        gate = _gate(tmp_path, probe=lambda g, n: False)
        (tmp_path / "tun-ownership.json").write_text(
            json.dumps(_record()), encoding="utf-8"
        )
        assert gate.reconcile_stale_ownership() == CLEAN
        assert gate.reconcile_stale_ownership() == CLEAN

    def test_owned_adapter_present_refused_record_kept(self, tmp_path):
        gate = _gate(tmp_path, probe=lambda g, n: True)
        path = tmp_path / "tun-ownership.json"
        path.write_text(json.dumps(_record()), encoding="utf-8")
        assert gate.reconcile_stale_ownership() == RECOVERY_UNVERIFIED
        record = json.loads(path.read_text())
        assert record["state"] == "unverified"

    def test_ambient_only_drift_not_remediated_and_cleared(self, tmp_path):
        commands = []

        def executor(cmd):
            commands.append(cmd)
            return ""

        base = _snapshot_dict()
        base["adapters"].append(
            {"Name": "singbox_tun", "InterfaceGuid": "sb", "InterfaceIndex": 29, "Status": "Up"}
        )
        base["routes"].append({
            "DestinationPrefix": "ff00::/8", "NextHop": "::",
            "InterfaceIndex": 29, "RouteMetric": 1,
            "PolicyStore": "ActiveStore", "ifMetric": None,
        })
        drifted = json.loads(json.dumps(base))
        drifted["routes"] = [
            r for r in drifted["routes"]
            if r.get("DestinationPrefix") != "ff00::/8"
        ]
        gate = _gate(
            tmp_path,
            probe=lambda g, n: False,
            capture_sequence=[drifted, drifted],
            rollback_executor=executor,
        )
        (tmp_path / "tun-ownership.json").write_text(
            json.dumps(_record(baseline=base)), encoding="utf-8"
        )
        assert gate.reconcile_stale_ownership() == CLEAN
        assert not (tmp_path / "tun-ownership.json").exists()
        assert commands == []

    def test_non_running_record_state_is_evidence_kept(self, tmp_path):
        gate = _gate(tmp_path, probe=lambda g, n: False)
        path = tmp_path / "tun-ownership.json"
        path.write_text(
            json.dumps(_record(state="unverified")), encoding="utf-8"
        )
        assert gate.reconcile_stale_ownership() == RECOVERY_UNVERIFIED
        assert path.exists()

    def test_cold_start_restores_residual_on_vanished_trial_ifindex(
        self, tmp_path
    ):
        """Production wiring proof: _restore_from_baseline must pass
        baseline_snapshot so a PersistentStore residual on the vanished trial
        ifIndex (64 absent from both snapshots' adapters) is owned and removed
        during cold-start reconciliation."""
        commands = []

        def executor(cmd):
            commands.append(cmd)
            return ""

        base = _snapshot_dict()
        current = json.loads(json.dumps(base))
        current["routes"].append({
            "DestinationPrefix": "0.0.0.0/0", "NextHop": "10.0.0.1",
            "InterfaceIndex": 64, "RouteMetric": 10,
            "PolicyStore": "PersistentStore", "ifMetric": None,
        })
        gate = _gate(
            tmp_path,
            probe=lambda g, n: False,
            capture_sequence=[current, base],
            rollback_executor=executor,
        )
        (tmp_path / "tun-ownership.json").write_text(
            json.dumps(_record(pid=123, create_time=100.0)), encoding="utf-8"
        )

        assert gate.reconcile_stale_ownership() == CLEAN

        # Without baseline wiring the residual would be ambient (the trial
        # adapter is absent from the current capture) and no command would run.
        assert commands == [
            "Remove-NetRoute -DestinationPrefix '0.0.0.0/0' -NextHop '10.0.0.1' "
            "-InterfaceIndex 64 -PolicyStore PersistentStore "
            "-Confirm:$false -ErrorAction SilentlyContinue"
        ]
        assert not (tmp_path / "tun-ownership.json").exists()


async def _instant_sleep(_seconds):
    return None


class TestReleasedOwnershipAfterTeardown:
    """Regression: switched countries, disconnected, cannot reconnect.

    Live log (2026-11-24T01:14): teardown probed the adapter with "is it Up?",
    saw Down, declared CLEAN and deleted the ownership record.  Seven seconds
    later the next Connect probed "does the row exist?", saw the same row and
    failed closed with "adapter 'PerchVPN'/None is already present without an
    ownership record" — permanently, because nothing in the UI can consume
    that latch.  A down row is provably ours and carries no traffic, so
    teardown now keeps a released record and pre_start consumes it.
    """

    @staticmethod
    def _gate(tmp_path, probe, creation):
        return TunRecoveryGate(
            enabled=True,
            state_path=tmp_path / "tun-ownership.json",
            adapter_probe=probe,
            creation_time_probe=lambda pid: creation["value"],
            identity_probe=lambda path: _identity(),
            snapshot_capture=_capture_of(_snapshot_dict()),
            window_seconds=0.05,
            sleep=_instant_sleep,
        )

    @pytest.mark.asyncio
    async def test_down_row_survives_teardown_and_the_next_connect_succeeds(
        self, tmp_path
    ):
        state = {"row": False, "up": False}
        creation = {"value": 100.0}

        def probe(guid, name, *, require_up=False):
            if not state["row"]:
                return False
            return state["up"] if require_up else True

        gate = self._gate(tmp_path, probe, creation)

        run = gate.pre_start("/fake/tun2proxy.exe")
        gate.mark_running(run, 4242, 100.0)
        state["row"], state["up"] = True, True

        # Disconnect: the sidecar exits, the driver tears down the device, but
        # Windows keeps the adapter row listed with IfOperStatus Down.
        state["up"] = False
        creation["value"] = None
        assert await gate.verify_after_exit(run) == CLEAN

        record = json.loads((tmp_path / "tun-ownership.json").read_text(encoding="utf-8"))
        assert record["state"] == "released"

        # Reconnect (after any number of country switches): must not latch.
        again = gate.pre_start("/fake/tun2proxy.exe")
        gate.mark_running(again, 4243, 101.0)
        assert again.record is not None

        # The row finally ages out and the second teardown clears everything.
        state["row"] = False
        assert await gate.verify_after_exit(again) == CLEAN
        assert not (tmp_path / "tun-ownership.json").exists()

    @pytest.mark.asyncio
    async def test_released_row_that_is_up_still_fails_closed(self, tmp_path):
        state = {"row": False, "up": False}
        creation = {"value": 100.0}

        def probe(guid, name, *, require_up=False):
            if not state["row"]:
                return False
            return state["up"] if require_up else True

        gate = self._gate(tmp_path, probe, creation)
        run = gate.pre_start("/fake/tun2proxy.exe")
        gate.mark_running(run, 4242, 100.0)
        state["row"], state["up"] = True, True

        state["up"] = False
        creation["value"] = None
        assert await gate.verify_after_exit(run) == CLEAN

        # Something now holds our name and it is up: keep the fail-closed gate.
        state["up"] = True
        with pytest.raises(RecoveryUnverified):
            gate.pre_start("/fake/tun2proxy.exe")

    @pytest.mark.asyncio
    async def test_released_record_with_a_live_sidecar_fails_closed(self, tmp_path):
        state = {"row": False, "up": False}
        creation = {"value": 100.0}

        def probe(guid, name, *, require_up=False):
            if not state["row"]:
                return False
            return state["up"] if require_up else True

        gate = self._gate(tmp_path, probe, creation)
        run = gate.pre_start("/fake/tun2proxy.exe")
        gate.mark_running(run, 4242, 100.0)
        state["row"], state["up"] = True, False

        # The device is down but the recorded helper process is still alive.
        creation["value"] = 100.0
        assert await gate.verify_after_exit(run) == CLEAN
        with pytest.raises(RecoveryUnverified):
            gate.pre_start("/fake/tun2proxy.exe")

    @pytest.mark.asyncio
    async def test_down_row_releases_early_instead_of_waiting_the_whole_window(
        self, tmp_path
    ):
        """A provably-down row must not hold Disconnect for the whole window.

        Live 2026-11-24 12:56:12 run: the sidecar exited in 0.22 s, the
        baseline restore finished ~1 s later, and teardown then sat on the
        adapter-absence poll until the 8.0 s deadline because Windows keeps
        the torn-down Wintun row listed with IfOperStatus Down.
        """
        state = {"row": False, "up": False}
        creation = {"value": 100.0}

        def probe(guid, name, *, require_up=False):
            if not state["row"]:
                return False
            return state["up"] if require_up else True

        gate = TunRecoveryGate(
            enabled=True,
            state_path=tmp_path / "tun-ownership.json",
            adapter_probe=probe,
            creation_time_probe=lambda pid: creation["value"],
            identity_probe=lambda path: _identity(),
            snapshot_capture=_capture_of(_snapshot_dict()),
            window_seconds=5.0,
        )

        run = gate.pre_start("/fake/tun2proxy.exe")
        gate.mark_running(run, 4242, 100.0)
        state["row"], state["up"] = True, True

        state["up"] = False
        creation["value"] = None
        started = time.monotonic()
        assert await gate.verify_after_exit(run) == CLEAN
        elapsed = time.monotonic() - started

        assert elapsed < 3.0, elapsed
        record = json.loads(
            (tmp_path / "tun-ownership.json").read_text(encoding="utf-8")
        )
        assert record["state"] == "released"

    @pytest.mark.asyncio
    async def test_early_release_waits_for_the_restore_and_the_grace(
        self, tmp_path
    ):
        """Fail closed: release only after a settled restore, never on tick 1."""
        state = {"row": False, "up": False}
        creation = {"value": 100.0}

        def probe(guid, name, *, require_up=False):
            if not state["row"]:
                return False
            return state["up"] if require_up else True

        gate = TunRecoveryGate(
            enabled=True,
            state_path=tmp_path / "tun-ownership.json",
            adapter_probe=probe,
            creation_time_probe=lambda pid: creation["value"],
            identity_probe=lambda path: _identity(),
            snapshot_capture=_capture_of(_snapshot_dict()),
            window_seconds=5.0,
        )
        run = gate.pre_start("/fake/tun2proxy.exe")
        gate.mark_running(run, 4242, 100.0)
        creation["value"] = None
        state["row"], state["up"] = True, False

        started = time.monotonic()
        assert await gate.verify_after_exit(run) == CLEAN
        elapsed = time.monotonic() - started

        assert elapsed >= _DOWN_ROW_RELEASE_GRACE_SECONDS, elapsed
        assert elapsed < 3.0, elapsed
        record = json.loads(
            (tmp_path / "tun-ownership.json").read_text(encoding="utf-8")
        )
        assert record["state"] == "released"
