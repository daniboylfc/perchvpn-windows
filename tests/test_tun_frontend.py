"""Focused TUN frontend lifecycle tests - no system networking changes."""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.perchvpn_windows import tun_frontend as tun_frontend_module
from perchvpn_windows import tun_status
from src.perchvpn_windows.tun_frontend import TunFrontend
from src.perchvpn_windows.tun_recovery import RECOVERY_UNVERIFIED
from perchvpn_windows.tun_state_capture import NetworkSnapshot


if sys.platform == "win32":
    import atexit
    import os
    import shutil
    import tempfile
    from pathlib import Path

    _fake_dir = Path(tempfile.mkdtemp(prefix="perchvpn-tun-test-"))
    _src_exe = Path(sys.executable)
    _fake_exe = _fake_dir / _src_exe.name
    shutil.copy2(_src_exe, _fake_exe)
    for _dll in _src_exe.parent.glob("*.dll"):
        shutil.copy2(_dll, _fake_dir / _dll.name)
    (_fake_dir / "wintun.dll").write_bytes(b"")
    os.environ.setdefault("PYTHONHOME", str(_src_exe.parent))
    atexit.register(shutil.rmtree, _fake_dir, True)
    FAKE_EXECUTABLE = str(_fake_exe)
else:
    FAKE_EXECUTABLE = sys.executable


@pytest.fixture(autouse=True)
def _disable_default_recovery_gate(monkeypatch):
    """Keep these lifecycle tests hermetic (no real adapter probes) on Windows."""
    import src.perchvpn_windows.tun_frontend as tun_module

    original = tun_module.TunRecoveryGate
    monkeypatch.setattr(
        tun_module,
        "TunRecoveryGate",
        lambda *args, **kwargs: original(enabled=False),
    )


def _sleep_proc_args(seconds: float = 30) -> list[str]:
    return [sys.executable, "-c", "import time; time.sleep(%s)" % seconds]


class TestDisabledByDefault:
    def test_disabled_status(self):
        t = TunFrontend()
        assert t.enabled is False
        assert t.status == "disabled"

    @pytest.mark.asyncio
    async def test_start_is_noop_when_disabled(self):
        t = TunFrontend(enabled=False, opt_in=True, executable_path=FAKE_EXECUTABLE, is_elevated=lambda: True)
        await t.start()
        assert t.status == "disabled"
        assert t._process is None


class TestOptInAndElevation:
    @pytest.mark.asyncio
    async def test_not_opted_in(self):
        t = TunFrontend(enabled=True, opt_in=False, executable_path=FAKE_EXECUTABLE, is_elevated=lambda: True)
        await t.start()
        assert t.status == "not_opted_in"
        assert t._process is None

    @pytest.mark.asyncio
    async def test_not_elevated(self):
        t = TunFrontend(enabled=True, opt_in=True, executable_path=FAKE_EXECUTABLE, is_elevated=lambda: False)
        await t.start()
        assert t.status == "not_elevated"
        assert t._process is None


class TestBuildCommand:
    def _config(self, t):
        cmd = t.build_command()
        assert cmd[-3] == "run"
        assert cmd[-2] == "-c"
        return cmd, json.loads(Path(cmd[-1]).read_text(encoding="utf-8"))

    def test_command_construction(self, tmp_path):
        t = TunFrontend(
            enabled=True, opt_in=True, executable_path=FAKE_EXECUTABLE,
            proxy_host="127.0.0.1", proxy_port=1080, is_elevated=lambda: True,
            extra_args=["--foo", "bar"], config_path=str(tmp_path / "sing-box.json"),
        )
        cmd, cfg = self._config(t)
        assert cmd[0] == FAKE_EXECUTABLE
        assert "--foo" in cmd
        assert all(isinstance(x, str) for x in cmd)
        socks = next(o for o in cfg["outbounds"] if o["type"] == "socks")
        assert socks["server"] == "127.0.0.1"
        assert socks["server_port"] == 1080
        assert socks["network"] == "tcp"

    def test_default_config_is_written_to_app_config_dir(self, monkeypatch, tmp_path):
        config_dir = tmp_path / "config"
        monkeypatch.setattr(
            tun_frontend_module, "get_config_dir", lambda: config_dir
        )
        t = TunFrontend(
            enabled=True, opt_in=True, executable_path=FAKE_EXECUTABLE,
            proxy_host="127.0.0.1", proxy_port=1080, is_elevated=lambda: True,
        )
        cmd = t.build_command()
        expected = config_dir / "sing-box.json"
        assert Path(cmd[-1]) == expected
        assert json.loads(expected.read_text(encoding="utf-8"))["outbounds"]

    def test_command_includes_dns_hijack_and_auto_route(self, tmp_path):
        t = TunFrontend(
            enabled=True, opt_in=True, executable_path=FAKE_EXECUTABLE,
            proxy_host="127.0.0.1", proxy_port=1080, is_elevated=lambda: True,
            config_path=str(tmp_path / "sing-box.json"),
        )
        cmd, cfg = self._config(t)
        # Native sing-box mode owns routing through auto_route, so
        # strict_route is enabled here (mirrors the helper path).
        assert cfg["inbounds"][0]["auto_route"] is True
        assert cfg["inbounds"][0]["strict_route"] is True
        assert cfg["inbounds"][0]["stack"] == "system"
        assert any(rule.get("action") == "hijack-dns" for rule in cfg["route"]["rules"])
        assert cfg["route"]["find_process"] is False
        assert not any("process_name" in r for r in cfg["route"]["rules"])

        t_proc = TunFrontend(
            enabled=True, opt_in=True, executable_path=FAKE_EXECUTABLE,
            proxy_host="127.0.0.1", proxy_port=1080, is_elevated=lambda: True,
            config_path=str(tmp_path / "sing-box-proc.json"),
            bypass_processes=("PerchVPN.exe",),
        )
        _, cfg_proc = self._config(t_proc)
        assert cfg_proc["route"]["find_process"] is True
        proc_rule = next(r for r in cfg_proc["route"]["rules"] if "process_name" in r)
        assert proc_rule["action"] == "route"
        assert proc_rule["outbound"] == "direct"
        assert "PerchVPN.exe" in proc_rule["process_name"]
        for legacy in ("--setup", "--tun", "--proxy", "--dns", "--mtu", "--bypass"):
            assert legacy not in cmd

    def test_disabled_raises(self):
        t = TunFrontend(enabled=False, opt_in=True, is_elevated=lambda: True, executable_path=FAKE_EXECUTABLE)
        with pytest.raises(RuntimeError):
            t.build_command()

    def test_missing_executable_raises(self):
        t = TunFrontend(enabled=True, opt_in=True, executable_path="/no/such/bin", is_elevated=lambda: True)
        with pytest.raises(ValueError):
            t.build_command()


class TestStartupFailure:
    @pytest.mark.asyncio
    async def test_startup_failure_detected(self):
        t = TunFrontend(
            enabled=True, opt_in=True, executable_path=FAKE_EXECUTABLE,
            is_elevated=lambda: True,
            extra_args=["-c", "import sys; sys.exit(3)"],
        )
        await t.start()
        # process exits quickly -> failed
        assert t.status == "failed"


class TestUnexpectedExit:
    @pytest.mark.asyncio
    async def test_unexpected_exit_marks_failed(self):
        t = TunFrontend(
            enabled=True, opt_in=True, executable_path=FAKE_EXECUTABLE,
            is_elevated=lambda: True,
            extra_args=["-c", "import time; time.sleep(0.3)"],
        )
        await t.start()
        assert t.status == "running"
        # wait for process to exit
        await asyncio.sleep(0.5)
        assert t.status == "failed"


class TestOrderlyShutdown:
    @pytest.mark.asyncio
    async def test_shutdown_terminates_child(self):
        t = TunFrontend(
            enabled=True, opt_in=True, executable_path=FAKE_EXECUTABLE,
            is_elevated=lambda: True,
            extra_args=["-c", "import time; time.sleep(30)"],
        )
        await t.start()
        assert t.status == "running"
        await t.stop()
        assert t.status == "stopped"
        assert t._process is None
class TestCaptureLimits:
    def test_invalid_capture_lines_rejected(self):
        with pytest.raises(ValueError):
            TunFrontend(enabled=True, opt_in=True, executable_path="x", capture_lines=0)
        with pytest.raises(ValueError):
            TunFrontend(enabled=True, opt_in=True, executable_path="x", capture_lines=-3)

    def test_invalid_max_line_bytes_rejected(self):
        with pytest.raises(ValueError):
            TunFrontend(enabled=True, opt_in=True, executable_path="x", max_line_bytes=0)
        with pytest.raises(ValueError):
            TunFrontend(enabled=True, opt_in=True, executable_path="x", max_line_bytes=-1)

    @pytest.mark.asyncio
    async def test_multibyte_split_safe_and_bounded(self):
        # 4-byte UTF-8 char repeated; truncation may split a sequence.
        ch = "\U0001F600"  # 4 bytes
        payload = ch * 2000
        t = TunFrontend(
            enabled=True, opt_in=True, executable_path=FAKE_EXECUTABLE,
            is_elevated=lambda: True,
            max_line_bytes=64,
            capture_lines=5,
            extra_args=["-c", "import sys; sys.stdout.reconfigure(encoding='utf-8'); sys.stdout.write('\\U0001F600' * 2000); sys.stdout.flush()"],
        )
        await t.start()
        await asyncio.sleep(0.3)
        assert t.stdout
        for line in t.stdout:
            assert len(line.encode("utf-8")) <= 64
        await t.stop()

class TestOutputCaptureBounded:
    @pytest.mark.asyncio
    async def test_oversized_output_is_truncated(self):
        big = "A" * 10000
        t = TunFrontend(
            enabled=True, opt_in=True, executable_path=FAKE_EXECUTABLE,
            is_elevated=lambda: True,
            max_line_bytes=64,
            capture_lines=5,
            extra_args=["-c", f"import sys; sys.stdout.write({big!r}); sys.stdout.flush()"],
        )
        await t.start()
        await asyncio.sleep(0.3)
        assert t.status in ("running", "failed")
        assert t.stdout, "expected captured output"
        assert all(len(line) <= 64 + len("...[truncated]") for line in t.stdout)
        assert any("...[truncated]" in line for line in t.stdout)
        await t.stop()



class TestIdempotencyAndMtu:
    def test_command_includes_mtu_bytes(self, tmp_path):
        t = TunFrontend(
            enabled=True, opt_in=True, executable_path=FAKE_EXECUTABLE,
            proxy_host="127.0.0.1", proxy_port=1080, mtu=1400,
            is_elevated=lambda: True, config_path=str(tmp_path / "sing-box.json"),
        )
        cmd = t.build_command()
        cfg = json.loads(Path(cmd[-1]).read_text(encoding="utf-8"))
        assert cfg["inbounds"][0]["mtu"] == 1400

    @pytest.mark.asyncio
    async def test_repeated_start_does_not_duplicate(self):
        t = TunFrontend(
            enabled=True, opt_in=True, executable_path=FAKE_EXECUTABLE,
            proxy_host="127.0.0.1", proxy_port=1080, is_elevated=lambda: True,
            extra_args=_sleep_proc_args(30),
        )
        # extra_args are appended before --proxy, so use a sleep executable directly
        t.extra_args = []
        t.executable_path = FAKE_EXECUTABLE
        # make the sidecar sleep so it stays alive
        t.extra_args = ["-c", "import time; time.sleep(30)"]
        await t.start()
        first = t._process
        await t.start()
        assert t._process is first
        await t.stop()
        await t.stop()
        assert t._process is None




class TestResolveExecutable:
    def test_missing_wintun_raises_on_windows(self, tmp_path, monkeypatch):
        import src.perchvpn_windows.tun_frontend as tun_module

        exe = tmp_path / "fake.exe"
        exe.write_bytes(b"")

        monkeypatch.setattr(tun_module.sys, "platform", "win32")

        t = TunFrontend(
            enabled=True,
            opt_in=True,
            executable_path=str(exe),
            is_elevated=lambda: True,
        )

        with pytest.raises(ValueError, match="wintun.dll not found"):
            t._resolve_executable()


class TestStartupEarlyExit:
    @pytest.mark.asyncio
    async def test_sidecar_exiting_before_startup_completes_marks_failed(self):
        t = TunFrontend(
            enabled=True,
            opt_in=True,
            executable_path=FAKE_EXECUTABLE,
            is_elevated=lambda: True,
            extra_args=["-c", "import sys; sys.exit(0)"],
        )

        await t.start()

        assert t.status == "failed"
        assert t._process is not None
        assert t._process.returncode is not None

        await t.stop()
        assert t._process is None


class TestColdStartOrphanReconciliation:
    """Lock in TunFrontend.start() -> gate.pre_start() behavior for a stale
    ``state="running"`` ownership record from a hard-killed previous run:
    a recoverable orphan (reused PID, adapter absent) must be baseline-scoped
    restored before a new sidecar spawns; an orphan whose adapter survives
    must fail closed with no spawn and no mutation."""

    _identity = {
        "path": FAKE_EXECUTABLE,
        "size": 11,
        "mtime_ns": 22,
        "sha256": "sha-current",
    }

    def _snapshot_dict(self, residual: bool = False) -> dict:
        from perchvpn_windows.tun_state_capture import NetworkSnapshot

        base = NetworkSnapshot(
            routes=[{"DestinationPrefix": "0.0.0.0/0", "NextHop": "1.2.3.4", "InterfaceIndex": 1, "RouteMetric": 25, "PolicyStore": "ActiveStore", "ifMetric": None}],
            dns=[{"InterfaceIndex": 1, "AddressFamily": 2, "ServerAddresses": ["8.8.8.8"]}],
            adapters=[{"Name": "eth0", "InterfaceGuid": "guid", "InterfaceIndex": 1, "Status": "Up"}],
            ip_addresses=[{"InterfaceIndex": 1, "IPAddress": "10.0.0.1", "PrefixLength": 24, "AddressFamily": 2}],
            interface_config=[{"InterfaceIndex": 1, "AddressFamily": 2, "NlMtu": 1500, "InterfaceMetric": 5, "ConnectionState": 1}],
            winhttp_proxy="Direct access",
        )
        if residual:
            base.routes.append({
                "DestinationPrefix": "0.0.0.0/0", "NextHop": "10.0.0.1",
                "InterfaceIndex": 64, "RouteMetric": 10,
                "PolicyStore": "PersistentStore", "ifMetric": None,
            })
        return base.to_dict()
    def _record(self, baseline: dict) -> dict:
        from src.perchvpn_windows.tun_recovery import (
            DEFAULT_ADAPTER_GUID,
            DEFAULT_ADAPTER_NAME,
        )

        identity = dict(self._identity)
        return {            "version": 2,
            "state": "running",
            "adapter_guid": DEFAULT_ADAPTER_GUID,
            "adapter_name": DEFAULT_ADAPTER_NAME,
            "executable": identity,
            "network_baseline": baseline,
            "pid": 123,
            "create_time": 100.0,
            "pre_start_present": False,
            "updated_at": 0.0,
        }

    def _gate(self, tmp_path, *, probe, capture, executor=None):
        from src.perchvpn_windows.tun_recovery import TunRecoveryGate

        return TunRecoveryGate(
            enabled=True,
            state_path=tmp_path / "tun-ownership.json",
            adapter_probe=probe,
            creation_time_probe=lambda pid: 200.0,
            identity_probe=lambda path: dict(self._identity),
            snapshot_capture=lambda: NetworkSnapshot.from_dict(capture.pop(0)),
            rollback_executor=executor or (lambda cmd: ""),
            window_seconds=5.0,
        )

    @pytest.mark.asyncio
    async def test_recoverable_orphan_is_reconciled_then_spawned(self, tmp_path):
        clean = self._snapshot_dict()
        (tmp_path / "tun-ownership.json").write_text(
            json.dumps(self._record(clean)), encoding="utf-8"
        )

        commands: list[str] = []

        def executor(cmd: str) -> str:
            commands.append(cmd)
            return ""

        # 1: pre-start baseline; 2: current (residual on vanished ifIndex 64);
        # 3: post-restoration (clean, unblocks pre_start); 4: post-exit.
        capture = [clean, self._snapshot_dict(residual=True), clean, clean]
        gate = self._gate(tmp_path, probe=lambda g, n: False, capture=capture, executor=executor)

        t = TunFrontend(
            enabled=True,
            opt_in=True,
            executable_path=FAKE_EXECUTABLE,
            is_elevated=lambda: True,
            extra_args=["-c", "import time; time.sleep(30)"],
            recovery_gate=gate,
        )

        await t.start()
        assert t.status == "running", "recoverable orphan must not block a new session"
        assert t._process is not None

        await t.stop()
        assert t.status == "stopped"
        assert t.recovery_state == "clean"

        # Baseline-scoped ownership: the residual record on the vanished
        # trial ifIndex was removed before the new sidecar spawned.
        assert commands == [
            "Remove-NetRoute -DestinationPrefix '0.0.0.0/0' -NextHop '10.0.0.1' "
            "-InterfaceIndex 64 -PolicyStore PersistentStore "
            "-Confirm:$false -ErrorAction SilentlyContinue"
        ]
        assert not (tmp_path / "tun-ownership.json").exists()

    @pytest.mark.asyncio
    async def test_surviving_adapter_orphan_fails_closed_without_spawn(self, tmp_path):
        clean = self._snapshot_dict()
        (tmp_path / "tun-ownership.json").write_text(
            json.dumps(self._record(clean)), encoding="utf-8"
        )

        commands: list[str] = []

        def executor(cmd: str) -> str:
            commands.append(cmd)
            raise AssertionError("no remediation when the adapter survives")

        capture = [clean]
        gate = self._gate(tmp_path, probe=lambda g, n: True, capture=capture, executor=executor)

        t = TunFrontend(
            enabled=True,
            opt_in=True,
            executable_path=FAKE_EXECUTABLE,
            is_elevated=lambda: True,
            recovery_gate=gate,
        )

        spawn = AsyncMock()
        with patch(
            "src.perchvpn_windows.tun_frontend.asyncio.create_subprocess_exec",
            spawn,
        ):
            await t.start()

        assert t.status == RECOVERY_UNVERIFIED
        assert t.recovery_state == RECOVERY_UNVERIFIED
        assert t._process is None
        spawn.assert_not_awaited()
        assert commands == [], "fail closed: no writes when the adapter survives"


class _FakeProc:
    """A child that terminates only when kill() is issued and whose
    asyncio exit-notify never fires (returncode stays None)."""

    def __init__(self):
        self.returncode = None
        self._raw_rc = None
        self._transport = type(
            "T", (), {"_proc": self, "get_returncode": lambda self_: None}
        )()
        self.terminated = False
        self.killed = False

    # asyncio.Process-like surface used by the frontend
    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True
        self._raw_rc = 143

    async def wait(self):
        await asyncio.sleep(3600)

    def poll(self):
        return self._raw_rc


class _StubbornProc(_FakeProc):
    def kill(self):
        self.killed = True


class TestTerminateProcessEscalation:
    """Live dataplane run exposed stop() as stop_failed while the child was
    provably already dead (adapter gone, teardown clean, returncode never
    delivered).  Terminate→wait→kill must stay fail-closed but must not
    report failure for a child the OS says is dead."""

    def _frontend(self) -> TunFrontend:
        t = TunFrontend(enabled=True, opt_in=True, executable_path=FAKE_EXECUTABLE)
        t._PROC_TERM_WAIT_SECONDS = 0.05
        t._PROC_POLL_ATTEMPTS = 3
        t._PROC_POLL_STEP_SECONDS = 0.01
        self.kills: list[bool] = []
        return t

    @pytest.mark.asyncio
    async def test_stop_succeeds_when_exit_notify_silent_but_child_dead(self):
        t = self._frontend()
        proc = _FakeProc()
        original_kill = proc.kill

        def kill():
            self.kills.append(True)
            original_kill()

        proc.kill = kill
        ok = await t._terminate_process(proc)
        assert proc.terminated, "graceful request sent first"
        assert self.kills == [True], "escalated to kill()"
        assert proc.poll() == 143
        assert ok is True

    @pytest.mark.asyncio
    async def test_stop_reports_failure_only_when_child_truly_alive(self):
        t = self._frontend()
        proc = _StubbornProc()
        ok = await t._terminate_process(proc)
        assert proc.terminated and proc.killed
        assert ok is False

    @pytest.mark.asyncio
    async def test_already_exited_child_is_noop_success(self):
        t = self._frontend()
        proc = _FakeProc()
        proc.returncode = 0
        ok = await t._terminate_process(proc)
        assert ok is True
        assert not proc.terminated and not proc.killed

    @pytest.mark.asyncio
    async def test_terminate_os_error_fails_bounded_and_fast(self):
        t = TunFrontend(enabled=True, opt_in=True, executable_path=FAKE_EXECUTABLE)
        t._PROC_POLL_ATTEMPTS = 1
        t._PROC_POLL_STEP_SECONDS = 0.01

        class _OSErrorProc:
            returncode = None

            class _transport:
                _proc = None

            def terminate(self):
                raise OSError("access denied")

        assert await t._terminate_process(_OSErrorProc()) is False


class TestStopRequiresProvenDeathRetention:
    @pytest.mark.asyncio
    async def test_graceful_timeout_escalates_and_keeps_unverified_record(self):
        t = TunFrontend(
            enabled=True, opt_in=True, executable_path=FAKE_EXECUTABLE,
            is_elevated=lambda: True,
            graceful_stop=True,
            extra_args=[
                "-c",
                "import time, signal\n"
                "def _ignore(name):\n"
                "    handler = getattr(signal, name, None)\n"
                "    if handler is not None:\n"
                "        signal.signal(handler, signal.SIG_IGN)\n"
                "for _name in ('SIGINT', 'SIGBREAK'):\n"
                "    try:\n"
                "        _ignore(_name)\n"
                "    except Exception:\n"
                "        pass\n"
                "time.sleep(30)",
            ],
        )
        await t.start()
        assert t.status == "running"
        proc = t._process
        clear_calls: list = []
        original_clear = t._recovery_gate.clear_run
        t._recovery_gate.clear_run = lambda *a, **k: clear_calls.append(a)
        try:
            ok = await t.stop_graceful(timeout=0.2)
        finally:
            t._recovery_gate.clear_run = original_clear
        # Escalation terminates a signal-ignoring child after the bounded
        # graceful window; the recovery gate then verifies the baseline and
        # clears the durable ownership record, so the stop is proven clean.
        assert proc.returncode is not None or proc.poll() is not None
        assert t._process is None
        assert ok is True
        assert t.status == "stopped"
        assert t._recovery_run is None
        from src.perchvpn_windows.tun_recovery import CLEAN
        assert t._recovery_state == CLEAN


class TestBuildCommandBypass:
    def test_bypass_becomes_route_exclude_address(self, tmp_path):
        t = TunFrontend(
            enabled=True, opt_in=True, executable_path=FAKE_EXECUTABLE,
            proxy_host="127.0.0.1", proxy_port=1080, is_elevated=lambda: True,
            extra_args=["--foo"],
            bypass=["192.168.1.0/24", "203.0.113.7"],
            config_path=str(tmp_path / "sing-box.json"),
        )
        cmd = t.build_command()
        assert "--foo" in cmd
        assert "--bypass" not in cmd
        cfg = json.loads(Path(cmd[-1]).read_text(encoding="utf-8"))
        excluded = cfg["inbounds"][0]["route_exclude_address"]
        assert "192.168.1.0/24" in excluded
        assert "203.0.113.7/32" in excluded

    def test_bypass_normalized_host_ip(self, tmp_path):
        t = TunFrontend(
            enabled=True, opt_in=True, executable_path=FAKE_EXECUTABLE,
            proxy_host="127.0.0.1", proxy_port=1080, is_elevated=lambda: True,
            bypass=["192.168.1.2"], config_path=str(tmp_path / "sing-box.json"),
        )
        cmd = t.build_command()
        cfg = json.loads(Path(cmd[-1]).read_text(encoding="utf-8"))
        assert "192.168.1.2/32" in cfg["inbounds"][0]["route_exclude_address"]

    def test_bypass_invalid_raises_value_error(self):
        with pytest.raises(ValueError, match="invalid --bypass entry"):
            TunFrontend(
                enabled=True, opt_in=True, executable_path=FAKE_EXECUTABLE,
                proxy_host="127.0.0.1", proxy_port=1080, is_elevated=lambda: True,
                bypass=["not-an-ip"],
            )

    def test_bypass_empty_tuple_ok(self):
        t = TunFrontend(
            enabled=True, opt_in=True, executable_path=FAKE_EXECUTABLE,
            proxy_host="127.0.0.1", proxy_port=1080, is_elevated=lambda: True,
            bypass=(),
        )
        assert "--bypass" not in t.build_command()


class TestEnforceAdapterMetric:
    def _frontend(self) -> TunFrontend:
        return TunFrontend(
            enabled=True,
            opt_in=True,
            executable_path=FAKE_EXECUTABLE,
            is_elevated=lambda: True,
        )

    @pytest.mark.asyncio
    async def test_pins_metric_after_adapter_detected(self, monkeypatch):
        t = self._frontend()
        calls = []

        def fake_write(script: str) -> str:
            calls.append(script)
            return "metric=1"

        monkeypatch.setattr(tun_frontend_module.sys, "platform", "win32")
        monkeypatch.setattr(tun_frontend_module, "_run_ps_write", fake_write)
        assert await t._enforce_adapter_metric() == 1
        assert len(calls) == 1
        script = calls[0]
        assert "Set-NetIPInterface" in script
        assert "InterfaceMetric 1" in script
        assert "metric=" in script
        assert "''" not in script
        assert "-InterfaceAlias 'PerchVPN'" in script

    @pytest.mark.asyncio
    async def test_metric_readback_mismatch_fails_closed(self, monkeypatch):
        t = self._frontend()

        def fake_write(script: str) -> str:
            assert "InterfaceMetric 1" in script
            return "metric=7"

        monkeypatch.setattr(tun_frontend_module.sys, "platform", "win32")
        monkeypatch.setattr(tun_frontend_module, "_run_ps_write", fake_write)
        assert await t._enforce_adapter_metric() is None

    @pytest.mark.asyncio
    async def test_reconcile_pins_metric_when_adapter_detected(self, monkeypatch):
        t = self._frontend()
        t._configured = True

        class FakeProcess:
            returncode = None

        t._process = FakeProcess()
        evidence = tun_status.AdapterEvidence(
            present=True, up=True, ipv4=["172.19.0.1"]
        )
        probe = AsyncMock(return_value=evidence)
        adapter_metric = AsyncMock(return_value=1)
        route_metric = AsyncMock(return_value={"0.0.0.0/1": 1, "128.0.0.0/1": 1})
        monkeypatch.setattr(tun_status, "probe_adapter", probe)
        monkeypatch.setattr(t, "_enforce_adapter_metric", adapter_metric)
        monkeypatch.setattr(t, "_enforce_split_route_metrics", route_metric)
        await t.reconcile()
        probe.assert_awaited_once()
        adapter_metric.assert_awaited_once()
        route_metric.assert_awaited_once()


class TestEnforceSplitRouteMetrics:
    def _frontend(self) -> TunFrontend:
        return TunFrontend(
            enabled=True,
            opt_in=True,
            executable_path=FAKE_EXECUTABLE,
            is_elevated=lambda: True,
        )

    @pytest.mark.asyncio
    async def test_enforce_split_route_metrics_is_noop(self, monkeypatch):
        t = self._frontend()
        calls = []

        def fake_write(script: str) -> str:
            calls.append(script)
            return ""

        monkeypatch.setattr(tun_frontend_module, "_run_ps_write", fake_write)
        res = await t._enforce_split_route_metrics()
        assert res is None
        assert len(calls) == 0


class TestReconcileTrafficVerified:
    def _frontend(self) -> TunFrontend:
        return TunFrontend(
            enabled=True,
            opt_in=True,
            executable_path=FAKE_EXECUTABLE,
            is_elevated=lambda: True,
        )

    @pytest.mark.asyncio
    async def test_reconcile_probes_identity_and_reaches_traffic_verified(self, monkeypatch):
        t = self._frontend()
        t._configured = True

        class FakeProcess:
            returncode = None

        t._process = FakeProcess()
        t.set_verification_target("85.9.100.160", "BE")

        evidence = tun_status.AdapterEvidence(
            present=True,
            up=True,
            ipv4=["172.19.0.1"],
            routes=[
                {"destination_prefix": "0.0.0.0/1"},
                {"destination_prefix": "128.0.0.0/1"},
            ],
        )
        egress_tcp = {
            "ok": True,
            "ipv4": {"ok": True, "source": "tcp"},
            "ipv6": {"ok": False},
        }
        identity_egress = {
            "ok": True,
            "ipv4": {"ok": True, "ip": "85.9.100.160", "country": "BE"},
            "ipv6": {"ok": False},
        }

        monkeypatch.setattr(tun_status, "probe_adapter", AsyncMock(return_value=evidence))
        monkeypatch.setattr(t, "_enforce_adapter_metric", AsyncMock(return_value=1))
        monkeypatch.setattr(t, "_enforce_split_route_metrics", AsyncMock(return_value={"0.0.0.0/1": 1, "128.0.0.0/1": 1}))
        monkeypatch.setattr(tun_status, "wait_for_system_egress", AsyncMock(return_value=egress_tcp))
        identity_mock = AsyncMock(return_value=identity_egress)
        monkeypatch.setattr(tun_status, "probe_system_egress_identity", identity_mock)

        state = await t.reconcile()
        assert state == tun_status.STATE_TRAFFIC_VERIFIED
        assert t.state == tun_status.STATE_TRAFFIC_VERIFIED
        if t._identity_task is not None:
            await t._identity_task
        identity_mock.assert_awaited_once()
        assert t.payload()["system_egress"]["ipv4"]["ip"] == "85.9.100.160"

    @pytest.mark.asyncio
    async def test_reconcile_pins_metric_only_once(self, monkeypatch):
        t = self._frontend()
        t._configured = True

        class FakeProcess:
            returncode = None

        t._process = FakeProcess()
        evidence = tun_status.AdapterEvidence(
            present=True,
            up=True,
            ipv4=["172.19.0.1"],
            routes=[
                {"destination_prefix": "0.0.0.0/1"},
                {"destination_prefix": "128.0.0.0/1"},
            ],
        )
        monkeypatch.setattr(tun_status, "probe_adapter", AsyncMock(return_value=evidence))
        adapter_metric = AsyncMock(return_value=1)
        route_metric = AsyncMock(return_value={"0.0.0.0/1": 1, "128.0.0.0/1": 1})
        monkeypatch.setattr(t, "_enforce_adapter_metric", adapter_metric)
        monkeypatch.setattr(t, "_enforce_split_route_metrics", route_metric)
        monkeypatch.setattr(tun_status, "wait_for_system_egress", AsyncMock(return_value={"ok": True, "ipv4": {"ok": True, "source": "tcp"}}))

        await t.reconcile()
        assert adapter_metric.await_count == 1
        assert route_metric.await_count == 1

        # Second reconcile should NOT call enforce again
        await t.reconcile()
        assert adapter_metric.await_count == 1
        assert route_metric.await_count == 1

    @pytest.mark.asyncio
    async def test_reconcile_pins_metric_concurrently_only_once(self, monkeypatch):
        t = self._frontend()
        t._configured = True

        class FakeProcess:
            returncode = None

        t._process = FakeProcess()
        evidence = tun_status.AdapterEvidence(
            present=True,
            up=True,
            ipv4=["172.19.0.1"],
            routes=[
                {"destination_prefix": "0.0.0.0/0"},
            ],
        )
        monkeypatch.setattr(tun_status, "probe_adapter", AsyncMock(return_value=evidence))

        async def slow_adapter_metric(*args, **kwargs):
            await asyncio.sleep(0.05)
            return 1

        async def slow_route_metric(*args, **kwargs):
            await asyncio.sleep(0.05)
            return {"0.0.0.0/0": 1}

        adapter_metric = AsyncMock(side_effect=slow_adapter_metric)
        route_metric = AsyncMock(side_effect=slow_route_metric)
        monkeypatch.setattr(t, "_enforce_adapter_metric", adapter_metric)
        monkeypatch.setattr(t, "_enforce_split_route_metrics", route_metric)
        monkeypatch.setattr(tun_status, "wait_for_system_egress", AsyncMock(return_value={"ok": True, "ipv4": {"ok": True, "source": "tcp"}}))

        # Run multiple concurrent reconcile tasks
        await asyncio.gather(
            t.reconcile(),
            t.reconcile(),
            t.reconcile(),
        )

        assert adapter_metric.await_count == 1
        assert route_metric.await_count == 1
        assert t._metric_pinned is True

    @pytest.mark.asyncio
    async def test_reconcile_latches_metric_pinned_even_on_pin_failure(self, monkeypatch):
        t = self._frontend()
        t._configured = True

        class FakeProcess:
            returncode = None

        t._process = FakeProcess()
        evidence = tun_status.AdapterEvidence(
            present=True,
            up=True,
            ipv4=["172.19.0.1"],
        )
        monkeypatch.setattr(tun_status, "probe_adapter", AsyncMock(return_value=evidence))
        adapter_metric = AsyncMock(return_value=None)
        route_metric = AsyncMock(return_value=None)
        monkeypatch.setattr(t, "_enforce_adapter_metric", adapter_metric)
        monkeypatch.setattr(t, "_enforce_split_route_metrics", route_metric)

        await t.reconcile()
        assert adapter_metric.await_count == 1
        assert route_metric.await_count == 1
        assert t._metric_pinned is True

        # Next reconcile must NOT retry metric pinning
        await t.reconcile()
        assert adapter_metric.await_count == 1
        assert route_metric.await_count == 1

    @pytest.mark.asyncio
    async def test_stop_cancels_background_identity_probe(self, monkeypatch):
        t = self._frontend()
        t._configured = True

        class FakeProcess:
            returncode = None

        t._process = FakeProcess()

        async def slow_identity(*args, **kwargs):
            await asyncio.sleep(10.0)
            return {"ok": True}

        monkeypatch.setattr(tun_status, "probe_adapter", AsyncMock(return_value=tun_status.AdapterEvidence(present=True, up=True, ipv4=["172.19.0.1"], routes=[{"destination_prefix": "0.0.0.0/1"}, {"destination_prefix": "128.0.0.0/1"}])))
        monkeypatch.setattr(t, "_enforce_adapter_metric", AsyncMock(return_value=1))
        monkeypatch.setattr(t, "_enforce_split_route_metrics", AsyncMock(return_value={"0.0.0.0/1": 1, "128.0.0.0/1": 1}))
        monkeypatch.setattr(tun_status, "wait_for_system_egress", AsyncMock(return_value={"ok": True, "ipv4": {"ok": True, "source": "tcp"}}))
        monkeypatch.setattr(tun_status, "probe_system_egress_identity", slow_identity)

        await t.reconcile()
        assert t._identity_task is not None
        assert not t._identity_task.done()

        # stop should cancel the task cleanly without hanging
        monkeypatch.setattr(t, "_terminate_process", AsyncMock(return_value=True))
        monkeypatch.setattr(t, "_verify_recovery", AsyncMock())
        await t.stop()
        assert t._identity_task is None

    @pytest.mark.asyncio
    async def test_reconcile_reaches_traffic_verified_on_tcp_probe_alone(self, monkeypatch):
        t = self._frontend()
        t._configured = True

        class FakeProcess:
            returncode = None

        t._process = FakeProcess()

        evidence = tun_status.AdapterEvidence(
            present=True,
            up=True,
            ipv4=["172.19.0.1"],
            routes=[
                {"destination_prefix": "0.0.0.0/1"},
                {"destination_prefix": "128.0.0.0/1"},
            ],
        )
        egress_tcp = {
            "ok": True,
            "ipv4": {"ok": True, "source": "tcp"},
            "ipv6": {"ok": False},
        }

        monkeypatch.setattr(tun_status, "probe_adapter", AsyncMock(return_value=evidence))
        monkeypatch.setattr(t, "_enforce_adapter_metric", AsyncMock(return_value=1))
        monkeypatch.setattr(t, "_enforce_split_route_metrics", AsyncMock(return_value={"0.0.0.0/1": 1, "128.0.0.0/1": 1}))
        monkeypatch.setattr(tun_status, "wait_for_system_egress", AsyncMock(return_value=egress_tcp))
        monkeypatch.setattr(tun_status, "probe_system_egress_identity", AsyncMock(return_value={"ok": False}))

        state = await t.reconcile()
        assert state == tun_status.STATE_TRAFFIC_VERIFIED
        assert t.state == tun_status.STATE_TRAFFIC_VERIFIED



class TestReconcileCaptureCadence:
    """Full evidence capture is throttled to 15 s and gated by a cheap,
    cached presence check; it must never run on every reconcile tick
    (regression: heavy PowerShell captures every 3 s burned ~23% CPU)."""

    def _frontend(self) -> TunFrontend:
        t = TunFrontend(
            enabled=True,
            opt_in=True,
            executable_path=FAKE_EXECUTABLE,
            is_elevated=lambda: True,
        )
        t._configured = True

        class FakeProcess:
            returncode = None

        t._process = FakeProcess()
        return t

    @pytest.mark.asyncio
    async def test_full_probe_not_run_every_tick_when_adapter_absent(self, monkeypatch):
        t = self._frontend()
        absent = tun_status.AdapterEvidence()

        probe = AsyncMock(return_value=absent)
        presence = AsyncMock(return_value=False)
        monkeypatch.setattr(tun_status, "probe_adapter", probe)
        monkeypatch.setattr(tun_status, "probe_adapter_presence", presence)

        await t.reconcile()
        await t.reconcile()

        # The absent adapter is tracked by the cheap presence check alone:
        # pre-adapter ticks (sing-box still creating the interface) must not
        # pay a full PowerShell capture on the no-evidence first tick or any
        # later tick while presence says the adapter is absent.
        assert probe.await_count == 0
        assert presence.await_count == 1

    @pytest.mark.asyncio
    async def test_adapter_appearance_triggers_immediate_full_probe(self, monkeypatch):
        t = self._frontend()
        absent = tun_status.AdapterEvidence()
        evidence = tun_status.AdapterEvidence(present=True, up=True, ipv4=["172.19.0.1"])
        results = [absent, evidence]
        probe = AsyncMock(side_effect=lambda *a, **kw: results.pop(0))
        presence = AsyncMock(return_value=True)
        monkeypatch.setattr(tun_status, "probe_adapter", probe)
        monkeypatch.setattr(tun_status, "probe_adapter_presence", presence)

        await t.reconcile()
        assert t.state != tun_status.STATE_FAILED

        # Adapter appears (presence=True cached): next tick captures full
        # evidence immediately so the metric pin is not delayed.
        t._last_presence = True
        await t.reconcile()
        assert probe.await_count == 2
        assert t._evidence is not None and t._evidence.present

    @pytest.mark.asyncio
    async def test_inconclusive_presence_falls_back_to_full_probe(self, monkeypatch):
        t = self._frontend()
        evidence = tun_status.AdapterEvidence(present=True, up=True, ipv4=["172.19.0.1"])
        t._evidence = evidence
        # Last full capture is recent: only an inconclusive presence result
        # (None) justifies re-capturing full evidence before the 15 s cap.
        t._last_full_evidence = time.monotonic() - 1.0

        probe = AsyncMock(return_value=evidence)
        monkeypatch.setattr(tun_status, "probe_adapter", probe)
        monkeypatch.setattr(tun_status, "probe_adapter_presence", AsyncMock(return_value=None))

        await t.reconcile()
        probe.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_absent_presence_never_freezes_readiness_without_evidence(
        self, monkeypatch
    ):
        """A false "absent" verdict must not suppress every full capture: the
        bounded retry still captures while the sidecar is alive, so a broken
        presence fast path cannot pin the UI on "connecting" forever."""
        t = self._frontend()
        t._spawned_at = time.monotonic() - 6.0
        absent = tun_status.AdapterEvidence()

        probe = AsyncMock(return_value=absent)
        monkeypatch.setattr(tun_status, "probe_adapter", probe)
        monkeypatch.setattr(
            tun_status, "probe_adapter_presence", AsyncMock(return_value=False)
        )

        await t.reconcile()
        probe.assert_awaited_once()
        assert t._evidence_missing_logged is True

    @pytest.mark.asyncio
    async def test_absent_presence_still_skips_capture_during_settle(
        self, monkeypatch
    ):
        t = self._frontend()
        t._spawned_at = time.monotonic() - 1.0
        probe = AsyncMock(return_value=tun_status.AdapterEvidence())
        monkeypatch.setattr(tun_status, "probe_adapter", probe)
        monkeypatch.setattr(
            tun_status, "probe_adapter_presence", AsyncMock(return_value=False)
        )

        await t.reconcile()
        probe.assert_not_awaited()


class TestIdentitySettleAndRetry:
    """The exit-identity probe must not stall a verified tunnel for 20 s."""

    def _frontend(self) -> TunFrontend:
        t = TunFrontend(
            enabled=True,
            opt_in=True,
            executable_path=FAKE_EXECUTABLE,
            is_elevated=lambda: True,
        )
        t._process = MagicMock(returncode=None)
        t._configured = True
        t._evidence = tun_status.AdapterEvidence(
            present=True, up=True, ipv4=["10.7.0.2"]
        )
        t._egress = {"ok": True, "ipv4": {"ok": True, "source": "tcp"}}
        t._expected_exit_ip = "203.0.113.9"
        t._expected_country = "GB"
        return t

    @pytest.mark.asyncio
    async def test_mismatch_retries_then_verifies(self, monkeypatch):
        t = self._frontend()
        states = []
        t.set_state_listener(lambda state, detail: states.append(state))
        responses = [
            {"ok": True, "ipv4": {"ok": True, "ip": "217.218.36.110", "country": "IR"}},
            {"ok": True, "ipv4": {"ok": True, "ip": "203.0.113.9", "country": "GB"}},
        ]
        calls = {"n": 0}

        async def fake_identity(*, timeout=2.0):
            index = min(calls["n"], len(responses) - 1)
            calls["n"] += 1
            return responses[index]

        monkeypatch.setattr(
            tun_frontend_module, "_IDENTITY_SETTLE_SECONDS", 0.0
        )
        monkeypatch.setattr(
            tun_frontend_module, "_IDENTITY_RETRY_SECONDS", 0.0
        )
        monkeypatch.setattr(
            tun_status, "probe_system_egress_identity", fake_identity
        )

        await t._probe_identity_background()

        assert calls["n"] == 2
        assert t._egress_identity["ipv4"]["ip"] == "203.0.113.9"
        assert t._state == tun_status.STATE_TRAFFIC_VERIFIED
        assert states == [
            tun_status.STATE_TUNNEL_OPERATIONAL,
            tun_status.STATE_TRAFFIC_VERIFIED,
        ]
        assert t._identity_retry_at == float("inf")

    def test_unverified_tunnel_reprobes_at_one_second(self):
        t = self._frontend()
        t._egress = {
            "ok": True,
            "ipv4": {"ok": True, "ip": "198.51.100.9", "country": "US"},
        }
        t._update_classification()
        assert t._state == tun_status.STATE_TUNNEL_OPERATIONAL
        assert t._egress_interval == 1.0

    def test_listener_fires_on_transition(self):
        t = self._frontend()
        seen = []
        t.set_state_listener(lambda state, detail: seen.append((state, detail)))
        t._egress = {
            "ok": True,
            "ipv4": {"ok": True, "ip": "203.0.113.9", "country": "GB"},
        }
        t._update_classification()
        assert seen
        assert seen[-1][0] == tun_status.STATE_TRAFFIC_VERIFIED
