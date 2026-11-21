"""Focused graceful-shutdown and ownership-safety tests (no live TUN)."""

from __future__ import annotations

import asyncio
import json
import sys
import pytest

import src.perchvpn_windows.tun_frontend as tun_module
from src.perchvpn_windows.tun_frontend import TunFrontend
from src.perchvpn_windows.tun_state_capture import NetworkSnapshot
from src.perchvpn_windows.tun_recovery import (
    CLEAN,
    DEFAULT_ADAPTER_GUID,
    DEFAULT_ADAPTER_NAME,
    RECOVERY_UNVERIFIED,
    TunRecoveryGate,
)

# Parent sends CTRL_BREAK_EVENT; the child handler observes SIGBREAK (21).
_WINDOWS_CTRL_BREAK_EVENT = 1


def _identity() -> dict:
    return {
        "path": "/fake/tun2proxy.exe",
        "size": 11,
        "mtime_ns": 22,
        "sha256": "sha-current",
    }


def _snapshot_dict() -> dict:
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


def _snapshot_capture_of(snapshot_dict: dict):
    return lambda: NetworkSnapshot.from_dict(snapshot_dict)


def _valid_snapshot_capture():
    return _snapshot_capture_of(_snapshot_dict())


@pytest.fixture(autouse=True)
def _fake_frontend_ps(monkeypatch):
    """The frontend no longer executes PowerShell directly; baseline
    restoration (+ verification) lives in TunRecoveryGate."""
    return


def _frontend(**kwargs) -> TunFrontend:
    extra_args = kwargs.pop(
        "extra_args", ["--tun", "wintun", "--verbosity", "debug"]
    )
    recovery_gate = kwargs.pop(
        "recovery_gate", TunRecoveryGate(enabled=False)
    )
    return TunFrontend(
        enabled=True,
        opt_in=True,
        executable_path=sys.executable,
        proxy_host="127.0.0.1",
        proxy_port=11080,
        mtu=1400,
        extra_args=extra_args,
        is_elevated=lambda: True,
        recovery_gate=recovery_gate,
        **kwargs,
    )


class _ExitedProcess:
    pid = 4242
    returncode = 0
    stdout = None
    stderr = None

    async def wait(self) -> int:
        return self.returncode


class _GracefulProcess:
    def __init__(self, *, exit_on_signal: bool = True) -> None:
        self.pid = 4242
        self.returncode = None
        self.stdout = None
        self.stderr = None
        self.signals: list[int] = []
        self.terminated = False
        self.killed = False
        self._done = asyncio.Event()
        self._exit_on_signal = exit_on_signal

    def send_signal(self, sig: int) -> None:
        self.signals.append(sig)
        if self._exit_on_signal:
            self.returncode = 0
            self._done.set()

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = -15
        self._done.set()

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9
        self._done.set()

    async def wait(self) -> int:
        await self._done.wait()
        return self.returncode


class _BlockingProcess:
    pid = 4242
    returncode = None
    stdout = None
    stderr = None

    def __init__(self) -> None:
        self.signals: list[int] = []
        self.terminated = False
        self.killed = False
        self._done = asyncio.Event()

    def send_signal(self, sig: int) -> None:
        self.signals.append(sig)

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True

    async def wait(self) -> int:
        await self._done.wait()
        return self.returncode

    def finish(self, code: int = 0) -> None:
        self.returncode = code
        self._done.set()


class _TerminateErrorProcess(_BlockingProcess):
    def terminate(self) -> None:
        raise OSError("terminate denied")


def _recovery_gate_and_run(tmp_path, present: dict):
    async def _no_sleep(seconds: float) -> None:
        return None

    gate = TunRecoveryGate(
        enabled=True,
        state_path=tmp_path / "tun-ownership.json",
        adapter_probe=lambda guid, name: present["value"],
        creation_time_probe=lambda pid: 100.0,
        identity_probe=lambda path: _identity(),
        snapshot_capture=_valid_snapshot_capture(),
        window_seconds=0.01,
        sleep=_no_sleep,
    )
    run = gate.pre_start("/fake/tun2proxy.exe")
    gate.mark_running(run, 4242, 100.0)
    return gate, run


@pytest.fixture(autouse=True)
def _windows_ctrl_break(monkeypatch):
    monkeypatch.setattr(
        tun_module, "_CTRL_BREAK_EVENT", _WINDOWS_CTRL_BREAK_EVENT, raising=False
    )


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal path")
@pytest.mark.asyncio
async def test_posix_graceful_stop_really_sends_sigint():
    code = (
        "import signal,sys,time\n"
        "signal.signal(signal.SIGINT, lambda *a: sys.exit(0))\n"
        "time.sleep(30)\n"
    )
    frontend = _frontend(graceful_stop=True, extra_args=["-c", code])
    await frontend.start()
    assert frontend.status == "running"
    await asyncio.sleep(0.4)
    assert await frontend.stop_graceful(timeout=3.0) is True
    assert frontend.status == "stopped"
    assert frontend._process is None


@pytest.mark.asyncio
async def test_windows_graceful_stop_sends_ctrl_break_without_kill(monkeypatch):
    monkeypatch.setattr(tun_module.sys, "platform", "win32")
    proc = _GracefulProcess()
    frontend = _frontend(graceful_stop=True)
    frontend._process = proc
    frontend._status = "running"

    assert await frontend.stop_graceful(timeout=1.0) is True
    assert proc.signals == [_WINDOWS_CTRL_BREAK_EVENT]
    assert proc.terminated is False
    assert proc.killed is False
    assert frontend._process is None
    assert frontend.status == "stopped"


@pytest.mark.asyncio
async def test_graceful_timeout_escalates_to_terminate(monkeypatch):
    """A sidecar that ignores CTRL_BREAK is terminated after the bounded
    graceful window: live measurement showed the multiplex-pool drain takes
    ~5-6s, which dominated the whole disconnect. The recovery gate restores
    the route/adapter baseline after the instant kill (sandbox-verified)."""
    monkeypatch.setattr(tun_module.sys, "platform", "win32")
    proc = _GracefulProcess(exit_on_signal=False)
    frontend = _frontend(graceful_stop=True)
    frontend._process = proc
    frontend._status = "running"

    assert await frontend.stop_graceful(timeout=0.05) is True
    assert proc.signals == [_WINDOWS_CTRL_BREAK_EVENT]
    assert proc.terminated is True
    assert proc.killed is False
    assert frontend._process is None
    assert frontend.status == "stopped"


@pytest.mark.asyncio
async def test_monitor_reconciles_late_timeout_exit_when_adapter_cleared(tmp_path):
    present = {"value": False}

    async def _no_sleep(seconds: float) -> None:
        return None

    gate = TunRecoveryGate(
        enabled=True,
        state_path=tmp_path / "tun-ownership.json",
        adapter_probe=lambda guid, name: present["value"],
        creation_time_probe=lambda pid: 100.0,
        identity_probe=lambda path: _identity(),
        snapshot_capture=_valid_snapshot_capture(),
        window_seconds=0.01,
        sleep=_no_sleep,
    )
    run = gate.pre_start("/fake/tun2proxy.exe")
    gate.mark_running(run, 4242, 100.0)
    frontend = _frontend(graceful_stop=True, recovery_gate=gate)
    frontend._process = _ExitedProcess()
    frontend._recovery_run = run
    frontend._spawn_confirmed = True
    frontend._stopping = True
    frontend._status = "stop_timeout"
    frontend._recovery_state = RECOVERY_UNVERIFIED

    await frontend._monitor()

    assert frontend.recovery_state == CLEAN
    assert frontend.status == "stop_timeout"
    assert frontend._process is not None
    assert not (tmp_path / "tun-ownership.json").exists()


@pytest.mark.asyncio
async def test_monitor_keeps_unverified_record_when_adapter_survives_timeout(tmp_path):
    present = {"value": False}

    async def _no_sleep(seconds: float) -> None:
        return None

    gate = TunRecoveryGate(
        enabled=True,
        state_path=tmp_path / "tun-ownership.json",
        adapter_probe=lambda guid, name: present["value"],
        creation_time_probe=lambda pid: 100.0,
        identity_probe=lambda path: _identity(),
        snapshot_capture=_valid_snapshot_capture(),
        window_seconds=0.01,
        sleep=_no_sleep,
    )
    run = gate.pre_start("/fake/tun2proxy.exe")
    gate.mark_running(run, 4242, 100.0)
    present["value"] = True
    frontend = _frontend(graceful_stop=True, recovery_gate=gate)
    frontend._process = _ExitedProcess()
    frontend._recovery_run = run
    frontend._spawn_confirmed = True
    frontend._stopping = True
    frontend._status = "stop_timeout"
    frontend._recovery_state = RECOVERY_UNVERIFIED

    await frontend._monitor()

    assert frontend.recovery_state == RECOVERY_UNVERIFIED
    assert frontend.status == RECOVERY_UNVERIFIED
    assert frontend._process is not None
    record = json.loads((tmp_path / "tun-ownership.json").read_text())
    assert record["state"] == "unverified"


@pytest.mark.asyncio
async def test_graceful_signal_failure_does_not_force_kill(monkeypatch):
    monkeypatch.setattr(tun_module.sys, "platform", "win32")

    class _NoConsoleProcess(_GracefulProcess):
        def send_signal(self, sig: int) -> None:
            self.signals.append(sig)
            raise OSError("no console")

    proc = _NoConsoleProcess()
    frontend = _frontend(graceful_stop=True)
    frontend._process = proc
    frontend._status = "running"

    assert await frontend.stop_graceful(timeout=0.1) is False
    assert proc.terminated is False
    assert proc.killed is False
    assert frontend._process is proc
    assert frontend.status == "stop_failed"
    assert frontend.recovery_state == RECOVERY_UNVERIFIED


@pytest.mark.asyncio
async def test_stop_graceful_cancellation_reconciles_late_exit(tmp_path, monkeypatch):
    present = {"value": False}
    gate, run = _recovery_gate_and_run(tmp_path, present)
    proc = _BlockingProcess()
    frontend = _frontend(graceful_stop=True, recovery_gate=gate)
    monkeypatch.setattr(
        frontend,
        "_send_graceful_shutdown",
        lambda p: p.send_signal(_WINDOWS_CTRL_BREAK_EVENT),
    )
    frontend._process = proc
    frontend._recovery_run = run
    frontend._spawn_confirmed = True
    frontend._status = "running"
    frontend._monitor_task = asyncio.create_task(frontend._monitor())
    await asyncio.sleep(0)

    stop_task = asyncio.create_task(frontend.stop_graceful(timeout=30.0))
    await asyncio.sleep(0.05)
    stop_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await stop_task

    assert proc.signals == [_WINDOWS_CTRL_BREAK_EVENT]
    assert frontend._process is proc
    assert frontend.status == "stop_failed"
    assert frontend.recovery_state == RECOVERY_UNVERIFIED

    proc.finish(0)
    await asyncio.wait_for(frontend._monitor_task, timeout=1.0)

    assert frontend.status == "stop_failed"
    assert frontend.recovery_state == CLEAN
    assert not (tmp_path / "tun-ownership.json").exists()


@pytest.mark.asyncio
async def test_stop_cancellation_reconciles_late_exit(tmp_path):
    present = {"value": False}
    gate, run = _recovery_gate_and_run(tmp_path, present)
    proc = _BlockingProcess()
    frontend = _frontend(recovery_gate=gate)
    frontend._process = proc
    frontend._recovery_run = run
    frontend._spawn_confirmed = True
    frontend._status = "running"
    frontend._monitor_task = asyncio.create_task(frontend._monitor())
    await asyncio.sleep(0)

    stop_task = asyncio.create_task(frontend.stop())
    await asyncio.sleep(0.05)
    stop_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await stop_task

    assert proc.terminated is True
    assert frontend._process is proc
    assert frontend.status == "stop_failed"
    assert frontend.recovery_state == RECOVERY_UNVERIFIED

    proc.finish(0)
    await asyncio.wait_for(frontend._monitor_task, timeout=1.0)

    assert frontend.status == "stop_failed"
    assert frontend.recovery_state == CLEAN
    assert not (tmp_path / "tun-ownership.json").exists()


@pytest.mark.asyncio
async def test_stop_termination_error_reconciles_late_exit(tmp_path):
    present = {"value": False}
    gate, run = _recovery_gate_and_run(tmp_path, present)
    proc = _TerminateErrorProcess()
    frontend = _frontend(recovery_gate=gate)
    frontend._process = proc
    frontend._recovery_run = run
    frontend._spawn_confirmed = True
    frontend._status = "running"
    frontend._monitor_task = asyncio.create_task(frontend._monitor())
    await asyncio.sleep(0)

    assert await frontend.stop() is False
    assert proc.terminated is False
    assert frontend._process is proc
    assert frontend.status == "stop_failed"
    assert frontend.recovery_state == RECOVERY_UNVERIFIED

    proc.finish(0)
    await asyncio.wait_for(frontend._monitor_task, timeout=1.0)

    assert frontend.status == "stop_failed"
    assert frontend.recovery_state == CLEAN
    assert not (tmp_path / "tun-ownership.json").exists()


@pytest.mark.asyncio
async def test_graceful_stop_requires_opt_in():
    frontend = _frontend()
    frontend._process = _GracefulProcess()
    with pytest.raises(RuntimeError, match="graceful_stop=True"):
        await frontend.stop_graceful(timeout=1.0)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX session path")
@pytest.mark.asyncio
async def test_start_uses_posix_session_when_graceful(monkeypatch):
    captured: dict = {}
    proc = _GracefulProcess()

    async def fake_spawn(*args, **kwargs):
        captured.update(kwargs)
        return proc

    monkeypatch.setattr(
        tun_module.asyncio, "create_subprocess_exec", fake_spawn
    )
    frontend = _frontend(graceful_stop=True)
    await frontend.start()
    try:
        assert captured.get("start_new_session") is True
        assert "creationflags" not in captured
    finally:
        await frontend.stop_graceful(timeout=1.0)


@pytest.mark.asyncio
async def test_start_uses_windows_process_group_when_graceful(monkeypatch):
    captured: dict = {}
    proc = _GracefulProcess()

    async def fake_spawn(*args, **kwargs):
        captured.update(kwargs)
        return proc

    monkeypatch.setattr(tun_module.sys, "platform", "win32")
    monkeypatch.setattr(tun_module, "_CREATE_NEW_PROCESS_GROUP", 0x200)
    monkeypatch.setattr(
        tun_module.asyncio, "create_subprocess_exec", fake_spawn
    )
    frontend = _frontend(graceful_stop=True)
    monkeypatch.setattr(frontend, "_resolve_executable", lambda: sys.executable)

    await frontend.start()
    try:
        flags = captured.get("creationflags") or 0
        # Process-group flag for graceful CTRL_BREAK delivery must be present,
        # and the sidecar console stays hidden (CREATE_NO_WINDOW).
        assert flags & 0x200 == 0x200
        assert flags & getattr(tun_module, "_CREATE_NO_WINDOW", 0x08000000) == 0x08000000
        assert "start_new_session" not in captured
    finally:
        await frontend.stop_graceful(timeout=1.0)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal path")
@pytest.mark.asyncio
async def test_surviving_adapter_after_graceful_stop_is_unverified(tmp_path):
    code = (
        "import signal,sys,time\n"
        "signal.signal(signal.SIGINT, lambda *a: sys.exit(0))\n"
        "time.sleep(30)\n"
    )
    present = {"value": False}
    gate = TunRecoveryGate(
        enabled=True,
        state_path=tmp_path / "tun-ownership.json",
        adapter_probe=lambda guid, name: present["value"],
        identity_probe=lambda path: _identity(),
        snapshot_capture=_valid_snapshot_capture(),
        window_seconds=0.01,
    )
    frontend = _frontend(
        graceful_stop=True, recovery_gate=gate, extra_args=["-c", code]
    )

    await frontend.start()
    assert frontend.status == "running"
    present["value"] = True

    assert await frontend.stop_graceful(timeout=3.0) is False
    assert frontend.recovery_state == RECOVERY_UNVERIFIED
    assert frontend._process is None
    record = json.loads((tmp_path / "tun-ownership.json").read_text())
    assert record["state"] == "unverified"


def test_pre_start_records_owned_adapter_without_deletion(tmp_path, monkeypatch):
    killed: list[tuple[int, int]] = []
    monkeypatch.setattr("os.kill", lambda pid, sig: killed.append((pid, sig)))

    gate = TunRecoveryGate(
        enabled=True,
        state_path=tmp_path / "tun-ownership.json",
        adapter_probe=lambda guid, name: False,
        creation_time_probe=lambda pid: 100.0,
        identity_probe=lambda path: _identity(),
        snapshot_capture=_valid_snapshot_capture(),
    )
    run = gate.pre_start("/fake/tun2proxy.exe")
    record = json.loads((tmp_path / "tun-ownership.json").read_text())

    assert run.enabled is True
    assert record["adapter_guid"] == DEFAULT_ADAPTER_GUID
    assert record["adapter_name"] == DEFAULT_ADAPTER_NAME
    assert record["pre_start_present"] is False
    assert record["state"] == "prepared"
    assert killed == []
