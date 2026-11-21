"""Regression tests for hidden Windows background process launches."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from perchvpn_windows import tun_helper, win_process


class _FakeStartupInfo:
    def __init__(self) -> None:
        self.dwFlags = 0
        self.wShowWindow = None


@pytest.fixture
def windows_startupinfo(monkeypatch):
    monkeypatch.setattr(
        win_process.subprocess, "STARTUPINFO", _FakeStartupInfo, raising=False
    )
    monkeypatch.setattr(win_process.sys, "platform", "win32")


def test_hidden_startupinfo_requests_sw_hide(windows_startupinfo):
    info = win_process.hidden_startupinfo()
    assert info is not None
    assert info.dwFlags & win_process.STARTF_USESHOWWINDOW
    assert info.wShowWindow == win_process.SW_HIDE


def test_hidden_process_kwargs_adds_no_window_and_process_group(windows_startupinfo):
    kwargs = win_process.hidden_process_kwargs(new_process_group=True)
    assert kwargs["creationflags"] == (
        win_process.CREATE_NO_WINDOW | win_process.CREATE_NEW_PROCESS_GROUP
    )
    assert kwargs["startupinfo"].wShowWindow == win_process.SW_HIDE


def test_run_hidden_forwards_hidden_launch_parameters(windows_startupinfo, monkeypatch):
    captured = {}

    def fake_run(args, **kwargs):
        captured["args"] = args
        captured.update(kwargs)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(win_process.subprocess, "run", fake_run)
    result = win_process.run_hidden(["taskkill", "/PID", "123"], capture_output=True)

    assert result.returncode == 0
    assert captured["args"] == ["taskkill", "/PID", "123"]
    assert captured["creationflags"] & win_process.CREATE_NO_WINDOW
    assert captured["startupinfo"].wShowWindow == win_process.SW_HIDE


def test_popen_hidden_forwards_hidden_launch_parameters(windows_startupinfo, monkeypatch):
    captured = {}

    def fake_popen(args, **kwargs):
        captured["args"] = args
        captured.update(kwargs)
        return SimpleNamespace(pid=1)

    monkeypatch.setattr(win_process.subprocess, "Popen", fake_popen)
    proc = win_process.popen_hidden(["sing-box.exe"], new_process_group=True)

    assert proc.pid == 1
    assert captured["args"] == ["sing-box.exe"]
    assert captured["creationflags"] & win_process.CREATE_NO_WINDOW
    assert captured["creationflags"] & win_process.CREATE_NEW_PROCESS_GROUP
    assert captured["startupinfo"].wShowWindow == win_process.SW_HIDE


def test_powershell_argv_is_non_interactive_and_hidden():
    argv = win_process.powershell_argv("Get-Date")
    assert argv[0] == "powershell.exe"
    assert "-NoProfile" in argv
    assert "-NonInteractive" in argv
    assert argv[argv.index("-WindowStyle") + 1] == "Hidden"
    assert argv[-2:] == ["-Command", "Get-Date"]


def test_terminate_pid_uses_hidden_taskkill(monkeypatch):
    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(tun_helper.sys, "platform", "win32")
    monkeypatch.setattr(tun_helper, "run_hidden", fake_run)

    assert tun_helper.terminate_pid(1234)
    assert calls[0][0] == ["taskkill", "/F", "/PID", "1234"]


def test_stale_wintun_removal_uses_hidden_pnputil(monkeypatch):
    scans = iter([["SWD\\WINTUN\\{AAAA}"], []])
    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(tun_helper.sys, "platform", "win32")
    monkeypatch.setattr(tun_helper, "_native_stale_wintun_devices", lambda: next(scans))
    monkeypatch.setattr(tun_helper, "run_hidden", fake_run)

    result = tun_helper.cleanup_stale_wintun_adapters("PerchVPN")
    assert result == {"removed": ["SWD\\WINTUN\\{AAAA}"], "remaining": 0}
    assert calls[0][0] == ["pnputil.exe", "/remove-device", "SWD\\WINTUN\\{AAAA}"]
