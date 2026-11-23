"""Tests for durable startup diagnostics and the single-instance guard.

The windowed build has no console: an unlogged startup failure used to exit
the process with no window, no dialog and no trace.  These tests pin the
crash-log path, the exception hooks, the helper-mode dialog suppression and
the ctypes last-error handling of the mutex probe.
"""

from __future__ import annotations

import ctypes
import sys
import types

import pytest

from perchvpn_windows import instance_guard, startup_diagnostics


class TestCrashLog:
    def test_crash_log_path_is_timestamped_under_perchvpn(self, monkeypatch, tmp_path):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        path = startup_diagnostics.crash_log_path()
        assert path.parent == tmp_path / "PerchVPN"
        assert path.name.startswith("crash-")
        assert path.suffix == ".log"

    def test_append_crash_log_writes_file(self, monkeypatch, tmp_path):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        path = startup_diagnostics.append_crash_log("boom")
        assert path is not None
        assert "boom" in path.read_text(encoding="utf-8")

    def test_report_startup_failure_returns_crash_file(self, monkeypatch, tmp_path):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        shown: list[str] = []
        monkeypatch.setattr(
            startup_diagnostics, "show_error_dialog", lambda text: shown.append(text)
        )
        path = startup_diagnostics.report_startup_failure(
            "cannot start", "port busy", hint="close it"
        )
        assert path.name.startswith("crash-")
        assert "port busy" in path.read_text(encoding="utf-8")
        assert shown and "close it" in shown[0]

    def test_message_box_is_suppressed_for_tun_helper(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["PerchVPN.exe", "--tun-helper", "spec.json"])
        monkeypatch.setattr(sys, "platform", "win32")
        assert startup_diagnostics._message_box("x") is False


class TestExceptionHooks:
    def test_install_excepthook_is_idempotent(self, monkeypatch, tmp_path):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        monkeypatch.setattr(sys, "excepthook", sys.__excepthook__)
        monkeypatch.setattr(sys, "__excepthook__", sys.__excepthook__)
        import threading

        monkeypatch.setattr(threading, "excepthook", threading.__excepthook__)

        startup_diagnostics.install_excepthook()
        first = sys.excepthook
        startup_diagnostics.install_excepthook()

        assert sys.excepthook is first
        assert getattr(sys.excepthook, "_perchvpn_startup_hook", False) is True
        assert getattr(threading.excepthook, "_perchvpn_startup_hook", False) is True

    def test_install_startup_logging_enables_faulthandler(self, monkeypatch, tmp_path):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        monkeypatch.setattr(startup_diagnostics, "_installed", False)
        monkeypatch.setattr(startup_diagnostics, "_log_path", None)
        path = startup_diagnostics.install_startup_logging()
        assert path.parent == tmp_path / "PerchVPN"
        assert (tmp_path / "PerchVPN" / "faulthandler.log").exists()


class _FakeFunction:
    def __init__(self, result):
        self.result = result
        self.calls: list[tuple] = []
        self.restype = None
        self.argtypes = None

    def __call__(self, *args):
        self.calls.append(args)
        return self.result


class _FakeKernel32:
    def __init__(self, handle=0x1234):
        self.CreateMutexW = _FakeFunction(handle)
        self.CloseHandle = _FakeFunction(True)


def _wire_mutex(monkeypatch, *, handle, last_error):
    fake = _FakeKernel32(handle=handle)
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(instance_guard, "_handle", None)
    monkeypatch.setattr(ctypes, "WinDLL", lambda *a, **k: fake, raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: last_error, raising=False)
    return fake


class TestInstanceGuard:
    def test_already_exists_uses_ctypes_last_error(self, monkeypatch):
        fake = _wire_mutex(monkeypatch, handle=0x1234, last_error=183)
        assert instance_guard.acquire() is False
        assert instance_guard._handle is None
        assert fake.CloseHandle.calls == [(0x1234,)]

    def test_fresh_mutex_is_acquired(self, monkeypatch):
        _wire_mutex(monkeypatch, handle=0x1234, last_error=0)
        assert instance_guard.acquire() is True
        assert instance_guard._handle == 0x1234

    def test_uses_win_dll_with_use_last_error(self, monkeypatch):
        seen: dict[str, object] = {}

        def fake_windll(name, **kwargs):
            seen["name"] = name
            seen["kwargs"] = kwargs
            return _FakeKernel32()

        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.setattr(instance_guard, "_handle", None)
        monkeypatch.setattr(ctypes, "WinDLL", fake_windll, raising=False)
        monkeypatch.setattr(ctypes, "get_last_error", lambda: 0, raising=False)

        assert instance_guard.acquire() is True
        assert seen["name"] == "kernel32"
        assert seen["kwargs"] == {"use_last_error": True}
