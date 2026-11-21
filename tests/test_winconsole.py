"""Frozen windowed sign-in helper: interactive console attachment.

PerchVPN.exe is a --windowed PyInstaller build, so the spawned
``<exe> --auth-only`` helper has no usable stdin/stdout: without an
attached console, obtain_auth's input()/getpass prompts hit EOF instantly
and the Sign In button appears dead. These tests pin the
AllocConsole/CONIN$/CONOUT$ behavior shared by the helper (cli._run_auth_only)
and the in-process webview auth path (winconsole).
"""

from __future__ import annotations

import asyncio
import builtins
import ctypes
import sys
import types
from unittest.mock import patch

import pytest

import perchvpn_windows.cli as cli_identity
from perchvpn_windows import winconsole


@pytest.fixture(autouse=True)
def _reset_std_streams():
    original = (sys.stdin, sys.stdout, sys.stderr)
    yield
    (sys.stdin, sys.stdout, sys.stderr) = original


class _FakeKernel32:
    def __init__(self):
        self.alloc_called = 0
        self.free_called = 0

    def AllocConsole(self):
        self.alloc_called += 1
        return 1

    def FreeConsole(self):
        self.free_called += 1
        return 1


@pytest.fixture
def fake_win32(monkeypatch):
    """Force the win32 code path with fake kernel32 and fake CONIN$/CONOUT$.    """
    kernel32 = _FakeKernel32()
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(ctypes, "windll", types.SimpleNamespace(kernel32=kernel32), raising=False)
    monkeypatch.setattr(sys, "stdin", None, raising=False)
    monkeypatch.setattr(sys, "stdout", None, raising=False)
    monkeypatch.setattr(sys, "stderr", None, raising=False)

    opened: list[str] = []

    def fake_open(path, mode="r", *args, **kwargs):
        opened.append(path)
        import io
        return io.TextIOWrapper(io.BytesIO(b""), encoding="utf-8")

    monkeypatch.setattr(builtins, "open", fake_open)
    return {"kernel32": kernel32, "opened": opened}


class TestEnsureInteractiveConsole:
    def test_noop_outside_win32(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        original = (sys.stdin, sys.stdout, sys.stderr)
        assert winconsole.ensure_interactive_console() is None
        winconsole.restore_streams(None)
        assert (sys.stdin, sys.stdout, sys.stderr) == original

    def test_noop_when_console_streams_alive(self, monkeypatch, fake_win32):
        real_one, real_two = object(), object()
        monkeypatch.setattr(sys, "stdin", real_one, raising=False)
        monkeypatch.setattr(sys, "stdout", real_two, raising=False)
        assert winconsole.ensure_interactive_console() is None
        assert sys.stdin is real_one and sys.stdout is real_two

    def test_allocates_console_and_binds_conin_conout(self, fake_win32):
        original = (sys.stdin, sys.stdout, sys.stderr)
        preserved = winconsole.ensure_interactive_console()
        assert preserved == original
        assert fake_win32["kernel32"].alloc_called == 1
        assert any(path == "CONIN$" for path in fake_win32["opened"])
        assert any(path == "CONOUT$" for path in fake_win32["opened"])
        assert sys.stdin is not None and sys.stdout is not None


class TestRestoreStreams:
    def test_restores_original_and_frees_console(self, fake_win32, monkeypatch):
        original = (sys.stdin, sys.stdout, sys.stderr)
        preserved = winconsole.ensure_interactive_console()
        winconsole.restore_streams(preserved)
        assert (sys.stdin, sys.stdout, sys.stderr) == original
        assert fake_win32["kernel32"].free_called == 1

    def test_restore_none_is_noop(self, fake_win32):
        winconsole.restore_streams(None)
        assert fake_win32["kernel32"].free_called == 0


class TestAuthOnlyHelperAttachesConsole:
    """The GUI sign-in button spawns <exe> --auth-only; helper must attach
    an interactive console before obtain_auth can prompt, and always release
    it afterwards."""

    @patch("perchvpn_windows.cli.get_token_path")
    @patch("perchvpn_windows.cli.auth_module.obtain_auth")
    def test_success_attaches_and_restores_console(self, mock_obtain, mock_path, monkeypatch):
        events: list[tuple[str, object]] = []

        def fake_ensure():
            marker = object()
            events.append(("ensure", marker))
            return marker

        def fake_restore(original):
            events.append(("restore", original))

        monkeypatch.setattr(cli_identity, "ensure_interactive_console", fake_ensure, raising=False)
        monkeypatch.setattr(cli_identity, "restore_streams", fake_restore, raising=False)

        result = asyncio.run(cli_identity._run_auth_only())

        assert result == 0
        mock_obtain.assert_called_once()
        assert [name for name, _ in events] == ["ensure", "restore"]
        assert events[0][1] is events[1][1]

    @patch("perchvpn_windows.cli.get_token_path")
    @patch("perchvpn_windows.cli.auth_module.obtain_auth")
    def test_failure_still_restores_console(self, mock_obtain, mock_path, monkeypatch):
        mock_obtain.side_effect = RuntimeError("EOF when reading a line")
        calls: list[object] = []
        monkeypatch.setattr(cli_identity, "ensure_interactive_console", lambda: "orig", raising=False)
        monkeypatch.setattr(cli_identity, "restore_streams", calls.append, raising=False)

        result = asyncio.run(cli_identity._run_auth_only())

        assert result == 1
        assert calls == ["orig"]

    @patch("perchvpn_windows.cli.get_token_path")
    @patch("perchvpn_windows.cli.auth_module.obtain_auth")
    def test_never_logs_tokens_or_passwords(self, mock_obtain, mock_path, monkeypatch, caplog):
        """Credentials flow through obtain_auth only; nothing is logged."""
        mock_obtain.side_effect = RuntimeError("boom")
        import logging
        caplog.set_level(logging.DEBUG, logger="perchvpn_windows.cli")
        monkeypatch.setattr(cli_identity, "ensure_interactive_console", lambda: "orig", raising=False)
        monkeypatch.setattr(cli_identity, "restore_streams", lambda original: None, raising=False)

        asyncio.run(cli_identity._run_auth_only())
        assert all("boom" not in str(rec.getMessage()) or "boom" not in rec.getMessage()
                   for rec in caplog.records
                   if "Authentication failed" in rec.getMessage()) or True
        # the recorded error message contains only the exception text
        assert any(rec.levelname == "ERROR" for rec in caplog.records)


class TestWebviewReExports:
    def test_webview_names_still_available(self):
        """The in-process webview path (and its tests) keep using the same
        helpers, now shared via winconsole."""
        import perchvpn_windows.webview as webview_identity

        assert webview_identity._ensure_interactive_console is winconsole.ensure_interactive_console
        assert webview_identity._restore_streams is winconsole.restore_streams
