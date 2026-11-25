"""Tests for the frozen (PyInstaller) entry-point dispatch and windowed auth.

These tests use the shipped package identity (``perchvpn_windows``) because
the frozen exe imports exactly that package; patching ``src.perchvpn_windows``
would not affect the code paths exercised here.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from pathlib import Path

import pytest

import perchvpn_windows.cli as cli_identity
import perchvpn_windows.main as main_identity
from perchvpn_windows.main import _dispatch
import perchvpn_windows.webview as webview_identity


class TestEntrypointDispatch:
    def test_version_flag_prints_and_returns_zero(self, capsys):
        assert _dispatch(["--version"]) == 0
        assert capsys.readouterr().out.strip() == "perchvpn 2.0.4"

    def test_help_flag_exits_zero(self):
        # argparse raises SystemExit(0) for -h/--help; the entry must not
        # swallow it, otherwise a --help request from a frozen exe would
        # silently fall through to the GUI.
        with pytest.raises(SystemExit) as excinfo:
            _dispatch(["--help"])
        assert excinfo.value.code == 0

    def test_unknown_flag_exits_two(self):
        with pytest.raises(SystemExit) as excinfo:
            _dispatch(["--definitely-not-a-flag"])
        assert excinfo.value.code == 2

    def test_tun_helper_flag_dispatches_without_cli(self, monkeypatch):
        import perchvpn_windows.tun_helper as helper_module

        calls = []

        def fake_helper_main(spec_path):
            calls.append(spec_path)
            return 7

        monkeypatch.setattr(helper_module, "helper_main", fake_helper_main)
        assert _dispatch(["--tun-helper", r"C:\spec.json"]) == 7
        assert calls == [r"C:\spec.json"]

    def test_tun_helper_equals_form_dispatches(self, monkeypatch):
        import perchvpn_windows.tun_helper as helper_module

        calls = []
        monkeypatch.setattr(
            helper_module, "helper_main", lambda path: calls.append(path) or 0
        )
        assert _dispatch([r"--tun-helper=C:\spec.json"]) == 0
        assert calls == [r"C:\spec.json"]

    def test_package_import_does_not_load_app_stack(self):
        root = Path(__file__).resolve().parents[1]
        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join(
            [str(root / "src"), env.get("PYTHONPATH", "")]
        ).rstrip(os.pathsep)
        code = (
            "import sys, perchvpn_windows; "
            "assert 'perchvpn_windows.app' not in sys.modules, 'app imported'; "
            "assert 'perchvpn.controller' not in sys.modules, 'controller imported'"
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            env=env,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr

    def test_no_args_runs_webview_and_propagates_exit_code(self, monkeypatch):
        received = {}

        def fake_launch_webview():
            received["called"] = True
            return 42

        monkeypatch.setattr(webview_identity, "launch_webview", fake_launch_webview)
        assert _dispatch([]) == 42
        assert received["called"] is True

    def test_no_args_does_not_start_a_second_instance(self, monkeypatch):
        import perchvpn_windows.instance_guard as guard

        monkeypatch.setattr(guard, "acquire", lambda: False)
        monkeypatch.setattr(
            webview_identity,
            "launch_webview",
            lambda: (_ for _ in ()).throw(AssertionError("must not launch")),
        )
        assert _dispatch([]) == 0


class TestWindowedAuthFlow:
    def _frozen_env(self, monkeypatch):
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr(webview_identity, "_has_valid_token", lambda: False)

    def test_frozen_auth_success_schedules_token_wait(self, monkeypatch):
        self._frozen_env(monkeypatch)
        calls = []

        async def fake_auth_only():
            calls.append("auth")
            return 0

        monkeypatch.setattr(cli_identity, "_run_auth_only", fake_auth_only)
        monkeypatch.setattr(webview_identity, "_wait_for_token_ready", lambda timeout=None: calls.append("wait") or True)
        stdin_before, stdout_before = sys.stdin, sys.stdout

        assert webview_identity._run_auth_flow() is True
        assert calls == ["auth", "wait"]
        assert sys.stdin is stdin_before and sys.stdout is stdout_before

    def test_frozen_auth_failure_returns_false_without_token_wait(self, monkeypatch):
        self._frozen_env(monkeypatch)
        calls = []

        async def fake_auth_only():
            return 5

        monkeypatch.setattr(cli_identity, "_run_auth_only", fake_auth_only)
        monkeypatch.setattr(
            webview_identity, "_wait_for_token_ready",
            lambda timeout=None: calls.append("wait") or True,
        )

        assert webview_identity._run_auth_flow() is False
        assert calls == []

    def test_console_helper_is_noop_outside_win32(self, monkeypatch):
        original = (sys.stdin, sys.stdout, sys.stderr)
        assert webview_identity._ensure_interactive_console() is None
        webview_identity._restore_streams(None)
        assert (sys.stdin, sys.stdout, sys.stderr) == original
