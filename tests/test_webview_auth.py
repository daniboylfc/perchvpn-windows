"""Unit tests for WebView authentication flow."""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from src.perchvpn_windows.webview import (
    _get_token_path,
    _has_valid_token,
    _run_auth_flow,
    _spawn_auth_helper,
    _wait_for_token_ready,
)


class TestWebViewAuthFlow:
    @patch("src.perchvpn_windows.webview._get_token_path")
    def test_has_valid_token_returns_false_when_file_missing(self, mock_path: Mock):
        """_has_valid_token returns False when token file doesn't exist."""
        mock_path.return_value = Path("/nonexistent/tokens.json")
        result = _has_valid_token()
        assert result is False

    @patch("src.perchvpn_windows.webview._get_token_path")
    def test_has_valid_token_returns_false_when_missing_access_token(self, mock_path: Mock, tmp_path: Path):
        """_has_valid_token returns False when access_token is missing."""
        token_file = tmp_path / "tokens.json"
        token_file.write_text(json.dumps({"refresh_token": "test", "expires_in": 3600, "obtained_at": time.time()}))
        mock_path.return_value = token_file
        result = _has_valid_token()
        assert result is False

    @patch("src.perchvpn_windows.webview._get_token_path")
    def test_has_valid_token_returns_false_when_expired(self, mock_path: Mock, tmp_path: Path):
        """_has_valid_token returns False when token is expired."""
        token_file = tmp_path / "tokens.json"
        token_file.write_text(json.dumps({
            "access_token": "test",
            "expires_in": 3600,
            "obtained_at": time.time() - 7200  # 2 hours ago, expired
        }))
        mock_path.return_value = token_file
        result = _has_valid_token()
        assert result is False

    @patch("src.perchvpn_windows.webview._get_token_path")
    def test_has_valid_token_returns_true_when_valid(self, mock_path: Mock, tmp_path: Path):
        """_has_valid_token returns True when token is valid."""
        token_file = tmp_path / "tokens.json"
        token_file.write_text(json.dumps({
            "access_token": "test",
            "expires_in": 3600,
            "obtained_at": time.time()
        }))
        mock_path.return_value = token_file
        result = _has_valid_token()
        assert result is True

    @patch("src.perchvpn_windows.webview._get_token_path")
    def test_has_valid_token_handles_malformed_json(self, mock_path: Mock, tmp_path: Path):
        """_has_valid_token handles malformed JSON gracefully."""
        token_file = tmp_path / "tokens.json"
        token_file.write_text("{ invalid json }")
        mock_path.return_value = token_file
        result = _has_valid_token()
        assert result is False

    @patch("src.perchvpn_windows.webview._get_token_path")
    def test_has_valid_token_handles_missing_expires_in(self, mock_path: Mock, tmp_path: Path):
        """_has_valid_token returns False when expires_in is missing."""
        token_file = tmp_path / "tokens.json"
        token_file.write_text(json.dumps({"access_token": "test", "obtained_at": time.time()}))
        mock_path.return_value = token_file
        result = _has_valid_token()
        assert result is False

    @patch("src.perchvpn_windows.webview._get_token_path")
    def test_has_valid_token_handles_zero_expires_in(self, mock_path: Mock, tmp_path: Path):
        """_has_valid_token returns False when expires_in is zero."""
        token_file = tmp_path / "tokens.json"
        token_file.write_text(json.dumps({
            "access_token": "test",
            "expires_in": 0,
            "obtained_at": time.time()
        }))
        mock_path.return_value = token_file
        result = _has_valid_token()
        assert result is False


class TestSpawnAuthHelper:
    @patch("shutil.which")
    def test_spawn_auth_helper_returns_none_when_wt_missing(self, mock_which: Mock):
        """_spawn_auth_helper returns None when wt.exe not found."""
        mock_which.return_value = None
        result = _spawn_auth_helper()
        assert result is None

    @patch("shutil.which")
    @patch("subprocess.Popen")
    def test_spawn_auth_helper_returns_process_when_wt_found(self, mock_popen: Mock, mock_which: Mock):
        """_spawn_auth_helper returns Popen object when wt.exe found."""
        mock_which.return_value = "/path/to/wt"
        mock_process = Mock()
        mock_popen.return_value = mock_process
        result = _spawn_auth_helper()
        assert result is mock_process
        mock_popen.assert_called_once()


class TestWaitForTokenReady:
    @patch("src.perchvpn_windows.webview._has_valid_token")
    def test_wait_for_token_ready_returns_true_immediately(self, mock_has: Mock):
        """_wait_for_token_ready returns True immediately if token already valid."""
        mock_has.return_value = True
        result = _wait_for_token_ready(timeout=1.0)
        assert result is True

    @patch("src.perchvpn_windows.webview._has_valid_token")
    @patch("src.perchvpn_windows.webview.time.monotonic")
    @patch("src.perchvpn_windows.webview.time.sleep")
    def test_wait_for_token_ready_waits_and_returns_true(self, mock_sleep: Mock, mock_monotonic: Mock, mock_has: Mock):
        """_wait_for_token_ready waits and returns True when token becomes valid."""
        start = 1000.0
        mock_monotonic.side_effect = [start, start + 0.5, start + 1.0, start + 1.1]
        mock_has.side_effect = [False, False, True]
        result = _wait_for_token_ready(timeout=5.0)
        assert result is True
        assert mock_has.call_count == 3
        mock_sleep.assert_called()


class TestRunAuthFlow:
    @patch("src.perchvpn_windows.webview._has_valid_token")
    def test_run_auth_flow_returns_true_when_token_valid(self, mock_has: Mock):
        """_run_auth_flow returns True immediately when token already valid."""
        mock_has.return_value = True
        result = _run_auth_flow()
        assert result is True

    @patch("src.perchvpn_windows.webview._has_valid_token")
    @patch("src.perchvpn_windows.webview._spawn_auth_helper")
    def test_run_auth_flow_returns_false_when_spawn_fails(self, mock_spawn: Mock, mock_has: Mock):
        """_run_auth_flow returns False when auth helper spawn fails."""
        mock_has.return_value = False
        mock_spawn.return_value = None
        result = _run_auth_flow()
        assert result is False

    @patch("src.perchvpn_windows.webview._has_valid_token")
    @patch("src.perchvpn_windows.webview._spawn_auth_helper")
    @patch("src.perchvpn_windows.webview._wait_for_token_ready")
    def test_run_auth_flow_returns_true_on_success(self, mock_wait: Mock, mock_spawn: Mock, mock_has: Mock):
        """_run_auth_flow returns True when auth succeeds and token appears."""
        mock_has.return_value = False
        mock_process = Mock()
        mock_process.wait.return_value = 0
        mock_spawn.return_value = mock_process
        mock_wait.return_value = True
        result = _run_auth_flow()
        assert result is True

    @patch("src.perchvpn_windows.webview._has_valid_token")
    @patch("src.perchvpn_windows.webview._spawn_auth_helper")
    def test_run_auth_flow_returns_false_on_cancel(self, mock_spawn: Mock, mock_has: Mock):
        """_run_auth_flow returns False when user cancels (exit code 130)."""
        mock_has.return_value = False
        mock_process = Mock()
        mock_process.wait.return_value = 130
        mock_spawn.return_value = mock_process
        result = _run_auth_flow()
        assert result is False

    @patch("src.perchvpn_windows.webview._has_valid_token")
    @patch("src.perchvpn_windows.webview._spawn_auth_helper")
    def test_run_auth_flow_returns_false_on_nonzero_exit(self, mock_spawn: Mock, mock_has: Mock):
        """_run_auth_flow returns False when auth exits with non-zero code."""
        mock_has.return_value = False
        mock_process = Mock()
        mock_process.wait.return_value = 1
        mock_spawn.return_value = mock_process
        result = _run_auth_flow()
        assert result is False

    @patch("src.perchvpn_windows.webview._has_valid_token")
    @patch("src.perchvpn_windows.webview._spawn_auth_helper")
    def test_run_auth_flow_returns_false_on_timeout(self, mock_spawn: Mock, mock_has: Mock):
        """_run_auth_flow returns False and kills process on timeout."""
        mock_has.return_value = False
        mock_process = Mock()
        mock_process.wait.side_effect = __import__("subprocess").TimeoutExpired("cmd", 300)
        mock_spawn.return_value = mock_process
        result = _run_auth_flow()
        assert result is False
        mock_process.terminate.assert_called_once()


class TestRunAuthOnly:
    @patch("src.perchvpn_windows.cli.auth_module.obtain_auth")
    def test_run_auth_only_returns_zero_on_success(self, mock_obtain: Mock):
        """_run_auth_only returns 0 on successful authentication."""
        from src.perchvpn_windows.cli import _run_auth_only
        import asyncio
        result = asyncio.run(_run_auth_only())
        assert result == 0

    @patch("src.perchvpn_windows.cli.auth_module.obtain_auth")
    def test_run_auth_only_returns_130_on_keyboard_interrupt(self, mock_obtain: Mock):
        """_run_auth_only returns 130 on KeyboardInterrupt."""
        from src.perchvpn_windows.cli import _run_auth_only
        import asyncio
        mock_obtain.side_effect = KeyboardInterrupt()
        result = asyncio.run(_run_auth_only())
        assert result == 130

    @patch("src.perchvpn_windows.cli.auth_module.obtain_auth")
    def test_run_auth_only_returns_1_on_exception(self, mock_obtain: Mock):
        """_run_auth_only returns 1 on authentication exception."""
        from src.perchvpn_windows.cli import _run_auth_only
        import asyncio
        mock_obtain.side_effect = RuntimeError("Auth failed")
        result = asyncio.run(_run_auth_only())
        assert result == 1