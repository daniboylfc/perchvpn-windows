"""Unit tests for WebView readiness check."""

from __future__ import annotations

import time
from unittest.mock import Mock, patch

import httpx
import pytest

from src.perchvpn_windows.webview import _wait_for_api_ready


class TestWaitForApiReady:
    @patch("src.perchvpn_windows.webview.time.monotonic")
    @patch("src.perchvpn_windows.webview.time.sleep")
    @patch("httpx.get")
    def test_positive_uptime_returns_true(
        self, mock_get: Mock, mock_sleep: Mock, mock_monotonic: Mock
    ):
        """HTTP 200 with positive uptime returns True immediately."""
        mock_monotonic.side_effect = [0.0, 0.1]
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"uptime": 1.5, "status": "connected"}
        mock_get.return_value = mock_resp

        result = _wait_for_api_ready()

        assert result is True
        mock_get.assert_called_once()
        mock_sleep.assert_not_called()

    @patch("src.perchvpn_windows.webview.time.monotonic")
    @patch("src.perchvpn_windows.webview.time.sleep")
    @patch("httpx.get")
    def test_zero_uptime_proxy_only_returns_true_immediately(
        self, mock_get: Mock, mock_sleep: Mock, mock_monotonic: Mock
    ):
        """HTTP 200 with uptime 0.0 and a recognized status is ready at once.

        Proxy-only mode has no controller, so /api/status reports uptime
        0.0 forever while the API is fully live; readiness must not wait
        for uptime > 0."""
        mock_monotonic.side_effect = [0.0, 0.1]
        resp = Mock()
        resp.status_code = 200
        resp.json.return_value = {"uptime": 0.0, "status": "disconnected"}
        mock_get.return_value = resp

        result = _wait_for_api_ready()

        assert result is True
        mock_get.assert_called_once()
        mock_sleep.assert_not_called()

    @patch("src.perchvpn_windows.webview.time.monotonic")
    @patch("src.perchvpn_windows.webview.time.sleep")
    @patch("httpx.get")
    def test_connection_errors_until_timeout_returns_false(
        self, mock_get: Mock, mock_sleep: Mock, mock_monotonic: Mock
    ):
        """Repeated connection errors until timeout returns False."""
        # Simulate time advancing to deadline
        start = 0.0
        deadline = start + 30.0
        mock_monotonic.side_effect = [start, 0.5, 1.0, 1.5, 2.0, 2.5, deadline + 1.0]

        mock_get.side_effect = httpx.RequestError("Connection refused")

        result = _wait_for_api_ready()

        assert result is False
        # Should have polled multiple times
        assert mock_get.call_count >= 5
        assert mock_sleep.call_count >= 5

    @patch("src.perchvpn_windows.webview.time.monotonic")
    @patch("src.perchvpn_windows.webview.time.sleep")
    @patch("httpx.get")
    def test_http_503_until_timeout_returns_false(
        self, mock_get: Mock, mock_sleep: Mock, mock_monotonic: Mock
    ):
        """Repeated HTTP 503 until timeout returns False."""
        start = 0.0
        deadline = start + 30.0
        mock_monotonic.side_effect = [start, 0.5, 1.0, 1.5, 2.0, 2.5, deadline + 1.0]

        mock_resp = Mock()
        mock_resp.status_code = 503
        mock_get.return_value = mock_resp

        result = _wait_for_api_ready()

        assert result is False
        assert mock_get.call_count >= 5
        assert mock_sleep.call_count >= 5

    @patch("src.perchvpn_windows.webview.time.monotonic")
    @patch("src.perchvpn_windows.webview.time.sleep")
    @patch("httpx.get")
    def test_malformed_json_handled_safely(
        self, mock_get: Mock, mock_sleep: Mock, mock_monotonic: Mock
    ):
        """Malformed JSON is caught and polling continues; no uncaught exception."""
        mock_monotonic.side_effect = [0.0, 0.5, 1.0, 1.1]
        # First call: malformed JSON
        resp1 = Mock()
        resp1.status_code = 200
        resp1.json.side_effect = ValueError("Invalid JSON")
        # Second call: valid positive uptime
        resp2 = Mock()
        resp2.status_code = 200
        resp2.json.return_value = {"uptime": 0.5, "status": "connected"}
        mock_get.side_effect = [resp1, resp2]

        result = _wait_for_api_ready()

        assert result is True
        assert mock_get.call_count == 2
        mock_sleep.assert_called_once_with(0.05)

    @patch("src.perchvpn_windows.webview.time.monotonic")
    @patch("src.perchvpn_windows.webview.time.sleep")
    @patch("httpx.get")
    def test_generic_exception_handled_safely(
        self, mock_get: Mock, mock_sleep: Mock, mock_monotonic: Mock
    ):
        """Generic exception during request is caught and logged; polling continues."""
        mock_monotonic.side_effect = [0.0, 0.5, 1.0, 1.1]
        # First call: generic exception
        mock_get.side_effect = RuntimeError("Unexpected error")
        # Second call: success
        resp2 = Mock()
        resp2.status_code = 200
        resp2.json.return_value = {"uptime": 0.5, "status": "connected"}
        mock_get.side_effect = [RuntimeError("Unexpected error"), resp2]

        result = _wait_for_api_ready()

        assert result is True
        assert mock_get.call_count == 2
        mock_sleep.assert_called_once_with(0.05)

    @patch("src.perchvpn_windows.webview.time.monotonic")
    @patch("src.perchvpn_windows.webview.time.sleep")
    @patch("httpx.get")
    def test_timeout_logs_error(
        self, mock_get: Mock, mock_sleep: Mock, mock_monotonic: Mock, caplog
    ):
        """Timeout logs error message at ERROR level."""
        start = 0.0
        deadline = start + 30.0
        mock_monotonic.side_effect = [start, 0.5, 1.0, 1.5, 2.0, 2.5, deadline + 1.0]
        mock_get.side_effect = httpx.RequestError("Connection refused")

        with caplog.at_level("ERROR"):
            result = _wait_for_api_ready()

        assert result is False
        assert any(
            "API server did not become ready" in record.message
            for record in caplog.records
        )

    @patch("src.perchvpn_windows.webview.time.monotonic")
    @patch("src.perchvpn_windows.webview.time.sleep")
    @patch("httpx.get")
    def test_success_logs_info(
        self, mock_get: Mock, mock_sleep: Mock, mock_monotonic: Mock, caplog
    ):
        """Success logs readiness at INFO level with uptime."""
        mock_monotonic.side_effect = [0.0, 0.1]
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"uptime": 2.5, "status": "connected"}
        mock_get.return_value = mock_resp

        with caplog.at_level("INFO"):
            result = _wait_for_api_ready()

        assert result is True
        assert any(
            "API ready (status=connected, uptime=2.50s)" in record.message
            for record in caplog.records
        )

    @patch("src.perchvpn_windows.webview.time.monotonic")
    @patch("src.perchvpn_windows.webview.time.sleep")
    @patch("httpx.get")
    def test_missing_uptime_key_with_status_is_ready(
        self, mock_get: Mock, mock_sleep: Mock, mock_monotonic: Mock
    ):
        """HTTP 200 with a recognized status but no uptime key is ready."""
        mock_monotonic.side_effect = [0.0, 0.1]
        resp = Mock()
        resp.status_code = 200
        resp.json.return_value = {"status": "disconnected"}
        mock_get.return_value = resp

        result = _wait_for_api_ready()

        assert result is True
        mock_get.assert_called_once()

    @patch("src.perchvpn_windows.webview.time.monotonic")
    @patch("src.perchvpn_windows.webview.time.sleep")
    @patch("httpx.get")
    def test_missing_status_keeps_polling_until_timeout(
        self, mock_get: Mock, mock_sleep: Mock, mock_monotonic: Mock
    ):
        """HTTP 200 without a 'status' key is not ready; polls to timeout."""
        mock_monotonic.side_effect = [0.0, 0.5, 1.0, 1.5, 2.0, 2.5, 31.0]
        resp = Mock()
        resp.status_code = 200
        resp.json.return_value = {"uptime": 3.0}
        mock_get.return_value = resp

        result = _wait_for_api_ready()

        assert result is False
        assert mock_get.call_count >= 5
        assert mock_sleep.call_count >= 5