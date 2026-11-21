"""Tests for WebView GUI lifecycle: deterministic API lifespan shutdown.

Uses the shipped package identity (``perchvpn_windows``) because the frozen
exe imports exactly that package.
"""

from __future__ import annotations

import sys
import types

import pytest

import perchvpn_windows.webview as webview_identity


class FakeThread:
    """Minimal thread stand-in recording join() calls."""

    def __init__(self, alive: bool = False):
        self._alive = alive
        self.join_calls: list[float | None] = []

    def is_alive(self) -> bool:
        return self._alive

    def join(self, timeout=None):
        self.join_calls.append(timeout)
        self._alive = False


class FakeServer:
    def __init__(self):
        self.should_exit = False


class TestLaunchWebviewShutdown:
    def _wire(
        self,
        monkeypatch,
        auth_ok=True,
        ready=True,
        server_returns=True,
    ):
        fake_mod = types.ModuleType("webview")
        fake_mod.create_window = lambda **kwargs: object()
        fake_mod.start = lambda **kwargs: None
        monkeypatch.setitem(sys.modules, "webview", fake_mod)

        monkeypatch.setattr(
            webview_identity,
            "_preflight_interactive_auth",
            lambda: not auth_ok,
        )
        monkeypatch.setattr(
            webview_identity, "_run_auth_flow", lambda: auth_ok
        )
        monkeypatch.setattr(
            webview_identity, "_wait_for_api_ready", lambda: ready
        )
        thread = FakeThread(alive=True)
        server = FakeServer()

        def fake_start_api_server():
            if not server_returns:
                return None, None
            return thread, server

        monkeypatch.setattr(
            webview_identity, "start_api_server", fake_start_api_server
        )
        return thread, server

    def test_ready_timeout_signals_shutdown_and_joins(self, monkeypatch):
        """launch_webview returning 1 on ready-timeout must flip
        server.should_exit and join the server thread so the FastAPI
        lifespan shutdown runs before the GUI returns."""
        thread, server = self._wire(monkeypatch, ready=False)

        assert webview_identity.launch_webview() == 1

        assert server.should_exit is True
        assert thread.join_calls == [webview_identity.SHUTDOWN_JOIN_TIMEOUT]

    def test_normal_window_close_signals_shutdown_and_joins(self, monkeypatch):
        """Normal GUI close (webview.start returns) must also trigger the
        deterministic lifespan shutdown before returning 0."""
        thread, server = self._wire(monkeypatch, ready=True)

        assert webview_identity.launch_webview() == 0

        assert server.should_exit is True
        assert thread.join_calls == [webview_identity.SHUTDOWN_JOIN_TIMEOUT]

    def test_webview_start_failure_signals_shutdown_and_joins(self, monkeypatch):
        """A ctor/start failure inside the GUI lifecycle must not skip the
        lifespan shutdown guarantee; the exception still propagates."""
        thread, server = self._wire(monkeypatch, ready=True)
        fake_mod = sys.modules["webview"]
        fake_mod.create_window = lambda **kwargs: object()

        def failing_start(**kwargs):
            raise RuntimeError("WebView2 runtime missing")

        fake_mod.start = failing_start

        assert webview_identity.launch_webview() == 1

        assert server.should_exit is True
        assert thread.join_calls == [webview_identity.SHUTDOWN_JOIN_TIMEOUT]

    def test_stuck_api_thread_is_forced_to_exit(self, monkeypatch):
        """A thread that ignores should_exit must get force_exit and a second
        join, so the process can release 127.0.0.1:1080 instead of ghosting."""
        thread, server = self._wire(monkeypatch, ready=True)

        class StuckThread(FakeThread):
            def is_alive(self):
                return True

        stuck = StuckThread()
        monkeypatch.setattr(
            webview_identity, "start_api_server", lambda: (stuck, server)
        )
        assert webview_identity.launch_webview() == 0
        assert server.should_exit is True
        assert server.force_exit is True
        assert stuck.join_calls == [webview_identity.SHUTDOWN_JOIN_TIMEOUT, 5.0]

    def test_auth_failure_returns_before_api_start(self, monkeypatch):
        """When re-authentication is required and the interactive auth flow
        fails, no API server is started and no shutdown signaling is
        required — launch_webview must return 1 without touching the
        server lifecycle."""

        def boom():
            raise AssertionError("start_api_server must not be called")

        monkeypatch.setitem(sys.modules, "webview", types.ModuleType("webview"))
        monkeypatch.setattr(webview_identity, "_preflight_interactive_auth", lambda: True)
        monkeypatch.setattr(webview_identity, "_run_auth_flow", lambda: False)
        monkeypatch.setattr(webview_identity, "start_api_server", boom)

        assert webview_identity.launch_webview() == 1


class TestWaitForApiReadyProxyOnly:
    """App-identity variants of the proxy-only readiness contract."""

    def _wire_poll(self, monkeypatch, payloads):
        import httpx

        state = {"t": 0.0, "i": 0}

        def fake_monotonic():
            return state["t"]

        def fake_sleep(_seconds):
            pass

        def fake_get(url, timeout=1.0):
            state["t"] += 5.0
            if state["i"] < len(payloads):
                data = payloads[state["i"]]
                state["i"] += 1
                resp = types.SimpleNamespace(status_code=200)
                resp.json = lambda: data
                return resp
            raise httpx.RequestError("exhausted")

        monkeypatch.setattr(webview_identity.time, "monotonic", fake_monotonic)
        monkeypatch.setattr(webview_identity.time, "sleep", fake_sleep)
        monkeypatch.setattr(httpx, "get", fake_get)

    def test_proxy_only_zero_uptime_is_ready(self, monkeypatch):
        """uptime == 0 with recognized status counts as ready (proxy-only)."""
        self._wire_poll(monkeypatch, [{"status": "disconnected", "uptime": 0.0}])
        assert webview_identity._wait_for_api_ready() is True

    def test_proxy_active_zero_uptime_is_ready(self, monkeypatch):
        """A proxy_active controller-less payload is also ready."""
        self._wire_poll(monkeypatch, [{"status": "proxy_active", "uptime": 0.0}])
        assert webview_identity._wait_for_api_ready() is True

    def test_payload_without_status_is_not_ready(self, monkeypatch):
        """A 200 payload missing the status key must not count as ready."""
        self._wire_poll(monkeypatch, [{"uptime": 5.0}])
        assert webview_identity._wait_for_api_ready() is False

    def test_connected_positive_uptime_is_ready(self, monkeypatch):
        """Regular tunnel-mode payload still signals readiness."""
        self._wire_poll(monkeypatch, [{"status": "connected", "uptime": 7.5}])
        assert webview_identity._wait_for_api_ready() is True
