"""Focused regression tests for the three surgical runtime fixes."""

from __future__ import annotations

import asyncio as asyncio_module
import logging

import pytest
from fastapi import WebSocketDisconnect

import src.perchvpn_windows.api as api_module
import perchvpn.controller as controller_module
from perchvpn import fxa, guardian
from perchvpn.auth import RuntimeAuth
from perchvpn.controller import ControllerConfig, ProxyController
from perchvpn.proxystate import ProxyCandidate


@pytest.mark.asyncio
async def test_startup_initializes_app_and_shutdown_cleans_up(monkeypatch):
    created = []

    class FakeApp:
        def __init__(self, config):
            self.config = config
            self.initialized = False
            self.shut_down = False
            created.append(self)

        async def initialize(self):
            self.initialized = True

        async def shutdown(self):
            self.shut_down = True

    config = object()
    monkeypatch.setattr(api_module, "PerchVPNApp", FakeApp)
    monkeypatch.setattr(api_module, "load_config", lambda: config)
    monkeypatch.setattr(api_module, "_app", None)
    monkeypatch.setattr(api_module, "_config", None)

    await api_module._startup()

    app = api_module._app
    assert isinstance(app, FakeApp)
    assert app.config is config
    # Boot is non-blocking: init runs in the background task, which the
    # shutdown path must sequence (await/cancel) before app shutdown.
    assert app.initialized is False
    assert api_module._init_task is not None

    await api_module._shutdown()
    assert app.shut_down is True
    assert api_module._app is None
    assert api_module._config is None


@pytest.mark.asyncio
async def test_ws_logs_registers_and_removes_client():
    class FakeWebSocket:
        def __init__(self):
            self.calls = 0

        async def accept(self):
            pass

        async def receive_text(self):
            self.calls += 1
            if self.calls == 1:
                assert self in api_module._log_websockets
                return "hello"
            raise WebSocketDisconnect()

    ws = FakeWebSocket()
    await api_module.websocket_logs(ws)
    assert ws not in api_module._log_websockets


@pytest.mark.asyncio
async def test_broadcast_log_prunes_failed_clients(monkeypatch):
    sent = []

    class Good:
        async def send_text(self, message):
            sent.append(message)

    class Bad:
        async def send_text(self, message):
            raise RuntimeError("closed")

    good, bad = Good(), Bad()
    monkeypatch.setattr(api_module, "_log_websockets", {good, bad})

    await api_module.broadcast_log("line")

    assert sent == ["line"]
    assert api_module._log_websockets == {good}


@pytest.mark.asyncio
async def test_quota_monitor_calls_synchronous_fetch_user_info(monkeypatch, caplog):
    controller = ProxyController(
        ControllerConfig(
            guardian_endpoint="https://guardian.example",
            candidate=ProxyCandidate(host="a", port=1, country_code="GB", country_name="UK"),
            upstream_conns=1,
            handshake_timeout=1.0,
        ),
        RuntimeAuth(token=fxa.TokenResponse(access_token="access", refresh_token="refresh", scope="scope", expires_in=3600)),
    )
    calls = []

    def fetch_user_info(endpoint, token):
        calls.append((endpoint, token))
        controller._stopped.set()

    monkeypatch.setattr(guardian, "fetch_user_info", fetch_user_info)
    monkeypatch.setattr(controller_module, "QUOTA_CHECK_INTERVAL_SECONDS", 0)

    with caplog.at_level(logging.WARNING, logger="perchvpn.controller"):
        await controller._quota_monitor_loop()

    assert calls == [("https://guardian.example", "access")]
    assert "quota check failed" not in caplog.text


@pytest.mark.asyncio
async def test_restart_refreshes_global_config(monkeypatch):
    class FakeApp:
        def __init__(self, config):
            self.config = config

        async def initialize(self):
            pass

        async def shutdown(self):
            pass

    config = object()
    old_config = object()
    monkeypatch.setattr(api_module, "PerchVPNApp", FakeApp)
    monkeypatch.setattr(api_module, "load_config", lambda: config)
    monkeypatch.setattr(api_module, "_app", None)
    monkeypatch.setattr(api_module, "_config", old_config)

    result = await api_module.restart()
    assert result["success"] is True

    # The restart completes in the background task.
    assert api_module._restart_task is not None
    await api_module._restart_task
    assert api_module._config is config
    assert api_module._app is not None
    assert api_module._app.config is config


@pytest.mark.asyncio
async def test_restart_task_cancellation_completes_old_shutdown(monkeypatch):
    """/api/disconnect cancels an in-flight restart task; the cancellation
    must never interrupt the old app's teardown mid-recovery-verification
    (that wedged the frontend live: ownership record intact + stale
    traffic_verified so every later disconnect/restart returned 500)."""
    import asyncio

    steps: list[str] = []

    class OldApp:
        def __init__(self, config):
            self.config = config

        async def initialize(self):
            pass

        async def shutdown(self):
            steps.append("begin")
            await asyncio.sleep(0.2)
            steps.append("verified")
            steps.append("done")

    class NewApp(OldApp):
        async def initialize(self):
            steps.append("new-init")

    monkeypatch.setattr(api_module, "PerchVPNApp", NewApp)
    monkeypatch.setattr(api_module, "load_config", lambda: object())
    monkeypatch.setattr(api_module, "_app", OldApp(object()))
    monkeypatch.setattr(api_module, "_config", None)

    result = await api_module.restart()
    assert result["success"] is True
    task = api_module._restart_task
    await asyncio.sleep(0.05)  # worker enters the shielded old shutdown
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    # The shielded teardown ran to completion before the task died.
    assert steps == ["begin", "verified", "done"]
    assert "new-init" not in steps


@pytest.mark.asyncio
async def test_broadcast_log_handles_concurrent_set_changes(monkeypatch):
    import asyncio

    started = asyncio.Event()
    release = asyncio.Event()

    class SlowClient:
        async def send_text(self, message):
            started.set()
            await release.wait()

    class LateClient:
        async def send_text(self, message):
            pass

    slow = SlowClient()
    late = LateClient()
    monkeypatch.setattr(api_module, "_log_websockets", {slow})

    task = asyncio.create_task(api_module.broadcast_log("line"))
    await started.wait()

    # Mutating the live set while broadcast is awaiting a client must not
    # raise "Set changed size during iteration".
    api_module._log_websockets.add(late)
    api_module._log_websockets.discard(slow)

    release.set()
    await task

    assert late in api_module._log_websockets


@pytest.mark.asyncio
async def test_lifespan_runs_startup_and_shutdown(monkeypatch):
    created = []

    class FakeApp:
        def __init__(self, config):
            self.config = config
            self.initialized = False
            self.shut_down = False
            created.append(self)

        async def initialize(self):
            self.initialized = True

        async def shutdown(self):
            self.shut_down = True

    fake_config = object()
    monkeypatch.setattr(api_module, "PerchVPNApp", FakeApp)
    monkeypatch.setattr(api_module, "load_config", lambda: fake_config)
    monkeypatch.setattr(api_module, "_app", None)
    monkeypatch.setattr(api_module, "_config", None)

    from asgi_lifespan import LifespanManager

    async with LifespanManager(api_module.app):
        app = api_module._app
        assert isinstance(app, FakeApp)
        assert app.initialized is True
    assert app.shut_down is True
    assert api_module._app is None
    assert api_module._config is None


@pytest.mark.asyncio
async def test_status_reports_connecting_while_background_init_running(monkeypatch):
    """Non-blocking boot must surface honest progress ("connecting"), not a
    false "disconnected", while initialize() is still dialling."""
    from src.perchvpn_windows.config import WindowsConfig

    released = asyncio_module.Event()

    class FakeApp:
        def __init__(self, config):
            self.config = config
            self._controller = None
            self._signed_out_boot = False
            self._status_state = "connecting"

        async def initialize(self):
            await released.wait()

        async def shutdown(self):
            pass

    config = WindowsConfig(proxy_only_mode=False, tun_enabled=False)
    monkeypatch.setattr(api_module, "PerchVPNApp", FakeApp)
    monkeypatch.setattr(api_module, "load_config", lambda: config)
    monkeypatch.setattr(api_module, "_app", None)
    monkeypatch.setattr(api_module, "_config", None)

    await api_module._startup()
    try:
        resp = await api_module.get_status()
        assert resp.status == "connecting"
    finally:
        released.set()
        await api_module._shutdown()
    # After shutdown the app handle is gone (get_status would 503, as ever).
    assert api_module._app is None



@pytest.mark.asyncio
async def test_shutdown_stops_tun_sidecar_before_controller():
    """The TUN sidecar owns every upstream session, so teardown must kill
    sing-box (and run the recovery gate) before the controller's pool drain,
    otherwise the disconnect blocks for the sidecar's multi-second self-exit."""
    import asyncio as aio
    from perchvpn_windows.app import PerchVPNApp

    order: list[str] = []

    class FakeController:
        async def stop(self):
            order.append("controller")

    class FakeTunFrontend:
        recovery_state = "clean"

        async def stop(self):
            order.append("tun")
            return True

    app = PerchVPNApp(config=object())
    app._controller = FakeController()
    app._tun_frontend = FakeTunFrontend()

    await aio.wait_for(app.shutdown(), timeout=5)
    assert order == ["tun", "controller"]
