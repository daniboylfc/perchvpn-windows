"""Real-time /ws/status state push.

The WebSocket must deliver the same payload as /api/status immediately on
every state transition (connection status, exit verification, tunnel
readiness, restart/disconnect) instead of waiting for the frontend's 2 s
poll. The monitor loop runs only while clients are connected.
"""

from __future__ import annotations

import asyncio
from typing import Optional
from unittest.mock import MagicMock

import pytest

import src.perchvpn_windows.api as api_module
from src.perchvpn_windows.api import StatusResponse
from src.perchvpn_windows.config import WindowsConfig


class _FakeMetrics:
    def __init__(self, downloaded=0, uploaded=0, active=0):
        self.downloaded = downloaded
        self.uploaded = uploaded
        self.download_speed = 0.0
        self.upload_speed = 0.0
        self.active_connections = active


def _make_app(controller_status: str = "ok", verification: str = "verified"):
    config = WindowsConfig()
    controller = MagicMock()
    controller.status = controller_status
    controller.uptime = 1.0
    controller.transport = "http/2"
    controller.metrics = _FakeMetrics()
    app_obj = MagicMock()
    app_obj._controller = controller
    app_obj._exit_ip = "198.51.100.7"
    app_obj._exit_country = "SE"
    app_obj._exit_verification_state = verification
    app_obj.tun_payload = lambda: {
        "enabled": True,
        "mode": "tun",
        "state": "traffic_verified",
        "detail": "System traffic exits through the VPN.",
    }
    return app_obj, config


class _FakeWebSocket:
    """Stand-in for fastapi WebSocket: records send_text payloads."""

    def __init__(self, fail: bool = False):
        self.frames: list[str] = []
        self.fail = fail
        self.closed = False

    async def send_text(self, payload: str) -> None:
        if self.fail:
            raise RuntimeError("connection gone")
        self.frames.append(payload)


@pytest.fixture(autouse=True)
def _reset_ws_globals():
    original_app = api_module._app
    original_config = api_module._config
    original_restart = api_module._restart_task
    original_clients = set(api_module._status_websockets)
    original_monitor = api_module._status_monitor_task
    original_pending = api_module._status_push_pending
    original_payload = api_module._status_last_payload
    api_module._status_websockets.clear()
    api_module._status_monitor_task = None
    api_module._status_push_pending = False
    api_module._status_last_payload = None
    yield
    api_module._app = original_app
    api_module._config = original_config
    api_module._restart_task = original_restart
    api_module._status_websockets.clear()
    api_module._status_websockets.update(original_clients)
    api_module._status_monitor_task = original_monitor
    api_module._status_push_pending = original_pending
    api_module._status_last_payload = original_payload


def _stub_build_status():
    """Replace _build_status_response with a mutable, deterministic stub."""
    state = {"payload": None}

    def set_payload(resp: StatusResponse) -> None:
        state["payload"] = resp

    async def build() -> StatusResponse:
        payload = state["payload"]
        if payload is None:
            raise RuntimeError("not initialized")
        return payload

    return state, build


def _base_payload(**overrides) -> StatusResponse:
    values = dict(
        status="connected",
        uptime=1.0,
        socks5_addr="127.0.0.1:1080",
        exit_ip="198.51.100.7",
        country="se",
        transport="http/2",
        downloaded=0,
        uploaded=0,
        download_speed=0.0,
        upload_speed=0.0,
        active_connections=0,
        exit_verification_state="verified",
        tunnel={"enabled": True, "state": "traffic_verified", "detail": ""},
        switch={},
        modes={},
    )
    values.update(overrides)
    return StatusResponse(**values)


class TestStateSignature:
    def test_transition_fields_are_covered(self):
        resp = _base_payload()
        sig = api_module._status_state_signature(resp)
        changed: dict[str, tuple] = {
            "status": sig,
            "verification": None,
            "exit_ip": None,
            "country": None,
            "transport": None,
            "tunnel_state": None,
            "tunnel_detail": None,
            "switch_state": None,
        }
        variants = {
            "status": _base_payload(status="disconnected"),
            "verification": _base_payload(exit_verification_state="failed"),
            "exit_ip": _base_payload(exit_ip="203.0.113.9"),
            "country": _base_payload(country="jp"),
            "transport": _base_payload(transport="h3"),
            "tunnel_state": _base_payload(tunnel={"enabled": True, "state": "degraded", "detail": ""}),
            "tunnel_detail": _base_payload(tunnel={"enabled": True, "state": "traffic_verified", "detail": "x"}),
            "switch_state": _base_payload(switch={"state": "complete"}),
        }
        for key, variant in variants.items():
            assert api_module._status_state_signature(variant) != sig, key


class TestBroadcastStatus:
    @pytest.mark.asyncio
    async def test_no_clients_is_a_no_op(self, monkeypatch):
        state, build = _stub_build_status()
        assert api_module._status_websockets == set()
        # _build_status_response raising (app not ready) must be swallowed.
        monkeypatch.setattr(api_module, "_build_status_response", build)
        await api_module.broadcast_status()

    @pytest.mark.asyncio
    async def test_pushes_frame_to_connected_clients(self, monkeypatch):
        state, build = _stub_build_status()
        state["payload"] = _base_payload()
        monkeypatch.setattr(api_module, "_build_status_response", build)
        ws = _FakeWebSocket()
        api_module._status_websockets.add(ws)
        await api_module.broadcast_status()
        assert len(ws.frames) == 1
        assert '"status":"connected"' in ws.frames[0]

    @pytest.mark.asyncio
    async def test_dead_client_is_discarded(self, monkeypatch):
        state, build = _stub_build_status()
        state["payload"] = _base_payload()
        monkeypatch.setattr(api_module, "_build_status_response", build)
        dead = _FakeWebSocket(fail=True)
        alive = _FakeWebSocket()
        api_module._status_websockets.update({dead, alive})
        await api_module.broadcast_status()
        assert dead not in api_module._status_websockets
        assert alive in api_module._status_websockets
        assert len(alive.frames) == 1


class TestStatusMonitorLoop:
    @pytest.mark.asyncio
    async def test_exits_immediately_without_clients(self, monkeypatch):
        state, build = _stub_build_status()
        # _build_status_response would raise if the loop ever polled it;
        # an empty client set must exit the loop before the first poll.
        monkeypatch.setattr(api_module, "_build_status_response", build)
        await asyncio.wait_for(api_module._status_monitor_loop(), timeout=1.0)

    @pytest.mark.asyncio
    async def test_pushes_on_state_change_only(self, monkeypatch):
        state, build = _stub_build_status()
        state["payload"] = _base_payload()
        monkeypatch.setattr(api_module, "_build_status_response", build)
        monkeypatch.setattr(api_module, "_STATUS_MONITOR_INTERVAL_SECONDS", 0.01)
        monkeypatch.setattr(api_module, "_STATUS_METRICS_PUSH_SECONDS", 3600.0)
        ws = _FakeWebSocket()
        api_module._status_websockets.add(ws)
        task = asyncio.ensure_future(api_module._status_monitor_loop())
        try:
            # Give the loop time to observe the initial state.
            await asyncio.sleep(0.05)
            assert len(ws.frames) == 1
            # No-op interval: unchanged state pushes nothing more.
            await asyncio.sleep(0.05)
            assert len(ws.frames) == 1
            # A transition (exit verification failed) pushes immediately.
            state["payload"] = _base_payload(
                exit_verification_state="failed",
                tunnel={"enabled": True, "state": "degraded", "detail": "probe"},
            )
            await asyncio.sleep(0.15)
            assert len(ws.frames) == 2
        finally:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

    @pytest.mark.asyncio
    async def test_app_not_ready_tolerated(self, monkeypatch):
        state, build = _stub_build_status()
        state["payload"] = None
        monkeypatch.setattr(api_module, "_build_status_response", build)
        monkeypatch.setattr(api_module, "_STATUS_MONITOR_INTERVAL_SECONDS", 0.01)
        ws = _FakeWebSocket()
        api_module._status_websockets.add(ws)
        task = asyncio.ensure_future(api_module._status_monitor_loop())
        try:
            await asyncio.sleep(0.05)
            assert ws.frames == []
            state["payload"] = _base_payload()
            await asyncio.sleep(0.15)
            assert len(ws.frames) == 1
        finally:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task


class TestMonitorLifecycle:
    @pytest.mark.asyncio
    async def test_ensure_starts_and_stop_cancels(self, monkeypatch):
        state, build = _stub_build_status()
        state["payload"] = _base_payload()
        monkeypatch.setattr(api_module, "_build_status_response", build)
        monkeypatch.setattr(api_module, "_STATUS_MONITOR_INTERVAL_SECONDS", 0.01)
        api_module._status_websockets.add(_FakeWebSocket())
        api_module._ensure_status_monitor()
        task = api_module._status_monitor_task
        assert task is not None and not task.done()
        await asyncio.sleep(0.05)
        await api_module._stop_status_monitor()
        assert api_module._status_monitor_task is None
        assert task.done()

    @pytest.mark.asyncio
    async def test_ensure_reuses_running_task(self, monkeypatch):
        state, build = _stub_build_status()
        state["payload"] = _base_payload()
        monkeypatch.setattr(api_module, "_build_status_response", build)
        monkeypatch.setattr(api_module, "_STATUS_MONITOR_INTERVAL_SECONDS", 5.0)
        api_module._status_websockets.add(_FakeWebSocket())
        api_module._ensure_status_monitor()
        first = api_module._status_monitor_task
        api_module._ensure_status_monitor()
        assert api_module._status_monitor_task is first
        await api_module._stop_status_monitor()


class TestStatusDedup:
    @pytest.mark.asyncio
    async def test_get_status_and_build_agree(self):
        app_obj, config = _make_app()
        api_module._app = app_obj
        api_module._config = config
        api_module._restart_task = None
        via_endpoint = (await api_module.get_status()).model_dump()
        via_build = (await api_module._build_status_response()).model_dump()
        assert via_endpoint == via_build


class TestNotifyStatusChanged:
    @pytest.mark.asyncio
    async def test_no_clients_is_a_no_op(self):
        api_module.notify_status_changed()
        await asyncio.sleep(0)
        assert api_module._status_push_pending is False

    @pytest.mark.asyncio
    async def test_schedules_immediate_push(self, monkeypatch):
        state, build = _stub_build_status()
        state["payload"] = _base_payload()
        monkeypatch.setattr(api_module, "_build_status_response", build)
        ws = _FakeWebSocket()
        api_module._status_websockets.add(ws)
        api_module.notify_status_changed()
        assert api_module._status_push_pending is True
        for _ in range(3):
            await asyncio.sleep(0)
        assert api_module._status_push_pending is False
        assert len(ws.frames) == 1
        assert '"status":"connected"' in ws.frames[0]

    @pytest.mark.asyncio
    async def test_bursts_coalesce_into_one_frame(self, monkeypatch):
        state, build = _stub_build_status()
        state["payload"] = _base_payload()
        monkeypatch.setattr(api_module, "_build_status_response", build)
        ws = _FakeWebSocket()
        api_module._status_websockets.add(ws)
        api_module.notify_status_changed()
        api_module.notify_status_changed()
        api_module.notify_status_changed()
        for _ in range(3):
            await asyncio.sleep(0)
        assert len(ws.frames) == 1


class TestPayloadCache:
    @pytest.mark.asyncio
    async def test_duplicate_payload_is_not_resent(self, monkeypatch):
        state, build = _stub_build_status()
        state["payload"] = _base_payload()
        monkeypatch.setattr(api_module, "_build_status_response", build)
        ws = _FakeWebSocket()
        api_module._status_websockets.add(ws)
        await api_module.broadcast_status()
        await api_module.broadcast_status()
        assert len(ws.frames) == 1
        state["payload"] = _base_payload(status="disconnected")
        await api_module.broadcast_status()
        assert len(ws.frames) == 2

    @pytest.mark.asyncio
    async def test_force_always_sends_snapshot(self):
        resp = _base_payload()
        ws = _FakeWebSocket()
        api_module._status_websockets.add(ws)
        await api_module._push_status_frame(resp, force=True)
        await api_module._push_status_frame(resp, force=True)
        assert len(ws.frames) == 2


class TestStatusPayloadOffload:
    @pytest.mark.asyncio
    async def test_build_status_collects_app_payloads_off_loop(self, monkeypatch):
        app_obj, config = _make_app()
        api_module._app = app_obj
        api_module._config = config
        api_module._restart_task = None
        seen = []

        async def fake_to_thread(fn, *args, **kwargs):
            seen.append(fn)
            return fn(*args, **kwargs)

        monkeypatch.setattr(api_module.asyncio, "to_thread", fake_to_thread)
        await api_module._build_status_response()
        assert api_module._status_payloads_of in seen


class TestHelperWatchCadence:
    def test_helper_state_watch_polls_at_200ms(self):
        import inspect
        from src.perchvpn_windows.app import PerchVPNApp

        src = inspect.getsource(PerchVPNApp._watch_tun_helper_state)
        assert "await asyncio.sleep(0.2)" in src
        assert "await asyncio.sleep(0.1)" not in src
        # The helper state file must be read in a worker thread, never on the
        # API event loop.
        assert "snapshot_async" in src
        assert "asyncio.to_thread" in src
