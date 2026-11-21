"""Transactional proxy <-> TUN mode switching at the app layer."""

from __future__ import annotations

import asyncio

from perchvpn_windows import app as app_module
from perchvpn_windows import config as config_module
from perchvpn_windows.config import WindowsConfig


class FakeHelper:
    def __init__(self, phase="stopped"):
        self.phase = phase
        self.stop_calls = 0
        self.stop_result = {"phase": "stopped"}

    def snapshot(self):
        return {"phase": self.phase, "adapter": "PerchVPN"}

    def is_running(self):
        return self.phase in ("starting", "ready", "stopping")

    async def stop(self, timeout=20.0):
        self.stop_calls += 1
        return self.stop_result


def _app(monkeypatch, **config):
    default = dict(tun_opt_in=True, tun_enabled=False)
    default.update(config)
    app = app_module.PerchVPNApp(WindowsConfig(**default))
    monkeypatch.setattr(config_module, "save_config", lambda cfg: None)
    return app


def _ready_frontend(app, monkeypatch):
    app._frontend = object()

    async def ready():
        return True

    monkeypatch.setattr(app, "_local_socks_ready", ready)


class TestApplyMode:
    def test_tun_ready_enables_tun_without_restart(self, monkeypatch):
        app = _app(monkeypatch)

        async def start_helper():
            return {"phase": "ready", "adapter": "PerchVPN"}

        monkeypatch.setattr(app, "_start_tun_helper", start_helper)
        payload = asyncio.run(app.apply_mode("tun"))

        assert app.config.tun_enabled is True
        assert app.config.proxy_only_mode is False
        assert payload["selected"] == "tun"
        assert payload["transition"]["state"] == "complete"

    def test_tun_failure_leaves_proxy_active_and_reports_reason(self, monkeypatch):
        app = _app(monkeypatch)
        helper = FakeHelper(phase="failed")
        app._tun_helper = helper

        async def start_helper():
            return {"phase": "failed", "error": "UAC cancelled"}

        monkeypatch.setattr(app, "_start_tun_helper", start_helper)
        payload = asyncio.run(app.apply_mode("tun"))

        # Deliberate: a failed activation never silently reverts the
        # selected mode; the GUI keeps the user's choice and the proxy
        # tunnel keeps running as the fallback.
        assert app.config.tun_enabled is True
        assert payload["selected"] == "tun"
        assert payload["active"] != "tun"
        assert "UAC cancelled" in payload["fallback_reason"]
        assert payload["transition"]["state"] == "failed"
        assert payload["transition"]["detail"] == "UAC cancelled"
        assert helper.stop_calls == 1
        assert app._tun_helper is None

    def test_proxy_stops_helper_and_clears_flags(self, monkeypatch):
        app = _app(monkeypatch, tun_enabled=True)
        helper = FakeHelper(phase="ready")
        app._tun_helper = helper
        _ready_frontend(app, monkeypatch)

        payload = asyncio.run(app.apply_mode("proxy"))

        assert helper.stop_calls == 1
        assert app.config.tun_enabled is False
        assert app.config.proxy_only_mode is False
        assert payload["transition"]["state"] == "complete"

    def test_start_helper_is_a_noop_in_proxy_mode(self, monkeypatch):
        app = _app(monkeypatch, tun_enabled=False, proxy_only_mode=True)

        state = asyncio.run(app._start_tun_helper())

        assert state["phase"] == "stopped"
        assert app._tun_helper is None

    def test_proxy_drops_terminal_helper_without_writing_stop(self, monkeypatch):
        app = _app(monkeypatch, tun_enabled=True)
        helper = FakeHelper(phase="failed")
        app._tun_helper = helper

        async def must_not_start():
            raise AssertionError("proxy mode must not launch the elevated helper")

        monkeypatch.setattr(app, "_start_tun_helper", must_not_start)
        _ready_frontend(app, monkeypatch)
        payload = asyncio.run(app.apply_mode("proxy"))

        assert helper.stop_calls == 0
        assert app._tun_helper is None
        assert payload["transition"]["state"] == "complete"
        assert app.config.tun_enabled is False

    def test_unverified_teardown_keeps_ownership_handle(self, monkeypatch):
        app = _app(monkeypatch, tun_enabled=True)
        helper = FakeHelper(phase="ready")
        helper.stop_result = {"phase": "recovery_required", "error": "routes left"}
        app._tun_helper = helper

        payload = asyncio.run(app.apply_mode("proxy"))

        assert payload["transition"]["state"] == "failed"
        assert "routes left" in payload["transition"]["detail"]
        assert app._tun_helper is helper  # recovery owner is never dropped

    def test_proxy_apply_never_inspects_adapters(self, monkeypatch):
        from perchvpn_windows import tun_helper
        from perchvpn_windows import tun_state_capture

        def fail(*args, **kwargs):
            raise AssertionError("proxy mode inspected adapters/routes")

        monkeypatch.setattr(tun_state_capture, "detect_physical_egress", fail)
        monkeypatch.setattr(tun_helper, "capture_adapter_dns", fail)
        monkeypatch.setattr(tun_helper, "find_route_interface", fail)
        app = _app(monkeypatch, tun_enabled=True)
        app._tun_helper = FakeHelper(phase="failed")
        _ready_frontend(app, monkeypatch)

        payload = asyncio.run(app.apply_mode("proxy"))

        assert payload["transition"]["state"] == "complete"
        assert app.config.tun_enabled is False

    def test_proxy_without_frontend_fails_with_reason(self, monkeypatch):
        app = _app(monkeypatch, tun_enabled=True)
        app._tun_helper = FakeHelper(phase="failed")

        async def must_not_probe():
            raise AssertionError("must not probe when the frontend is absent")

        monkeypatch.setattr(app, "_local_socks_ready", must_not_probe)
        payload = asyncio.run(app.apply_mode("proxy"))

        assert payload["transition"]["state"] == "failed"
        assert "Local proxy service not running" in payload["transition"]["detail"]
        assert "frontend not initialized" in payload["transition"]["detail"]
        assert app.config.tun_enabled is False

    def test_proxy_with_dead_frontend_fails_with_reason(self, monkeypatch):
        app = _app(monkeypatch, tun_enabled=True)
        app._tun_helper = FakeHelper(phase="failed")
        app._frontend = object()

        async def not_ready():
            return False

        monkeypatch.setattr(app, "_local_socks_ready", not_ready)
        payload = asyncio.run(app.apply_mode("proxy"))

        assert payload["transition"]["state"] == "failed"
        assert "Local proxy service not running" in payload["transition"]["detail"]
        assert "not accepting connections" in payload["transition"]["detail"]

    def test_unsupported_target_raises(self, monkeypatch):
        app = _app(monkeypatch)
        try:
            asyncio.run(app.apply_mode("bogus"))
        except ValueError as exc:
            assert "unsupported mode" in str(exc)
        else:
            raise AssertionError("expected ValueError")

    def test_tun_mode_without_proxy_fails_before_helper(self, monkeypatch):
        import socket

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        app = _app(monkeypatch)
        app.config.listen_port = port
        app._tun_helper = None

        payload = asyncio.run(app.apply_mode("tun"))

        assert payload["transition"]["state"] == "failed"
        assert "Local proxy service not running" in payload["transition"]["detail"]
        assert app._tun_helper is None


class TestResolveTunExecutable:
    def test_stale_tun2proxy_path_falls_back_to_bundled_singbox(
        self, monkeypatch, tmp_path
    ):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "bin").mkdir()
        bundled = tmp_path / "bin" / "sing-box.exe"
        bundled.write_bytes(b"")
        monkeypatch.setattr(app_module.sys, "platform", "win32")

        resolved = app_module.resolve_tun_executable(
            "C:\\old\\dist-candidate\\tun2proxy-bin.exe"
        )

        assert resolved == str(bundled)

    def test_configured_singbox_path_wins(self, monkeypatch, tmp_path):
        configured = tmp_path / "sing-box.exe"
        configured.write_bytes(b"")
        monkeypatch.setattr(app_module.sys, "platform", "win32")

        assert app_module.resolve_tun_executable(str(configured)) == str(configured)


class TestBeginModeApply:
    def test_slow_engine_returns_within_bound_and_finishes_in_background(
        self, monkeypatch
    ):
        app = _app(monkeypatch)
        release = asyncio.Event()

        async def start_helper():
            await release.wait()
            return {"phase": "ready", "adapter": "PerchVPN"}

        monkeypatch.setattr(app, "_start_tun_helper", start_helper)

        async def scenario():
            payload = await app.begin_mode_apply("tun", ack_timeout=0.05)
            assert payload["transition"]["state"] != "complete"
            assert app._mode_task is not None
            assert not app._mode_task.done()
            release.set()
            await app._mode_task
            return app.mode_payload()

        settled = asyncio.run(scenario())
        assert settled["selected"] == "tun"
        assert settled["transition"]["state"] == "complete"


class TestLocalSocksPrerequisite:
    def test_detects_listening_and_closed_socks_port(self, monkeypatch):
        app = _app(monkeypatch)

        async def scenario():
            server = await asyncio.start_server(
                lambda r, w: w.close(), "127.0.0.1", 0
            )
            port = server.sockets[0].getsockname()[1]
            app.config.listen_port = port
            assert await app._local_socks_ready(timeout=1.0) is True
            server.close()
            await server.wait_closed()
            return await app._local_socks_ready(timeout=0.2)

        assert asyncio.run(scenario()) is False

    def test_tun_helper_refuses_to_spawn_without_proxy(self, monkeypatch):
        import socket

        from perchvpn_windows import tun_helper

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        app = _app(monkeypatch)
        app.config.tun_enabled = True
        app.config.listen_port = port
        launched = []

        class FakeHelper:
            def __init__(self, **kwargs):
                launched.append(kwargs)

        monkeypatch.setattr(tun_helper, "TunHelperClient", FakeHelper)

        state = asyncio.run(app._start_tun_helper())

        assert state["phase"] == tun_helper.PHASE_FAILED
        assert "Local proxy service not running" in state["error"]
        assert state["error"] == app._tun_start_error
        assert launched == []
