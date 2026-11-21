"""Boot-idle and mode-dispatch contracts for PerchVPN.

These tests pin the two reported regressions:
* boot prepares the app but never dials or starts TUN/SOCKS on its own;
* an explicit mode selection reaches Connect and a proxy Connect cannot
  steer into the TUN path.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

import src.perchvpn_windows.api as api_module
from perchvpn.proxystate import ProxyCandidate
from src.perchvpn_windows import app as app_module
from src.perchvpn_windows.app import PerchVPNApp
from src.perchvpn_windows.config import WindowsConfig


def _config(tmp_path, **overrides):
    base = dict(
        explicit_proxy="1.2.3.4:1080",
        verify_exit=False,
        dashboard=False,
        log_level="error",
        tun_enabled=False,
        tun_opt_in=False,
    )
    base.update(overrides)
    return WindowsConfig(**base)


class TestBootIdle:
    @pytest.mark.asyncio
    async def test_initialize_without_connect_stays_disconnected(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        app = PerchVPNApp(_config(tmp_path, tun_enabled=True, tun_opt_in=True))

        async def forbidden(*args, **kwargs):
            raise AssertionError("idle boot must not dial or activate anything")

        monkeypatch.setattr(app, "_obtain_auth", forbidden)
        monkeypatch.setattr(app, "_start_tun_frontend", forbidden)
        monkeypatch.setattr(app, "_start_tun_helper", forbidden)

        await app.initialize(auto_connect=False)

        assert app._status_state == "disconnected"
        assert app._boot_idle is True
        assert app.is_connected() is False
        assert app._controller is None
        assert app._frontend is None
        assert app._tun_frontend is None
        assert app._tun_helper is None

    @pytest.mark.asyncio
    async def test_api_startup_uses_idle_initializer(self, monkeypatch):
        created = []

        class FakeApp:
            def __init__(self, config):
                self.config = config
                self.idle = False
                self.shut_down = False
                created.append(self)

            async def initialize(self):
                raise AssertionError("startup must not connect")

            async def initialize_idle(self):
                self.idle = True

            async def shutdown(self):
                self.shut_down = True

        config = object()
        monkeypatch.setattr(api_module, "PerchVPNApp", FakeApp)
        monkeypatch.setattr(api_module, "load_config", lambda: config)
        monkeypatch.setattr(api_module, "_schedule_serverlist_refresh", lambda: None)
        monkeypatch.setattr(api_module, "_app", None)
        monkeypatch.setattr(api_module, "_config", None)
        monkeypatch.setattr(api_module, "_init_task", None)

        await api_module._startup()
        assert api_module._init_task is not None
        await api_module._init_task
        assert created[0].idle is True
        await api_module._shutdown()
        assert created[0].shut_down is True

    @pytest.mark.asyncio
    async def test_idle_mode_payload_reports_selected_tun_but_disconnected(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        app = PerchVPNApp(_config(tmp_path, tun_enabled=True, tun_opt_in=True))
        await app.initialize(auto_connect=False)

        payload = app.mode_payload()

        assert payload["selected"] == "tun"
        assert payload["active"] == "disconnected"


class TestModeDispatch:
    @pytest.mark.asyncio
    async def test_mode_selection_while_idle_only_persists(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        # The app booted with TUN selected; the persisted config has already
        # moved to proxy.  The idle response must report the new selection.
        idle = PerchVPNApp(
            _config(tmp_path, tun_enabled=True, tun_opt_in=True)
        )
        await idle.initialize(auto_connect=False)
        config = _config(tmp_path)
        saved = []

        async def must_not_apply(*args, **kwargs):
            raise AssertionError("idle mode selection must not apply a switch")

        monkeypatch.setattr(idle, "begin_mode_apply", must_not_apply)
        monkeypatch.setattr(api_module, "load_config", lambda: config)
        monkeypatch.setattr(api_module, "save_config", lambda cfg: saved.append(cfg))
        monkeypatch.setattr(api_module, "_app", idle)
        monkeypatch.setattr(api_module, "_config", config)

        result = await api_module.set_connection_mode(
            api_module.ConnectionModeRequest(mode="proxy", apply=True)
        )

        assert result["success"] is True
        assert result["applied"] is False
        assert "press Connect" in result["detail"]
        assert result["modes"]["selected"] == "proxy"
        assert result["modes"]["active"] == "disconnected"
        assert config.tun_enabled is False
        assert idle.config.tun_enabled is False
        assert idle.config.proxy_only_mode is False
        assert saved == [config]

    @pytest.mark.asyncio
    async def test_proxy_connect_never_calls_tun_frontend(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        app = PerchVPNApp(_config(tmp_path, tun_enabled=False))

        fake_pool = object()

        class FakeController:
            metrics = MagicMock()
            current_candidate = ProxyCandidate(
                "1.2.3.4", 1080, "us", "United States"
            )

            def __init__(self, *args, **kwargs):
                pass

            async def start(self):
                return fake_pool

            async def stop(self):
                pass

        class FakeFrontend:
            def __init__(self, *args, **kwargs):
                self.started = False

            async def start(self):
                self.started = True

            async def stop(self):
                pass

        async def forbidden_tun(*args, **kwargs):
            raise AssertionError("proxy Connect must never start TUN")

        monkeypatch.setattr(
            app, "_obtain_auth", AsyncMock(return_value=MagicMock())
        )
        monkeypatch.setattr(app_module, "ProxyController", FakeController)
        monkeypatch.setattr(app_module, "Socks5Frontend", FakeFrontend)
        monkeypatch.setattr(app, "_start_tun_frontend", forbidden_tun)
        monkeypatch.setattr(app, "_start_tun_helper", forbidden_tun)

        await app.initialize()

        assert app.config.tun_enabled is False
        assert app._tun_frontend is None
        assert app._tun_helper is None
        assert app._frontend is not None
        assert app._frontend.started is True

    @pytest.mark.asyncio
    async def test_connect_payload_proxy_overrides_stale_tun_config(
        self, monkeypatch
    ):
        stale = WindowsConfig(
            tun_enabled=True,
            tun_opt_in=True,
            explicit_proxy="1.2.3.4:1080",
            verify_exit=False,
        )
        old_app = MagicMock()
        old_app.shutdown = AsyncMock()
        seen = []

        class RecordingApp:
            def __init__(self, config):
                self.config = config

            async def initialize(self):
                seen.append((self.config.tun_enabled, self.config.proxy_only_mode))

            async def shutdown(self):
                pass

        monkeypatch.setattr(api_module, "load_config", lambda: stale)
        monkeypatch.setattr(api_module, "save_config", lambda cfg: None)
        monkeypatch.setattr(api_module, "PerchVPNApp", RecordingApp)
        monkeypatch.setattr(api_module.tokens_module, "load_tokens", lambda *a, **k: object())
        monkeypatch.setattr(api_module, "_app", old_app)
        monkeypatch.setattr(api_module, "_config", stale)
        monkeypatch.setattr(api_module, "_restart_task", None)

        result = await api_module.restart(api_module.ConnectRequest(mode="proxy"))
        assert result["success"] is True
        await api_module._restart_task

        assert seen == [(False, False)]
        assert isinstance(api_module._app, RecordingApp)
        assert api_module._app.config.tun_enabled is False


class TestSocksBeforeTun:
    @pytest.mark.asyncio
    async def test_down_listener_is_started_before_tun_returns(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        app = PerchVPNApp(_config(tmp_path))
        app._pool = object()
        started = []
        probes = iter([False, True])

        class FakeFrontend:
            def __init__(self, *args, **kwargs):
                pass

            async def start(self):
                started.append("socks5")

            async def stop(self):
                pass

        async def probe(timeout=2.0):
            return next(probes, True)

        monkeypatch.setattr(app_module, "Socks5Frontend", FakeFrontend)
        monkeypatch.setattr(app, "_local_socks_ready", probe)

        assert await app._ensure_local_socks() is True
        assert started == ["socks5"]
        assert app._frontend is not None

    @pytest.mark.asyncio
    async def test_no_pool_fails_closed_instead_of_binding_useless_socks(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        app = PerchVPNApp(_config(tmp_path))
        app._pool = None

        async def probe(timeout=2.0):
            return False

        monkeypatch.setattr(app, "_local_socks_ready", probe)

        assert await app._ensure_local_socks() is False
        assert "no authenticated session" in app._tun_start_error
        assert app._frontend is None
