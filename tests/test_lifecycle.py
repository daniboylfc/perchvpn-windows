"""Focused lifecycle regression tests – mocked, no real VPN traffic."""

from __future__ import annotations

import asyncio
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import BaseModel, Field

from fastapi import HTTPException
from perchvpn.exceptions import TokenInvalidError

from src.perchvpn_windows.app import PerchVPNApp
import src.perchvpn_windows.api as api_module
from src.perchvpn_windows.config import WindowsConfig
from src.perchvpn_windows.tun_recovery import CLEAN, RECOVERY_UNVERIFIED


class CountrySelection(BaseModel):
    country_code: str = Field(min_length=2, max_length=2)
    city_code: Optional[str] = None


def _set_app(app):
    api_module._app = app


def _make_app(*, controller_status="disconnected"):
    app = PerchVPNApp(WindowsConfig())
    app._controller = MagicMock()
    c = app._controller
    c.status = controller_status
    c.uptime = 12.5
    c.transport = "http/2"
    c.accepting = controller_status in ("connected", "connecting")
    c._reason = "ok" if c.accepting else "starting"
    c.metrics = MagicMock()
    c.metrics.download_speed = c.metrics.upload_speed = 0.0
    c.metrics.active_connections = 0
    app._exit_ip = "0.0.0.0"
    app._exit_country = "--"
    app._exit_verification_state = "not_applicable"
    app._candidate = MagicMock()
    app._candidate.authority = "1.2.3.4:1080"
    app._candidate.country_code = "GB"
    app._candidate.country_name = "United Kingdom"
    app._pool = MagicMock()
    app._controller.stop = AsyncMock()
    app._frontend = AsyncMock()
    app._exit_check_task = None
    # The fixture's components are MagicMocks, not live listeners, so it
    # exercises the cold-restart fallback; hot-swap has its own suite in
    # test_country_hot_swap.py.
    app.can_hot_swap = lambda: False
    return app


class _UnresolvedTunApp:
    def __init__(self, config):
        self.config = config
        self._tun_frontend = MagicMock()

    async def initialize(self) -> None:
        raise RuntimeError("initialization failed with unresolved TUN")


class TestDnsCacheInitialization:
    def test_constructor_initializes_writable_dns_cache(self):
        app = PerchVPNApp(WindowsConfig())

        assert app._dns_cache == {}

        app._record_cached_ip("cache.example", ["198.51.100.7"])

        assert app._dns_cache["cache.example"] == ["198.51.100.7"]


class TestDisconnect:
    @pytest.mark.asyncio
    async def test_disconnect_when_running(self):
        app = _make_app(controller_status="connected")
        _set_app(app)
        app._controller.stop = AsyncMock()
        result = await api_module.disconnect()
        assert result["success"] is True
        assert result["detail"] == "Disconnected"
        assert app._controller is None

    @pytest.mark.asyncio
    async def test_disconnect_idempotent_when_idle(self):
        api_module._app = None
        result = await api_module.disconnect()
        assert result["success"] is True
        assert result["detail"] == "Not connected"

    @pytest.mark.asyncio
    async def test_disconnect_cancels_in_flight_restart(self):
        api_module._app = _make_app(controller_status="connected")
        api_module._app._controller.stop = AsyncMock()
        cancelled = asyncio.Event()

        async def worker():
            try:
                await asyncio.sleep(30)
            except asyncio.CancelledError:
                cancelled.set()
                raise

        api_module._restart_task = asyncio.create_task(worker())
        await asyncio.sleep(0)

        result = await api_module.disconnect()

        assert cancelled.is_set()
        assert api_module._restart_task is None
        assert result["success"] is True
        assert result["detail"] == "Disconnected"
        api_module._app = None


class TestRestart:
    @pytest.mark.asyncio
    async def test_restart_success_with_mocked_init(self):
        api_module._app = None
        api_module._restart_task = None
        with patch.object(PerchVPNApp, "initialize", return_value=None):
            result = await api_module.restart()
            assert result["success"] is True
            assert result["detail"].startswith("Restart started")
            assert api_module._restart_task is not None
            await api_module._restart_task
        assert api_module._app is not None

    @pytest.mark.asyncio
    async def test_restart_failure_sets_app_none(self):
        api_module._restart_task = None
        api_module._app = _make_app(controller_status="connected")
        api_module._app._controller.stop = AsyncMock()
        with patch.object(PerchVPNApp, "initialize", side_effect=RuntimeError("boom")):
            result = await api_module.restart()
            assert result["success"] is True
            with pytest.raises(HTTPException) as excinfo:
                await api_module._restart_task
        # The worker's except block guarantees _app = None
        assert api_module._app is None
        assert excinfo.value.status_code == 500

    @pytest.mark.asyncio
    async def test_restart_rejected_token_returns_to_signed_out(self, monkeypatch):
        """Guardian can reject a locally-valid persisted token after startup.

        The failed restart must clear the dead session, retain a clean
        disconnected app so /api/account reports "signed out", and stop the
        UI from sitting on an optimistic "connecting" frame.
        """

        class RejectedTokenApp:
            def __init__(self, config):
                self.config = config
                self._runtime_auth = object()
                self._signed_out_boot = False
                self._status_state = "connecting"
                self._tun_frontend = None

            async def initialize(self):
                raise TokenInvalidError(
                    "access token was rejected by Guardian", status_code=401
                )

            async def shutdown(self):
                pass

        config = WindowsConfig()
        deleted = []
        monkeypatch.setattr(api_module, "PerchVPNApp", RejectedTokenApp)
        monkeypatch.setattr(api_module, "load_config", lambda: config)
        monkeypatch.setattr(
            api_module.tokens_module,
            "delete_tokens",
            lambda *args, **kwargs: deleted.append(True),
        )
        monkeypatch.setattr(api_module, "_app", None)
        monkeypatch.setattr(api_module, "_config", None)
        monkeypatch.setattr(api_module, "_restart_task", None)

        result = await api_module.restart()
        assert result["success"] is True
        task = api_module._restart_task
        assert task is not None
        with pytest.raises(HTTPException) as excinfo:
            await task

        assert excinfo.value.status_code == 409
        assert "sign in again" in excinfo.value.detail
        assert deleted == [True]
        assert isinstance(api_module._app, RejectedTokenApp)
        assert api_module._app._runtime_auth is None
        assert api_module._app._signed_out_boot is True
        assert api_module._app._status_state == "disconnected"

    @pytest.mark.asyncio
    async def test_cancel_connecting_then_connect_starts_fresh_restart(self, monkeypatch):
        """Cancel while initialize() is in flight must leave a reusable API."""

        started = asyncio.Event()

        class SlowInitApp:
            def __init__(self, config):
                self.config = config
                self._runtime_auth = None
                self._status_state = "connecting"
                self._tun_frontend = None

            async def initialize(self):
                started.set()
                await asyncio.sleep(30)

            async def shutdown(self):
                pass

        class ReadyApp(SlowInitApp):
            async def initialize(self):
                self._status_state = "connected"

        monkeypatch.setattr(api_module, "PerchVPNApp", SlowInitApp)
        monkeypatch.setattr(api_module, "load_config", lambda: WindowsConfig())
        monkeypatch.setattr(api_module, "_app", None)
        monkeypatch.setattr(api_module, "_config", None)
        monkeypatch.setattr(api_module, "_restart_task", None)

        await api_module.restart()
        first_task = api_module._restart_task
        assert first_task is not None
        await started.wait()

        result = await api_module.disconnect()
        assert result["success"] is True
        assert first_task.done()
        assert api_module._restart_task is None

        monkeypatch.setattr(api_module, "PerchVPNApp", ReadyApp)
        await api_module.restart()
        second_task = api_module._restart_task
        assert second_task is not None
        await second_task
        assert isinstance(api_module._app, ReadyApp)

    @pytest.mark.asyncio
    async def test_restart_refuses_while_previous_restart_running(self):
        api_module._restart_task = None
        api_module._app = None

        release = asyncio.Event()

        async def worker():
            await release.wait()

        api_module._restart_task = asyncio.create_task(worker())
        with pytest.raises(HTTPException) as excinfo:
            await api_module.restart()
        assert excinfo.value.status_code == 409
        assert "already in progress" in excinfo.value.detail
        release.set()
        await api_module._restart_task
        api_module._app = None
        api_module._restart_task = None

    @pytest.mark.asyncio
    async def test_restart_old_shutdown_failure_retains_app(self):
        api_module._restart_task = None
        old_app = _make_app(controller_status="connected")
        old_app.shutdown = AsyncMock(side_effect=RuntimeError("old shutdown failed"))
        api_module._app = old_app
        with patch.object(PerchVPNApp, "initialize") as initialize:
            result = await api_module.restart()
            assert result["success"] is True
            with pytest.raises(HTTPException) as excinfo:
                await api_module._restart_task
        assert excinfo.value.status_code == 500
        assert api_module._app is old_app
        initialize.assert_not_called()

    @pytest.mark.asyncio
    async def test_restart_init_failure_retains_unresolved_tun_owner(self):
        api_module._restart_task = None
        config = object()
        api_module._app = None
        with patch.object(api_module, "PerchVPNApp", _UnresolvedTunApp):
            with patch.object(api_module, "load_config", return_value=config):
                result = await api_module.restart()
                assert result["success"] is True
                with pytest.raises(HTTPException) as excinfo:
                    await api_module._restart_task
        assert excinfo.value.status_code == 500
        assert isinstance(api_module._app, _UnresolvedTunApp)
        assert api_module._app._tun_frontend is not None
        assert api_module._config is config


class TestShutdown:
    def test_shutdown_resets_all_refs_even_on_error(self):
        """After shutdown with a component stop error, all references are
        cleared and RuntimeError is raised propagates the original failure."""
        app = _make_app(controller_status="connected")

        # Make controller.stop raise RuntimeError
        app._controller.stop = AsyncMock(side_effect=RuntimeError("controller stop failed"))

        with pytest.raises(RuntimeError) as excinfo:
            asyncio.run(app.shutdown())

        # Verify the error was propagated
        assert "controller stop failed" in str(excinfo.value)

        # Verify all references were cleared despite the error
        assert app._controller is None
        assert app._frontend is None   # frontend.stop() was still attempted
        assert app._pool is None
        assert app._candidate is None
        assert app._exit_check_task is None

    def test_shutdown_tolerates_stop_errors_collects_both(self):
        """If both controller.stop() and frontend.stop() raise, RuntimeError
        aggregates both failures and all references are still cleared."""
        app = _make_app(controller_status="connected")

        # Make controller.stop raise
        app._controller.stop = AsyncMock(side_effect=RuntimeError("controller stop failed"))
        # Make frontend.stop also raise
        app._frontend.stop = AsyncMock(side_effect=RuntimeError("frontend stop failed"))

        with pytest.raises(RuntimeError) as excinfo:
            asyncio.run(app.shutdown())

        # Verify both failures are in the error message
        assert "controller stop failed" in str(excinfo.value)
        assert "frontend stop failed" in str(excinfo.value)

        # All references cleared despite dual failure
        assert app._controller is None
        assert app._frontend is None
        assert app._pool is None
        assert app._candidate is None


class TestTunShutdownOwnership:
    def _app_with_tun(self, stop):
        app = PerchVPNApp(WindowsConfig())
        tun = MagicMock()
        tun.stop = stop
        app._tun_frontend = tun
        return app, tun

    @pytest.mark.asyncio
    async def test_unverified_stop_retains_tun_frontend(self):
        tun_stop = AsyncMock(return_value=False)
        app, tun = self._app_with_tun(tun_stop)
        tun.recovery_state = RECOVERY_UNVERIFIED

        with pytest.raises(RuntimeError, match="TUN shutdown incomplete"):
            await app.shutdown()

        assert app._tun_frontend is tun

    @pytest.mark.asyncio
    async def test_stop_error_retains_tun_frontend(self):
        app, tun = self._app_with_tun(
            AsyncMock(side_effect=RuntimeError("tun stop failed"))
        )

        with pytest.raises(RuntimeError, match="tun stop failed"):
            await app.shutdown()

        assert app._tun_frontend is tun

    @pytest.mark.asyncio
    async def test_cancelled_stop_retains_tun_frontend(self):
        app, tun = self._app_with_tun(AsyncMock(side_effect=asyncio.CancelledError))

        with pytest.raises(asyncio.CancelledError):
            await app.shutdown()

        assert app._tun_frontend is tun

    @pytest.mark.asyncio
    async def test_clean_stop_clears_tun_frontend(self):
        app, tun = self._app_with_tun(AsyncMock(return_value=True))
        tun.recovery_state = CLEAN

        await app.shutdown()

        assert app._tun_frontend is None


class TestInitializationFailure:
    def test_init_failure_leave_refs_none(self):
        app = PerchVPNApp(WindowsConfig())
        assert app._controller is None
        assert app._pool is None
        assert app._frontend is None
        assert app._candidate is None
        assert app._exit_check_task is None


class TestInitializationMetricsWiring:
    @pytest.mark.asyncio
    async def test_initialize_passes_controller_metrics_to_frontend(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        import perchvpn.auth as auth_module
        from src.perchvpn_windows.app import ProxyController, Socks5Frontend

        metrics = MagicMock()
        pool = MagicMock()
        controller = MagicMock()
        controller.start = AsyncMock(return_value=pool)
        controller.metrics = metrics

        app = PerchVPNApp(WindowsConfig(explicit_proxy="1.2.3.4:1080", verify_exit=False))

        fe_instance = MagicMock()
        fe_instance.start = AsyncMock()

        with patch.object(auth_module, "obtain_auth", return_value=MagicMock()):
            with patch("src.perchvpn_windows.app.ProxyController", return_value=controller):
                with patch("src.perchvpn_windows.app.Socks5Frontend", return_value=fe_instance) as frontend_cls:
                    await app.initialize()

                    assert frontend_cls.call_count == 1
                    assert frontend_cls.call_args.kwargs.get("metrics") is metrics


class TestInitializationCancellation:
    def _app(self):
        return PerchVPNApp(WindowsConfig(explicit_proxy="1.2.3.4:1080", verify_exit=False))

    @pytest.mark.asyncio
    async def test_initialize_cleans_up_when_cancelled(self):
        """Cancelling initialize() while the controller starts must tear down
        started resources and re-raise CancelledError.

        Regression: the cleanup handler caught only Exception, so CancelledError
        (a BaseException) skipped teardown and left _controller/_pool set.
        """
        controller = MagicMock()
        controller.start = AsyncMock(side_effect=asyncio.CancelledError())
        controller.stop = AsyncMock()

        app = self._app()
        with patch.object(PerchVPNApp, "_obtain_auth", AsyncMock(return_value=MagicMock())):
            with patch("src.perchvpn_windows.app.ProxyController", return_value=controller):
                with pytest.raises(asyncio.CancelledError):
                    await app.initialize()

        controller.stop.assert_awaited_once()
        assert app._controller is None
        assert app._pool is None
        assert app._frontend is None
        assert app._candidate is None
        assert app._exit_check_task is None

    @pytest.mark.asyncio
    async def test_initialize_cleanup_survives_cancelled_stop(self):
        """A cancellation raised while stopping one component must not skip the
        remaining teardown; the original failure is still propagated."""
        controller = MagicMock()
        controller.start = AsyncMock(side_effect=RuntimeError("start failed"))
        controller.stop = AsyncMock(side_effect=asyncio.CancelledError())

        app = self._app()
        with patch.object(PerchVPNApp, "_obtain_auth", AsyncMock(return_value=MagicMock())):
            with patch("src.perchvpn_windows.app.ProxyController", return_value=controller):
                with pytest.raises(RuntimeError):
                    await app.initialize()

        controller.stop.assert_awaited_once()
        assert app._controller is None
        assert app._pool is None
        assert app._frontend is None


class TestCountrySwitch:
    @pytest.fixture(autouse=True)
    def _hermetic_serverlist(self):
        """Country switch validation now goes through the shared server-list
        snapshot; keep it isolated from other tests and offline."""
        api_module._serverlist_cache = {"countries": None, "at": 0.0}
        with patch(
            "perchvpn.serverlist.fetch_server_list",
            return_value=[MagicMock(code="GB")],
        ):
            yield
        api_module._serverlist_cache = {"countries": None, "at": 0.0}

    @pytest.mark.asyncio
    async def test_country_switch_success(self):
        """/api/country switches country and updates _app."""
        api_module._app = _make_app(controller_status="connected")
        with patch.object(PerchVPNApp, "initialize", return_value=None):
            result = await api_module.set_country(selection=CountrySelection(country_code="GB"))
        assert result["success"] is True
        assert result["detail"] == "Country set to GB"
        assert api_module._app is not None

    @pytest.mark.asyncio
    async def test_country_switch_old_shutdown_failure(self):
        """/api/country keeps the old app when old-app shutdown fails."""
        old_app = _make_app(controller_status="connected")
        old_app._controller.stop = AsyncMock(side_effect=RuntimeError("shutdown failed"))
        api_module._app = old_app
        with patch.object(PerchVPNApp, "initialize") as initialize:
            with pytest.raises(HTTPException) as excinfo:
                await api_module.set_country(selection=CountrySelection(country_code="GB"))
        assert excinfo.value.status_code == 500
        assert api_module._app is old_app
        initialize.assert_not_called()

    @pytest.mark.asyncio
    async def test_country_switch_init_failure(self):
        """/api/country init failure leaves _app = None and state safe for retry."""
        api_module._app = _make_app(controller_status="connected")
        with patch.object(PerchVPNApp, "initialize", side_effect=RuntimeError("boom")):
            with pytest.raises(HTTPException):
                await api_module.set_country(selection=CountrySelection(country_code="GB"))
        # The handler's except block guarantees _app = None
        assert api_module._app is None

    @pytest.mark.asyncio
    async def test_country_switch_init_failure_retains_unresolved_tun_owner(self):
        config = MagicMock()
        api_module._app = None
        with patch.object(api_module, "PerchVPNApp", _UnresolvedTunApp):
            with patch.object(api_module, "load_config", return_value=config):
                with patch.object(api_module, "save_config"):
                    with pytest.raises(HTTPException) as excinfo:
                        await api_module.set_country(
                            selection=CountrySelection(country_code="GB")
                        )
        assert excinfo.value.status_code == 500
        assert isinstance(api_module._app, _UnresolvedTunApp)
        assert api_module._app._tun_frontend is not None
        assert api_module._config is config

    @pytest.mark.asyncio
    async def test_country_switch_no_app(self):
        """/api/country with no existing app creates fresh app and sets _app."""
        api_module._app = None
        with patch.object(PerchVPNApp, "initialize", return_value=None):
            result = await api_module.set_country(selection=CountrySelection(country_code="GB"))
        assert result["success"] is True
        assert api_module._app is not None


class TestInitializationRollbackFrontend:
    """A frontend that started successfully must be stopped exactly once if a
    later initialization step fails."""

    @pytest.mark.asyncio
    async def test_socks5_frontend_stopped_once_on_rollback(self):
        controller = MagicMock()
        controller.start = AsyncMock(return_value=MagicMock())
        controller.stop = AsyncMock()
        controller.metrics = MagicMock()

        frontend = MagicMock()
        frontend.start = AsyncMock()
        frontend.stop = AsyncMock()

        tun = MagicMock()
        tun.stop = AsyncMock(return_value=True)
        tun.recovery_state = CLEAN

        app = PerchVPNApp(
            WindowsConfig(
                explicit_proxy="1.2.3.4:1080",
                verify_exit=False,
                tun_enabled=True,
                tun_opt_in=True,
            )
        )

        async def fail_tun():
            app._tun_frontend = tun
            raise RuntimeError("tun failed")

        with patch.object(
            PerchVPNApp, "_obtain_auth", AsyncMock(return_value=MagicMock())
        ):
            with patch(
                "src.perchvpn_windows.app.ProxyController", return_value=controller
            ):
                with patch(
                    "src.perchvpn_windows.app.Socks5Frontend", return_value=frontend
                ):
                    with patch.object(app, "_start_tun_frontend", fail_tun):
                        with pytest.raises(RuntimeError):
                            await app.initialize()

        frontend.start.assert_awaited_once()
        frontend.stop.assert_awaited_once()
        tun.stop.assert_awaited_once()
        controller.stop.assert_awaited_once()
        assert app._frontend is None
        assert app._tun_frontend is None

    @pytest.mark.asyncio
    async def test_proxy_only_frontend_stopped_once_when_http_proxy_fails(self):
        frontend = MagicMock()
        frontend.start = AsyncMock()
        frontend.stop = AsyncMock()

        http_proxy = MagicMock()
        http_proxy.start = AsyncMock(side_effect=RuntimeError("http failed"))
        http_proxy.stop = AsyncMock()

        app = PerchVPNApp(
            WindowsConfig(proxy_only_mode=True, http_proxy_enabled=True)
        )

        with patch.object(
            PerchVPNApp, "_obtain_auth", AsyncMock(return_value=MagicMock())
        ):
            with patch(
                "src.perchvpn_windows.app.Socks5Frontend", return_value=frontend
            ):
                with patch(
                    "src.perchvpn_windows.app.HttpProxyServer",
                    return_value=http_proxy,
                ):
                    with pytest.raises(RuntimeError):
                        await app.initialize()

        frontend.start.assert_awaited_once()
        frontend.stop.assert_awaited_once()
        http_proxy.stop.assert_awaited_once()
        assert app._frontend is None
        assert app._http_proxy is None


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
