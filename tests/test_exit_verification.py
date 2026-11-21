"""Focused tests for exit-location verification lifecycle."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.perchvpn_windows.app import PerchVPNApp
from src.perchvpn_windows.config import WindowsConfig
import src.perchvpn_windows.app as app_module


@pytest.mark.asyncio
async def test_exit_check_disabled_is_not_applicable():
    app = PerchVPNApp(WindowsConfig(verify_exit=False))
    app._candidate = MagicMock(country_code="GB")
    verify = AsyncMock(return_value=("1.2.3.4", "GB"))
    with patch.object(app_module, "verify_exit_country", verify):
        await app._run_exit_check("socks5://127.0.0.1:1080")
    assert app._exit_verification_state == "not_applicable"
    verify.assert_not_awaited()


@pytest.mark.asyncio
async def test_exit_check_missing_country_is_not_applicable():
    app = PerchVPNApp(WindowsConfig(verify_exit=True))
    app._candidate = MagicMock(country_code="")
    verify = AsyncMock(return_value=("1.2.3.4", "GB"))
    with patch.object(app_module, "verify_exit_country", verify):
        await app._run_exit_check("socks5://127.0.0.1:1080")
    assert app._exit_verification_state == "not_applicable"
    verify.assert_not_awaited()


@pytest.mark.asyncio
async def test_exit_check_success_sets_verified():
    app = PerchVPNApp(WindowsConfig(verify_exit=True))
    app._candidate = MagicMock(country_code="GB")
    verify = AsyncMock(return_value=("203.0.113.9", "GB"))
    with patch.object(app_module, "verify_exit_country", verify):
        await app._run_exit_check("socks5://127.0.0.1:1080")
    assert app._exit_verification_state == "verified"
    assert app._exit_ip == "203.0.113.9"
    assert app._exit_country == "GB"


@pytest.mark.asyncio
async def test_exit_check_mismatch_sets_failed():
    app = PerchVPNApp(WindowsConfig(verify_exit=True))
    app._candidate = MagicMock(country_code="GB")
    verify = AsyncMock(return_value=("203.0.113.9", "US"))
    with patch.object(app_module, "verify_exit_country", verify):
        await app._run_exit_check("socks5://127.0.0.1:1080")
    assert app._exit_verification_state == "failed"


@pytest.mark.asyncio
async def test_exit_check_probe_failure_sets_failed():
    app = PerchVPNApp(WindowsConfig(verify_exit=True))
    app._candidate = MagicMock(country_code="GB")
    verify = AsyncMock(return_value=None)
    with patch.object(app_module, "verify_exit_country", verify):
        await app._run_exit_check("socks5://127.0.0.1:1080")
    assert app._exit_verification_state == "failed"


@pytest.mark.asyncio
async def test_exit_check_scheduled_after_successful_initialize(tmp_path, monkeypatch):
    monkeypatch.setenv("APPDATA", str(tmp_path))
    import perchvpn.auth as auth_module
    from src.perchvpn_windows.app import ProxyController, Socks5Frontend

    metrics = MagicMock()
    pool = MagicMock()
    controller = MagicMock()
    controller.start = AsyncMock(return_value=pool)
    controller.metrics = metrics
    controller.current_candidate = MagicMock(country_code="GB")

    app = PerchVPNApp(WindowsConfig(explicit_proxy="1.2.3.4:1080", country="GB", verify_exit=True))

    fe_instance = MagicMock()
    fe_instance.start = AsyncMock()

    verify = AsyncMock(return_value=("203.0.113.9", "GB"))
    with patch.object(auth_module, "obtain_auth", return_value=MagicMock()):
        with patch("src.perchvpn_windows.app.ProxyController", return_value=controller):
            with patch("src.perchvpn_windows.app.Socks5Frontend", return_value=fe_instance):
                with patch.object(app_module, "verify_exit_country", verify):
                    await app.initialize()
                    assert app._exit_check_task is not None
                    await app._exit_check_task
                    assert app._exit_verification_state == "verified"


@pytest.mark.asyncio
async def test_exit_check_cancelled_during_shutdown():
    app = PerchVPNApp(WindowsConfig(verify_exit=True))
    app._controller = MagicMock()
    app._controller.stop = AsyncMock()
    app._frontend = AsyncMock()
    app._pool = MagicMock()
    app._exit_check_task = asyncio.create_task(asyncio.sleep(10))

    await app.shutdown()

    assert app._exit_check_task is None
    assert app._controller is None
    assert app._frontend is None

def test_local_proxy_url_uses_socks5h():
    app = PerchVPNApp(WindowsConfig(listen_host="127.0.0.1", listen_port=1080))
    assert app._local_proxy_url() == "socks5h://127.0.0.1:1080"


@pytest.mark.asyncio
async def test_pool_replaced_clears_failed_latch_and_reverifies():
    app = PerchVPNApp(WindowsConfig(verify_exit=True))
    app._candidate = MagicMock(country_code="GB")
    app._frontend = MagicMock()
    app._controller = MagicMock(metrics=MagicMock())
    app._exit_verification_state = "failed"
    verify = AsyncMock(return_value=("203.0.113.9", "GB"))
    with patch.object(app_module, "verify_exit_country", verify):
        await app._repoint_frontend_pool(object())
        # The pre-fallback "failed" latch is cleared immediately...
        assert app._exit_verification_state == "pending"
        assert app._frontend.set_pool.called
        # ...and the re-check resolves against the replacement pool.
        await app._exit_check_task
    assert app._exit_verification_state == "verified"
    assert app._exit_ip == "203.0.113.9"


@pytest.mark.asyncio
async def test_close_storm_fallback_reverifies_exit():
    # Full fallback path: h1 close storm -> controller rebuilds the pool on
    # http2 -> on_pool_replaced repoints the frontend and re-schedules the
    # exit check, so the UI EXIT INFORMATION card flips failed -> verified.
    import src.perchvpn.controller as controller_module
    from src.perchvpn.controller import ControllerConfig, ProxyController
    from src.perchvpn.proxystate import ProxyCandidate

    config = ControllerConfig(
        guardian_endpoint="https://guardian.example",
        candidate=ProxyCandidate("203.0.113.7", 443, "gb", "United Kingdom"),
        upstream_conns=2,
        handshake_timeout=5.0,
        transport_version="h1",
    )
    controller = object.__new__(ProxyController)
    controller.config = config
    controller.proxy_pass = None
    controller.auth = MagicMock(access_token_expired=MagicMock(return_value=False))
    controller.pool = None
    controller.accepting = False
    controller._reason = "starting"
    controller._tasks = []
    controller._stopped = asyncio.Event()
    controller._started_at = None
    controller._metrics = None
    controller._candidates = [config.candidate]
    controller._candidate_index = 0
    controller._auth_lock = asyncio.Lock()
    controller._effective_transport = config.transport_version
    controller._effective_use_http3 = config.use_http3
    controller._transport_fallback_in_progress = False
    controller.on_pool_replaced = None

    app = PerchVPNApp(WindowsConfig(verify_exit=True))
    app._candidate = MagicMock(country_code="GB")
    app._frontend = MagicMock()
    app._controller = MagicMock(metrics=MagicMock())
    app._exit_verification_state = "failed"
    controller.on_pool_replaced = app._repoint_frontend_pool

    old_pool = MagicMock()
    old_pool.close = AsyncMock()
    controller.pool = old_pool
    replacement = MagicMock()
    replacement.start = AsyncMock()
    replacement.close = AsyncMock()

    verify = AsyncMock(return_value=("203.0.113.9", "GB"))
    with patch.object(
        controller_module, "SessionPool", lambda *a, **kw: replacement
    ), patch.object(app_module, "verify_exit_country", verify):
        await controller._handle_close_storm()

        assert controller._effective_transport == "h2"
        assert app._exit_verification_state == "pending"
        assert app._frontend.set_pool.called
        await app._exit_check_task

    assert app._exit_verification_state == "verified"
    assert app._exit_ip == "203.0.113.9"
    old_pool.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_verify_exit_country_normalizes_socks5_to_socks5h(monkeypatch):
    import perchvpn.exitcheck as exitcheck_module

    captured_proxy = None

    class FakeAsyncClient:
        def __init__(self, proxy=None, timeout=None):
            nonlocal captured_proxy
            captured_proxy = proxy

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        def stream(self, method, url, headers=None):
            class FakeStream:
                async def __aenter__(self):
                    resp = MagicMock()
                    resp.status_code = 200

                    async def fake_aiter():
                        yield b"ip=203.0.113.9\nloc=GB\n"

                    resp.aiter_bytes = fake_aiter
                    return resp

                async def __aexit__(self, *args):
                    pass

            return FakeStream()

    monkeypatch.setattr(exitcheck_module.httpx, "AsyncClient", FakeAsyncClient)
    res = await exitcheck_module.verify_exit_country("socks5://127.0.0.1:1080", "GB")
    assert res == ("203.0.113.9", "GB")
    assert captured_proxy == "socks5h://127.0.0.1:1080"
