"""Responsiveness guarantees for lifecycle and latency-sweep endpoints.

A disconnect must answer even when elevated teardown is slow, and a burst of
country-row latency probes must never occupy the shared API worker pool.
"""

from __future__ import annotations

import asyncio
import threading
from types import SimpleNamespace

import pytest

import src.perchvpn_windows.api as api_module


@pytest.fixture(autouse=True)
def _reset_globals():
    original = (
        api_module._app,
        api_module._config,
        api_module._restart_task,
        api_module._bg_shutdown_task,
    )
    yield
    (
        api_module._app,
        api_module._config,
        api_module._restart_task,
        api_module._bg_shutdown_task,
    ) = original


class TestBoundedDisconnect:
    def test_slow_teardown_returns_and_continues_in_background(
        self, monkeypatch
    ):
        release = threading.Event()

        async def slow_shutdown() -> None:
            await asyncio.to_thread(release.wait, 5.0)

        app_obj = SimpleNamespace(shutdown=slow_shutdown)
        api_module._app = app_obj
        api_module._config = None
        api_module._restart_task = None
        api_module._bg_shutdown_task = None
        monkeypatch.setattr(
            api_module, "_DISCONNECT_HTTP_TIMEOUT_SECONDS", 0.1
        )
        monkeypatch.setattr(
            api_module, "broadcast_status", _noop_broadcast
        )

        async def run():
            body = await api_module.disconnect()
            deferred = api_module._bg_shutdown_task
            # Let the background teardown finish inside this loop so the
            # test never leaks a worker thread into the next test.
            release.set()
            await api_module._await_background_shutdown()
            return body, deferred

        body, deferred = asyncio.run(run())
        assert body["success"] is True
        assert "background" in body["detail"]
        assert deferred is not None
        assert api_module._bg_shutdown_task is None

    def test_background_teardown_is_awaited_and_cleared(self, monkeypatch):
        async def quick_shutdown() -> None:
            return None

        monkeypatch.setattr(api_module, "broadcast_status", _noop_broadcast)
        api_module._app = SimpleNamespace(shutdown=quick_shutdown)
        api_module._restart_task = None
        api_module._bg_shutdown_task = None

        async def run() -> dict:
            return await api_module.disconnect()

        body = asyncio.run(run())
        assert body["detail"] == "Disconnected"
        # Nothing was left half-torn-down behind the HTTP response.
        assert api_module._bg_shutdown_task is None

    def test_restart_waits_for_background_teardown(self, monkeypatch):
        finished = {"done": False}

        async def mark_done() -> None:
            await asyncio.sleep(0)
            finished["done"] = True

        loop = asyncio.new_event_loop()
        try:
            api_module._bg_shutdown_task = loop.create_task(mark_done())
            asyncio.set_event_loop(loop)
            loop.run_until_complete(api_module._await_background_shutdown())
            assert finished["done"] is True
            assert api_module._bg_shutdown_task is None
        finally:
            loop.close()
            asyncio.set_event_loop(None)


class TestIsolatedUrltestPool:
    def test_pass_minting_does_not_use_the_api_pool(self):
        def record() -> str:
            return threading.current_thread().name

        name = asyncio.run(api_module._run_in_urltest_pool(record))
        assert name.startswith("perchvpn-urltest")

    def test_urltest_endpoint_mints_on_the_isolated_pool(self):
        import inspect

        source = inspect.getsource(api_module.get_urltest)
        assert "_run_in_urltest_pool(_get_urltest_raw_token)" in source
        assert "_run_in_api_pool(_get_urltest_raw_token)" not in source


async def _noop_broadcast() -> None:
    return None
