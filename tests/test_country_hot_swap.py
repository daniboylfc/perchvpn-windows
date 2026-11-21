"""Country hot-swap: exchange the upstream without restarting the listener.

The old path tore down the whole app (SOCKS5 listener + TUN forwarding) and
re-ran auth/DoH/Guardian, which blocked the API for ~13 s. These tests pin the
new contract: the switch returns immediately, the listener is untouched, only
the pool is swapped, and superseded switches can never publish state.
"""

from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from perchvpn import guardian
from perchvpn.controller import ControllerConfig, ProxyController
from perchvpn.proxy.pool import SessionPool
from perchvpn.proxystate import ProxyCandidate
from perchvpn_windows.app import PerchVPNApp
from perchvpn_windows.config import WindowsConfig
from src.perchvpn_windows import api as api_module


class FakePool:
    def __init__(self, name="pool"):
        self.name = name
        self.closed = False

    async def close(self):
        self.closed = True


class FakeController:
    instances: list = []

    def __init__(self, config, auth):
        self.config = config
        self.pool = FakePool("pool-%d" % len(FakeController.instances))
        self.metrics = SimpleNamespace(
            downloaded=0, uploaded=0, download_speed=0.0,
            upload_speed=0.0, active_connections=0,
        )
        self.current_candidate = config.candidate
        self.status = "ok"
        self.uptime = 1.0
        self.transport = "http2"
        self.proxy_pass = SimpleNamespace(raw_token="reused-token")
        self.initial_pass = "unset"
        self.stopped = False
        FakeController.instances.append(self)

    async def start(self, initial_pass=None):
        self.initial_pass = initial_pass
        return self.pool

    async def stop(self):
        self.stopped = True


class FakeFrontend:
    def __init__(self):
        self.pools: list = []

    def set_pool(self, pool, metrics=None):
        self.pools.append((pool, metrics))


@pytest.fixture(autouse=True)
def _clean_instances():
    FakeController.instances.clear()
    yield
    FakeController.instances.clear()


def _app() -> PerchVPNApp:
    app = object.__new__(PerchVPNApp)
    app.config = WindowsConfig(
        country="BE",
        verify_exit=False,
        resolver_dns_provider="system",
    )
    old = FakeController(SimpleNamespace(candidate=ProxyCandidate("203.0.113.1", 443, "be", "Belgium")), None)
    app._controller = old
    app._pool = old.pool
    app._frontend = FakeFrontend()
    app._http_proxy = None
    app._candidate = old.current_candidate
    app._runtime_auth = MagicMock()
    app._source_bind_ip = None
    app._resolved_edge_host = None
    app._exit_check_task = None
    app._exit_ip = "0.0.0.0"
    app._exit_country = "--"
    app._exit_verification_state = "verified"
    app._tun_frontend = None
    app._tun_baseline = None
    app._switch_id = 0
    app._switch_task = None
    app._switch_state = "idle"
    app._switch_target = ""
    app._switch_started_at = 0.0
    app._switch_duration_ms = 0.0
    app._switch_phases = []
    app._switch_error = ""
    app._drain_old_upstream = AsyncMock()
    app._tun_helper = None
    return app


def _patch_switch_deps(monkeypatch, target: ProxyCandidate):
    countries = [SimpleNamespace(code="SE", name="Sweden")]
    monkeypatch.setattr(
        "perchvpn_windows.app.serverlist.fetch_server_list", lambda _p: countries
    )
    monkeypatch.setattr(
        "perchvpn_windows.app.resolve_proxy", lambda *a, **k: (target, False)
    )
    monkeypatch.setattr(
        "perchvpn_windows.app.alternate_candidates", lambda *a, **k: []
    )
    monkeypatch.setattr("perchvpn_windows.app.ProxyController", FakeController)
    monkeypatch.setattr("perchvpn_windows.app.ProxyStateStore", lambda _p: None)
    monkeypatch.setattr(
        "perchvpn_windows.config.load_config", lambda: WindowsConfig()
    )
    monkeypatch.setattr("perchvpn_windows.config.save_config", lambda _c: None)


def _target() -> ProxyCandidate:
    return ProxyCandidate("198.51.100.7", 443, "se", "Sweden")


class TestHotSwap:
    def test_switch_requires_live_components(self):
        app = _app()
        app._frontend = None
        assert app.can_hot_swap() is False
        app._frontend = FakeFrontend()
        assert app.can_hot_swap() is True

    @pytest.mark.asyncio
    async def test_swap_keeps_listener_and_reuses_pass(self, monkeypatch):
        app = _app()
        _patch_switch_deps(monkeypatch, _target())
        old_controller = app._controller

        result = app.begin_country_switch("se")
        assert result["mode"] == "hot_swap"
        assert result["switch_id"] == 1
        assert app._switch_state == "switching"

        await app._switch_task

        assert app._switch_state == "complete"
        assert app._controller is not old_controller
        assert app._pool is app._controller.pool
        assert app._frontend.pools[-1][0] is app._pool
        assert app._controller.initial_pass is old_controller.proxy_pass
        assert app._candidate.country_code == "se"
        assert [p["phase"] for p in app._switch_phases][:5] == [
            "plan", "resolve", "pin_upstream", "dial", "swap",
        ]

    @pytest.mark.asyncio
    async def test_superseded_switch_never_swaps(self, monkeypatch):
        app = _app()
        _patch_switch_deps(monkeypatch, _target())
        old_controller = app._controller

        app.begin_country_switch("se")
        app._switch_id += 1  # newer request wins before the dial completes

        await app._switch_task

        assert app._switch_state == "stale"
        assert app._controller is old_controller
        assert app._frontend.pools == []

    @pytest.mark.asyncio
    async def test_failure_keeps_the_old_upstream(self, monkeypatch):
        app = _app()
        _patch_switch_deps(monkeypatch, _target())
        old_controller = app._controller

        class Boom(FakeController):
            async def start(self, initial_pass=None):
                raise RuntimeError("dial refused")

        monkeypatch.setattr("perchvpn_windows.app.ProxyController", Boom)

        app.begin_country_switch("se")
        await app._switch_task

        assert app._switch_state == "failed"
        assert "dial refused" in app._switch_error
        assert app._controller is old_controller
        assert app._frontend.pools == []

    @pytest.mark.asyncio
    async def test_status_exposes_switch_report(self, monkeypatch):
        app = _app()
        _patch_switch_deps(monkeypatch, _target())
        api_module._app = app
        api_module._config = app.config

        app.begin_country_switch("se")
        await app._switch_task

        body = (await api_module.get_status()).model_dump()
        assert body["switch"]["id"] == 1
        assert body["switch"]["state"] == "complete"
        assert body["switch"]["target"] == "SE"
        assert body["switch"]["in_progress"] is False


class TestCountryEndpointHotPath:
    def test_country_request_returns_immediately(self, monkeypatch):
        fake_app = MagicMock()
        fake_app.can_hot_swap.return_value = True
        fake_app.begin_country_switch.return_value = {
            "mode": "hot_swap", "switch_id": 3, "target": "SE",
        }
        fake_app.config = WindowsConfig()
        monkeypatch.setattr(api_module, "_app", fake_app)
        monkeypatch.setattr(api_module, "_config", fake_app.config)
        monkeypatch.setattr(
            api_module, "_cached_countries",
            lambda allow_refresh=True: [SimpleNamespace(code="SE", name="Sweden", cities=[])],
        )

        started = time.monotonic()
        result = asyncio.run(
            api_module.set_country(api_module.CountrySelection(country_code="se"))
        )
        elapsed = time.monotonic() - started

        assert result["mode"] == "hot_swap"
        assert result["switch_id"] == 3
        assert elapsed < 0.5
        assert fake_app.begin_country_switch.call_args.args[0] == "SE"
        fake_app.shutdown.assert_not_called()


class TestCountryHotPathAdapterIsolation:
    def test_hot_switch_never_inspects_adapters(self, monkeypatch):
        from perchvpn_windows import tun_helper
        from perchvpn_windows import tun_state_capture

        def fail(*args, **kwargs):
            raise AssertionError("proxy country switch inspected adapters/routes")

        monkeypatch.setattr(tun_state_capture, "detect_physical_egress", fail)
        monkeypatch.setattr(tun_helper, "capture_adapter_dns", fail)
        monkeypatch.setattr(tun_helper, "find_route_interface", fail)
        fake_app = MagicMock()
        fake_app.can_hot_swap.return_value = True
        fake_app.begin_country_switch.return_value = {
            "mode": "hot_swap", "switch_id": 9, "target": "SE",
        }
        fake_app.config = WindowsConfig()
        monkeypatch.setattr(api_module, "_app", fake_app)
        monkeypatch.setattr(api_module, "_config", fake_app.config)
        monkeypatch.setattr(
            api_module, "_cached_countries",
            lambda allow_refresh=True: [SimpleNamespace(code="SE", name="Sweden", cities=[])],
        )

        result = asyncio.run(
            api_module.set_country(api_module.CountrySelection(country_code="se"))
        )

        assert result["mode"] == "hot_swap"
        assert result["switch_id"] == 9
        fake_app.begin_country_switch.assert_called_once()
        fake_app.shutdown.assert_not_called()


class TestControllerPassReuse:
    def _controller(self) -> ProxyController:
        config = ControllerConfig(
            guardian_endpoint="https://guardian.example",
            candidate=ProxyCandidate("198.51.100.7", 443, "se", "Sweden"),
            upstream_conns=1,
            handshake_timeout=0.01,
        )
        return ProxyController(config, MagicMock())

    @pytest.mark.asyncio
    async def test_valid_pass_skips_guardian_round_trip(self, monkeypatch):
        ctrl = self._controller()
        now = time.time()
        pass_info = guardian.ProxyPassInfo(
            raw_token="tok",
            claims=guardian.ProxyPassClaims(nbf=int(now) - 10, exp=int(now) + 3600),
        )
        acquired = []

        async def fake_acquire():
            acquired.append(True)

        async def pool_start(_self):
            _self._sessions = []

        monkeypatch.setattr(ctrl, "_acquire_initial_pass", fake_acquire)
        monkeypatch.setattr(SessionPool, "start", pool_start)
        monkeypatch.setattr(ctrl, "_write_status_file", AsyncMock())

        await ctrl.start(initial_pass=pass_info)

        assert acquired == []
        assert ctrl.proxy_pass is pass_info
        await ctrl.stop()

    @pytest.mark.asyncio
    async def test_expired_pass_is_never_reused(self, monkeypatch):
        ctrl = self._controller()
        now = time.time()
        pass_info = guardian.ProxyPassInfo(
            raw_token="old",
            claims=guardian.ProxyPassClaims(nbf=int(now) - 100, exp=int(now) - 1),
        )
        acquired = []

        async def fake_acquire():
            acquired.append(True)
            ctrl.proxy_pass = SimpleNamespace(raw_token="fresh")

        async def pool_start(_self):
            _self._sessions = []

        monkeypatch.setattr(ctrl, "_acquire_initial_pass", fake_acquire)
        monkeypatch.setattr(SessionPool, "start", pool_start)
        monkeypatch.setattr(ctrl, "_write_status_file", AsyncMock())

        await ctrl.start(initial_pass=pass_info)

        assert acquired == [True]
        assert ctrl.proxy_pass.raw_token == "fresh"
        await ctrl.stop()


class FakeTunHelper:
    def __init__(self, phase="ready"):
        self.phase = phase
        self.updates: list = []
        self.prunes: list = []

    def snapshot(self):
        return {"phase": self.phase, "adapter": "PerchVPN"}

    async def update_bypass(
        self, ips, *, persist=(), prune=False, version=None, timeout=20.0
    ):
        if prune:
            self.prunes.append((list(ips), list(persist)))
        else:
            self.updates.append(list(ips))
        return {"phase": "ready", "bypass_version": 1}


class TestHotSwapPinsBeforeDial:
    @pytest.mark.asyncio
    async def test_new_edge_is_pinned_before_the_guardian_dials(self, monkeypatch):
        app = _app()
        helper = FakeTunHelper()
        app._tun_helper = helper
        events: list = []
        _patch_switch_deps(monkeypatch, _target())

        class OrderedController(FakeController):
            async def start(self, initial_pass=None):
                events.append("dial")
                return await super().start(initial_pass)

        monkeypatch.setattr("perchvpn_windows.app.ProxyController", OrderedController)
        original_update = helper.update_bypass

        async def update(ips, *, persist=(), prune=False, version=None, timeout=20.0):
            events.append("prune" if prune else "pin")
            return await original_update(
                ips, persist=persist, prune=prune, version=version, timeout=timeout
            )

        helper.update_bypass = update

        app.begin_country_switch("se")
        await app._switch_task

        assert events[:2] == ["pin", "dial"]
        assert events[2:] in ([], ["prune"])
        assert "198.51.100.7" in helper.updates[0]

    @pytest.mark.asyncio
    async def test_unpinnable_edge_refuses_to_dial_through_the_tun(self, monkeypatch):
        app = _app()
        app._tun_helper = FakeTunHelper()
        before = len(FakeController.instances)
        hostname = ProxyCandidate("", 443, "se", "Sweden")
        _patch_switch_deps(monkeypatch, hostname)

        app.begin_country_switch("se")
        await app._switch_task

        assert app._switch_state == "failed"
        assert "refusing to dial through the tunnel" in app._switch_error
        assert len(FakeController.instances) == before

    @pytest.mark.asyncio
    async def test_no_pin_when_tun_is_not_active(self, monkeypatch):
        app = _app()
        helper = FakeTunHelper(phase="failed")
        app._tun_helper = helper
        _patch_switch_deps(monkeypatch, _target())

        app.begin_country_switch("se")
        await app._switch_task

        assert app._switch_state == "complete"
        assert helper.updates == []

    @pytest.mark.asyncio
    async def test_switch_during_tun_startup_refuses_to_dial(self, monkeypatch):
        app = _app()
        app._tun_pin_wait = 0.0
        helper = FakeTunHelper(phase="starting")
        app._tun_helper = helper
        before = len(FakeController.instances)
        _patch_switch_deps(monkeypatch, _target())

        app.begin_country_switch("se")
        await app._switch_task

        assert app._switch_state == "failed"
        assert "still starting" in app._switch_error
        assert helper.updates == []
        assert len(FakeController.instances) == before


class TestUpstreamPinLifecycle:
    @pytest.mark.asyncio
    async def test_three_hot_swaps_prune_only_the_superseded_endpoint(self, monkeypatch):
        app = _app()
        helper = FakeTunHelper()
        app._tun_helper = helper
        endpoints = [
            ("us", "198.51.100.1"),
            ("fi", "198.51.100.2"),
            ("de", "198.51.100.3"),
        ]
        for code, host in endpoints:
            _patch_switch_deps(
                monkeypatch, ProxyCandidate(host, 443, code, code.upper())
            )
            app.begin_country_switch(code)
            await app._switch_task
            await asyncio.sleep(0.05)
            assert app._switch_state == "complete"

        # One pin update before each dial, one prune after each swap.
        assert [update for update in helper.updates] == [
            [host] for _code, host in endpoints
        ]
        assert [keep for keep, _persist in helper.prunes] == [
            [host] for _code, host in endpoints
        ]
        assert helper.prunes[-1][1] == []

    @pytest.mark.asyncio
    async def test_failed_switch_prunes_only_the_candidate_pins(self, monkeypatch):
        app = _app()
        helper = FakeTunHelper()
        app._tun_helper = helper
        _patch_switch_deps(monkeypatch, _target())

        class RefusingController(FakeController):
            async def start(self, initial_pass=None):
                events.append("dial")
                raise RuntimeError("dial refused")

        events: list = []
        monkeypatch.setattr("perchvpn_windows.app.ProxyController", RefusingController)

        app.begin_country_switch("se")
        await app._switch_task

        assert app._switch_state == "failed"
        assert "dial refused" in app._switch_error
        # The candidate was pinned before the dial, then pruned back to the
        # previous country's endpoint set.
        assert helper.updates[0] == ["198.51.100.7"]
        assert helper.prunes == [(["203.0.113.1"], [])]

    @pytest.mark.asyncio
    async def test_prune_runs_after_the_old_upstream_is_drained(self, monkeypatch):
        app = _app()
        helper = FakeTunHelper()
        app._tun_helper = helper
        events: list = []

        async def drain(controller, pool):
            events.append("drain")

        app._drain_old_upstream = drain
        original = helper.update_bypass

        async def update(ips, *, persist=(), prune=False, version=None, timeout=20.0):
            if prune:
                events.append("prune")
            return await original(
                ips, persist=persist, prune=prune, version=version, timeout=timeout
            )

        helper.update_bypass = update
        _patch_switch_deps(monkeypatch, _target())
        app.begin_country_switch("se")
        await app._switch_task
        await asyncio.sleep(0.05)
        assert events == ["drain", "prune"]
