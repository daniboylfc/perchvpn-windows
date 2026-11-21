"""Focused checks for the connection-mode switch (/api/mode), the URL ping
probe (/api/url-ping), and honest proxy-only status reporting (/api/status).

Like test_status_presentation.py, the endpoints are invoked directly (not
through a TestClient with a lifespan) because the real lifespan performs live
authentication and network calls.

Cases:
* /api/status reports "proxy_active" in proxy-only mode while the app serves,
  and "disconnected" after shutdown / failed initialization (stale
  "proxy_active" must never outlive its proxy).
* /api/mode persists exactly one of proxy_only/tun; the two flags stay mutually
  exclusive; invalid modes are rejected.
* /api/url-ping rejects non-http(s) targets, refuses via_proxy when the local
  proxy is not running, and otherwise measures time-to-first-byte through an
  httpx client — direct or routed through the configured (loopback) SOCKS5
  address with bind-host remapping of 0.0.0.0.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import httpx
import pytest
from pydantic import ValidationError
from unittest.mock import MagicMock

import src.perchvpn_windows.api as api_module
from src.perchvpn_windows.api import (
    ConnectionModeRequest,
    StatusResponse,
    UrlPingRequest,
)
from src.perchvpn_windows.config import WindowsConfig


@pytest.fixture(autouse=True)
def _reset_globals():
    """Ensure no test leaks global state into another."""
    original_app = api_module._app
    original_config = api_module._config
    yield
    api_module._app = original_app
    api_module._config = original_config


def _proxy_only_app(status_state: str) -> MagicMock:
    app_obj = MagicMock()
    app_obj._controller = None
    app_obj._status_state = status_state
    return app_obj


def _get_status(app_obj, config) -> dict:
    api_module._app = app_obj
    api_module._config = config
    return asyncio.run(api_module.get_status()).model_dump()


class TestProxyOnlyStatusHonest:
    def test_proxy_active_while_local_proxy_serves(self):
        app_obj = _proxy_only_app("proxy_active")
        config = WindowsConfig(proxy_only_mode=True)
        body = _get_status(app_obj, config)

        assert body["status"] == "proxy_active"
        assert body["proxy_only_mode"] is True
        assert body["exit_verification_state"] == "not_applicable"

    def test_disconnected_after_shutdown_or_failed_init(self):
        app_obj = _proxy_only_app("disconnected")
        config = WindowsConfig(proxy_only_mode=True)
        body = _get_status(app_obj, config)

        assert body["status"] == "disconnected"
        assert body["proxy_only_mode"] is True

    def test_tunnel_mode_ignores_stale_status_state(self):
        # A retained app in tunnel mode with no controller must always be
        # "disconnected" even if _status_state is stale.
        app_obj = _proxy_only_app("proxy_active")
        config = WindowsConfig(proxy_only_mode=False)
        body = _get_status(app_obj, config)

        assert body["status"] == "disconnected"

    def test_status_response_proxy_only_default_false(self):
        resp = StatusResponse(
            status="connected",
            uptime=0.0,
            socks5_addr="127.0.0.1:1080",
            exit_ip="0.0.0.0",
            country="--",
            transport="--",
            downloaded=0,
            uploaded=0,
            download_speed=0.0,
            upload_speed=0.0,
            active_connections=0,
        )
        assert resp.proxy_only_mode is False


class TestConnectionModeEndpoint:
    def _run_mode(self, mode: str, monkeypatch):
        saved: dict = {}

        config = WindowsConfig(proxy_only_mode=True, tun_enabled=False)

        monkeypatch.setattr(api_module, "load_config", lambda: config)
        monkeypatch.setattr(
            api_module,
            "save_config",
            lambda cfg: saved.update(proxy=cfg.proxy_only_mode, tun=cfg.tun_enabled),
        )
        request = ConnectionModeRequest(mode=mode)
        result = asyncio.run(api_module.set_connection_mode(request))
        return saved, result, config

    def test_mode_proxy_only(self, monkeypatch):
        saved, result, config = self._run_mode("proxy_only", monkeypatch)

        assert config.proxy_only_mode is True
        assert config.tun_enabled is False
        assert saved == {"proxy": True, "tun": False}
        assert result["mode"] == "proxy_only"
        assert result["proxy_only_mode"] is True
        assert result["tun_enabled"] is False

    def test_mode_tun(self, monkeypatch):
        # Prerequisites pass via the gate (opt-in assumed satisfied here; the
        # gate itself is covered by dedicated tests below).
        config = WindowsConfig(proxy_only_mode=False, tun_opt_in=True)
        monkeypatch.setattr(api_module, "load_config", lambda: config)
        monkeypatch.setattr(api_module, "_check_tun_prerequisites", lambda cfg: (True, ""))
        saved: dict = {}
        monkeypatch.setattr(
            api_module,
            "save_config",
            lambda cfg: saved.update(proxy=cfg.proxy_only_mode, tun=cfg.tun_enabled),
        )
        request = ConnectionModeRequest(mode="tun")
        result = asyncio.run(api_module.set_connection_mode(request))

        assert config.proxy_only_mode is False
        assert config.tun_enabled is True
        assert saved == {"proxy": False, "tun": True}
        assert result["mode"] == "tun"
        assert result["proxy_only_mode"] is False
        assert result["tun_enabled"] is True

    def test_mode_proxy_clears_both_flags(self, monkeypatch):
        saved, result, config = self._run_mode("proxy", monkeypatch)

        assert config.proxy_only_mode is False
        assert config.tun_enabled is False
        assert saved == {"proxy": False, "tun": False}
        assert result["mode"] == "proxy"
        assert result["applied"] is False

    def test_apply_runs_transactional_switch(self, monkeypatch):
        calls = []

        class FakeApp:
            async def apply_mode(self, target):
                calls.append(target)
                return {
                    "selected": target,
                    "active": target,
                    "transition": {"id": 3, "state": "complete", "detail": ""},
                }

        config = WindowsConfig(proxy_only_mode=False, tun_opt_in=True)
        monkeypatch.setattr(api_module, "load_config", lambda: config)
        monkeypatch.setattr(api_module, "save_config", lambda cfg: None)
        monkeypatch.setattr(api_module, "_app", FakeApp())
        monkeypatch.setattr(api_module, "_check_tun_prerequisites", lambda cfg: (True, ""))

        result = asyncio.run(
            api_module.set_connection_mode(ConnectionModeRequest(mode="tun", apply=True))
        )
        assert calls == ["tun"]
        assert result["applied"] is True
        assert result["success"] is True
        assert result["active"] == "tun"

    def test_apply_returns_early_while_engine_starts(self, monkeypatch):
        calls = []

        class FakeApp:
            async def begin_mode_apply(self, target):
                calls.append(target)
                return {
                    "selected": target,
                    "active": "proxy",
                    "transition": {
                        "id": 4,
                        "state": "verifying",
                        "detail": "Mode switch is still running",
                    },
                }

            async def apply_mode(self, target):  # pragma: no cover - must not run
                raise AssertionError("blocking apply_mode must not be awaited")

        config = WindowsConfig(proxy_only_mode=False, tun_opt_in=True)
        monkeypatch.setattr(api_module, "load_config", lambda: config)
        monkeypatch.setattr(api_module, "save_config", lambda cfg: None)
        monkeypatch.setattr(api_module, "_app", FakeApp())
        monkeypatch.setattr(api_module, "_check_tun_prerequisites", lambda cfg: (True, ""))

        result = asyncio.run(
            api_module.set_connection_mode(ConnectionModeRequest(mode="tun", apply=True))
        )
        assert calls == ["tun"]
        assert result["applied"] is False
        assert result["started"] is True
        assert result["success"] is True
        assert result["active"] == "proxy"

    def test_invalid_mode_rejected(self):
        with pytest.raises(ValidationError):
            ConnectionModeRequest(mode="bogus")

    def test_tun_mode_auto_opt_in_when_unset(self, monkeypatch):
        """The UI click is the opt-in itself: an unset tun_opt_in must be
        set (and persisted) by the endpoint, never reason for a 400."""
        saved: dict = {}
        config = WindowsConfig(
            proxy_only_mode=True, tun_enabled=False, tun_opt_in=False
        )
        monkeypatch.setattr(api_module, "load_config", lambda: config)
        monkeypatch.setattr(api_module, "_check_tun_prerequisites", lambda cfg: (True, ""))
        monkeypatch.setattr(
            api_module,
            "save_config",
            lambda cfg: saved.update(
                changed=True,
                tun_opt_in=cfg.tun_opt_in,
                tun_enabled=cfg.tun_enabled,
                proxy_only=cfg.proxy_only_mode,
            ),
        )

        result = asyncio.run(api_module.set_connection_mode(ConnectionModeRequest(mode="tun")))
        assert config.tun_opt_in is True
        assert config.tun_enabled is True
        assert config.proxy_only_mode is False
        assert saved == {
            "changed": True,
            "tun_opt_in": True,
            "tun_enabled": True,
            "proxy_only": False,
        }
        assert result["tun_opt_in"] is True
        assert result["tun_opt_in_auto_enabled"] is True

    def test_tun_mode_refused_when_sidecar_missing(self, monkeypatch):
        config = WindowsConfig(
            proxy_only_mode=True,
            tun_enabled=False,
            tun_opt_in=True,
            tun_executable_path="",
        )
        monkeypatch.setattr(api_module, "load_config", lambda: config)
        monkeypatch.setattr(api_module, "save_config", lambda cfg: None)

        with pytest.raises(api_module.HTTPException) as exc_info:
            asyncio.run(api_module.set_connection_mode(ConnectionModeRequest(mode="tun")))
        assert exc_info.value.status_code == 400
        assert "TUN sidecar not ready" in exc_info.value.detail

    def test_tun_mode_saved_when_prerequisites_pass(self, monkeypatch):
        # _check_tun_prerequisites is the platform-dependent gate (elevation,
        # sidecar resolution) — mock its positive outcome.
        monkeypatch.setattr(
            api_module, "_check_tun_prerequisites", lambda cfg: (True, "")
        )
        saved: dict = {}
        config = WindowsConfig(proxy_only_mode=True, tun_opt_in=True)
        monkeypatch.setattr(api_module, "load_config", lambda: config)
        monkeypatch.setattr(
            api_module,
            "save_config",
            lambda cfg: saved.update(proxy=cfg.proxy_only_mode, tun=cfg.tun_enabled),
        )

        result = asyncio.run(api_module.set_connection_mode(ConnectionModeRequest(mode="tun")))
        assert saved == {"proxy": False, "tun": True}
        assert result["tun_enabled"] is True


# ---------------------------------------------------------------------------
# /api/url-ping


class _FakeResponse:
    status_code = 200
    headers = {"content-type": "text/html"}


class _FakeStreamCtx:
    async def __aenter__(self):
        return _FakeResponse()

    async def __aexit__(self, *exc):
        return False


class _FakeAsyncClient:
    calls: list = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        _FakeAsyncClient.calls.append(kwargs)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def stream(self, method, url):
        _FakeAsyncClient.calls.append({"method": method, "url": url})
        return _FakeStreamCtx()


class TestUrlPingEndpoint:
    def setup_method(self):
        _FakeAsyncClient.calls = []

    def test_rejects_non_http_scheme(self):
        with pytest.raises(api_module.HTTPException) as exc_info:
            asyncio.run(api_module.url_ping(UrlPingRequest(url="ftp://example.com")))
        assert exc_info.value.status_code == 400

    def test_rejects_relative_url(self):
        with pytest.raises(api_module.HTTPException) as exc_info:
            asyncio.run(api_module.url_ping(UrlPingRequest(url="/just-a-path")))
        assert exc_info.value.status_code == 400

    def test_via_proxy_refused_when_frontend_down(self):
        api_module._app = None
        with pytest.raises(api_module.HTTPException) as exc_info:
            asyncio.run(api_module.url_ping(
                UrlPingRequest(url="https://example.com", via_proxy=True)
            ))
        assert exc_info.value.status_code == 409

    def test_direct_ping_success(self, monkeypatch):
        monkeypatch.setattr(httpx, "AsyncClient", _FakeAsyncClient)
        request = UrlPingRequest(url="https://example.com", via_proxy=False)
        result = asyncio.run(api_module.url_ping(request))

        assert result["success"] is True
        assert result["status_code"] == 200
        assert isinstance(result["elapsed_ms"], int)
        assert result["url"] == "https://example.com"
        assert result["via_proxy"] is False
        assert "proxy" not in _FakeAsyncClient.calls[0]
        proxyless = [c for c in _FakeAsyncClient.calls if "url" in c]
        assert proxyless[0]["url"] == "https://example.com"

    def test_via_proxy_routes_through_configured_socks5(self, monkeypatch):
        monkeypatch.setattr(httpx, "AsyncClient", _FakeAsyncClient)
        api_module._app = MagicMock(_frontend=MagicMock())
        api_module._config = SimpleNamespace(listen_host="0.0.0.0", listen_port=18983)
        request = UrlPingRequest(url="https://example.com", via_proxy=True)
        result = asyncio.run(api_module.url_ping(request))

        assert result["success"] is True
        assert result["via_proxy"] is True
        client_kwargs = _FakeAsyncClient.calls[0]
        assert client_kwargs["proxy"] == "socks5://127.0.0.1:18983"

    def test_ping_failure_maps_to_504(self, monkeypatch):
        class _FailingClient(_FakeAsyncClient):
            def stream(self, method, url):
                raise httpx.ConnectError("connection refused")

        monkeypatch.setattr(httpx, "AsyncClient", _FailingClient)
        with pytest.raises(api_module.HTTPException) as exc_info:
            asyncio.run(api_module.url_ping(UrlPingRequest(url="https://10.255.255.1/")))
        assert exc_info.value.status_code == 504


# ---------------------------------------------------------------------------
# /api/urltest — per-city Clash-style URL test through the edge relay


class _FakeH2Stream:
    def __init__(self, payload: bytes):
        self._payload = payload
        self.written: list[bytes] = []

    async def write(self, data: bytes) -> None:
        self.written.append(data)

    async def read(self) -> bytes:
        return self._payload


class _FakeH2Session:
    """Mimics H2ProxySession's connect/open_stream/close contract."""

    instances: list = []
    fail_connect: bool = False

    def __init__(self, host: str, port: int, token: str, **kwargs):
        self.host = host
        self.port = port
        self.token = token
        self.kwargs = kwargs
        self.closed = False
        _FakeH2Session.instances.append(self)

    async def connect(self, timeout: float = 10.0) -> None:
        await asyncio.sleep(0.005)  # measurable-ish probe timing
        if _FakeH2Session.fail_connect:
            raise RuntimeError("handshake failed")

    async def open_stream(self, target_host: str, target_port: int, metrics=None):
        assert target_host == "www.gstatic.com"
        assert target_port == 80
        return _FakeH2Stream(b"HTTP/1.1 204 No Content\r\n\r\n")

    async def close(self) -> None:
        self.closed = True


class TestUrlTestEndpoint:
    def setup_method(self):
        api_module._urltest_pass_cache = {"token": None, "at": 0.0}
        _FakeH2Session.instances = []
        _FakeH2Session.fail_connect = False

    def _setup_app_and_guardian(self, monkeypatch):
        app_obj = MagicMock()
        app_obj._source_bind_ip = None
        app_obj._controller = None
        app_obj._runtime_auth = SimpleNamespace(access_token="oauth-token")
        api_module._app = app_obj
        api_module._config = WindowsConfig(listen_host="127.0.0.1", listen_port=1080)

        monkeypatch.setattr(
            "perchvpn.guardian.fetch_proxy_pass",
            lambda endpoint, access_token: SimpleNamespace(raw_token="pass-token"),
        )
        monkeypatch.setattr(
            "perchvpn.proxy.session.H2ProxySession", _FakeH2Session
        )

    def test_rejects_invalid_target(self, monkeypatch):
        self._setup_app_and_guardian(monkeypatch)
        with pytest.raises(api_module.HTTPException) as exc_info:
            asyncio.run(api_module.get_urltest(host="", port=2499))
        assert exc_info.value.status_code == 400
        with pytest.raises(api_module.HTTPException) as exc_info:
            asyncio.run(api_module.get_urltest(host="edge", port=0))
        assert exc_info.value.status_code == 400

    def test_success_measures_through_relay(self, monkeypatch):
        self._setup_app_and_guardian(monkeypatch)
        result = asyncio.run(api_module.get_urltest(host="edge1", port=2499))

        assert result["success"] is True
        assert result["host"] == "edge1"
        assert result["elapsed_ms"] > 0
        session = _FakeH2Session.instances[0]
        assert session.token == "pass-token"
        assert session.closed is True

    def test_proxy_pass_fetched_once_per_cycle(self, monkeypatch):
        self._setup_app_and_guardian(monkeypatch)
        calls: list = []

        def _fetch(endpoint, access_token):
            calls.append(access_token)
            return SimpleNamespace(raw_token="pass-token")

        monkeypatch.setattr("perchvpn.guardian.fetch_proxy_pass", _fetch)
        asyncio.run(api_module.get_urltest(host="edge1", port=2499))
        asyncio.run(api_module.get_urltest(host="edge2", port=2499))
        # One pass for the whole countries-refresh cycle.
        assert len(calls) == 1

    def test_handshake_failure_maps_to_504(self, monkeypatch):
        self._setup_app_and_guardian(monkeypatch)
        _FakeH2Session.fail_connect = True
        with pytest.raises(api_module.HTTPException) as exc_info:
            asyncio.run(api_module.get_urltest(host="edge1", port=2499))
        assert exc_info.value.status_code == 504
        # The throwaway session is always closed.
        assert _FakeH2Session.instances[0].closed is True

    def test_requires_initialized_app(self, monkeypatch):
        api_module._app = None
        with pytest.raises(api_module.HTTPException) as exc_info:
            asyncio.run(api_module.get_urltest(host="edge1", port=2499))
        assert exc_info.value.status_code == 503

    def test_requires_runtime_auth_for_pass_fetch(self, monkeypatch):
        app_obj = MagicMock(_controller=None, _runtime_auth=None, _source_bind_ip=None)
        api_module._app = app_obj
        api_module._config = WindowsConfig()
        with pytest.raises(api_module.HTTPException) as exc_info:
            asyncio.run(api_module.get_urltest(host="edge1", port=2499))
        assert exc_info.value.status_code == 503
        assert "signed in" in exc_info.value.detail

    def test_reuses_live_controller_pass(self, monkeypatch):
        # Tunnel mode: no guardian fetch at all.
        controller = MagicMock(proxy_pass=SimpleNamespace(raw_token="live-pass"))
        app_obj = MagicMock(_controller=controller, _source_bind_ip=None)
        api_module._app = app_obj
        api_module._config = WindowsConfig()
        monkeypatch.setattr("perchvpn.proxy.session.H2ProxySession", _FakeH2Session)

        def _fail_fetch(endpoint, access_token):
            raise AssertionError("guardian must not be contacted when a pass is live")

        monkeypatch.setattr("perchvpn.guardian.fetch_proxy_pass", _fail_fetch)
        result = asyncio.run(api_module.get_urltest(host="edge1", port=2499))
        assert result["success"] is True
        assert _FakeH2Session.instances[0].token == "live-pass"
