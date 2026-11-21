"""Unified-delay /api/urltest semantics.

The probe must measure the surgical Stage-2 round trip of /generate_204
over a warm keep-alive tunnel — NOT the cold handshake and never the
Guardian pass minting (which is TTL-cached) — falling back to the
Cloudflare target when gstatic fails end-to-end.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import src.perchvpn_windows.api as api_module
from perchvpn.exceptions import ProxyError
from src.perchvpn_windows.config import WindowsConfig


class _KeepAliveStream:
    def __init__(self, payload=b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"):
        self.written: list[bytes] = []
        self._payload = payload

    async def write(self, data: bytes) -> None:
        self.written.append(data)

    async def read(self) -> bytes:
        return self._payload


class _KeepAliveSession:
    """Fails the primary gstatic target once, then serves every target."""

    instances: list = []
    streams: list = []
    fail_primary: bool = False
    payload: bytes = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"

    def __init__(self, host: str, port: int, token: str, **kwargs):
        self.host = host
        self.port = port
        self.token = token
        self.kwargs = kwargs
        self.closed = False
        _KeepAliveSession.instances.append(self)

    async def connect(self, timeout: float = 10.0) -> None:
        pass

    async def open_stream(self, target_host: str, target_port: int, metrics=None):
        if (
            _KeepAliveSession.fail_primary
            and target_host == "www.gstatic.com"
            and len(_KeepAliveSession.streams) == 0
        ):
            raise ProxyError("gstatic blocked")
        stream = _KeepAliveStream(_KeepAliveSession.payload)
        _KeepAliveSession.streams.append((self, target_host, target_port, stream))
        return stream

    async def close(self) -> None:
        self.closed = True


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    api_module._urltest_pass_cache = {"token": None, "at": 0.0}
    _KeepAliveSession.instances = []
    _KeepAliveSession.streams = []
    _KeepAliveSession.fail_primary = False
    _KeepAliveSession.payload = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
    app_obj = MagicMock(_controller=None, _source_bind_ip=None)
    app_obj._runtime_auth = SimpleNamespace(access_token="oauth-token")
    api_module._app = app_obj
    api_module._config = WindowsConfig()
    monkeypatch.setattr(
        "perchvpn.guardian.fetch_proxy_pass",
        lambda endpoint, access_token: SimpleNamespace(raw_token="pass-token"),
    )
    monkeypatch.setattr(
        "perchvpn.proxy.session.H2ProxySession", _KeepAliveSession
    )
    yield
    api_module._app = None


class TestTwoStageUnifiedDelay:
    def test_success_reports_surgical_fields(self):
        result = asyncio.run(api_module.get_urltest(host="edge1", port=2499))
        assert result["success"] is True
        assert result["target"] == "www.gstatic.com"
        assert result["latency_ms"] >= 1  # never a fabricated 0 ms
        assert result["elapsed_ms"] == result["latency_ms"]
        assert result["cold_ms"] >= 0 and result["connect_ms"] >= 0

    def test_stage1_warmup_then_stage2_timed_on_keep_alive(self):
        asyncio.run(api_module.get_urltest(host="edge1", port=2499))
        # One session, one tunnel, two requests: warm-up then timed.
        assert len(_KeepAliveSession.instances) == 1
        assert len(_KeepAliveSession.streams) == 1
        _, target_host, target_port, stream = _KeepAliveSession.streams[0]
        assert target_host == "www.gstatic.com"
        assert target_port == 80
        assert len(stream.written) == 2
        for request in stream.written:
            assert request.count(b"generate_204") == 1
            assert request.endswith(b"Connection: keep-alive\r\n\r\n")

    def test_cloudflare_fallback_after_primary_failure(self):
        _KeepAliveSession.fail_primary = True
        result = asyncio.run(api_module.get_urltest(host="edge1", port=2499))
        assert result["success"] is True
        assert result["target"] == "cp.cloudflare.com"
        # First attempt failed, second attempt succeeded.
        assert len(_KeepAliveSession.instances) == 2

    def test_all_targets_failing_maps_to_504(self):
        _KeepAliveSession.fail_primary = True
        _KeepAliveSession.payload = b"HTTP/1.1 500 Oops\r\nContent-Length: 0\r\n\r\n"
        with pytest.raises(api_module.HTTPException) as exc_info:
            asyncio.run(api_module.get_urltest(host="edge1", port=2499))
        assert exc_info.value.status_code == 504

    def test_session_closed_after_success(self):
        asyncio.run(api_module.get_urltest(host="edge1", port=2499))
        assert _KeepAliveSession.instances[0].closed is True


class TestPassTtlHonoursExpiry:
    def _fetch_with_ttl(self, remaining: timedelta, calls: list):
        def _fetch(endpoint, access_token):
            calls.append(access_token)
            return SimpleNamespace(
                raw_token="pass-token",
                expires_at=lambda: datetime.now(timezone.utc) + remaining,
            )

        return _fetch

    def test_longlived_pass_cached_within_cap(self, monkeypatch):
        calls: list = []
        monkeypatch.setattr(
            "perchvpn.guardian.fetch_proxy_pass",
            self._fetch_with_ttl(timedelta(minutes=30), calls),
        )
        api_module._get_urltest_raw_token()
        api_module._get_urltest_raw_token()
        assert len(calls) == 1
        assert api_module._urltest_pass_cache["ttl"] == api_module._URLTEST_PASS_TTL_SECONDS

    def test_soonexiring_pass_uses_remaining_validity(self, monkeypatch):
        calls: list = []
        monkeypatch.setattr(
            "perchvpn.guardian.fetch_proxy_pass",
            self._fetch_with_ttl(timedelta(seconds=35), calls),
        )
        api_module._get_urltest_raw_token()
        # 35s validity minus the 10s safety margin, floor 2s.
        assert api_module._urltest_pass_cache["ttl"] == pytest.approx(25.0, abs=0.05)

    def test_abouttoexpire_pass_caches_briefly(self, monkeypatch):
        calls: list = []
        monkeypatch.setattr(
            "perchvpn.guardian.fetch_proxy_pass",
            self._fetch_with_ttl(timedelta(seconds=3), calls),
        )
        api_module._get_urltest_raw_token()
        assert api_module._urltest_pass_cache["ttl"] == pytest.approx(2.0)
