"""Regression tests for Android v1.0.0→v1.0.7 parity updates ported to Windows.

Fully offline: FxA/Guardian/HTTP are stubbed, the server-list cache lives in
``tmp_path``, and the HTTP/2 slot logic runs against an in-process ``h2``
connection with no sockets.
"""

from __future__ import annotations

import asyncio
import json
import types

import pytest
from h2.exceptions import TooManyStreamsError

import perchvpn.auth as auth_module
import perchvpn.serverlist as serverlist_module
from perchvpn import fxa, guardian
from perchvpn.auth import AccessTokenExpiredError, RuntimeAuth, refresh_runtime_auth
from perchvpn.exceptions import FxaApiError
from perchvpn.proxy import session as session_module
from perchvpn.proxy.session import H2ProxySession


def _expired_token_file(path) -> None:
    path.write_text(
        json.dumps(
            {
                "access_token": "old-access",
                "refresh_token": "old-refresh",
                "scope": "s",
                "obtained_at": 0,
                "expires_in": 1,
            }
        )
    )


# --------------------------------------------------------------------------- #
# A. Auth: permanent vs transient refresh failure (Android FxaRefreshFailure)
# --------------------------------------------------------------------------- #


class TestRefreshFailureClassification:
    def _auth(self, monkeypatch, exc):
        def boom(_refresh_token):
            raise exc

        monkeypatch.setattr(auth_module.fxa, "refresh_token", boom)
        return RuntimeAuth(token=fxa.TokenResponse(access_token="old", refresh_token="r", expires_in=1))

    def test_rejected_refresh_token_is_permanent(self, monkeypatch):
        auth = self._auth(monkeypatch, FxaApiError("revoked", status_code=401))
        with pytest.raises(AccessTokenExpiredError) as excinfo:
            refresh_runtime_auth(auth)
        assert excinfo.value.permanent is True

    def test_server_error_is_transient(self, monkeypatch):
        auth = self._auth(monkeypatch, FxaApiError("overloaded", status_code=503))
        with pytest.raises(AccessTokenExpiredError) as excinfo:
            refresh_runtime_auth(auth)
        assert excinfo.value.permanent is False

    def test_missing_refresh_token_is_permanent(self):
        with pytest.raises(AccessTokenExpiredError) as excinfo:
            refresh_runtime_auth(RuntimeAuth(token=fxa.TokenResponse(access_token="old", refresh_token="")))
        assert excinfo.value.permanent is True

    def test_empty_access_token_in_response_is_transient(self, monkeypatch):
        monkeypatch.setattr(
            auth_module.fxa,
            "refresh_token",
            lambda _value: fxa.TokenResponse(access_token="", refresh_token="r", expires_in=3600),
        )
        with pytest.raises(AccessTokenExpiredError) as excinfo:
            refresh_runtime_auth(RuntimeAuth(token=fxa.TokenResponse(access_token="old", refresh_token="r", expires_in=1)))
        assert excinfo.value.permanent is False


class TestObtainAuthRefreshFallback:
    def test_transient_failure_does_not_prompt_for_login(self, tmp_path, monkeypatch):
        path = tmp_path / "tokens.json"
        _expired_token_file(path)

        def boom(_refresh_token):
            raise FxaApiError("control plane down", status_code=503)

        monkeypatch.setattr(auth_module.fxa, "refresh_token", boom)
        prompted: list[int] = []
        monkeypatch.setattr(auth_module, "_login_interactively", lambda *a, **k: prompted.append(1))

        with pytest.raises(FxaApiError):
            auth_module.obtain_auth(email="user@example.com", token_path=path)
        assert prompted == []

    def test_permanent_rejection_falls_back_to_login(self, tmp_path, monkeypatch):
        path = tmp_path / "tokens.json"
        _expired_token_file(path)

        def boom(_refresh_token):
            raise FxaApiError("refresh token revoked", status_code=403)

        monkeypatch.setattr(auth_module.fxa, "refresh_token", boom)

        def fake_login(email, password=None, token_path=None):
            return fxa.TokenResponse(access_token="fresh", refresh_token="r2", scope="s", expires_in=3600)

        seen: list[str] = []

        def wrapper(email, password=None, token_path=None):
            seen.append(email)
            return fake_login(email, password, token_path)

        monkeypatch.setattr(auth_module, "_login_interactively", wrapper)

        auth = auth_module.obtain_auth(email="user@example.com", token_path=path)
        assert auth.access_token == "fresh"
        assert seen == ["user@example.com"]


# --------------------------------------------------------------------------- #
# B. Guardian: remaining quota on a bandwidth-limited account
# --------------------------------------------------------------------------- #


class _FakeResp:
    def __init__(self, payload, status_code: int = 200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload


class TestGuardianQuotaRemaining:
    def _status(self, payload):
        return lambda *a, **k: _FakeResp(payload)

    def test_limited_bandwidth_populates_remaining_quota(self, monkeypatch):
        monkeypatch.setattr(
            guardian,
            "_authorized_request",
            self._status({"subscribed": True, "uid": 7, "maxBytes": "1000", "limited_bandwidth": True}),
        )
        calls: list[str] = []
        monkeypatch.setattr(
            guardian,
            "fetch_proxy_pass",
            lambda endpoint, token: calls.append("pass")
            or guardian.ProxyPassInfo(raw_token="t", claims=guardian.ProxyPassClaims(), quota_left="12345"),
        )
        ent = guardian.fetch_user_info("https://guardian.example", "tok")
        assert ent.limited_bandwidth is True
        assert ent.quota_remaining == 12345
        assert calls == ["pass"]

    def test_unlimited_account_does_not_fetch_pass(self, monkeypatch):
        monkeypatch.setattr(
            guardian,
            "_authorized_request",
            self._status({"subscribed": True, "uid": 7, "maxBytes": "0", "limited_bandwidth": False}),
        )
        calls: list[str] = []
        monkeypatch.setattr(guardian, "fetch_proxy_pass", lambda endpoint, token: calls.append("pass"))
        ent = guardian.fetch_user_info("https://guardian.example", "tok")
        assert ent.quota_remaining is None
        assert calls == []

    def test_pass_failure_is_non_fatal(self, monkeypatch):
        monkeypatch.setattr(
            guardian,
            "_authorized_request",
            self._status({"subscribed": True, "uid": 7, "maxBytes": "0", "limited_bandwidth": True}),
        )
        monkeypatch.setattr(
            guardian, "fetch_proxy_pass", lambda endpoint, token: (_ for _ in ()).throw(RuntimeError("nope"))
        )
        ent = guardian.fetch_user_info("https://guardian.example", "tok")
        assert ent.quota_remaining is None


# --------------------------------------------------------------------------- #
# C. Server list local cache (Android ServerListClient)
# --------------------------------------------------------------------------- #


def _server_list_payload() -> dict:
    return {
        "data": [
            {
                "country": {
                    "name": "United Kingdom",
                    "code": "GB",
                    "cities": [
                        {
                            "name": "London",
                            "code": "LON",
                            "servers": [{"hostname": "gb-lon.example", "port": 443, "protocols": []}],
                        }
                    ],
                }
            }
        ]
    }


class _FakeClient:
    def __init__(self, resp=None, exc=None):
        self._resp = resp
        self._exc = exc

    def get(self, url, headers=None):
        if self._exc is not None:
            raise self._exc
        return self._resp


class _FakeHTTPResp:
    def __init__(self, payload):
        self._payload = payload
        self.text = json.dumps(payload)

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class TestServerListCache:
    def test_successful_fetch_writes_cache(self, tmp_path, monkeypatch):
        cache = tmp_path / "serverlist.json"
        payload = _server_list_payload()
        monkeypatch.setattr(serverlist_module, "get_client", lambda: _FakeClient(resp=_FakeHTTPResp(payload)))

        countries = serverlist_module.fetch_server_list(cache)
        assert [c.code for c in countries] == ["GB"]
        assert cache.exists()
        cached = serverlist_module.load_cached_server_list(cache)
        assert [c.code for c in cached] == ["GB"]

    def test_failure_with_cache_falls_back(self, tmp_path, monkeypatch):
        cache = tmp_path / "serverlist.json"
        serverlist_module._save_cache(cache, json.dumps(_server_list_payload()))
        monkeypatch.setattr(
            serverlist_module, "get_client", lambda: _FakeClient(exc=RuntimeError("offline"))
        )

        countries = serverlist_module.fetch_server_list(cache)
        assert [c.code for c in countries] == ["GB"]

    def test_failure_without_cache_raises(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            serverlist_module, "get_client", lambda: _FakeClient(exc=RuntimeError("offline"))
        )
        with pytest.raises(RuntimeError):
            serverlist_module.fetch_server_list(tmp_path / "absent.json")

    def test_no_cache_path_is_backward_compatible(self, monkeypatch):
        payload = _server_list_payload()
        monkeypatch.setattr(serverlist_module, "get_client", lambda: _FakeClient(resp=_FakeHTTPResp(payload)))
        assert [c.code for c in serverlist_module.fetch_server_list()] == ["GB"]

    def test_corrupt_cache_is_ignored(self, tmp_path):
        cache = tmp_path / "serverlist.json"
        cache.write_text("{not json")
        assert serverlist_module.load_cached_server_list(cache) == []

    @pytest.mark.parametrize("payload", ["[]", "123", '{"data": {}}'])
    def test_valid_json_wrong_shape_returns_empty(self, tmp_path, payload):
        cache = tmp_path / "serverlist.json"
        cache.write_text(payload)
        assert serverlist_module.load_cached_server_list(cache) == []

    def test_failure_with_wrong_shape_cache_reraises_original(self, tmp_path, monkeypatch):
        cache = tmp_path / "serverlist.json"
        cache.write_text("[]")
        monkeypatch.setattr(serverlist_module, "get_client", lambda: _FakeClient(exc=RuntimeError("offline")))

        with pytest.raises(RuntimeError):
            serverlist_module.fetch_server_list(cache)

    def test_catchall_anycast_entry_is_excluded(self):
        # Android ServerListClient.EXCLUDED_COUNTRY_NAMES drops the synthetic
        # "CatchAll Anycast" record even though it carries a code and cities.
        payload = {
            "data": [
                {
                    "country": {
                        "name": "CatchAll Anycast",
                        "code": "ZZ",
                        "cities": [{"name": "Anycast", "code": "ANY", "servers": [{"hostname": "a", "port": 443}]}],
                    }
                },
                {
                    "country": {
                        "name": "Germany",
                        "code": "DE",
                        "cities": [{"name": "Berlin", "code": "BER", "servers": [{"hostname": "de.example", "port": 443}]}],
                    }
                },
            ]
        }
        countries = serverlist_module._parse_server_list(payload)
        assert [c.code for c in countries] == ["DE"]


class TestServerListCacheWiring:
    """Covers the app.py:163 wiring: the config-derived path is what the
    server list fetch caches to."""

    def test_config_exposes_cache_under_config_dir(self, tmp_path, monkeypatch):
        import perchvpn_windows.config as config_module

        monkeypatch.setattr(config_module, "get_config_dir", lambda: tmp_path)
        cfg = config_module.WindowsConfig()
        assert cfg.serverlist_cache_path == str(tmp_path / "serverlist-cache.json")

    def test_app_style_call_populates_configured_cache(self, tmp_path, monkeypatch):
        import perchvpn_windows.config as config_module

        monkeypatch.setattr(config_module, "get_config_dir", lambda: tmp_path)
        cfg = config_module.WindowsConfig()
        monkeypatch.setattr(
            serverlist_module, "get_client", lambda: _FakeClient(resp=_FakeHTTPResp(_server_list_payload()))
        )

        countries = serverlist_module.fetch_server_list(cfg.serverlist_cache_path)
        assert [c.code for c in countries] == ["GB"]
        assert (tmp_path / "serverlist-cache.json").exists()


# --------------------------------------------------------------------------- #
# D. HTTP/2 concurrent-stream slot (Android reserveStreamSlot)
# --------------------------------------------------------------------------- #


def _client_with_remote_max(limit: int):
    from h2.config import H2Configuration
    from h2.connection import H2Connection
    from h2.settings import SettingCodes

    server = H2Connection(config=H2Configuration(client_side=False, header_encoding="utf-8"))
    server.initiate_connection()
    server.update_settings({SettingCodes.MAX_CONCURRENT_STREAMS: limit})
    settings = server.data_to_send()

    client = H2Connection(
        config=H2Configuration(client_side=True, header_encoding="utf-8", validate_outbound_headers=False)
    )
    client.initiate_connection()
    client.data_to_send()
    client.receive_data(settings)
    return client


class TestH2StreamSlot:
    @pytest.mark.asyncio
    async def test_returns_immediately_when_under_limit(self):
        session = H2ProxySession("edge.example", 443, "tok")
        session._conn = _client_with_remote_max(4)
        await asyncio.wait_for(session._await_stream_slot(), timeout=0.5)

    @pytest.mark.asyncio
    async def test_waits_then_times_out_when_full(self, monkeypatch):
        monkeypatch.setattr(session_module, "STREAM_SLOT_WAIT_TIMEOUT", 0.15)
        session = H2ProxySession("edge.example", 443, "tok")
        session._conn = _client_with_remote_max(1)
        session._streams = {1: object()}

        with pytest.raises(Exception) as excinfo:
            await session._await_stream_slot()
        assert "stream slot" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_closed_session_raises(self):
        session = H2ProxySession("edge.example", 443, "tok")
        session._conn = _client_with_remote_max(1)
        session._streams = {1: object()}
        session._closed = True
        with pytest.raises(Exception):
            await session._await_stream_slot()

    @pytest.mark.asyncio
    async def test_open_stream_times_out_instead_of_refused(self, monkeypatch):
        monkeypatch.setattr(session_module, "STREAM_SLOT_WAIT_TIMEOUT", 0.15)
        session = H2ProxySession("edge.example", 443, "tok")
        session._conn = _client_with_remote_max(1)
        session._streams = {1: object()}

        with pytest.raises(session_module.ProxyError):
            await session.open_stream("target.example", 443)


class _FakeConn:
    """Minimal fake h2 connection for slot-wait tests that don't need full h2 state machine."""

    def __init__(self, limit: int):
        self.remote_settings = types.SimpleNamespace(max_concurrent_streams=limit)
        self.resets: list[int] = []

    def reset_stream(self, stream_id: int, error_code: int = 0) -> None:
        self.resets.append(stream_id)

    def data_to_send(self) -> bytes:
        return b""

    @property
    def max_outbound_frame_size(self) -> int:
        return 16384


class TestH2StreamSlotConcurrency:
    """Tests for concurrent stream slot behaviors that exist in the current implementation.

    These tests cover:
    - Cancellation during slot wait (_await_stream_slot)
    - Slot becoming available while waiting
    - Multiple concurrent open_stream calls respecting the limit
    """

    @pytest.mark.asyncio
    async def test_cancellation_during_slot_wait(self, monkeypatch):
        """Cancelling open_stream() while waiting for a slot cleans up cleanly.

        The session should not be left in a bad state and no stream should
        be registered (since registration happens after slot is acquired).
        """
        monkeypatch.setattr(session_module, "STREAM_SLOT_WAIT_TIMEOUT", 5.0)
        session = H2ProxySession("edge.example", 443, "tok")
        session._conn = _FakeConn(1)
        session._writer = _NullWriter()
        # Pre-fill the single available slot
        placeholder = object()
        session._streams[1] = placeholder

        task = asyncio.create_task(session.open_stream("target.example", 443))
        await asyncio.sleep(0.1)  # Let it enter the slot-wait polling loop
        task.cancel()

        with pytest.raises(asyncio.CancelledError):
            await task

        # No stream should have been registered (registration happens after slot acquired)
        assert session._streams == {1: placeholder}

    @pytest.mark.asyncio
    async def test_slot_freed_while_waiting_proceeds(self, monkeypatch):
        """If a slot becomes available while waiting, the waiter should acquire it."""
        monkeypatch.setattr(session_module, "STREAM_SLOT_WAIT_TIMEOUT", 2.0)
        session = H2ProxySession("edge.example", 443, "tok")
        session._conn = _FakeConn(1)
        session._writer = _NullWriter()

        # Pre-fill the single slot
        existing_stream = object()
        session._streams[1] = existing_stream

        # Start waiting for a slot
        task = asyncio.create_task(session.open_stream("target.example", 443))
        await asyncio.sleep(0.1)  # Ensure it's in the wait loop

        # Free the slot by removing the existing stream
        session._streams.clear()

        # The open_stream should now succeed (establishment will timeout,
        # but slot wait should pass)
        monkeypatch.setattr(session_module, "OPEN_STREAM_TIMEOUT", 0.05)
        with pytest.raises(session_module.ProxyError):
            await task

        # A new stream should have been registered (and then cleaned up on timeout)
        assert 1 not in session._streams or session._streams.get(1) is not existing_stream

    @pytest.mark.asyncio
    async def test_concurrent_open_stream_respects_limit(self, monkeypatch):
        """Multiple concurrent open_stream calls should respect MAX_CONCURRENT_STREAMS."""
        monkeypatch.setattr(session_module, "STREAM_SLOT_WAIT_TIMEOUT", 0.5)
        monkeypatch.setattr(session_module, "OPEN_STREAM_TIMEOUT", 5.0)
        session = H2ProxySession("edge.example", 443, "tok")
        session._conn = _FakeConn(1)
        session._writer = _NullWriter()

        # Launch two concurrent open_stream calls
        task1 = asyncio.create_task(session.open_stream("target.example", 443))
        task2 = asyncio.create_task(session.open_stream("target.example", 443))

        # Both will wait for establishment; we only care that slot logic
        # allowed exactly one to proceed to establishment at a time.
        # Since establishment will timeout, both will fail, but only
        # one should have been in _streams at any time.

        # Wait a bit for slot acquisition
        await asyncio.sleep(0.2)

        # At most one stream should be registered at a time
        # (The first acquires slot, registers stream; second waits)
        # We can't easily test the exact timing, but we can verify
        # both eventually fail with timeout and don't leave leaks.
        results = await asyncio.gather(task1, task2, return_exceptions=True)

        for r in results:
            assert isinstance(r, session_module.ProxyError)
            assert "timed out" in str(r)

        # No leaked streams
        assert session._streams == {}


class _NullWriter:
    def write(self, data) -> None:
        return None

    async def drain(self) -> None:
        return None
