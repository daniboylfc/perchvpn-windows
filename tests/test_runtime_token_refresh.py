"""Focused tests for runtime access-token refresh (P1-1).

All offline: FxA/Guardian/persistence are monkeypatched; no sockets, no
network, and no real home-directory files are touched.
"""

from __future__ import annotations

import asyncio
import time

import pytest

import perchvpn.auth as auth_module
from perchvpn import fxa, guardian, tokens
from perchvpn.auth import (
    AccessTokenExpiredError,
    RuntimeAuth,
    refresh_runtime_auth,
)
from perchvpn.controller import ControllerConfig, ProxyController
from perchvpn.proxystate import ProxyCandidate


class _Clock:
    def __init__(self, t: float) -> None:
        self.t = t

    def time(self) -> float:
        return self.t


def _token(access: str = "access", refresh: str = "refresh", expires_in: int = 3600) -> fxa.TokenResponse:
    return fxa.TokenResponse(access_token=access, refresh_token=refresh, scope="scope", expires_in=expires_in)


def _controller(auth: RuntimeAuth) -> ProxyController:
    config = ControllerConfig(
        guardian_endpoint="https://guardian.example",
        candidate=ProxyCandidate(host="a", port=1, country_code="GB", country_name="UK"),
        upstream_conns=1,
        handshake_timeout=1.0,
    )
    return ProxyController(config, auth)


class TestExpiryMetadata:
    def test_valid_token_not_expired(self):
        assert RuntimeAuth(token=_token(expires_in=3600)).access_token_expired() is False

    def test_past_expiry_is_expired(self, monkeypatch):
        now = 1_000_000.0
        monkeypatch.setattr(auth_module, "time", _Clock(now))
        auth = RuntimeAuth(token=_token(expires_in=100), obtained_at=now - 1000)
        assert auth.access_token_expired() is True

    def test_exactly_at_lead_boundary_is_expired(self, monkeypatch):
        now = 1_000_000.0
        monkeypatch.setattr(auth_module, "time", _Clock(now))
        lead = tokens.ACCESS_TOKEN_EXPIRY_LEAD_SECONDS
        auth = RuntimeAuth(token=_token(expires_in=lead), obtained_at=now)
        assert auth.access_token_expired() is True

    def test_one_second_before_boundary_not_expired(self, monkeypatch):
        now = 1_000_000.0
        monkeypatch.setattr(auth_module, "time", _Clock(now))
        lead = tokens.ACCESS_TOKEN_EXPIRY_LEAD_SECONDS
        auth = RuntimeAuth(token=_token(expires_in=lead + 1), obtained_at=now)
        assert auth.access_token_expired() is False

    def test_unknown_expiry_is_not_expired(self):
        assert RuntimeAuth(token=_token(expires_in=0)).access_token_expired() is False

    def test_missing_access_token_is_not_expired(self):
        assert RuntimeAuth(token=_token(access="", expires_in=100)).access_token_expired() is False


class TestRefreshRuntimeAuth:
    def test_refresh_persists_to_same_path(self, tmp_path, monkeypatch):
        path = tmp_path / "tokens.json"
        monkeypatch.setattr(
            auth_module.fxa,
            "refresh_token",
            lambda value: fxa.TokenResponse(access_token="new", refresh_token="r2", scope="s", expires_in=7200),
        )
        out = refresh_runtime_auth(RuntimeAuth(token=_token(refresh="r1"), token_path=path))
        assert out.access_token == "new"
        assert out.token_path == path
        assert out.session_token_pool is None
        saved = tokens.load_tokens(path)
        assert saved is not None and saved.access_token == "new"

    def test_refresh_missing_expires_in_uses_default(self, tmp_path, monkeypatch):
        path = tmp_path / "tokens.json"
        monkeypatch.setattr(
            auth_module.fxa,
            "refresh_token",
            lambda value: fxa.TokenResponse(access_token="new", refresh_token="r", scope="s", expires_in=0),
        )
        out = refresh_runtime_auth(RuntimeAuth(token=_token(), token_path=path))
        assert out.token.expires_in == auth_module.DEFAULT_ACCESS_TOKEN_TTL_SECONDS
        assert tokens.load_tokens(path).expires_in == auth_module.DEFAULT_ACCESS_TOKEN_TTL_SECONDS

    def test_refresh_empty_access_token_raises(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            auth_module.fxa,
            "refresh_token",
            lambda value: fxa.TokenResponse(access_token="", refresh_token="r", scope="s", expires_in=3600),
        )
        with pytest.raises(AccessTokenExpiredError):
            refresh_runtime_auth(RuntimeAuth(token=_token(), token_path=tmp_path / "t.json"))

    def test_refresh_without_refresh_token_raises(self):
        with pytest.raises(AccessTokenExpiredError):
            refresh_runtime_auth(RuntimeAuth(token=_token(refresh="")))


class TestControllerEnsureFresh:
    @pytest.mark.asyncio
    async def test_valid_token_does_not_refresh(self, monkeypatch):
        calls: list[int] = []
        monkeypatch.setattr(auth_module, "refresh_runtime_auth", lambda a: calls.append(1) or a)
        controller = _controller(RuntimeAuth(token=_token(expires_in=3600)))
        await controller._ensure_fresh_access_token()
        assert calls == []

    @pytest.mark.asyncio
    async def test_expired_token_refreshed(self, monkeypatch):
        fresh = RuntimeAuth(token=_token(access="new", expires_in=3600))
        monkeypatch.setattr(auth_module, "refresh_runtime_auth", lambda a: fresh)
        controller = _controller(RuntimeAuth(token=_token(access="old", expires_in=1), obtained_at=time.time() - 100))
        await controller._ensure_fresh_access_token()
        assert controller.auth is fresh

    @pytest.mark.asyncio
    async def test_failed_refresh_falls_back_to_pool(self, monkeypatch):
        def boom(auth):
            raise AccessTokenExpiredError("renewal failed")

        rotated = RuntimeAuth(token=_token(access="rotated", expires_in=3600))
        monkeypatch.setattr(auth_module, "refresh_runtime_auth", boom)
        monkeypatch.setattr(auth_module, "rotate_session_token", lambda a, token_path=None: rotated)
        controller = _controller(RuntimeAuth(token=_token(access="old", expires_in=1), obtained_at=time.time() - 100))
        await controller._ensure_fresh_access_token()
        assert controller.auth is rotated

    @pytest.mark.asyncio
    async def test_failed_refresh_without_pool_raises(self, monkeypatch):
        def boom(auth):
            raise AccessTokenExpiredError("renewal failed")

        monkeypatch.setattr(auth_module, "refresh_runtime_auth", boom)
        monkeypatch.setattr(auth_module, "rotate_session_token", lambda a, token_path=None: None)
        controller = _controller(RuntimeAuth(token=_token(access="old", expires_in=1), obtained_at=time.time() - 100))
        with pytest.raises(AccessTokenExpiredError):
            await controller._ensure_fresh_access_token()

    @pytest.mark.asyncio
    async def test_unknown_expiry_does_not_refresh(self, monkeypatch):
        calls: list[int] = []
        monkeypatch.setattr(auth_module, "refresh_runtime_auth", lambda a: calls.append(1) or a)
        controller = _controller(RuntimeAuth(token=_token(expires_in=0)))
        await controller._ensure_fresh_access_token()
        assert calls == []

    @pytest.mark.asyncio
    async def test_concurrent_calls_refresh_once(self, monkeypatch):
        calls: list[int] = []
        fresh = RuntimeAuth(token=_token(access="new", expires_in=3600))

        def refresh(auth):
            calls.append(1)
            return fresh

        monkeypatch.setattr(auth_module, "refresh_runtime_auth", refresh)
        controller = _controller(RuntimeAuth(token=_token(access="old", expires_in=1), obtained_at=time.time() - 100))
        await asyncio.gather(
            controller._ensure_fresh_access_token(),
            controller._ensure_fresh_access_token(),
        )
        assert len(calls) == 1
        assert controller.auth is fresh


class TestRefreshPrecedesAcquisition:
    @pytest.mark.asyncio
    async def test_acquire_usable_pass_refreshes_before_fetch(self, monkeypatch):
        order: list[object] = []

        def refresh(auth):
            order.append("refresh")
            return RuntimeAuth(token=_token(access="new", expires_in=3600))

        def fetch(endpoint, token):
            order.append(("fetch", token))
            return object()

        monkeypatch.setattr(auth_module, "refresh_runtime_auth", refresh)
        monkeypatch.setattr(guardian, "fetch_proxy_pass", fetch)
        controller = _controller(RuntimeAuth(token=_token(access="old", expires_in=1), obtained_at=time.time() - 100))
        await controller._acquire_usable_pass()
        assert order == ["refresh", ("fetch", "new")]


class TestTokenPathPropagation:
    def test_rotation_keeps_configured_token_path(self, tmp_path, monkeypatch):
        custom = tmp_path / "tokens.json"
        pool_file = tmp_path / "pool.txt"
        pool_file.write_text("session-one\nsession-two\n")

        monkeypatch.setattr(
            auth_module.fxa,
            "oauth_token",
            lambda session_token: fxa.TokenResponse(
                access_token=f"access-{session_token}", refresh_token="r", scope="s", expires_in=3600
            ),
        )
        # Fail loudly if any code path falls back to the default home token file.
        real_token_path = tokens._token_path
        seen: list[object] = []

        def guard(override=None):
            seen.append(override)
            assert override is not None, "default home token path was used"
            return real_token_path(override)

        monkeypatch.setattr(tokens, "_token_path", guard)

        auth = auth_module.obtain_auth(session_token_or_path=str(pool_file), token_path=custom)
        assert auth.token_path == custom

        rotated = auth_module.rotate_session_token(auth)  # no explicit path
        assert rotated is not None
        assert rotated.token_path == custom
        assert custom.exists()
        assert seen and all(entry is not None for entry in seen)
