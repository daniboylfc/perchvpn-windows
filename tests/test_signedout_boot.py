"""Signed-out boot and honest first-run behavior.

The app must open as a real GUI (onboarding prompt visible) when a new
user has no credentials at all, instead of failing behind an interactive
console login. Interactive authentication is reserved for re-auth when a
previous session's tokens exist but are unusable.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

import perchvpn.auth as auth_module
import src.perchvpn_windows.api as api_module
from src.perchvpn_windows import webview
from src.perchvpn_windows.app import PerchVPNApp
from src.perchvpn_windows.config import WindowsConfig


@pytest.fixture(autouse=True)
def _reset_api_globals():
    api_module._app = None
    api_module._config = None
    yield
    api_module._app = None
    api_module._config = None


class TestObtainAuthInteractiveGate:
    @pytest.mark.asyncio
    async def test_obtain_auth_raises_interactive_login_required_when_disabled(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        with pytest.raises(auth_module.InteractiveLoginRequired):
            auth_module.obtain_auth(interactive=False)


class TestSignedOutBoot:
    @pytest.mark.asyncio
    async def test_initialize_boots_signed_out_without_credentials(self):
        app = PerchVPNApp(WindowsConfig(explicit_proxy="1.2.3.4:1080", verify_exit=False))
        with patch.object(
            PerchVPNApp,
            "_obtain_auth",
            AsyncMock(side_effect=auth_module.InteractiveLoginRequired("interactive login is required but disabled")),
        ):
            await app.initialize()

        assert app._runtime_auth is None
        assert app._signed_out_boot is True
        assert app._controller is None
        assert app._pool is None
        assert app._frontend is None

    @pytest.mark.asyncio
    async def test_initialize_still_raises_transient_auth_errors(self):
        """A transient FxA refresh failure must not silently boot signed out."""
        app = PerchVPNApp(WindowsConfig(explicit_proxy="1.2.3.4:1080", verify_exit=False))
        with patch.object(
            PerchVPNApp,
            "_obtain_auth",
            AsyncMock(side_effect=auth_module.FxaApiError("server unavailable")),
        ), pytest.raises(auth_module.FxaApiError):
            await app.initialize()

        assert app._signed_out_boot is False


class TestPreflightInteractiveAuth:
    def test_valid_token_skips_preflight(self):
        with patch.object(webview, "_has_valid_token", return_value=True):
            assert webview._preflight_interactive_auth() is False

    def test_no_tokens_at_all_opens_signed_out(self, tmp_path):
        token_path = tmp_path / "tokens.json"  # does not exist
        with patch.object(webview, "_get_token_path", return_value=token_path):
            with patch.object(webview, "_has_valid_token", return_value=False):
                assert webview._preflight_interactive_auth() is False

    def test_stale_token_file_requires_reauth(self, tmp_path):
        token_path = tmp_path / "tokens.json"
        token_path.write_text("{}", encoding="utf-8")
        with patch.object(webview, "_get_token_path", return_value=token_path):
            with patch.object(webview, "_has_valid_token", return_value=False):
                assert webview._preflight_interactive_auth() is True


class TestRestartSignedOut:
    @pytest.mark.asyncio
    async def test_connect_while_signed_out_returns_409(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        signed_out_app = MagicMock(_signed_out_boot=True, _runtime_auth=None)
        api_module._app = signed_out_app
        api_module._config = WindowsConfig()

        with patch.object(api_module.tokens_module, "load_tokens", return_value=None):
            with pytest.raises(HTTPException) as excinfo:
                await api_module.restart()

        assert excinfo.value.status_code == 409
        assert excinfo.value.detail == "Not signed in: sign in first, then connect"
        signed_out_app.shutdown.assert_not_called()

    @pytest.mark.asyncio
    async def test_connect_proceeds_once_helper_persisted_tokens(self, tmp_path, monkeypatch):
        """Tokens appearing after boot (via the helper) unblock Connect."""
        monkeypatch.setenv("APPDATA", str(tmp_path))
        signed_out_app = MagicMock(_signed_out_boot=True, _runtime_auth=None)
        signed_out_app.shutdown = AsyncMock()
        api_module._app = signed_out_app
        api_module._config = WindowsConfig()

        new_app = MagicMock()
        new_app.initialize = AsyncMock()

        with patch.object(api_module.tokens_module, "load_tokens", return_value=object()):
            with patch.object(api_module, "PerchVPNApp", return_value=new_app):
                result = await api_module.restart()
                assert result["success"] is True
                assert api_module._restart_task is not None
                await api_module._restart_task

        new_app.initialize.assert_awaited_once()
        signed_out_app.shutdown.assert_awaited_once()
        assert api_module._app is new_app

    @pytest.mark.asyncio
    async def test_restart_409_when_initialize_hits_interactive_login(self, tmp_path, monkeypatch):
        """Safety net: an initialize() that still raises InteractiveLoginRequired
        yields a 409, not a generic 500."""
        monkeypatch.setenv("APPDATA", str(tmp_path))
        old_app = MagicMock()
        old_app.shutdown = AsyncMock()
        api_module._app = old_app
        api_module._config = WindowsConfig()

        new_app = PerchVPNApp(WindowsConfig(explicit_proxy="1.2.3.4:1080", verify_exit=False))
        with patch.object(api_module, "PerchVPNApp", return_value=new_app):
            with patch.object(
                PerchVPNApp,
                "initialize",
                AsyncMock(side_effect=auth_module.InteractiveLoginRequired("interactive login is required but disabled")),
            ):
                result = await api_module.restart()
                assert result["success"] is True
                with pytest.raises(HTTPException) as excinfo:
                    await api_module._restart_task

        assert excinfo.value.status_code == 409
        # The failed replacement must not be live; state is safe to retry.
        assert api_module._app is not new_app
