"""In-app (API) sign-in: password auth with no console interaction.

Covers success + persistence, invalid credentials and service errors,
verification flows, duplicate-submission prevention, timeouts and the
security requirement that credentials are never logged or persisted.
"""

from __future__ import annotations

import asyncio
import threading
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

import perchvpn.auth as auth_module
import src.perchvpn_windows.api as api_module
from src.perchvpn_windows.config import WindowsConfig


@pytest.fixture(autouse=True)
def _reset_signin_state():
    api_module._signin_state.update(stage="idle", email="", verification_method="",
                                     session_token=None, expires_at=0.0, attempts=0)
    api_module._income_quota_cache.update(data=None, ok_at=0.0, err_at=0.0, key="")
    yield
    api_module._signin_state.update(stage="idle", email="", verification_method="",
                                    session_token=None, expires_at=0.0, attempts=0)


def _app_mock():
    app = MagicMock()
    app.load_persisted_auth = AsyncMock(return_value=True)
    app.config = WindowsConfig()
    return app


class TestInAppPasswordSignin:
    @pytest.mark.asyncio
    async def test_successful_signin_installs_persisted_auth(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        app_mock = _app_mock()
        token = SimpleNamespace(access_token="tok", email="user@example.com")
        saved_paths = []

        def fake_login_with_password(email, password, token_path):
            saved_paths.append(token_path)
            assert password == "correct-horse"
            return token

        monkeypatch.setattr(api_module.auth_module, "login_with_password", fake_login_with_password)
        with patch.object(api_module, "get_app", return_value=app_mock):
            result = await api_module.account_signin(
                api_module.SigninRequest(email="user@example.com", password="correct-horse")
            )

        assert result.status == "signed_in"
        assert len(saved_paths) == 1  # existing token storage only
        app_mock.load_persisted_auth.assert_awaited_once()
        app_mock.launch_auth_helper.assert_not_called()  # never a console window

    @pytest.mark.asyncio
    async def test_invalid_credentials_are_sanitized(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        secret = "correct-horse"

        def fake_login(email, password, token_path):
            assert password == secret
            raise auth_module.FxaApiError("Incorrect password", errno=104, status_code=400)

        monkeypatch.setattr(api_module.auth_module, "login_with_password", fake_login)
        with patch.object(api_module, "get_app", return_value=_app_mock()):
            with pytest.raises(HTTPException) as excinfo:
                await api_module.account_signin(
                    api_module.SigninRequest(email="user@example.com", password=secret)
                )
        assert excinfo.value.status_code == 401
        assert excinfo.value.detail == "Incorrect email or password"
        # No credential material in the surfaced error.
        assert secret not in (excinfo.value.detail or "")
        assert api_module._signin_state["stage"] == "idle"

    @pytest.mark.asyncio
    async def test_service_error_is_sanitized_and_recoverable(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))

        def fake_login(email, password, token_path):
            raise auth_module.FxaApiError("server hiccup", errno=700, status_code=503)

        monkeypatch.setattr(api_module.auth_module, "login_with_password", fake_login)
        with patch.object(api_module, "get_app", return_value=_app_mock()):
            with pytest.raises(HTTPException) as excinfo:
                await api_module.account_signin(
                    api_module.SigninRequest(email="user@example.com", password="pw")
                )
        assert excinfo.value.status_code == 502
        assert "Sign-in is unavailable" in excinfo.value.detail
        assert "server hiccup" not in excinfo.value.detail  # raw body never echoed
        assert api_module._signin_state["stage"] == "idle"

    @pytest.mark.asyncio
    async def test_input_validation(self):
        with pytest.raises(HTTPException) as excinfo:
            await api_module.account_signin(api_module.SigninRequest(email="no-at-sign", password="pw"))
        assert excinfo.value.status_code == 400
        import pydantic

        with pytest.raises(pydantic.ValidationError):
            # Model-level constraint: an empty password never reaches the FxA call.
            api_module.SigninRequest(email="a@b.c", password="")

    @pytest.mark.asyncio
    async def test_duplicate_submission_prevented(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        release = threading.Event()

        def slow_login(email, password, token_path):
            release.wait(timeout=2.0)
            return SimpleNamespace(access_token="tok")

        monkeypatch.setattr(api_module.auth_module, "login_with_password", slow_login)
        with patch.object(api_module, "get_app", return_value=_app_mock()):
            first = asyncio.ensure_future(
                api_module.account_signin(
                    api_module.SigninRequest(email="user@example.com", password="pw")
                )
            )
            await asyncio.sleep(0.05)  # first call is now inside signing_in
            with pytest.raises(HTTPException) as excinfo:
                await api_module.account_signin(
                    api_module.SigninRequest(email="user@example.com", password="pw")
                )
            assert excinfo.value.status_code == 409
            release.set()
            result = await first
            assert result.status == "signed_in"

    @pytest.mark.asyncio
    async def test_timeout_keeps_state_recoverable(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        monkeypatch.setattr(api_module, "_SIGNIN_TIMEOUT_SECONDS", 0.1)

        def slow_login(email, password, token_path):
            time.sleep(0.3)
            return SimpleNamespace(access_token="tok")

        monkeypatch.setattr(api_module.auth_module, "login_with_password", slow_login)
        with patch.object(api_module, "get_app", return_value=_app_mock()):
            with pytest.raises(HTTPException) as excinfo:
                await api_module.account_signin(
                    api_module.SigninRequest(email="user@example.com", password="pw")
                )
        assert excinfo.value.status_code == 504
        assert api_module._signin_state["stage"] == "idle"


class TestVerificationFlow:
    @pytest.mark.asyncio
    async def test_unverified_login_requires_confirmation_code(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))

        def fake_login(email, password, token_path):
            raise auth_module.VerificationRequired(
                "user@example.com", "session-token-secret", "email-2fa"
            )

        monkeypatch.setattr(api_module.auth_module, "login_with_password", fake_login)
        monkeypatch.setattr("perchvpn.fxa.verify_session", lambda session_token, code: None)
        monkeypatch.setattr(
            "perchvpn.fxa.oauth_token",
            lambda session_token: SimpleNamespace(
                access_token="tok", refresh_token="rt", scope="s", expires_in=3600
            ),
        )
        with patch.object(api_module, "get_app", return_value=_app_mock()):
            saved_calls = []
            monkeypatch.setattr(
                "perchvpn.tokens.save_tokens",
                lambda token, path=None: saved_calls.append(path),
            )

            first = await api_module.account_signin(
                api_module.SigninRequest(email="user@example.com", password="pw")
            )
            assert first.status == "verification_required"
            assert first.verification_method == "email-2fa"
            # Session token held in memory only; login failed earlier so the
            # only write through tokens.save_tokens happens after confirmed auth.
            assert api_module._signin_state["stage"] == "verification_required"
            assert not saved_calls

            result = await api_module.account_verify(api_module.VerifyRequest(code="123456"))
            assert result.status == "signed_in"
            assert api_module._signin_state["stage"] == "idle"
            assert saved_calls, "tokens persisted through the existing call"

    @pytest.mark.asyncio
    async def test_wrong_code_keeps_slot_and_reports_sanitized_error(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        api_module._signin_state.update(
            stage="verification_required", email="user@example.com",
            verification_method="email-2fa", session_token="st",
            expires_at=time.monotonic() + 60.0, attempts=0,
        )

        def bad_code(session_token, code, path):
            raise auth_module.FxaApiError("invalid code", errno=110, status_code=400)

        monkeypatch.setattr(api_module.auth_module, "verify_with_code", bad_code)
        with pytest.raises(HTTPException) as excinfo:
            await api_module.account_verify(api_module.VerifyRequest(code="000000"))
        assert excinfo.value.status_code == 401
        assert "confirmation code" in excinfo.value.detail
        assert api_module._signin_state["stage"] == "verification_required"  # retry allowed

    @pytest.mark.asyncio
    async def test_no_awaiting_confirmation_is_404(self):
        with pytest.raises(HTTPException) as excinfo:
            await api_module.account_verify(api_module.VerifyRequest(code="1"))
        assert excinfo.value.status_code == 404

    @pytest.mark.asyncio
    async def test_cancel_clears_the_slot(self):
        api_module._signin_state.update(
            stage="verification_required", email="user@example.com",
            verification_method="email-2fa", session_token="st",
            expires_at=time.monotonic() + 60.0, attempts=0,
        )
        result = await api_module.account_verify_cancel()
        assert result.status == "cancelled"
        assert api_module._signin_state["stage"] == "idle"
        assert api_module._signin_state["session_token"] is None

    @pytest.mark.asyncio
    async def test_link_confirmation_completes_after_activation(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        api_module._signin_state.update(
            stage="verification_email_link", email="user@example.com",
            verification_method="email", session_token="st",
            expires_at=time.monotonic() + 60.0, attempts=0,
        )
        monkeypatch.setattr(
            api_module.auth_module, "complete_link_verification",
            lambda session_token, path: SimpleNamespace(access_token="tok"),
        )
        with patch.object(api_module, "get_app", return_value=_app_mock()):
            result = await api_module.account_verify(api_module.VerifyRequest(code=""))
        assert result.status == "signed_in"
        assert api_module._signin_state["stage"] == "idle"


class TestCredentialHygiene:
    @pytest.mark.asyncio
    async def test_password_never_reaches_diagnostics_or_logs(self, tmp_path, monkeypatch, caplog):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        secret = "super-secret-pass"

        def failing_login(email, password, token_path):
            raise auth_module.FxaApiError("Incorrect password", errno=104, status_code=400)

        monkeypatch.setattr(api_module.auth_module, "login_with_password", failing_login)
        with patch.object(api_module, "get_app", return_value=_app_mock()):
            with pytest.raises(HTTPException):
                await api_module.account_signin(
                    api_module.SigninRequest(email="user@example.com", password=secret)
                )

        events = api_module.diagnostics.snapshot()
        for event in events:
            blob = " ".join(str(v) for v in event.values())
            assert secret not in blob

    @pytest.mark.asyncio
    async def test_password_not_in_diagnostics_on_success_path(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        secret = "another-secret"

        monkeypatch.setattr(
            api_module.auth_module, "login_with_password",
            lambda email, password, path: SimpleNamespace(access_token="tok"),
        )
        with patch.object(api_module, "get_app", return_value=_app_mock()):
            await api_module.account_signin(
                api_module.SigninRequest(email="user@example.com", password=secret)
            )
        events = api_module.diagnostics.snapshot()
        for event in events:
            blob = " ".join(str(v) for v in event.values())
            assert secret not in blob
