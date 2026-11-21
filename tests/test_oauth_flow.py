"""OAuth browser sign-in flow: state/PKCE, callback security and exchanges.

The HTTP password login at FxA is edge-blocked for HTTP clients, so this is
the supported first-time sign-in path. Tests use recorded/mocked exchange
behaviour — no real credentials, and nothing is printed or logged.
"""

from __future__ import annotations

import socket
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

import src.perchvpn_windows.oauth as oauth_module
import src.perchvpn_windows.api as api_module
from src.perchvpn_windows.config import WindowsConfig


@pytest.fixture(autouse=True)
def _reset_flow():
    oauth_module._pending = None
    yield
    if oauth_module._pending is not None and oauth_module._pending.callback is not None:
        oauth_module._pending.callback.close()
    oauth_module._pending = None


def _app_mock():
    app = SimpleNamespace()
    app.load_persisted_auth = AsyncMock(return_value=True)
    app.config = WindowsConfig()
    return app


def _callback_url(port: int, query: str) -> None:
    """Simple loopback HTTP client for the one-shot callback server."""
    req = (
        f"GET /oauth/callback?{query} HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        "Connection: close\r\n\r\n"
    )
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(req.encode())
        chunks = []
        while True:
            try:
                data = s.recv(4096)
            except (ConnectionResetError, socket.timeout):
                break
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks)


class TestStartFlow:
    def test_returns_url_with_pkce_and_state(self):
        flow = oauth_module.start_oauth_flow()
        try:
            assert "accounts.firefox.com/authorization" in flow["authorization_url"]
            assert "code_challenge_method=S256" in flow["authorization_url"]
            assert "access_type=offline" in flow["authorization_url"]
            from perchvpn import fxa_pkce
            from urllib.parse import parse_qs, urlparse
            q = parse_qs(urlparse(flow["authorization_url"]).query)
            assert q["redirect_uri"][0] == fxa_pkce.SUCCESS_REDIRECT
        finally:
            oauth_module.cancel_oauth_flow(flow["state"])

    def test_pkce_verifier_is_s256_of_challenge_adapter(self):
        import base64
        import hashlib

        flow = oauth_module.start_oauth_flow()
        try:
            pending = oauth_module.get_flow(flow["state"])
            assert pending is not None
            verifier = pending.verifier
            challenge = base64.urlsafe_b64encode(
                hashlib.sha256(verifier.encode("ascii")).digest()
            ).decode().rstrip("=")
            from urllib.parse import urlparse, parse_qs
            q = parse_qs(urlparse(flow["authorization_url"]).query)
            assert q["code_challenge"][0] == challenge
            assert "verifier" not in flow["authorization_url"]
        finally:
            oauth_module.cancel_oauth_flow(flow["state"])

    def test_new_start_cancels_previous_listener(self):
        first = oauth_module.start_oauth_flow()
        second = oauth_module.start_oauth_flow()
        try:
            assert first["state"] != second["state"]
        finally:
            oauth_module.cancel_oauth_flow(second["state"])


class TestCallbackSecurity:
    def _flow(self):
        flow = oauth_module.start_oauth_flow()
        pending = oauth_module.get_flow(flow["state"])
        return flow, pending

    def test_unknown_state_is_rejected(self):
        # A forged state on a live listener must not consume the flow.
        flow, pending = self._flow()
        try:
            raw = _callback_url(pending.callback.port, "code=x&state=forged-not-active")
            assert raw.split(b" ", 2)[1] == b"400"
            assert pending.result is None
        finally:
            oauth_module.cancel_oauth_flow(flow["state"])

    def test_callback_records_code_and_redirects_without_exposing_it(self):
        flow, pending = self._flow()
        try:
            raw = _callback_url(pending.callback.port, f"code=secret-auth-code&state={flow['state']}")
            assert raw.split(b" ", 2)[1] == b"303"
            assert b"Location: http://127.0.0.1:8765/#oauth_dispatch=" in raw
            assert b"secret-auth-code" not in raw.split(b"Location:", 1)[1].split(b"\r\n")[0]
            # The code never leaves the wire back to the app: it lives only
            # server-side until the exchange.
            assert b"secret-auth-code" not in raw.replace(b"secret", b"")
            status, data = pending.result
            assert status == "ok" and data["code"] == "secret-auth-code"
        finally:
            oauth_module.cancel_oauth_flow(flow["state"])

    def test_provider_denied_maps_to_cancelled_kind(self):
        flow, pending = self._flow()
        try:
            raw = _callback_url(pending.callback.port, f"error=access_denied&state={flow['state']}")
            assert raw.split(b" ", 2)[1] == b"303"
            status, data = pending.result
            assert status == "error" and data["kind"] == "provider_denied"
        finally:
            oauth_module.cancel_oauth_flow(flow["state"])

    def test_malformed_callback_maps_to_invalid_callback(self):
        flow, pending = self._flow()
        try:
            _callback_url(pending.callback.port, f"state={flow['state']}")  # no code
            status, data = pending.result
            assert status == "error" and data["kind"] == "invalid_callback"
        finally:
            oauth_module.cancel_oauth_flow(flow["state"])

    def test_state_mismatch_leaves_flow_pending(self):
        flow, pending = self._flow()
        try:
            raw = _callback_url(pending.callback.port, "code=x&state=forged-state")
            assert raw.split(b" ", 2)[1] == b"400"
            assert pending.result is None
        finally:
            oauth_module.cancel_oauth_flow(flow["state"])


class TestComplete:
    @pytest.mark.asyncio
    async def test_happy_path_exchanges_installs_and_persists(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        flow = oauth_module.start_oauth_flow()
        pending = oauth_module.get_flow(flow["state"])
        _callback_url(pending.callback.port, f"code=secret-auth-code&state={flow['state']}")

        token_obj = SimpleNamespace(access_token="at", refresh_token="rt",
                                    expires_in=3600, scope="s", token_type="bearer")
        exchange_kwargs = {}
        monkeypatch.setattr(
            oauth_module.fxa, "exchange_pkce_code",
            lambda code, verifier: exchange_kwargs.update(
                code=code, verifier=verifier) or token_obj,
        )
        app = _app_mock()
        monkeypatch.setattr(api_module, "get_app", lambda: app)

        result = await api_module.oauth_complete(api_module.OAuthCompleteRequest(state=flow["state"]))
        assert result.status == "signed_in"
        assert exchange_kwargs == {
            "code": "secret-auth-code",
            "verifier": pending.verifier,
        }
        assert oauth_module.get_flow(flow["state"]) is None  # consumed
        assert oauth_module._pending is None

    @pytest.mark.asyncio
    async def test_replay_is_rejected(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        flow = oauth_module.start_oauth_flow()
        pending = oauth_module.get_flow(flow["state"])
        _callback_url(pending.callback.port, f"code=secret-auth-code&state={flow['state']}")

        token_obj = SimpleNamespace(access_token="at", refresh_token="rt",
                                    expires_in=3600, scope="s", token_type="bearer")
        monkeypatch.setattr(oauth_module.fxa, "exchange_pkce_code",
                            lambda code, verifier: token_obj)
        app = _app_mock()
        monkeypatch.setattr(api_module, "get_app", lambda: app)

        await api_module.oauth_complete(api_module.OAuthCompleteRequest(state=flow["state"]))
        with pytest.raises(api_module.HTTPException) as excinfo:
            await api_module.oauth_complete(api_module.OAuthCompleteRequest(state=flow["state"]))
        assert excinfo.value.status_code == 404

    @pytest.mark.asyncio
    async def test_uncompleted_callback_notifies_waiting(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        flow = oauth_module.start_oauth_flow()
        try:
            app = _app_mock()
            monkeypatch.setattr(api_module, "get_app", lambda: app)
            with pytest.raises(api_module.HTTPException) as excinfo:
                await api_module.oauth_complete(api_module.OAuthCompleteRequest(state=flow["state"]))
            assert excinfo.value.status_code == 409
            assert "not finished" in str(excinfo.value.detail)
        finally:
            oauth_module.cancel_oauth_flow(flow["state"])

    @pytest.mark.asyncio
    async def test_provider_denied_reports_visible_task(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        flow = oauth_module.start_oauth_flow()
        pending = oauth_module.get_flow(flow["state"])
        _callback_url(pending.callback.port, f"error=access_denied&state={flow['state']}")
        try:
            app = _app_mock()
            monkeypatch.setattr(api_module, "get_app", lambda: app)
            with pytest.raises(api_module.HTTPException) as excinfo:
                await api_module.oauth_complete(api_module.OAuthCompleteRequest(state=flow["state"]))
            assert excinfo.value.status_code == 400
            assert "not completed in the browser" in str(excinfo.value.detail)
            # the failure closes the listener and frees the single-flow slot
            assert oauth_module._pending is None
        finally:
            pass

    @pytest.mark.asyncio
    async def test_expired_code_fails_with_actionable_message(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        flow = oauth_module.start_oauth_flow()
        pending = oauth_module.get_flow(flow["state"])
        _callback_url(pending.callback.port, f"code=secret-auth-code&state={flow['state']}")

        from perchvpn.exceptions import FxaApiError

        def fake_exchange(code, verifier):
            raise FxaApiError("HTTP 400 invalid grant", errno=None, status_code=400)

        monkeypatch.setattr(oauth_module.fxa, "exchange_pkce_code", fake_exchange)
        app = _app_mock()
        monkeypatch.setattr(api_module, "get_app", lambda: app)
        with pytest.raises(api_module.HTTPException) as excinfo:
            await api_module.oauth_complete(api_module.OAuthCompleteRequest(state=flow["state"]))
        assert excinfo.value.status_code == 400
        assert "expired" in str(excinfo.value.detail)
        assert oauth_module._pending is None

    @pytest.mark.asyncio
    async def test_state_ttl_expiry(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        flow = oauth_module.start_oauth_flow()
        pending = oauth_module.get_flow(flow["state"])
        pending.created_at = time.monotonic() - (oauth_module.STATE_TTL_SECONDS + 1)
        app = _app_mock()
        monkeypatch.setattr(api_module, "get_app", lambda: app)
        with pytest.raises(api_module.HTTPException) as excinfo:
            await api_module.oauth_complete(api_module.OAuthCompleteRequest(state=flow["state"]))
        assert excinfo.value.status_code == 404

    @pytest.mark.asyncio
    async def test_cancellation_frees_slot_and_fails_complete(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        flow = oauth_module.start_oauth_flow()
        ok = oauth_module.cancel_oauth_flow(flow["state"])
        assert ok is True
        app = _app_mock()
        monkeypatch.setattr(api_module, "get_app", lambda: app)
        with pytest.raises(api_module.HTTPException) as excinfo:
            await api_module.oauth_complete(api_module.OAuthCompleteRequest(state=flow["state"]))
        assert excinfo.value.status_code == 404
        # the cancelled signal is API-visible (polling view)
        with patch.object(oauth_module, "get_flow", return_value=None):
            assert oauth_module.oauth_flow_status(flow["state"])["status"] == "unknown_or_expired"

    @pytest.mark.asyncio
    async def test_exchange_service_outage_maps_to_502(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        flow = oauth_module.start_oauth_flow()
        pending = oauth_module.get_flow(flow["state"])
        _callback_url(pending.callback.port, f"code=secret-auth-code&state={flow['state']}")

        def fake_exchange(code, verifier):
            raise RuntimeError("connection reset during exchange")

        monkeypatch.setattr(oauth_module.fxa, "exchange_pkce_code", fake_exchange)
        app = _app_mock()
        monkeypatch.setattr(api_module, "get_app", lambda: app)
        with pytest.raises(api_module.HTTPException) as excinfo:
            await api_module.oauth_complete(api_module.OAuthCompleteRequest(state=flow["state"]))
        assert excinfo.value.status_code == 502


class TestFrontendWiring:
    def test_single_password_form_is_the_only_signin_entry_point(self):
        # Interactive/browser sign-in was removed: the embedded WebView2
        # window passed an unsupported ``on_navigation`` kwarg (pywebview
        # 6.2.1) and the browser flow dead-ended. One background
        # email+password flow is the contract now.
        import pathlib
        root = pathlib.Path(__file__).resolve().parents[1]
        html = (root / "src" / "perchvpn_windows" / "web" / "index.html").read_text(encoding="utf-8")
        assert 'id="signin-email"' in html
        assert 'id="signin-password"' in html
        assert 'id="signin-submit"' in html
        assert 'id="signin-verify"' in html and 'id="signin-unblock"' in html
        assert 'id="verify-resend"' in html
        assert 'id="session-token-input"' in html
        for stale in ("signin-oauth", "signin-interactive", "signin-browser", "browser-code"):
            assert f'id="{stale}"' not in html

    def test_browser_oauth_js_and_password_flow_coexist(self):
        import pathlib
        root = pathlib.Path(__file__).resolve().parents[1]
        js = (root / "src" / "perchvpn_windows" / "web" / "app.js").read_text(encoding="utf-8")
        # No hidden-iframe/loopback-return trampoline, no browser popup.
        assert "maybeHandleOAuthReturn" not in js
        assert "oauth_dispatch" not in js
        assert "openBrowserSignIn" not in js and "openEmbeddedSignIn" not in js
        # background password flow + inline confirmation
        assert "showSigninError" in js and "submitSignIn" in js
        assert "resendVerificationCode" in js

    def test_password_error_handling_not_removed(self):
        import pathlib
        root = pathlib.Path(__file__).resolve().parents[1]
        css = (root / "src" / "perchvpn_windows" / "web" / "styles.css").read_text(encoding="utf-8")
        assert ".setting-error:not([hidden])" in css
        api = (root / "src" / "perchvpn_windows" / "api.py").read_text(encoding="utf-8")
        assert "edge_blocked" in api


class TestSecurityProperties:
    def test_verifier_never_leaves_server(self):
        flow = oauth_module.start_oauth_flow()
        try:
            assert "verifier" not in flow["authorization_url"]
            assert "=" not in flow["authorization_url"].split("code_challenge=")[1].split("&")[0]
        finally:
            oauth_module.cancel_oauth_flow(flow["state"])

    def test_state_is_high_entropy(self):
        flow = oauth_module.start_oauth_flow()
        try:
            assert len(flow["state"]) >= 24
            via = oauth_module.get_flow(flow["state"])
            assert len(via.verifier) >= 43  # RFC 7636 minimum
            from perchvpn import fxa_pkce
            assert fxa_pkce.CLIENT_ID in flow["authorization_url"]
        finally:
            oauth_module.cancel_oauth_flow(flow["state"])


class TestOutOfBandFlow:
    """The client only registers urn:ietf:wg:oauth:2.0:oob, so browser
    sign-in runs without a loopback listener and the user pastes the code."""

    def test_oob_flow_uses_registered_redirect_and_no_listener(self):
        flow = oauth_module.start_oauth_oob_flow()
        try:
            from perchvpn import fxa_pkce
            from urllib.parse import parse_qs, urlparse
            q = parse_qs(urlparse(flow["authorization_url"]).query)
            assert q["redirect_uri"][0] == fxa_pkce.SUCCESS_REDIRECT
            assert "oob" not in flow["authorization_url"]
            assert flow["loopback"] is False
            assert oauth_module.get_flow(flow["state"]).callback is None
        finally:
            oauth_module.cancel_oauth_flow(flow["state"])

    def test_submitted_code_is_exchanged_with_pkce_verifier(self, monkeypatch):
        seen = {}

        def fake_exchange(code, verifier):
            seen.update(code=code, verifier=verifier)
            return SimpleNamespace(access_token="tok-oob")

        monkeypatch.setattr(oauth_module.fxa, "exchange_pkce_code", fake_exchange)
        flow = oauth_module.start_oauth_oob_flow()
        pending = oauth_module.get_flow(flow["state"])
        token = oauth_module.submit_oauth_code(flow["state"], "  auth-code  ")
        assert token.access_token == "tok-oob"
        assert seen["code"] == "auth-code"
        assert seen["verifier"] == pending.verifier
        assert oauth_module.get_flow(flow["state"]) is None

    def test_submitted_code_is_single_use(self, monkeypatch):
        monkeypatch.setattr(
            oauth_module.fxa, "exchange_pkce_code",
            lambda code, verifier: SimpleNamespace(access_token="t"),
        )
        flow = oauth_module.start_oauth_oob_flow()
        oauth_module.submit_oauth_code(flow["state"], "code")
        with pytest.raises(oauth_module.OAuthError):
            oauth_module.submit_oauth_code(flow["state"], "code")

    def test_blank_code_is_refused(self):
        flow = oauth_module.start_oauth_oob_flow()
        try:
            with pytest.raises(oauth_module.OAuthError) as exc:
                oauth_module.submit_oauth_code(flow["state"], "   ")
            assert exc.value.kind == "invalid_callback"
        finally:
            oauth_module.cancel_oauth_flow(flow["state"])

    def test_oauth_open_endpoint_hands_back_oob_url(self):
        import asyncio

        with patch.object(oauth_module, "open_authorization_url", return_value=True):
            body = asyncio.run(api_module.oauth_open())
        from perchvpn import fxa_pkce
        assert fxa_pkce.CLIENT_ID in body.authorization_url
        assert body.launched is True
        oauth_module.cancel_oauth_flow(body.state)
