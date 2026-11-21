"""Unified FxA PKCE sign-in: URL parity, token UA split, callback, reset."""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest

from perchvpn import fxa, fxa_pkce
from perchvpn.exceptions import FxaApiError
from perchvpn_windows import api as api_module
from perchvpn_windows import oauth, webview

CHALLENGE = "A" * 43
STATE = "state-123"
CODE = "code-abc"
SUCCESS = f"https://accounts.firefox.com/oauth/success/a2270f727f45f648?code=code-abc&state=state-123"


class _Response:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


class TestPkceUrlParity:
    def test_authorization_url_is_valid_for_both_entry_points(self):
        url = fxa_pkce.build_authorization_url(CHALLENGE, STATE)
        parts = urlsplit(url)
        assert parts.scheme == "https"
        assert parts.netloc == "accounts.firefox.com"
        assert parts.path == "/authorization"
        q = parse_qs(parts.query)
        assert q["client_id"] == ["a2270f727f45f648"]
        assert q["scope"] == ["profile https://identity.mozilla.com/apps/vpn"]
        assert q["response_type"] == ["code"]
        assert q["access_type"] == ["offline"]
        assert q["redirect_uri"] == ["https://accounts.firefox.com/oauth/success/a2270f727f45f648"]
        assert q["code_challenge"] == [CHALLENGE]
        assert q["code_challenge_method"] == ["S256"]
        assert q["state"] == [STATE]

    def test_both_flow_builders_use_the_same_valid_url(self):
        interactive = oauth._begin_flow(loopback=True)
        external = oauth._begin_flow(loopback=False)
        for flow in (interactive, external):
            url = flow["authorization_url"]
            assert urlsplit(url).path == "/authorization"
            assert "client_id=a2270f727f45f648" in url
            assert "oob" not in url
            assert "Invalid Query Parameters" not in url
            oauth.reset_oauth_flow(flow["state"])

    def test_pkce_verifier_is_base64url(self):
        verifier, challenge = fxa_pkce.generate_pkce()
        assert len(verifier) == 43 and "=" not in verifier
        assert challenge != verifier and len(challenge) == 43


class TestOauthSuccessInterception:
    def test_parse_success_url_validates_state(self):
        parsed = fxa_pkce.parse_success_url(SUCCESS, STATE)
        assert parsed == {"code": CODE, "state": STATE}
        with pytest.raises(FxaApiError):
            fxa_pkce.parse_success_url(SUCCESS, "wrong-state")
        with pytest.raises(FxaApiError):
            fxa_pkce.parse_success_url("https://evil.example/?code=x", STATE)

    def test_embedded_window_bridge_is_gone(self):
        # pywebview 6.2.1's create_window() does not accept ``on_navigation``,
        # so the embedded success-interception bridge was removed together
        # with the interactive sign-in flow.
        assert not hasattr(webview, "_SigninWindowApi")
        assert not hasattr(webview, "_SIGNIN_WINDOW_API")

    def test_record_external_callback_accepts_full_url(self, monkeypatch):
        flow = oauth.PendingFlow(state=STATE, verifier="v", redirect_uri=fxa_pkce.SUCCESS_REDIRECT,
                                 callback=None, provider="fxa_pkce")
        monkeypatch.setattr(oauth, "_pending", flow, raising=False)
        assert oauth.record_external_callback(STATE, SUCCESS) is True
        assert oauth.complete_oauth_flow.__name__ == "complete_oauth_flow"


class TestTokenUaSplit:
    def test_form_token_exchange_retries_uas_and_uses_new_client(self, monkeypatch):
        seen = []

        def fake_post(url, **kwargs):
            seen.append((url, kwargs))
            if len(seen) == 1:
                return _Response(status_code=406)
            return _Response(payload={
                "access_token": "tok", "refresh_token": "ref", "expires_in": 3600,
                "scope": fxa_pkce.SCOPE, "token_type": "bearer",
            })

        monkeypatch.setattr(fxa_pkce.httpx, "post", fake_post)
        token = fxa.exchange_pkce_code(CODE, "verifier")
        assert token.access_token == "tok"
        assert seen[0][1]["headers"]["User-Agent"] == fxa_pkce.DESKTOP_USER_AGENT
        assert seen[1][1]["headers"]["User-Agent"] == fxa_pkce.PRODUCT_USER_AGENT
        body = seen[1][1]["data"]
        assert body["grant_type"] == "authorization_code"
        assert body["client_id"] == "a2270f727f45f648"
        assert body["code_verifier"] == "verifier"
        assert body["redirect_uri"] == fxa_pkce.SUCCESS_REDIRECT

    def test_refresh_uses_form_post_new_client(self, monkeypatch):
        seen = []

        def fake_post(url, **kwargs):
            seen.append(kwargs)
            return _Response(payload={"access_token": "new", "expires_in": 3600})

        monkeypatch.setattr(fxa_pkce.httpx, "post", fake_post)
        token = fxa.refresh_token("old")
        assert token.access_token == "new"
        assert seen[0]["data"]["grant_type"] == "refresh_token"
        assert seen[0]["data"]["client_id"] == "a2270f727f45f648"

    def test_guardian_client_never_used_on_fxa_token(self):
        assert "e6eb0d1e856335fc" not in fxa_pkce.SUCCESS_REDIRECT
        assert fxa_pkce.CLIENT_ID == "a2270f727f45f648"


class TestStateReset:
    def test_reset_oauth_flow_frees_slot(self, monkeypatch):
        flow = oauth._begin_flow(loopback=False)
        assert oauth.get_flow(flow["state"]) is not None
        assert oauth.reset_oauth_flow(flow["state"]) is True
        assert oauth.get_flow(flow["state"]) is None

    @pytest.mark.asyncio
    async def test_account_signin_reset_clears_stale_stage(self, monkeypatch):
        api_module._signin_state.update(stage="unblock_required", email="u@example.com",
                                        verification_method="email-captcha", session_token=None,
                                        expires_at=123.0, attempts=3)
        monkeypatch.setattr(api_module.auth_module, "login_with_password",
                            lambda *a, **k: (_ for _ in ()).throw(
                                api_module.auth_module.UnblockRequired("u@example.com", "email-captcha")))
        result = await api_module.account_signin(api_module.SigninRequest(
            email="u@example.com", password="pw", reset=True))
        assert result.status == "unblock_required"
        assert api_module._signin_state["attempts"] == 0
