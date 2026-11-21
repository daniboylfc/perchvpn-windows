"""Firefox Accounts anti-bot resilience.

Covers the two supported ways around FxA's login anti-bot filter:

* a fresh ``metrics-flow`` (``flowId``/``flowBeginTime``) attached to the
  login body as ``metricsContext`` -- the documented prerequisite for a
  relying-party hosted email form;
* an ``errno 125`` "request blocked" answer, which means FxA emailed an
  unblock code: surface it in the UI and retry ``account/login`` with
  ``unblockCode`` instead of failing dead.

The browser PKCE flow already exists; these tests pin the new UI/API wiring
so a regression cannot silently remove the fallback paths.
"""

from __future__ import annotations

import pathlib
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import src.perchvpn_windows.api as api_module

# Use the exact module objects the API calls, so exception identity matches
# even when the test imports the tree as ``src.*``.
auth_module = api_module.auth_module
fxa = auth_module.fxa
FxaApiError = auth_module.FxaApiError
FxaUnblockCodeRequired = auth_module.FxaUnblockCodeRequired

WEB = pathlib.Path(__file__).resolve().parents[1] / "src" / "perchvpn_windows" / "web"


class _FakeResponse:
    def __init__(self, status_code=200, payload=None, content=b"x"):
        self.status_code = status_code
        self._payload = payload or {}
        self.content = content
        self.text = ""

    def json(self):
        return self._payload


class _FakeClient:
    def __init__(self, get_response=None, request_response=None):
        self.get_response = get_response or _FakeResponse()
        self.request_response = request_response or _FakeResponse(
            payload={"sessionToken": "ab" * 32, "uid": "u", "verified": True}
        )
        self.gets: list[tuple[str, dict]] = []
        self.requests: list[tuple[str, str, dict]] = []

    def get(self, url, params=None, headers=None):
        self.gets.append((url, dict(params or {})))
        return self.get_response

    def request(self, method, url, headers=None, content=None):
        self.requests.append((method, url, {"headers": headers, "content": content}))
        return self.request_response


class TestMetricsFlow:
    def test_fetch_metrics_flow_parses_flow_id_and_begin_time(self):
        client = _FakeClient(_FakeResponse(payload={"flowId": "a" * 64, "flowBeginTime": 1_700_000_000}))
        flow = fxa.fetch_metrics_flow(client)
        assert flow["flowId"] == "a" * 64
        assert flow["flowBeginTime"] == 1_700_000_000
        assert len(flow["deviceId"]) == 32
        assert flow["entrypoint"] == fxa.FXA_METRICS_ENTRYPOINT
        assert flow["formType"] == fxa.FXA_METRICS_CONTEXT_FORM
        url, params = client.gets[0]
        assert url == fxa.FXA_METRICS_FLOW_URL
        assert params["form_type"] == "email"
        assert params["entrypoint"] == fxa.FXA_METRICS_ENTRYPOINT

    def test_fetch_metrics_flow_is_best_effort(self):
        assert fxa.fetch_metrics_flow(_FakeClient(_FakeResponse(status_code=500))) is None
        assert fxa.fetch_metrics_flow(_FakeClient(_FakeResponse(payload={"flowId": ""}))) is None
        assert fxa.fetch_metrics_flow(_FakeClient(_FakeResponse(payload={"flowId": "a" * 64}))) is None

    def test_login_attaches_metrics_context_and_verification_method(self, monkeypatch):
        client = _FakeClient()
        monkeypatch.setattr(fxa, "get_client", lambda: client)
        monkeypatch.setattr(
            fxa, "fetch_metrics_flow",
            lambda *a, **k: {"flowId": "b" * 64, "flowBeginTime": 1_700_000_001},
        )
        response = fxa.login("user@example.com", "pw")
        assert response.session_token == "ab" * 32
        body = client.requests[-1][2]["content"]
        assert b'"metricsContext"' in body
        assert b'"flowId"' in body and b"1" in body
        assert b'"verificationMethod":"email-2fa"' in body

    def test_login_can_skip_metrics_flow(self, monkeypatch):
        client = _FakeClient()
        monkeypatch.setattr(fxa, "get_client", lambda: client)
        fxa.login("user@example.com", "pw", fetch_flow=False)
        assert b"metricsContext" not in client.requests[-1][2]["content"]


class TestUnblockCode:
    def test_errno_125_raises_unblock_required_with_method(self, monkeypatch):
        blocked = _FakeResponse(
            status_code=400,
            payload={
                "errno": 125,
                "message": "The request was blocked for security reasons",
                "verificationMethod": "email-captcha",
            },
        )
        client = _FakeClient(request_response=blocked)
        monkeypatch.setattr(fxa, "get_client", lambda: client)
        monkeypatch.setattr(fxa, "fetch_metrics_flow", lambda *a, **k: None)
        with pytest.raises(FxaUnblockCodeRequired) as excinfo:
            fxa.login("user@example.com", "pw")
        assert excinfo.value.verification_method == "email-captcha"
        assert excinfo.value.errno == 125

    def test_retry_sends_unblock_code(self, monkeypatch):
        client = _FakeClient()
        monkeypatch.setattr(fxa, "get_client", lambda: client)
        monkeypatch.setattr(fxa, "fetch_metrics_flow", lambda *a, **k: None)
        fxa.login("user@example.com", "pw", unblock_code="ABC123")
        body = client.requests[-1][2]["content"]
        assert b'"unblockCode":"ABC123"' in body

    def test_send_unblock_code_endpoint_call(self, monkeypatch):
        client = _FakeClient(request_response=_FakeResponse(payload={}))
        monkeypatch.setattr(fxa, "get_client", lambda: client)
        monkeypatch.setattr(fxa, "fetch_metrics_flow", lambda *a, **k: None)
        fxa.send_unblock_code("user@example.com")
        method, url, _ = client.requests[-1]
        assert method == "POST"
        assert url.endswith("/account/login/send_unblock_code")

    def test_classification_marks_block_and_bad_code(self):
        blocked = FxaApiError("blocked", errno=125, status_code=400)
        kind, message = api_module._classify_fxa_signin_error(blocked)
        assert kind == "unblock_required"
        assert "authorization code" in message

        bad = FxaApiError("bad code", errno=127, status_code=400)
        kind, message = api_module._classify_fxa_signin_error(bad)
        assert kind == "invalid_unblock_code"


class TestSigninEndpointUnblock:
    @pytest.mark.asyncio
    async def test_blocked_login_returns_unblock_required(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        api_module._signin_state.update(stage="idle", email="", verification_method="",
                                        session_token=None, expires_at=0.0, attempts=0)
        seen = {}

        def fake_login(email, password, token_path, unblock_code=None):
            seen["unblock_code"] = unblock_code
            raise api_module.auth_module.UnblockRequired(email, "email-captcha")

        sent = []
        monkeypatch.setattr(api_module.auth_module, "login_with_password", fake_login)
        monkeypatch.setattr(
            api_module.auth_module, "send_unblock_code", lambda email: sent.append(email)
        )
        result = await api_module.account_signin(
            api_module.SigninRequest(email="user@example.com", password="pw")
        )
        assert result.status == "unblock_required"
        assert result.verification_method == "email-captcha"
        assert seen["unblock_code"] is None
        assert sent == ["user@example.com"]
        assert result.authorization_url == "" and result.state == ""
        assert api_module._signin_state["stage"] == "unblock_required"

    @pytest.mark.asyncio
    async def test_retry_passes_the_code_and_signs_in(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        api_module._signin_state.update(stage="unblock_required", email="user@example.com",
                                        verification_method="email-captcha",
                                        session_token=None, expires_at=0.0, attempts=0)
        seen = {}

        def fake_login(email, password, token_path, unblock_code=None):
            seen["unblock_code"] = unblock_code
            return SimpleNamespace(access_token="tok")

        async def fake_install():
            return True

        monkeypatch.setattr(api_module.auth_module, "login_with_password", fake_login)
        monkeypatch.setattr(api_module, "_install_signed_in_auth", fake_install)
        result = await api_module.account_signin(
            api_module.SigninRequest(
                email="user@example.com", password="pw", unblock_code="ABC123"
            )
        )
        assert result.status == "signed_in"
        assert seen["unblock_code"] == "ABC123"


class TestSessionTokenImport:
    @pytest.mark.asyncio
    async def test_import_signs_in(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        api_module._signin_state.update(stage="idle", email="", verification_method="",
                                        session_token=None, expires_at=0.0, attempts=0)

        def fake_exchange(session_token, token_path):
            assert session_token == "ab" * 32
            return SimpleNamespace(access_token="tok")

        async def fake_install():
            return True

        monkeypatch.setattr(api_module.auth_module, "login_with_session_token", fake_exchange)
        monkeypatch.setattr(api_module, "_install_signed_in_auth", fake_install)
        result = await api_module.account_session_token(
            api_module.SessionTokenRequest(session_token="ab" * 32)
        )
        assert result.status == "signed_in"

    @pytest.mark.asyncio
    async def test_invalid_token_is_401(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        api_module._signin_state.update(stage="idle", email="", verification_method="",
                                        session_token=None, expires_at=0.0, attempts=0)

        def fake_exchange(session_token, token_path):
            raise FxaApiError("invalid", errno=None, status_code=400)

        monkeypatch.setattr(api_module.auth_module, "login_with_session_token", fake_exchange)
        with pytest.raises(api_module.HTTPException) as excinfo:
            await api_module.account_session_token(
                api_module.SessionTokenRequest(session_token="nope")
            )
        assert excinfo.value.status_code == 401


class TestAccountUiWiring:
    def test_only_background_password_signin_is_offered(self):
        html = (WEB / "index.html").read_text(encoding="utf-8")
        js = (WEB / "app.js").read_text(encoding="utf-8")
        for stale in ("signin-oauth", "signin-interactive", "signin-browser",
                      "browser-code", "openEmbeddedSignIn", "on_navigation"):
            assert stale not in html and stale not in js
        assert 'id="signin-email"' in html and 'id="signin-password"' in html
        assert "/api/account/signin" in js
        assert "/api/account/verify/resend" in js

    def test_unblock_panel_and_retry_wiring(self):
        html = (WEB / "index.html").read_text(encoding="utf-8")
        js = (WEB / "app.js").read_text(encoding="utf-8")
        assert 'id="signin-unblock"' in html and 'id="session-token-box"' in html
        assert "unblock_required" in js
        assert "payload.unblock_code = unblockCode" in js
        assert "/api/account/unblock/send" in js

    def test_session_token_controls_present(self):
        html = (WEB / "index.html").read_text(encoding="utf-8")
        js = (WEB / "app.js").read_text(encoding="utf-8")
        for element_id in ("session-token-input", "session-token-feedback",
                           "btn-save-token", "btn-import-token", "btn-clear-tokens",
                           "session-token-file"):
            assert f'id="{element_id}"' in html, element_id
        assert "/api/account/session-token" in js
