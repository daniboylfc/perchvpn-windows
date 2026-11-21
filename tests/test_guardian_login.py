"""Guardian v2 desktop PKCE flow and FxA anti-bot hardening."""

from __future__ import annotations

import base64
import hashlib
import json
from urllib.parse import parse_qs, urlsplit

import pytest

from perchvpn import fxa, guardian_login
from perchvpn_windows import oauth, webview

CODE = "a" * 80


class _Resp:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text
        self.content = text.encode() if text else b"{}"

    def json(self):
        return self._payload


class _Client:
    def __init__(self, get_resp=None, post_resp=None):
        self.get_resp = get_resp or _Resp()
        self.post_resp = post_resp or _Resp()
        self.gets = []
        self.posts = []

    def get(self, url, **kwargs):
        self.gets.append((url, kwargs))
        return self.get_resp

    def post(self, url, **kwargs):
        self.posts.append((url, kwargs))
        return self.post_resp

    def request(self, method, url, **kwargs):
        self.posts.append((method, url, kwargs))
        return self.post_resp


def _fxa_oauth():
    return {
        "url": "https://accounts.firefox.com/authorization",
        "params": {
            "client_id": "e6eb0d1e856335fc",
            "scope": "profile https://identity.mozilla.com/account/subscriptions",
            "response_type": "code",
            "redirect_uri": "https://vpn.mozilla.org/oauth/success",
            "access_type": "offline",
            "action": "email",
            "state": "pkce43817-test",
            "device_id": "d" * 32,
            "flow_begin_time": "1795128051059",
            "flow_id": "f" * 64,
        },
    }


class TestGuardianPkceUrl:
    def test_authorization_url_uses_guardian_client_and_challenge(self):
        url = guardian_login.build_authorization_url(_fxa_oauth(), "CHALLENGE")
        parts = urlsplit(url)
        assert parts.netloc == "accounts.firefox.com"
        assert parts.path == "/authorization"
        query = parse_qs(parts.query)
        assert query["client_id"] == ["e6eb0d1e856335fc"]
        assert query["code_challenge"] == ["CHALLENGE"]
        assert query["code_challenge_method"] == ["S256"]
        assert query["redirect_uri"] == ["https://vpn.mozilla.org/oauth/success"]
        assert "5882386c6d801776" not in url
        assert "oob" not in url

    def test_request_login_url_sends_pkce_params_and_mozilla_ua(self):
        client = _Client(_Resp(payload={"fxa_oauth": _fxa_oauth()}))
        info = guardian_login.request_login_url("CHALLENGE", 43817, client=client)
        url, kwargs = client.gets[0]
        assert url == (
            guardian_login.GUARDIAN_LOGIN_ENDPOINT
            + guardian_login.GUARDIAN_LOGIN_PATH
        )
        assert kwargs["params"] == {
            "code_challenge": "CHALLENGE",
            "code_challenge_method": "S256",
            "port": 43817,
        }
        assert kwargs["headers"]["User-Agent"].startswith("MozillaVPN/")
        assert info["port"] == 43817
        assert "accounts.firefox.com/authorization" in info["authorization_url"]

    def test_pkce_challenge_is_s256(self):
        verifier, challenge = guardian_login.generate_pkce()
        expected = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()
        ).decode().rstrip("=")
        assert challenge == expected
        assert "=" not in verifier and "=" not in challenge


class TestGuardianCallback:
    def test_callback_code_is_80_hex(self):
        assert guardian_login.is_valid_callback_code(CODE)
        assert guardian_login.is_valid_callback_code(CODE.upper())
        assert not guardian_login.is_valid_callback_code("short")
        assert not guardian_login.is_valid_callback_code("g" * 80)

    def test_loopback_callback_records_code_without_state(self, monkeypatch):
        flow = oauth.PendingFlow(
            state="state-1", verifier="verifier", redirect_uri="http://127.0.0.1:1/",
            callback=None, provider="guardian",
        )
        monkeypatch.setattr(oauth, "_pending", flow, raising=False)
        status, headers, _body = oauth._process_callback("GET", "/", f"code={CODE}")
        assert status == 303
        assert headers.startswith("Location:")
        assert flow.result == ("ok", {"code": CODE})

    def test_malformed_loopback_callback_records_error(self, monkeypatch):
        flow = oauth.PendingFlow(
            state="state-2", verifier="verifier", redirect_uri="http://127.0.0.1:1/",
            callback=None, provider="guardian",
        )
        monkeypatch.setattr(oauth, "_pending", flow, raising=False)
        oauth._process_callback("GET", "/", "code=bad")
        assert flow.result == ("error", {"kind": "invalid_callback"})


class TestGuardianTokenExchange:
    def test_exchange_posts_code_and_verifier(self):
        client = _Client(
            post_resp=_Resp(payload={"token": "guardian-token", "user": {}})
        )
        token = guardian_login.exchange_login_code(CODE, "verifier", client=client)
        assert token == "guardian-token"
        url, kwargs = client.posts[0]
        assert url.endswith(guardian_login.GUARDIAN_VERIFY_PATH)
        assert kwargs["json"] == {"code": CODE, "code_verifier": "verifier"}
        assert kwargs["headers"]["User-Agent"].startswith("MozillaVPN/")

    def test_exchange_refuses_invalid_code(self):
        with pytest.raises(Exception):
            guardian_login.exchange_login_code("bad", "verifier", client=_Client())

    def test_install_token_persists_access_token(self, tmp_path):
        path = tmp_path / "tokens.json"
        guardian_login.install_login_token("guardian-token", path)
        saved = json.loads(path.read_text(encoding="utf-8"))
        assert saved["access_token"] == "guardian-token"


class TestFxaDesktopIdentity:
    def test_login_sends_product_ua_with_browser_headers(self, monkeypatch):
        client = _Client(
            post_resp=_Resp(
                payload={"sessionToken": "ab" * 32, "uid": "u", "verified": True}
            )
        )
        monkeypatch.setattr(fxa, "get_client", lambda: client)
        monkeypatch.setattr(fxa, "fetch_metrics_flow", lambda: None)
        fxa.login("user@example.com", "pw")
        headers = client.posts[0][2]["headers"]
        assert headers["User-Agent"] == fxa.FXA_API_USER_AGENT
        assert headers["Origin"] == fxa.FXA_ORIGIN
        assert headers["Referer"] == fxa.FXA_REFERER
        assert "MozillaVPN" not in headers["User-Agent"]

    def test_metrics_context_is_complete(self):
        client = _Client(
            get_resp=_Resp(
                payload={"flowId": "f" * 64, "flowBeginTime": 1_700_000_000}
            )
        )
        context = fxa.fetch_metrics_flow(client)
        for key in ("flowId", "flowBeginTime", "deviceId", "entrypoint", "formType"):
            assert context[key]
        assert context["deviceId"] != fxa.fetch_metrics_flow(client)["deviceId"]


class TestEmbeddedWindowRemoved:
    def test_webview_no_longer_exposes_a_signin_bridge(self):
        # pywebview 6.2.1's create_window() has no ``on_navigation`` kwarg, so
        # the embedded sign-in window could never open. It was removed in
        # favour of the single background password flow.
        assert not hasattr(webview, "_SIGNIN_WINDOW_API")
        assert not hasattr(webview, "_SigninWindowApi")
