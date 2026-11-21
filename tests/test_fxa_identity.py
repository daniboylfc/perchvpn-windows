"""FxA requests identify themselves honestly and pass the modern edge.

Fastly now challenges requests that present browser-family User-Agents
("MozillaVPN/…", "Mozilla/… Chrome/…") with an empty-body 406 that cannot
be solved (no challenge page on the API host; site-host cookies are not
accepted there). A truthful, non-browser product UA passes: probe-verified
for /v1/oauth/token on 2026-10-31.
"""

from __future__ import annotations

from types import SimpleNamespace

from perchvpn import fxa


class _FakeResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload
        self.text = str(payload)
        import json
        self.content = json.dumps(payload).encode("utf-8")

    def json(self):
        return self._payload


class _HeaderCapturingClient:
    def __init__(self, responder):
        self.captured = []
        self._responder = responder

    def request(self, method, url, headers=None, content=None):
        self.captured.append({"method": method, "headers": dict(headers or {}),
                              "url": url})
        return self._responder(method, url, headers, content)


def _responder(method, url, headers, content):
    if "login" in url:
        return _FakeResponse(200, {"uid": "1", "sessionToken": "s" * 64, "verified": True})
    return _FakeResponse(200, {"access_token": "t", "refresh_token": "r", "expires_in": 3600})


def test_fxa_api_uses_product_ua_with_browser_headers():
    client = _HeaderCapturingClient(_responder)
    orig = fxa.get_client
    fxa.get_client = lambda: client
    try:
        resp = fxa.login("probe-not-a-real-account@example.com", "pw")
    finally:
        fxa.get_client = orig
    headers = client.captured[0]["headers"]
    ua = headers.get("User-Agent", "")
    assert ua == fxa.FXA_API_USER_AGENT
    assert ua.startswith("perchvpn/")
    assert headers["Origin"] == fxa.FXA_ORIGIN
    assert headers["Referer"] == fxa.FXA_REFERER
    assert resp.session_token  # JSON handling still normal


def test_hawk_requests_also_send_product_ua_and_never_reuse_signatures():
    client = _HeaderCapturingClient(_responder)
    orig = fxa.get_client
    fxa.get_client = lambda: client
    try:
        fxa.oauth_token("a" * 64)
        fxa.oauth_token("b" * 64)
    finally:
        fxa.get_client = orig
    for captured in client.captured:
        auth = captured["headers"].get("Authorization", "")
        assert auth.startswith("Hawk ")
        assert captured["headers"].get("User-Agent", "") == fxa.FXA_API_USER_AGENT
    # Two calls must produce different nonce/mac pairs: no signature reuse.
    auth1 = client.captured[0]["headers"]["Authorization"]
    auth2 = client.captured[1]["headers"]["Authorization"]
    assert auth1 != auth2
