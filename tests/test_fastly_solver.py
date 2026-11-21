"""Fastly challenge solver: browser-TLS transport and host fallback.

A plain OpenSSL/httpx client is served an unsolvable ``captcha`` challenge
by Fastly; a browser TLS fingerprint (curl_cffi) is offered the solvable
PAT -> PoW -> clientmetrics chain. These tests pin the host fallback (the
API host root answers 406 without a challenge page) and the cookie install
that lets the retried httpx API call pass.
"""

from __future__ import annotations

import hashlib

import httpx
import pytest

from perchvpn import fastly
from perchvpn.exceptions import FastlyChallengeError

API = "https://api.accounts.firefox.com"
SITE = "https://accounts.firefox.com"
PREFIX = "/_fs-ch-TEST"


class _Resp:
    def __init__(self, status_code=200, text="", payload=None):
        self.status_code = status_code
        self.text = text
        self._payload = payload if payload is not None else {}

    def json(self):
        return self._payload


class _FakeSession:
    def __init__(self, script, postbacks):
        self.script = script
        self.postbacks = list(postbacks)
        self.cookies = {}
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(("GET", url))
        if url == API + "/":
            return _Resp(406, "")
        if url == SITE + "/":
            return _Resp(200, '<title>Client Challenge</title><script src="' + PREFIX + '/script.js"></script>')
        if url == SITE + PREFIX + "/script.js?reload=true":
            return _Resp(200, self.script)
        return _Resp(404, "")

    def post(self, url, **kwargs):
        self.calls.append(("POST", url))
        if "/pat?token=" in url:
            return _Resp(400, "")
        if url.endswith("/fst-post-back"):
            response = self.postbacks.pop(0)
            if response._payload.get("status") == "success":
                self.cookies = {"_fs_ch_st_TEST": "solved"}
            return response
        return _Resp(404, "")

    def close(self):
        pass


def _pow_data():
    base = "b"
    return {"ty": "pow", "data": {"base": base, "hash": hashlib.sha256((base + "aa").encode()).hexdigest(), "hmac": "h", "expires": "e"}}


def test_api_host_406_falls_through_and_cookies_are_installed(monkeypatch):
    script = 'init([{"ty":"pat"}],"tok1","/next")'
    postbacks = [
        _Resp(200, payload={"status": "next", "tok": "tok2", "ch": [_pow_data(), {"ty": "clientmetrics"}]}),
        _Resp(200, payload={"status": "success"}),
    ]
    session = _FakeSession(script, postbacks)
    monkeypatch.setattr(fastly, "_browser_session", lambda: session)

    client = httpx.Client()
    fastly.solve_fastly_challenge(client, _Resp(406))

    assert session.calls[0] == ("GET", API + "/")
    assert ("GET", SITE + "/") in session.calls
    assert client.cookies.get("_fs_ch_st_TEST", domain="firefox.com") == "solved"
    request = client.build_request("POST", API + "/v1/account/login")
    assert "_fs_ch_st_TEST=solved" in request.headers.get("cookie", "")


def test_captcha_challenge_raises_clear_error(monkeypatch):
    session = _FakeSession('init([{"ty":"captcha"}],"tok1","/next")', [])
    monkeypatch.setattr(fastly, "_browser_session", lambda: session)

    with pytest.raises(FastlyChallengeError, match="captcha"):
        fastly.solve_fastly_challenge(httpx.Client(), _Resp(406))


def test_solve_pow_finds_expected_suffix():
    base = "abc"
    target = hashlib.sha256((base + "Z9").encode()).hexdigest()
    assert fastly._solve_pow(base, target) == "Z9"
    assert fastly._solve_pow(base, "not-hex") is None
