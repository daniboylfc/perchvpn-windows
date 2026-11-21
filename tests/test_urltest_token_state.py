"""URL-test token acquisition honesty: signed-out vs. no-pass vs. quota.

The bug: with a stale/invalid persisted token the Guardian pass fetch
failed per country row with "URL test proxy pass unavailable", which the
frontend rendered as "No pass" on every row — a failed authentication
request masquerading as a genuine pass/quota condition. And each row ran
its own Guardian request because failures were never cached.

Now:
* a rejected access token maps to 401 "Not signed in …" (frontend label
  "Sign in", never "No pass"),
* failed pass fetches are negative-cached briefly so one refresh cycle
  cannot hammer the Guardian endpoint once per country row.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

import src.perchvpn_windows.api as api_module
from perchvpn.exceptions import TokenInvalidError
from src.perchvpn_windows.config import WindowsConfig


@pytest.fixture(autouse=True)
def _reset_globals():
    api_module._urltest_pass_cache = {"token": None, "at": 0.0}
    original_app = api_module._app
    original_config = api_module._config
    yield
    api_module._app = original_app
    api_module._config = original_config
    api_module._urltest_pass_cache = {"token": None, "at": 0.0}


def _app_with_auth(token: str = "oauth-token"):
    app_obj = MagicMock(_controller=None, _source_bind_ip=None)
    app_obj._runtime_auth = MagicMock(access_token=token)
    app_obj._runtime_auth.access_token = token
    api_module._app = app_obj
    api_module._config = WindowsConfig()


class TestRejectedTokenIsSignedOutNotNoPass:
    def test_rejected_token_maps_to_401_signed_in_message(self, monkeypatch):
        _app_with_auth()
        monkeypatch.setattr(
            "perchvpn.guardian.fetch_proxy_pass",
            lambda endpoint, access_token: (_ for _ in ()).throw(
                TokenInvalidError("access token was rejected by Guardian", status_code=401)
            ),
        )
        with pytest.raises(api_module.HTTPException) as exc_info:
            api_module._get_urltest_raw_token()
        assert exc_info.value.status_code == 401
        assert "Not signed in" in exc_info.value.detail
        # must not read like a pass/quota problem
        assert "No pass" not in exc_info.value.detail
        assert "proxy pass unavailable" not in exc_info.value.detail

    def test_other_pass_failures_keep_502(self, monkeypatch):
        _app_with_auth()
        monkeypatch.setattr(
            "perchvpn.guardian.fetch_proxy_pass",
            lambda endpoint, access_token: (_ for _ in ()).throw(
                RuntimeError("network unreachable")
            ),
        )
        with pytest.raises(api_module.HTTPException) as exc_info:
            api_module._get_urltest_raw_token()
        assert exc_info.value.status_code == 502
        assert "URL test proxy pass unavailable" in exc_info.value.detail


class TestPassFetchNegativeCache:
    def test_negative_cache_prevents_guardian_hammering(self, monkeypatch):
        _app_with_auth()
        calls: list = []

        def _fetch(endpoint, access_token):
            calls.append(access_token)
            raise TokenInvalidError("rejected", status_code=401)

        monkeypatch.setattr("perchvpn.guardian.fetch_proxy_pass", _fetch)

        for _ in range(5):
            with pytest.raises(api_module.HTTPException) as exc_info:
                api_module._get_urltest_raw_token()
            assert exc_info.value.status_code == 401

        assert len(calls) == 1  # a probe cycle costs exactly one guardian call

    def test_positive_cache_still_accepted_after_failures(self, monkeypatch):
        _app_with_auth()
        state = {"fail": True}

        def _fetch(endpoint, access_token):
            if state["fail"]:
                raise TokenInvalidError("rejected", status_code=401)
            from types import SimpleNamespace

            return SimpleNamespace(raw_token="fresh-pass")

        monkeypatch.setattr("perchvpn.guardian.fetch_proxy_pass", _fetch)

        with pytest.raises(api_module.HTTPException):
            api_module._get_urltest_raw_token()

        # Expire the negative cache, then the next fetch succeeds.
        api_module._urltest_pass_cache = {"token": None, "at": 0.0}
        state["fail"] = False
        token = api_module._get_urltest_raw_token()
        assert token == "fresh-pass"


class TestSignedOutNoPassFetch:
    def test_no_runtime_auth_raises_503_signed_in(self, monkeypatch):
        app_obj = MagicMock(_controller=None, _runtime_auth=None, _source_bind_ip=None)
        api_module._app = app_obj
        api_module._config = WindowsConfig()

        def _fail(endpoint, access_token):
            raise AssertionError("guardian must not be contacted while signed out")

        monkeypatch.setattr("perchvpn.guardian.fetch_proxy_pass", _fail)
        with pytest.raises(api_module.HTTPException) as exc_info:
            api_module._get_urltest_raw_token()
        assert exc_info.value.status_code == 503
        assert "Not signed in" in exc_info.value.detail
