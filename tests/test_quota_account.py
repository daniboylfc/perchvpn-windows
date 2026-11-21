"""Allowance gauge data integrity — Guardian-reported quota only.

Mirrors the FoxyVPN Android client's data sources: /api/v1/fpn/status
(subscribed, uid, maxBytes, limited_bandwidth) and the X-Quota-Limit /
X-Quota-Remaining / X-Quota-Reset headers on the proxy-pass response.
Missing data must surface as "unavailable", never as fabricated zeros.
"""

from __future__ import annotations

import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import src.perchvpn_windows.api as api_module
from perchvpn.exceptions import GuardianHTTPError, QuotaExceededError, TokenInvalidError
from perchvpn import guardian
from src.perchvpn_windows.config import WindowsConfig


@pytest.fixture(autouse=True)
def _reset():
    api_module._signin_state.update(stage="idle", email="", verification_method="",
                                     session_token=None, expires_at=0.0, attempts=0)
    api_module._income_quota_cache.update(data=None, ok_at=0.0, err_at=0.0, key="")
    yield
    api_module._signin_state.update(stage="idle", email="", verification_method="",
                                    session_token=None, expires_at=0.0, attempts=0)
    api_module._income_quota_cache.update(data=None, ok_at=0.0, err_at=0.0, key="")


def _app_mock(config: WindowsConfig | None = None):
    app = MagicMock()
    app.load_persisted_auth = AsyncMock(return_value=True)
    app.config = config or WindowsConfig()
    return app


class TestQuotaParsing:
    def test_parse_int_bytes(self):
        assert api_module._parse_int_bytes("50000000000") == 50000000000
        assert api_module._parse_int_bytes(10737418240) == 10737418240
        assert api_module._parse_int_bytes("") is None
        assert api_module._parse_int_bytes(None) is None
        assert api_module._parse_int_bytes("bogus") is None
        assert api_module._parse_int_bytes("-5") is None

    def test_parse_reset_epoch_plausibility(self):
        now = time.time()
        plausible = now - 3600 + int(10 * 24 * 3600)  # ~10 days ahead
        assert api_module._parse_reset_epoch(str(int(plausible)), now) == int(plausible)
        assert api_module._parse_reset_epoch("0", now) is None
        assert api_module._parse_reset_epoch("bogus", now) is None
        assert api_module._parse_reset_epoch(str(int(now + 10 * 365 * 24 * 3600)), now) is None

    def test_mask_identifier(self):
        assert api_module._mask_identifier("1234567890123", "") == "1234\u202223"
        assert api_module._mask_identifier("", "k@example.com").endswith("@example.com")
        assert "\u2022" in api_module._mask_identifier("", "kop@example.com")


class TestQuotaStates:
    @pytest.mark.asyncio
    async def test_unlimited_account(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        app = _app_mock()
        token = SimpleNamespace(access_token="tok", email="user@example.com")
        app._runtime_auth = SimpleNamespace(token=token, access_token=token.access_token)

        def fake_user_info(endpoint, access_token):
            return guardian.Entitlement(subscribed=True, uid="9876543210",
                                        max_bytes="", limited_bandwidth=False)

        monkeypatch.setattr(api_module.guardian, "fetch_user_info", fake_user_info)
        with patch.object(api_module, "get_app", return_value=app):
            result = await api_module._guardian_quota_fetch("tok")
        assert result.account_state == "signed_in"
        assert result.gauge_state == "unlimited"
        assert result.max_bytes is None  # never fabricate a cap
        assert result.usage_source == "guardian"

    @pytest.mark.asyncio
    async def test_limited_account_complete_headers(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        app = _app_mock()
        token = SimpleNamespace(access_token="tok", email="user@example.com")
        app._runtime_auth = SimpleNamespace(token=token, access_token=token.access_token)
        reset_epoch = int(time.time()) + 5 * 24 * 3600

        def fake_user_info(endpoint, access_token):
            return guardian.Entitlement(subscribed=True, uid="9876543210",
                                        max_bytes="50000000000", limited_bandwidth=True)

        def fake_pass(endpoint, access_token):
            return SimpleNamespace(
                raw_token="t", claims=SimpleNamespace(nbf=0, exp=0),
                clock_offset=__import__("datetime").timedelta(0),
                quota_max="50000000000", quota_left="37600000000",
                quota_reset=str(reset_epoch),
            )

        monkeypatch.setattr(api_module.guardian, "fetch_user_info", fake_user_info)
        monkeypatch.setattr(api_module.guardian, "fetch_proxy_pass", fake_pass)
        with patch.object(api_module, "get_app", return_value=app):
            result = await api_module._guardian_quota_fetch("tok")

        assert result.gauge_state == "ok"
        assert result.max_bytes == 50000000000  # 50 GB
        assert result.remaining_bytes == 37600000000
        assert result.used_bytes == 12400000000  # 12.4 GB used
        assert result.used_percent == 24.8
        assert abs(result.remaining_percent - 75.2) < 1e-6
        assert result.reset_epoch == reset_epoch
        assert result.usage_source == "guardian"

    @pytest.mark.asyncio
    async def test_allowance_exhausted_is_reported_not_100_percent_free(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        app = _app_mock()
        token = SimpleNamespace(access_token="tok", email="user@example.com")
        app._runtime_auth = SimpleNamespace(token=token, access_token=token.access_token)

        def fake_user_info(endpoint, access_token):
            return guardian.Entitlement(subscribed=True, uid="9876543210",
                                        max_bytes="50000000000", limited_bandwidth=True)

        def fake_pass(endpoint, access_token):
            return SimpleNamespace(
                raw_token="t", claims=SimpleNamespace(nbf=0, exp=0),
                clock_offset=__import__("datetime").timedelta(0),
                quota_max="50000000000", quota_left="0",
                quota_reset="",
            )

        monkeypatch.setattr(api_module.guardian, "fetch_user_info", fake_user_info)
        monkeypatch.setattr(api_module.guardian, "fetch_proxy_pass", fake_pass)
        with patch.object(api_module, "get_app", return_value=app):
            result = await api_module._guardian_quota_fetch("tok")
        assert result.account_state == "quota_exhausted"
        assert result.used_percent == 100.0
        assert result.remaining_percent == 0.0
        assert result.reset_epoch is None  # no reset header: no invented date

    @pytest.mark.asyncio
    async def test_missing_remaining_is_unavailable_never_zero(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        app = _app_mock()
        token = SimpleNamespace(access_token="tok", email="user@example.com")
        app._runtime_auth = SimpleNamespace(token=token, access_token=token.access_token)

        def fake_user_info(endpoint, access_token):
            return guardian.Entitlement(subscribed=True, uid="9876543210",
                                        max_bytes="50000000000", limited_bandwidth=True)

        def fake_pass(endpoint, access_token):
            return SimpleNamespace(
                raw_token="t", claims=SimpleNamespace(nbf=0, exp=0),
                clock_offset=__import__("datetime").timedelta(0),
                quota_max="50000000000", quota_left="",
                quota_reset="",
            )

        monkeypatch.setattr(api_module.guardian, "fetch_user_info", fake_user_info)
        monkeypatch.setattr(api_module.guardian, "fetch_proxy_pass", fake_pass)
        with patch.object(api_module, "get_app", return_value=app):
            result = await api_module._guardian_quota_fetch("tok")
        assert result.gauge_state == "unavailable"
        assert result.used_bytes is None
        assert result.used_percent is None
        assert "complete quota information" in result.message

    @pytest.mark.asyncio
    async def test_rejected_session_is_auth_error(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        app = _app_mock()
        token = SimpleNamespace(access_token="tok", email="user@example.com")
        app._runtime_auth = SimpleNamespace(token=token, access_token=token.access_token)

        def fake_user_info(endpoint, access_token):
            raise TokenInvalidError("access token was rejected by Guardian", status_code=401)

        monkeypatch.setattr(api_module.guardian, "fetch_user_info", fake_user_info)
        with patch.object(api_module, "get_app", return_value=app):
            result = await api_module._guardian_quota_fetch("tok")
        assert result.account_state == "auth_error"
        assert result.gauge_state == "unavailable"
        assert "sign in again" in result.message

    @pytest.mark.asyncio
    async def test_429_reports_quota_exhausted(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        app = _app_mock()
        token = SimpleNamespace(access_token="tok", email="user@example.com")
        app._runtime_auth = SimpleNamespace(token=token, access_token=token.access_token)

        def fake_user_info(endpoint, access_token):
            raise QuotaExceededError("account proxy quota exceeded", status_code=429)

        monkeypatch.setattr(api_module.guardian, "fetch_user_info", fake_user_info)
        with patch.object(api_module, "get_app", return_value=app):
            result = await api_module._guardian_quota_fetch("tok")
        assert result.account_state == "quota_exhausted"

    @pytest.mark.asyncio
    async def test_service_outage_is_service_error(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        app = _app_mock()
        token = SimpleNamespace(access_token="tok", email="user@example.com")
        app._runtime_auth = SimpleNamespace(token=token, access_token=token.access_token)

        def fake_user_info(endpoint, access_token):
            raise GuardianHTTPError("failed to fetch account info: HTTP 503: gateway down", status_code=503)

        monkeypatch.setattr(api_module.guardian, "fetch_user_info", fake_user_info)
        with patch.object(api_module, "get_app", return_value=app):
            result = await api_module._guardian_quota_fetch("tok")
        assert result.account_state == "service_error"
        assert "gateway down" not in result.message  # raw body never echoed

    @pytest.mark.asyncio
    async def test_not_signed_in_short_circuit(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        app = _app_mock()
        app._runtime_auth = None
        with patch.object(api_module, "get_app", return_value=app):
            result = await api_module.get_account_quota()
        assert result.account_state == "signed_out"


class TestQuotaCaching:
    @pytest.mark.asyncio
    async def test_hit_within_ttl_does_not_refetch(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        app = _app_mock()
        token = SimpleNamespace(access_token="tok", email="u@example.com")
        app._runtime_auth = SimpleNamespace(token=token, access_token=token.access_token)

        calls = []

        def fake_user_info(endpoint, access_token):
            calls.append(1)
            return guardian.Entitlement(subscribed=True, uid="9876543210",
                                        max_bytes="", limited_bandwidth=False)

        monkeypatch.setattr(api_module.guardian, "fetch_user_info", fake_user_info)
        with patch.object(api_module, "get_app", return_value=app):
            await api_module.get_account_quota()
            assert len(calls) == 1
            await api_module.get_account_quota()
            assert len(calls) == 1  # cached within TTL

    @pytest.mark.asyncio
    async def test_refresh_flag_forces_refetch(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        app = _app_mock()
        token = SimpleNamespace(access_token="tok", email="u@example.com")
        app._runtime_auth = SimpleNamespace(token=token, access_token=token.access_token)

        calls = []

        def fake_user_info(endpoint, access_token):
            calls.append(1)
            return guardian.Entitlement(subscribed=True, uid="9876543210",
                                        max_bytes="", limited_bandwidth=False)

        monkeypatch.setattr(api_module.guardian, "fetch_user_info", fake_user_info)
        with patch.object(api_module, "get_app", return_value=app):
            await api_module.get_account_quota()
            await api_module.get_account_quota(refresh=True)
            assert len(calls) == 2

    @pytest.mark.asyncio
    async def test_new_token_invalidates_cache(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        app = _app_mock()
        token = SimpleNamespace(access_token="first", email="u@example.com")
        app._runtime_auth = SimpleNamespace(token=token, access_token=token.access_token)

        calls = []

        def fake_user_info(endpoint, access_token):
            calls.append(1)
            return guardian.Entitlement(subscribed=True, uid="9876543210",
                                        max_bytes="", limited_bandwidth=False)

        monkeypatch.setattr(api_module.guardian, "fetch_user_info", fake_user_info)
        with patch.object(api_module, "get_app", return_value=app):
            await api_module.get_account_quota()
            token = SimpleNamespace(access_token="second", email="u@example.com")
            app._runtime_auth = SimpleNamespace(token=token, access_token=token.access_token)
            await api_module.get_account_quota()
            assert len(calls) == 2
