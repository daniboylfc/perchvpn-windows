"""FxA v1/v2 key stretching and the single background sign-in flow.

The login form derives ``authPW`` locally. Accounts created before the v2
rollout use PBKDF2-SHA256(1000, ``quickStretch:<email>``); v2 accounts use
PBKDF2-SHA256(650000, server-provided ``quickStretchV2:<32 hex>``). Sending
the v1 value to a v2 account (or vice versa) fails with errno 107
"incorrect password", so ``/account/credentials/status`` must be consulted
before every password login.
"""

from __future__ import annotations

import hashlib

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from perchvpn import fxa

import src.perchvpn_windows.api as api_module

api_module_fxa = api_module.auth_module.fxa
assert api_module_fxa is fxa


def _hkdf_auth_pw(quick_stretched: bytes) -> str:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"\x00" * 32,
        info=b"identity.mozilla.com/picl/v1/authPW",
    ).derive(quick_stretched).hex()


class _Response:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = str(self._payload)
        import json

        self.content = json.dumps(self._payload).encode("utf-8")

    def json(self):
        return self._payload


class _RoutedClient:
    """Return a response by URL fragment; records every request."""

    def __init__(self, routes):
        self.routes = routes
        self.requests: list[tuple[str, str, bytes]] = []

    def request(self, method, url, headers=None, content=None):
        self.requests.append((method, url, content or b""))
        for fragment, response in self.routes.items():
            if fragment in url:
                return response
        return _Response(200, {})

    def get(self, url, params=None, headers=None):
        return _Response(200, {})


@pytest.fixture()
def no_metrics(monkeypatch):
    monkeypatch.setattr(fxa, "fetch_metrics_flow", lambda *a, **k: None)


class TestKeyStretching:
    def test_v1_derivation_matches_reference(self):
        email, password = "user@example.com", "hunter2"
        quick = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            b"identity.mozilla.com/picl/v1/quickStretch:" + email.encode(),
            1000,
            dklen=32,
        )
        assert fxa._derive_auth_pw(email, password).hex() == _hkdf_auth_pw(quick)

    def test_v2_derivation_matches_reference(self):
        salt = "identity.mozilla.com/picl/v1/quickStretchV2:" + "ab" * 16
        quick = hashlib.pbkdf2_hmac(
            "sha256", b"hunter2", salt.encode(), 650000, dklen=32
        )
        assert fxa._derive_auth_pw_v2(salt, "hunter2").hex() == _hkdf_auth_pw(quick)

    def test_v2_rounds_constant(self):
        assert fxa.V2_PBKDF2_ROUNDS == 650000


class TestCredentialStatusSelection:
    def test_v2_account_sends_v2_auth_pw_only(self, monkeypatch, no_metrics):
        salt = "identity.mozilla.com/picl/v1/quickStretchV2:" + "cd" * 16
        client = _RoutedClient(
            {
                "/account/credentials/status": _Response(
                    200,
                    {
                        "upgradeNeeded": False,
                        "currentVersion": "v2",
                        "clientSalt": salt,
                    },
                ),
                "/account/login": _Response(
                    200, {"uid": "u", "sessionToken": "ab" * 32, "verified": True}
                ),
            }
        )
        monkeypatch.setattr(fxa, "get_client", lambda: client)
        fxa.login("user@example.com", "pw")
        login = next(r for r in client.requests if r[1].endswith("/account/login"))
        assert fxa._derive_auth_pw_v2(salt, "pw").hex().encode() in login[2]
        assert b"clientSalt" not in login[2]
        assert b"authPWVersion2" not in login[2]

    def test_v1_account_keeps_email_salt(self, monkeypatch, no_metrics):
        client = _RoutedClient(
            {
                "/account/credentials/status": _Response(
                    200, {"upgradeNeeded": False, "currentVersion": "v1"}
                ),
                "/account/login": _Response(
                    200, {"uid": "u", "sessionToken": "ab" * 32, "verified": True}
                ),
            }
        )
        monkeypatch.setattr(fxa, "get_client", lambda: client)
        fxa.login("user@example.com", "pw")
        login = next(r for r in client.requests if r[1].endswith("/account/login"))
        assert fxa._derive_auth_pw("user@example.com", "pw").hex().encode() in login[2]

    def test_unknown_account_falls_back_to_v1(self, monkeypatch, no_metrics):
        client = _RoutedClient(
            {
                "/account/credentials/status": _Response(
                    400, {"errno": 102, "message": "Unknown account"}
                ),
                "/account/login": _Response(
                    200, {"uid": "u", "sessionToken": "ab" * 32, "verified": True}
                ),
            }
        )
        monkeypatch.setattr(fxa, "get_client", lambda: client)
        assert fxa.fetch_credentials_status("nobody@example.com").version == 1
        fxa.login("nobody@example.com", "pw")
        login = next(r for r in client.requests if r[1].endswith("/account/login"))
        assert fxa._derive_auth_pw("nobody@example.com", "pw").hex().encode() in login[2]

    def test_status_failure_is_best_effort(self, monkeypatch, no_metrics):
        client = _RoutedClient(
            {"/account/credentials/status": _Response(500, {"errno": 999})}
        )
        monkeypatch.setattr(fxa, "get_client", lambda: client)
        assert fxa.fetch_credentials_status("user@example.com").version == 1


class TestVerificationMethodNormalization:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("totp-2fa", "totp"),
            ("totp", "totp"),
            ("email-2fa", "email-2fa"),
            ("email-otp", "email-2fa"),
            ("email", "email"),
            (None, "email-2fa"),
        ],
    )
    def test_mapping(self, raw, expected):
        assert api_module._normalize_verification_method(raw) == expected


class TestEdgeBlockMessage:
    def test_406_names_the_edge_rejection_and_remedy(self):
        kind, message = api_module._classify_fxa_signin_error(
            api_module.auth_module.FxaApiError("blocked", errno=None, status_code=406)
        )
        assert kind == "edge_blocked"
        assert "HTTP 406" in message
        assert "switch networks" in message


class TestResendEndpoint:
    @pytest.mark.asyncio
    async def test_resends_confirmation_for_session(self, monkeypatch):
        seen = []
        api_module._signin_state.update(
            stage="verification_required",
            email="user@example.com",
            verification_method="email-2fa",
            session_token="ab" * 32,
            expires_at=0.0,
            attempts=0,
        )
        monkeypatch.setattr(
            api_module.auth_module,
            "resend_verification_code",
            lambda token: seen.append(token),
        )
        result = await api_module.account_resend_verification()
        assert result.status == "sent"
        assert seen == ["ab" * 32]

    @pytest.mark.asyncio
    async def test_resends_unblock_code(self, monkeypatch):
        seen = []
        api_module._signin_state.update(
            stage="unblock_required",
            email="user@example.com",
            verification_method="email-captcha",
            session_token=None,
            expires_at=0.0,
            attempts=0,
        )
        monkeypatch.setattr(
            api_module.auth_module,
            "send_unblock_code",
            lambda email: seen.append(email),
        )
        result = await api_module.account_resend_verification()
        assert result.status == "sent"
        assert seen == ["user@example.com"]

    @pytest.mark.asyncio
    async def test_no_pending_signin_is_404(self):
        api_module._signin_state.update(
            stage="idle",
            email="",
            verification_method="",
            session_token=None,
            expires_at=0.0,
            attempts=0,
        )
        with pytest.raises(api_module.HTTPException) as excinfo:
            await api_module.account_resend_verification()
        assert excinfo.value.status_code == 404
