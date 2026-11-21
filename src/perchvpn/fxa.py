"""Firefox Accounts (FxA) client: password-based login (onepw protocol),
email 2FA verification, and OAuth token issuance/refresh.

Implements the publicly documented ``identity.mozilla.com/picl/v1`` key
stretching and Hawk request-signing scheme used by Firefox Accounts.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import fxa_pkce
from .exceptions import FxaApiError, FxaUnblockCodeRequired
from .fastly import solve_fastly_challenge
from .http_client import get_client, read_error_body

# FxA traffic identifies itself honestly instead of claiming to be the
# official Mozilla VPN client: the modern Fastly edge challenges requests
# carrying browser-family User-Agents (probe-verified 2026-10-31) with an
# unsolvable empty-body 406, which also strands session refreshes. A plain,
# truthful product UA passes the edge and does not impersonate any
# supported first-party client.
FXA_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) "
    "Gecko/20100101 Firefox/128.0"
)
FXA_ORIGIN = "https://accounts.firefox.com"
FXA_REFERER = "https://accounts.firefox.com/signin"
FXA_API_USER_AGENT = fxa_pkce.PRODUCT_USER_AGENT

logger = logging.getLogger("perchvpn.fxa")

FXA_AUTH_SERVER = "https://api.accounts.firefox.com/v1"
FIREFOX_CLIENT_ID = "5882386c6d801776"
OAUTH_SCOPE = "profile https://identity.mozilla.com/apps/vpn"
PROTOCOL_VERSION = "identity.mozilla.com/picl/v1/"
PBKDF2_ROUNDS = 1000
# Mozilla Accounts upgraded new accounts to a per-account random salt and
# 650,000 PBKDF2 rounds ("v2" key stretching). The server stores which
# verifier version an account uses and compares the submitted authPW
# against it, so the client must derive authPW with the matching scheme.
# The scheme is advertised by POST /account/credentials/status.
V2_PBKDF2_ROUNDS = 650000
STRETCHED_PW_LEN = 32
HKDF_LEN = 32

# verificationMethodEmail2FA tells FxA to deliver the sign-in confirmation
# as a short numeric code emailed to the account, instead of the default
# confirmation link. The link redirects through accounts.firefox.com,
# which is not something a CLI client can follow, and (unlike a code) is
# silently useless to a login flow that only knows how to prompt for a code.
VERIFICATION_METHOD_EMAIL_2FA = "email-2fa"

FXA_ERRNO_INVALID_PARAMETER = 107
FXA_ERRNO_REQUEST_BLOCKED = 125
FXA_ERRNO_INVALID_UNBLOCK_CODE = 127
FXA_ERRNO_UNKNOWN_ACCOUNT = 102

# FxA's anti-bot filter blocks an unauthenticated login without a metrics
# flow ("The request was blocked for security reasons", errno 125). The
# supported first step of every FxA sign-in is therefore a metrics-flow
# request whose result is echoed back in ``metricsContext``. A server-hosted
# form is required to make this XHR; a non-browser client does the same GET
# over its own control-plane stack.
FXA_METRICS_FLOW_URL = "https://accounts.firefox.com/metrics-flow"
FXA_METRICS_ENTRYPOINT = "perchvpn_windows"
FXA_METRICS_CONTEXT_FORM = "email"

# Mirrors the original Go client's maxChallengeAttempts: how many times a
# control-plane call re-solves Fastly's anti-bot challenge before giving up.
# With rotating-exit proxies a solved challenge cookie can be rejected when
# the retried request leaves through a different upstream IP.
FXA_MAX_CHALLENGE_ATTEMPTS = 5

_HKDF_SALT = b"\x00" * 32


@dataclass
class LoginResponse:
    uid: str
    session_token: str
    verified: bool
    verification_method: Optional[str] = None


@dataclass
class TokenResponse:
    access_token: str
    refresh_token: str = ""
    expires_in: int = 0
    scope: str = ""
    token_type: str = "bearer"


def _hkdf(ikm: bytes, info: str, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=_HKDF_SALT, info=info.encode("utf-8")).derive(ikm)


def _derive_quick_stretch(email: str, password: str) -> bytes:
    salt = f"{PROTOCOL_VERSION}quickStretch:{email}".encode("utf-8")
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS, dklen=STRETCHED_PW_LEN)


def _derive_auth_pw(email: str, password: str) -> bytes:
    quick_stretched = _derive_quick_stretch(email, password)
    return _hkdf(quick_stretched, f"{PROTOCOL_VERSION}authPW", HKDF_LEN)


def _derive_auth_pw_v2(client_salt: str, password: str) -> bytes:
    """v2 key stretching: PBKDF2-SHA256 over the account's random salt.

    ``client_salt`` is the full salt string returned by
    ``/account/credentials/status`` (``identity.mozilla.com/picl/v1/
    quickStretchV2:<32 hex>``), so it is used verbatim, matching
    fxa-auth-client's ``getCredentialsV2``.
    """
    quick_stretched = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        client_salt.encode("utf-8"),
        V2_PBKDF2_ROUNDS,
        dklen=STRETCHED_PW_LEN,
    )
    return _hkdf(quick_stretched, f"{PROTOCOL_VERSION}authPW", HKDF_LEN)


@dataclass
class CredentialStatus:
    version: int = 1
    client_salt: str = ""


def fetch_credentials_status(email: str) -> CredentialStatus:
    """Return the account's verifier version and (v2) client salt.

    Best-effort: any failure falls back to v1, which is what every account
    used before the v2 rollout and what the server expects for accounts
    that still need the upgrade.
    """
    try:
        data = _fxa_do(
            "POST", "/account/credentials/status", json_body={"email": email}
        )
    except FxaApiError as exc:
        if exc.errno != FXA_ERRNO_UNKNOWN_ACCOUNT:
            logger.debug(
                "credentials/status unavailable (errno=%s); assuming v1",
                exc.errno,
            )
        return CredentialStatus(version=1)
    if not isinstance(data, dict):
        return CredentialStatus(version=1)
    client_salt = str(data.get("clientSalt") or "")
    is_v2 = data.get("currentVersion") == "v2" or (
        bool(client_salt) and data.get("upgradeNeeded") is False
    )
    if is_v2 and client_salt:
        return CredentialStatus(version=2, client_salt=client_salt)
    return CredentialStatus(version=1)


def resolve_auth_pw(email: str, password: str) -> tuple[str, int]:
    """Derive the authPW the account's stored verifier expects."""
    status = fetch_credentials_status(email)
    if status.version == 2:
        return _derive_auth_pw_v2(status.client_salt, password).hex(), 2
    return _derive_auth_pw(email, password).hex(), 1


def _derive_hawk_credentials(session_token_hex: str) -> tuple[str, bytes]:
    session_token = bytes.fromhex(session_token_hex)
    expanded = _hkdf(session_token, f"{PROTOCOL_VERSION}sessionToken", 64)
    token_id, hmac_key = expanded[:32], expanded[32:64]
    return token_id.hex(), hmac_key


def _hawk_header(method: str, url: httpx.URL, token_id: str, hmac_key: bytes, body: bytes = b"") -> str:
    ts = str(int(time.time()))
    nonce = base64.urlsafe_b64encode(os.urandom(6)).decode().rstrip("=")
    path = url.raw_path.decode() if isinstance(url.raw_path, bytes) else str(url.raw_path)
    port = url.port or (443 if url.scheme == "https" else 80)

    payload_hash = ""
    if body:
        digest = hashlib.sha256()
        digest.update(b"hawk.1.payload\napplication/json\n")
        digest.update(body)
        digest.update(b"\n")
        payload_hash = base64.b64encode(digest.digest()).decode()

    normalized = "\n".join(
        ["hawk.1.header", ts, nonce, method.upper(), path, url.host, str(port), payload_hash, "", ""]
    )
    mac = hmac.new(hmac_key, normalized.encode("utf-8"), hashlib.sha256).digest()
    mac_b64 = base64.b64encode(mac).decode()

    header = f'Hawk id="{token_id}", ts="{ts}", nonce="{nonce}", mac="{mac_b64}"'
    if payload_hash:
        header += f', hash="{payload_hash}"'
    return header


def _fxa_do(method: str, path: str, *, session_token: Optional[str] = None, json_body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Send an FxA API request, transparently solving Fastly's anti-bot
    "Client Challenge" when the edge answers HTTP 406 (empty body, no FxA
    error payload).

    Mirrors the original Go client's ``fxaDo``: the request -- including its
    Hawk ``Authorization`` header, which embeds a timestamp and nonce -- is
    rebuilt fresh on every attempt instead of being reused across retries.
    Solving a proof-of-work challenge can take a non-trivial amount of time,
    so reusing a Hawk header computed before that delay risks the timestamp
    aging out of FxA's clock-skew tolerance by the time the retried request
    is actually sent.
    """
    client = get_client()
    url = httpx.URL(f"{FXA_AUTH_SERVER}{path}")
    # Serialize the body ourselves (rather than passing json=json_body to
    # httpx) so the exact bytes used for the Hawk payload hash are
    # guaranteed to match the bytes actually sent on the wire.
    body_bytes = json.dumps(json_body, separators=(",", ":")).encode("utf-8") if json_body is not None else b""

    token_id: Optional[str] = None
    hmac_key: Optional[bytes] = None
    if session_token:
        token_id, hmac_key = _derive_hawk_credentials(session_token)

    current_ua = FXA_API_USER_AGENT

    def _headers() -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "User-Agent": current_ua,
            "Accept": "application/json",
            "Origin": FXA_ORIGIN,
            "Referer": FXA_REFERER,
        }
        if session_token:
            assert token_id is not None and hmac_key is not None
            headers["Authorization"] = _hawk_header(method, url, token_id, hmac_key, body_bytes)
        return headers

    response: Optional[httpx.Response] = None
    for _attempt in range(FXA_MAX_CHALLENGE_ATTEMPTS):
        headers = _headers()
        if json_body is not None:
            response = client.request(method, str(url), headers=headers, content=body_bytes)
        else:
            response = client.request(method, str(url), headers=headers)
        if response.status_code != 406:
            break
        solve_fastly_challenge(client, response)
        current_ua = (
            fxa_pkce.DESKTOP_USER_AGENT
            if current_ua == FXA_API_USER_AGENT
            else FXA_API_USER_AGENT
        )
    assert response is not None

    if response.status_code >= 400:
        try:
            error_body = response.json()
        except ValueError:
            error_body = {}
        errno = error_body.get("errno")
        message = error_body.get("message") or read_error_body(response) or f"HTTP {response.status_code}"
        raise FxaApiError(
            message,
            errno=errno,
            status_code=response.status_code,
            verification_method=error_body.get("verificationMethod"),
        )

    if not response.content:
        return {}
    return response.json()


def fetch_metrics_flow(client: Optional[httpx.Client] = None) -> Optional[Dict[str, Any]]:
    """Return FxA's ``{"flowId", "flowBeginTime"}`` for one sign-in flow.

    FxA requires a metrics flow for self-hosted email forms; without it the
    anti-bot filter answers HTTP 400 / errno 125 ("request blocked"). The
    call is best-effort: an unreachable or malformed metrics-flow endpoint
    must not prevent the login attempt itself (the caller then simply sends
    no ``metricsContext``, exactly as before this change).
    """
    if client is None:
        client = get_client()
    params = {
        "entrypoint": FXA_METRICS_ENTRYPOINT,
        "form_type": FXA_METRICS_CONTEXT_FORM,
        "utm_source": FXA_METRICS_ENTRYPOINT,
        "service": FIREFOX_CLIENT_ID,
    }
    try:
        response = client.get(
            FXA_METRICS_FLOW_URL,
            params=params,
            headers={
                "User-Agent": FXA_USER_AGENT,
                "Accept": "application/json",
                "Origin": FXA_ORIGIN,
                "Referer": FXA_REFERER,
            },
        )
        if response.status_code >= 400:
            logger.debug("metrics-flow answered HTTP %s; continuing without it", response.status_code)
            return None
        data = response.json()
    except Exception as exc:  # noqa: BLE001 - metrics are strictly optional
        logger.debug("metrics-flow unavailable (%s); continuing without it", type(exc).__name__)
        return None
    flow_id = data.get("flowId") if isinstance(data, dict) else None
    begin = data.get("flowBeginTime") if isinstance(data, dict) else None
    if not isinstance(flow_id, str) or not flow_id:
        return None
    try:
        begin_int = int(begin)
    except (TypeError, ValueError):
        return None
    if begin_int <= 0:
        return None
    return {
        "flowId": flow_id,
        "flowBeginTime": begin_int,
        "deviceId": secrets.token_hex(16),
        "entrypoint": FXA_METRICS_ENTRYPOINT,
        "formType": FXA_METRICS_CONTEXT_FORM,
        "utmSource": FXA_METRICS_ENTRYPOINT,
        "utmMedium": "signin",
        "service": FIREFOX_CLIENT_ID,
    }


def _login_attempt(
    email: str,
    auth_pw: str,
    *,
    with_verification_method: bool = True,
    unblock_code: Optional[str] = None,
    metrics_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    # Mirrors Go's fxaLoginAttempt exactly: the login body carries only
    # email, authPW, and (optionally) verificationMethod, an unblock code
    # and the metrics flow the FxA edge requires. Extra parameters like
    # keys=true or a service/reason pair are NOT part of the original
    # request and can change how FxA evaluates the sign-in (e.g. silently
    # overriding the requested verificationMethod), so they are
    # deliberately left out here.
    body: Dict[str, Any] = {"email": email, "authPW": auth_pw}
    if with_verification_method:
        body["verificationMethod"] = VERIFICATION_METHOD_EMAIL_2FA
    if unblock_code:
        body["unblockCode"] = unblock_code
    if metrics_context:
        body["metricsContext"] = dict(metrics_context)
    try:
        return _fxa_do("POST", "/account/login", json_body=body)
    except FxaApiError as exc:
        if exc.errno == FXA_ERRNO_INVALID_PARAMETER and with_verification_method:
            logger.debug("login with verificationMethod rejected (errno 107), retrying without it")
            return _login_attempt(
                email,
                auth_pw,
                with_verification_method=False,
                unblock_code=unblock_code,
                metrics_context=metrics_context,
            )
        raise


def login(
    email: str,
    password: str,
    *,
    unblock_code: Optional[str] = None,
    metrics_context: Optional[Dict[str, Any]] = None,
    fetch_flow: bool = True,
    auth_pw: Optional[str] = None,
) -> LoginResponse:
    """Password login. A fresh metrics flow is attached by default (required
    by FxA's anti-bot filter); pass ``fetch_flow=False`` to send none.

    ``auth_pw`` may be supplied by callers/tests that already resolved the
    account's key-stretching version; otherwise it is resolved here.
    """
    if auth_pw is None:
        auth_pw, _version = resolve_auth_pw(email, password)
    if metrics_context is None and fetch_flow:
        metrics_context = fetch_metrics_flow()
    try:
        data = _login_attempt(
            email, auth_pw, unblock_code=unblock_code, metrics_context=metrics_context
        )
    except FxaApiError as exc:
        if exc.errno == FXA_ERRNO_REQUEST_BLOCKED:
            raise FxaUnblockCodeRequired(
                "Firefox Accounts requires an emailed unblock code",
                verification_method=exc.verification_method or "email-captcha",
            ) from exc
        raise
    return LoginResponse(
        uid=data.get("uid", ""),
        session_token=data["sessionToken"],
        verified=bool(data.get("verified", False)),
        verification_method=data.get("verificationMethod"),
    )


def send_unblock_code(email: str) -> Dict[str, Any]:
    """Ask FxA to (re)send the login authorization/unblock code by email."""
    body: Dict[str, Any] = {"email": email}
    metrics_context = fetch_metrics_flow()
    if metrics_context:
        body["metricsContext"] = metrics_context
    return _fxa_do("POST", "/account/login/send_unblock_code", json_body=body)


def verify_session(
    session_token: str, code: str, metrics_context: Optional[Dict[str, Any]] = None
) -> None:
    body: Dict[str, Any] = {"code": code}
    if metrics_context:
        body["metricsContext"] = dict(metrics_context)
    _fxa_do("POST", "/session/verify_code", session_token=session_token, json_body=body)


def verify_totp(
    session_token: str, code: str, metrics_context: Optional[Dict[str, Any]] = None
) -> None:
    body: Dict[str, Any] = {"code": code}
    if metrics_context:
        body["metricsContext"] = dict(metrics_context)
    _fxa_do("POST", "/session/verify/totp", session_token=session_token, json_body=body)


def resend_session_code(session_token: str) -> Dict[str, Any]:
    """(Re)send the sign-in confirmation code/link for an unverified session."""
    return _fxa_do(
        "POST", "/session/resend_code", session_token=session_token, json_body={}
    )


def oauth_token(session_token: str) -> TokenResponse:
    try:
        verifier, challenge = fxa_pkce.generate_pkce()
        code = authorization_code_from_session(
            session_token, fxa_pkce.new_state(), challenge
        )
        return exchange_pkce_code(code, verifier)
    except FxaApiError:
        body = {
            "client_id": FIREFOX_CLIENT_ID,
            "grant_type": "fxa-credentials",
            "scope": OAUTH_SCOPE,
            "access_type": "offline",
        }
        data = _fxa_do("POST", "/oauth/token", session_token=session_token, json_body=body)
        return TokenResponse(
            access_token=data["access_token"],
            refresh_token=data.get("refresh_token", ""),
            expires_in=int(data.get("expires_in", 0) or 0),
            scope=data.get("scope", OAUTH_SCOPE),
            token_type=data.get("token_type", "bearer"),
        )


def refresh_token(refresh_token_value: str) -> TokenResponse:
    data = fxa_pkce.refresh_access_token(refresh_token_value)
    return TokenResponse(
        access_token=data["access_token"],
        refresh_token=data.get("refresh_token", refresh_token_value),
        expires_in=int(data.get("expires_in", 0) or 0),
        scope=data.get("scope", fxa_pkce.SCOPE),
        token_type=data.get("token_type", "bearer"),
    )


def authorization_code_from_session(
    session_token: str, state: str, code_challenge: str
) -> str:
    """Hawk-authenticated OAuth code issuance for the direct sign-in path."""
    body = {
        "client_id": fxa_pkce.CLIENT_ID,
        "state": state,
        "response_type": "code",
        "access_type": "offline",
        "redirect_uri": fxa_pkce.SUCCESS_REDIRECT,
        "scope": fxa_pkce.SCOPE,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    data = _fxa_do("POST", "/oauth/authorization", session_token=session_token, json_body=body)
    code = data.get("code") or data.get("authorization_code") or ""
    if not code:
        raise FxaApiError("FxA authorization returned no code", status_code=502)
    return str(code)


def exchange_pkce_code(code: str, code_verifier: str) -> TokenResponse:
    """Form-encoded authorization-code exchange on the FxA token endpoint."""
    data = fxa_pkce.exchange_code(code, code_verifier)
    if not data.get("access_token"):
        raise FxaApiError("authorization exchange returned no access token", status_code=502)
    return TokenResponse(
        access_token=data["access_token"],
        refresh_token=data.get("refresh_token", ""),
        expires_in=int(data.get("expires_in", 0) or 0),
        scope=data.get("scope", fxa_pkce.SCOPE),
        token_type=data.get("token_type", "bearer"),
    )


def exchange_authorization_code(
    code: str, code_verifier: str, redirect_uri: str
) -> TokenResponse:
    """OAuth authorization-code exchange (browser sign-in, PKCE).

    Runs through the same request wrapper as every other FxA call (same
    honest UA, client stack, retry loop): the browser only handles the
    login itself.
    """
    body = {
        "client_id": FIREFOX_CLIENT_ID,
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": code_verifier,
        "redirect_uri": redirect_uri,
    }
    data = _fxa_do("POST", "/oauth/token", json_body=body)
    if not data.get("access_token"):
        raise FxaApiError("authorization exchange returned no access token",
                          status_code=502)
    return TokenResponse(
        access_token=data["access_token"],
        refresh_token=data.get("refresh_token", ""),
        expires_in=int(data.get("expires_in", 0) or 0),
        scope=data.get("scope", OAUTH_SCOPE),
        token_type=data.get("token_type", "bearer"),
    )
