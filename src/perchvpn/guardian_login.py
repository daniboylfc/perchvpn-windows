"""Guardian v2 desktop PKCE login with loopback code capture."""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlencode

import httpx

from . import tokens
from .exceptions import GuardianHTTPError
from .headers import apply_mozilla_vpn_headers
from .http_client import get_client, read_error_body

GUARDIAN_LOGIN_ENDPOINT = "https://vpn.mozilla.org"
GUARDIAN_LOGIN_PATH = "/api/v2/vpn/login/linux"
GUARDIAN_VERIFY_PATH = "/api/v2/vpn/login/verify"
GUARDIAN_LOGIN_USER_AGENT = "MozillaVPN/2.35.0 (sys:windows; iap:true)"
CALLBACK_CODE_RE = re.compile(r"^[0-9a-f]{80}$")


def generate_pkce() -> Tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).decode().rstrip("=")
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).decode().rstrip("=")
    return verifier, challenge


def is_valid_callback_code(code: str) -> bool:
    return bool(CALLBACK_CODE_RE.fullmatch(str(code or "").strip().lower()))


def build_authorization_url(fxa_oauth: Dict[str, Any], challenge: str) -> str:
    base = str(fxa_oauth.get("url") or "").strip()
    if not base:
        raise GuardianHTTPError("Guardian returned no FxA authorization URL")
    params = dict(fxa_oauth.get("params") or {})
    if not params.get("client_id"):
        raise GuardianHTTPError("Guardian returned no OAuth client id")
    params["code_challenge"] = challenge
    params["code_challenge_method"] = "S256"
    separator = "&" if "?" in base else "?"
    return f"{base}{separator}{urlencode(params)}"


def request_login_url(
    challenge: str,
    port: int,
    *,
    client: Optional[httpx.Client] = None,
    endpoint: str = GUARDIAN_LOGIN_ENDPOINT,
) -> Dict[str, Any]:
    if client is None:
        client = get_client()
    url = f"{endpoint.rstrip('/')}{GUARDIAN_LOGIN_PATH}"
    headers = apply_mozilla_vpn_headers(
        {"User-Agent": GUARDIAN_LOGIN_USER_AGENT, "Accept": "application/json"}
    )
    params = {
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "port": int(port),
    }
    try:
        response = client.get(url, params=params, headers=headers, timeout=15.0)
    except httpx.HTTPError as exc:
        raise GuardianHTTPError(f"Guardian login is unreachable: {exc}") from exc
    if response.status_code >= 400:
        raise GuardianHTTPError(
            f"Guardian login returned HTTP {response.status_code}: "
            f"{read_error_body(response)}",
            status_code=response.status_code,
        )
    try:
        payload = response.json()
    except ValueError as exc:
        raise GuardianHTTPError("Guardian login returned invalid JSON") from exc
    fxa_oauth = payload.get("fxa_oauth") if isinstance(payload, dict) else None
    if not isinstance(fxa_oauth, dict):
        raise GuardianHTTPError("Guardian login returned no fxa_oauth document")
    return {
        "authorization_url": build_authorization_url(fxa_oauth, challenge),
        "fxa_oauth": fxa_oauth,
        "port": int(port),
    }


def exchange_login_code(
    code: str,
    code_verifier: str,
    *,
    client: Optional[httpx.Client] = None,
    endpoint: str = GUARDIAN_LOGIN_ENDPOINT,
) -> str:
    if not is_valid_callback_code(code):
        raise GuardianHTTPError("Guardian returned an invalid authorization code")
    if not code_verifier:
        raise GuardianHTTPError("No PKCE verifier for this sign-in")
    if client is None:
        client = get_client()
    url = f"{endpoint.rstrip('/')}{GUARDIAN_VERIFY_PATH}"
    headers = apply_mozilla_vpn_headers(
        {"User-Agent": GUARDIAN_LOGIN_USER_AGENT, "Accept": "application/json"}
    )
    try:
        response = client.post(
            url,
            headers=headers,
            json={"code": code.strip().lower(), "code_verifier": code_verifier},
            timeout=15.0,
        )
    except httpx.HTTPError as exc:
        raise GuardianHTTPError(f"Guardian code exchange is unreachable: {exc}") from exc
    if response.status_code >= 400:
        raise GuardianHTTPError(
            f"Guardian rejected the login code (HTTP {response.status_code})",
            status_code=response.status_code,
        )
    try:
        payload = response.json()
    except ValueError as exc:
        raise GuardianHTTPError("Guardian login verify returned invalid JSON") from exc
    token = payload.get("token") if isinstance(payload, dict) else None
    if not isinstance(token, str) or not token:
        raise GuardianHTTPError("Guardian login verify returned no token")
    return token


def install_login_token(token: str, token_path: Optional[Any] = None) -> None:
    from .fxa import TokenResponse, OAUTH_SCOPE

    tokens.save_tokens(
        TokenResponse(access_token=token, scope=OAUTH_SCOPE, token_type="bearer"),
        token_path,
    )
