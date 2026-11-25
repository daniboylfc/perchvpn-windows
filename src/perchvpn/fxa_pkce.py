"""Unified FxA OAuth PKCE flow shared by browser and in-app sign-in."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx

from .exceptions import FxaApiError

CLIENT_ID = "a2270f727f45f648"
SCOPE = "profile https://identity.mozilla.com/apps/vpn"
AUTHORIZATION_ENDPOINT = "https://accounts.firefox.com/authorization"
SUCCESS_REDIRECT = f"https://accounts.firefox.com/oauth/success/{CLIENT_ID}"
TOKEN_ENDPOINT = "https://api.accounts.firefox.com/v1/token"
OAUTH_TOKEN_ENDPOINT = "https://oauth.accounts.firefox.com/v1/token"
DESKTOP_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) "
    "Gecko/20100101 Firefox/128.0"
)
PRODUCT_USER_AGENT = "perchvpn/2.0.4 (windows)"
USER_AGENTS = (DESKTOP_USER_AGENT, PRODUCT_USER_AGENT)


def generate_pkce() -> Tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).decode().rstrip("=")
    return verifier, challenge


def new_state() -> str:
    return secrets.token_urlsafe(24)


def build_authorization_url(challenge: str, state: str) -> str:
    if not challenge or not state:
        raise FxaApiError("PKCE challenge and state are required", status_code=400)
    params = {
        "client_id": CLIENT_ID,
        "scope": SCOPE,
        "response_type": "code",
        "access_type": "offline",
        "redirect_uri": SUCCESS_REDIRECT,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return f"{AUTHORIZATION_ENDPOINT}?{urlencode(params)}"


def is_success_url(url: str) -> bool:
    parts = urlsplit(str(url or ""))
    return (
        parts.scheme == "https"
        and parts.netloc == "accounts.firefox.com"
        and parts.path == f"/oauth/success/{CLIENT_ID}"
    )


def parse_success_url(url: str, expected_state: str = "") -> Dict[str, str]:
    if not is_success_url(url):
        raise FxaApiError("Not a Firefox Accounts OAuth success URL", status_code=400)
    params = parse_qs(urlsplit(url).query)
    code = (params.get("code") or [""])[0]
    state = (params.get("state") or [""])[0]
    if not code:
        raise FxaApiError("The sign-in URL contains no authorization code", status_code=400)
    if expected_state and not hmac.compare_digest(state, expected_state):
        raise FxaApiError("The sign-in URL state does not match this attempt", status_code=400)
    return {"code": code, "state": state}


def _post_form(path_or_url: str, fields: Dict[str, str]) -> Dict[str, Any]:
    url = (
        path_or_url
        if path_or_url.startswith("https://")
        else f"https://api.accounts.firefox.com/v1/{path_or_url.lstrip('/')}"
    )
    last_status = 0
    for ua in USER_AGENTS:
        try:
            response = httpx.post(
                url,
                data=fields,
                headers={
                    "User-Agent": ua,
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                    "Origin": "https://accounts.firefox.com",
                    "Referer": "https://accounts.firefox.com/signin",
                },
                timeout=20.0,
            )
        except httpx.HTTPError as exc:
            raise FxaApiError(f"FxA token endpoint unreachable: {exc}", status_code=502) from exc
        last_status = response.status_code
        if response.status_code == 406:
            continue
        if response.status_code >= 400:
            try:
                payload = response.json()
            except ValueError:
                payload = {}
            raise FxaApiError(
                payload.get("message") or f"FxA token endpoint returned HTTP {response.status_code}",
                errno=payload.get("errno"),
                status_code=response.status_code,
            )
        try:
            return response.json()
        except ValueError as exc:
            raise FxaApiError("FxA token endpoint returned invalid JSON", status_code=502) from exc
    raise FxaApiError(
        f"FxA token endpoint blocked all User-Agents (HTTP {last_status})",
        status_code=406,
    )


def exchange_code(code: str, code_verifier: str) -> Dict[str, Any]:
    return _post_form(TOKEN_ENDPOINT, {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "code": code,
        "code_verifier": code_verifier,
        "redirect_uri": SUCCESS_REDIRECT,
    })


def refresh_access_token(refresh_token_value: str) -> Dict[str, Any]:
    return _post_form(TOKEN_ENDPOINT, {
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "refresh_token": refresh_token_value,
        "scope": SCOPE,
    })
