"""Client-side solver for Fastly's JavaScript anti-bot "Client Challenge",
served with HTTP 406 responses in front of some Firefox Accounts endpoints.

Ported from the original Go client's fastly.go: two candidate hosts are
tried in order (the FxA API host, then the FxA site host, since the API
host itself usually serves no challenge page at all and the cookie Fastly
issues is scoped to Domain=firefox.com). The solve runs through a
throwaway curl_cffi session with a browser TLS fingerprint and the same
source address as the shared control-plane client: Fastly offers a plain
OpenSSL/httpx client an unsolvable captcha, while a browser fingerprint
gets the solvable PAT/PoW chain, and the cookie is bound to the same exit
IP that will make the retried API call.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import re
import threading
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import httpx

from .exceptions import FastlyChallengeError

FXA_API_HOST = "https://api.accounts.firefox.com"
FXA_SITE_URL = "https://accounts.firefox.com"

FASTLY_SOLVE_TIMEOUT = 60.0
MAX_POST_BACK_ROUNDS = 3
# Fastly classifies a plain OpenSSL/httpx TLS fingerprint as a bot and serves
# an unsolvable captcha challenge. A browser TLS fingerprint is offered the
# solvable PAT -> PoW -> clientmetrics chain instead, so the challenge is
# always solved through curl_cffi's browser impersonation.
FASTLY_BROWSER_IMPERSONATE = "firefox133"
_HTML_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
_JS_ACCEPT = "*/*"

_CHALLENGE_PREFIX_RE = re.compile(r"/_fs-ch-[A-Za-z0-9]+")
_INIT_CALL_RE = re.compile(r'init\((\[[^\]]*\]),\s*"([^"]+)",\s*"([^"]+)"')
# The challenge script brute-forces a fixed 2-character alphanumeric suffix
# such that sha256(base + suffix) equals the target hash; this mirrors the
# exact alphabet and length the real Fastly challenge script uses.
_POW_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_SHA256_DIGEST_SIZE = 32

# Serializes the whole solve-challenge flow across concurrent callers,
# matching the original Go client's package-level challengeSolveMu: two
# challenge solves running at once would otherwise race on the shared
# control-plane client's cookie jar while installing the resulting cookies.
_CHALLENGE_SOLVE_LOCK = threading.Lock()


class _NoChallengePage(Exception):
    """Raised internally when a host does not serve a Fastly challenge page."""


def _base_origin(prefix_url: str) -> str:
    idx = prefix_url.find("/_fs-ch-")
    if idx > 0:
        return prefix_url[:idx]
    return prefix_url


def _solve_pow(base: str, target_hex: str) -> Optional[str]:
    try:
        target = bytes.fromhex(target_hex)
    except ValueError:
        return None
    if len(target) != _SHA256_DIGEST_SIZE:
        return None
    for a, b in itertools.product(_POW_ALPHABET, repeat=2):
        suffix = a + b
        if hashlib.sha256((base + suffix).encode()).digest() == target:
            return suffix
    return None


def _browser_session():
    """A browser-fingerprinted HTTP session for the challenge solve.

    The session binds to the same physical source address and proxy as the
    shared control-plane client, so the cookie Fastly issues is bound to the
    same exit IP that will make the retried API call.
    """
    try:
        from curl_cffi import requests as cffi_requests
    except ImportError as exc:
        raise FastlyChallengeError(
            "browser-TLS challenge solver unavailable: curl_cffi is not installed"
        ) from exc
    from . import http_client

    kwargs: Dict[str, Any] = {
        "impersonate": FASTLY_BROWSER_IMPERSONATE,
        "timeout": FASTLY_SOLVE_TIMEOUT,
    }
    local_address = http_client.control_plane_local_address()
    if local_address:
        kwargs["interface"] = local_address
    proxy = http_client.control_plane_proxy_url()
    if proxy:
        kwargs["proxy"] = proxy
    return cffi_requests.Session(**kwargs)


def _parse_challenge_init(script: str) -> Tuple[List[Dict[str, Any]], str]:
    matches = _INIT_CALL_RE.findall(script)
    if not matches:
        raise FastlyChallengeError("challenge init() call not found in script")
    challenges_json, token, _next_path = matches[-1]
    try:
        challenges = json.loads(challenges_json)
    except json.JSONDecodeError as exc:
        raise FastlyChallengeError(f"could not parse challenge list: {exc}") from exc
    if not challenges:
        raise FastlyChallengeError("empty challenge list")
    return challenges, token


def _client_metrics_answer() -> Dict[str, Any]:
    # Mozilla's configuration currently issues PAT/PoW challenges, so this
    # is a best-effort fallback mirroring the Go client's benign static
    # browser-metrics payload.
    return {
        "ty": "clientmetrics",
        "webdriver": False,
        "bot_detection_result": {"bot_detected": False, "bot_kind": None},
        "browser_metrics": {"client_data": "{}", "error_trace": None},
        "detector_results": {},
        "v": 2,
    }


def _fetch_pat(session, prefix_url: str, token: str) -> str:
    """POST for a Private Access Token. A 400/401 means the client cannot
    mint one (a browser-platform feature); returning an empty auth value
    makes the server fall back to solvable challenges, matching the Go
    client's fetchPAT."""
    response = session.post(
        f"{prefix_url}/pat?token={quote(token, safe='')}",
        headers={
            "Accept": "text/plain",
            "Content-Type": "application/json",
            "Origin": _base_origin(prefix_url),
        },
        data="{}",
    )
    if response.status_code in (400, 401):
        return ""
    if response.status_code != 200:
        raise FastlyChallengeError(f"PAT request returned HTTP {response.status_code}")
    try:
        auth = (response.json() or {}).get("auth", "")
    except Exception as exc:  # noqa: BLE001
        raise FastlyChallengeError(f"could not parse PAT response: {exc}") from exc
    return auth or ""


def _answer_challenge(
    session, prefix_url: str, token: str, challenge: Dict[str, Any]
) -> Dict[str, Any]:
    challenge_type = challenge.get("ty")
    data = challenge.get("data") or {}
    if challenge_type == "pow":
        base = data.get("base", "")
        answer = _solve_pow(base, data.get("hash", ""))
        if answer is None:
            raise FastlyChallengeError(f"no proof-of-work solution found for base {base!r}")
        return {
            "ty": "pow",
            "base": base,
            "answer": answer,
            "hmac": data.get("hmac", ""),
            "expires": data.get("expires", ""),
        }
    if challenge_type == "pat":
        return {"ty": "pat", "auth": _fetch_pat(session, prefix_url, token)}
    if challenge_type == "clientmetrics":
        return _client_metrics_answer()
    raise FastlyChallengeError(
        f"unsupported Fastly challenge type {challenge_type!r} "
        "(a captcha cannot be solved automatically)"
    )


def _install_challenge_cookies(main_client: httpx.Client, cookies: Dict[str, str]) -> None:
    if not cookies:
        raise FastlyChallengeError("challenge completed but no cookies were issued")
    # The cookie is issued host-only for accounts.firefox.com; widening it to
    # Domain=firefox.com makes the same challenge pass cover the API host
    # (api.accounts.firefox.com) where the retried request goes.
    for name, value in cookies.items():
        main_client.cookies.set(name, value, domain="firefox.com")


def _solve_challenge_on_host(main_client: httpx.Client, base: str) -> None:
    """Solve the challenge served by ``base`` and install its cookies.

    A throw-away browser-fingerprinted session with a fresh cookie jar is
    used: re-solving with a client that already holds a valid challenge
    cookie fails because Fastly then serves the real page instead of the
    challenge page.
    """
    session = _browser_session()
    try:
        page_url = base + "/"
        page = session.get(page_url, headers={"Accept": _HTML_ACCEPT})
        if (
            page.status_code != 200
            or "/_fs-ch-" not in page.text
            or "Client Challenge" not in page.text
        ):
            # The API host root answers 406 without a challenge page; that is
            # "no challenge here", not a hard failure, so the caller moves on
            # to the site host.
            raise _NoChallengePage()

        prefix_match = _CHALLENGE_PREFIX_RE.search(page.text)
        if not prefix_match:
            raise FastlyChallengeError(f"challenge asset prefix not found on {base}")
        prefix_url = base + prefix_match.group(0)

        script = session.get(
            f"{prefix_url}/script.js?reload=true", headers={"Accept": _JS_ACCEPT}
        )
        if script.status_code != 200:
            raise FastlyChallengeError(
                f"GET {prefix_url}/script.js returned HTTP {script.status_code}"
            )
        challenges, token = _parse_challenge_init(script.text)

        for _round in range(MAX_POST_BACK_ROUNDS):
            answers = [
                _answer_challenge(session, prefix_url, token, challenge)
                for challenge in challenges
            ]
            response = session.post(
                f"{prefix_url}/fst-post-back",
                json={"token": token, "data": answers},
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Origin": _base_origin(prefix_url),
                },
            )
            if response.status_code != 200:
                raise FastlyChallengeError(
                    f"challenge post-back returned HTTP {response.status_code}"
                )
            body = response.json()
            if body.get("status") == "success":
                _install_challenge_cookies(
                    main_client, {name: value for name, value in session.cookies.items()}
                )
                return
            next_challenges, next_token = body.get("ch") or [], body.get("tok") or ""
            if not next_challenges or not next_token:
                raise FastlyChallengeError(f"unexpected post-back response: {body!r}")
            challenges, token = next_challenges, next_token
        raise FastlyChallengeError(
            f"Fastly challenge did not complete within {MAX_POST_BACK_ROUNDS} rounds"
        )
    finally:
        session.close()


def solve_fastly_challenge(client: httpx.Client, response: httpx.Response) -> None:
    """Given a 406 response believed to be a Fastly challenge, solve it and
    install the resulting cookies on ``client`` so a retried request will
    succeed. Raises FastlyChallengeError if no candidate host actually
    serves a solvable challenge.

    Serialized process-wide via _CHALLENGE_SOLVE_LOCK, matching the Go
    client's challengeSolveMu, so concurrent callers never interleave
    cookie installs on the shared client.
    """
    with _CHALLENGE_SOLVE_LOCK:
        last_error: Optional[Exception] = None
        for base in (FXA_API_HOST, FXA_SITE_URL):
            try:
                _solve_challenge_on_host(client, base)
                return
            except _NoChallengePage:
                continue
            except FastlyChallengeError as exc:
                last_error = exc
        raise last_error or FastlyChallengeError("host did not serve a Fastly challenge page")
