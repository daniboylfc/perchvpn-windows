"""High-level authentication orchestration: cached tokens, refresh, fresh
interactive login, and session-token-pool rotation on quota exhaustion.
"""

from __future__ import annotations

import getpass
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import fxa, tokens
from .exceptions import PerchVPNError, FxaApiError, FxaUnblockCodeRequired
from .session_tokens import SessionTokenPool

logger = logging.getLogger("perchvpn.auth")

# Fallback access-token lifetime when FxA's refresh response omits
# ``expires_in``. Mirrors the Android client's DEFAULT_ACCESS_TOKEN_TTL
# (24h), so a refresh whose response carries no expiry is not mistaken for
# an immediately-expired token and retried on every subsequent pass.
DEFAULT_ACCESS_TOKEN_TTL_SECONDS = 24 * 60 * 60

# FxA answers a refresh for a revoked/expired/otherwise unusable refresh token
# with one of these statuses. Any other FxA error (5xx, 429, ...) is treated as
# transient so a flaky control plane does not sign the user out.
_PERMANENT_REFRESH_REJECTION_STATUS = frozenset({400, 401, 403})


def _is_permanent_refresh_rejection(exc: FxaApiError) -> bool:
    return exc.status_code in _PERMANENT_REFRESH_REJECTION_STATUS


class AccessTokenExpiredError(PerchVPNError):
    """Raised when the access token is known to be expired/expiring and
    cannot be renewed or rotated. Callers must not proceed with it.

    Deliberately *not* a :class:`~perchvpn.exceptions.TokenInvalidError`: that
    error triggers Guardian entitlement activation, which is pointless with a
    token we already know is dead.

    ``permanent`` mirrors the Android client's ``FxaRefreshFailure``: a
    *permanent* failure means Firefox Accounts itself rejected the refresh
    token (HTTP 400/401/403), so the stored session is dead and a fresh
    sign-in is required. A *transient* failure (an unavailable/overloaded
    server, or a refresh response missing an access token) means the stored
    session is probably still good, so callers must not sign the user out or
    prompt for credentials on the strength of it alone. Unknown causes default
    to permanent so existing callers keep their current (fail-closed)
    behaviour.
    """

    def __init__(self, message: str, *, permanent: bool = True) -> None:
        super().__init__(message)
        self.permanent = permanent


class InteractiveLoginRequired(PerchVPNError):
    """Raised when no usable credentials exist and interactive login is
    disabled. Callers (the API/process backend) use this to open fully
    signed out instead of failing startup — the GUI sign-in helper is the
    only interactive entry point and drives the flow after boot."""


@dataclass
class RuntimeAuth:
    token: fxa.TokenResponse
    session_token_pool: Optional[SessionTokenPool] = None
    token_path: Optional[Path] = None
    obtained_at: float = field(default_factory=time.time)

    @property
    def access_token(self) -> str:
        return self.token.access_token

    def access_token_expired(self) -> bool:
        """True only when expiry metadata is present *and* the token is at or
        past the refresh lead. Unknown expiry (missing/``0`` ``expires_in``)
        is never treated as expired here, so we do not refresh on every pass
        when the server did not tell us the lifetime."""
        if not self.token.access_token or not self.token.expires_in:
            return False
        expires_at = self.obtained_at + self.token.expires_in
        return time.time() >= (expires_at - tokens.ACCESS_TOKEN_EXPIRY_LEAD_SECONDS)


def _verify_session_interactively(email: str, session_token: str, verification_method: Optional[str]) -> None:
    """Confirm a new sign-in, matching the original Go client's behavior.

    FxA can confirm a sign-in from an unrecognized device either by
    emailing a short numeric code (verification_method == "email-2fa",
    which is what we ask for during login) or, if that is unavailable, by
    emailing a confirmation *link* (verification_method == "email"). A
    link can't be "entered", so it needs its own prompt instead of the
    numeric-code flow.
    """
    if verification_method == "email":
        print(f"This sign-in must be confirmed: a confirmation link was sent to {email}.")
        input("Open the link from the email, then press Enter here to continue: ")
        return

    while True:
        code = input("Enter the confirmation code emailed to you: ").strip()
        if not code:
            continue
        try:
            fxa.verify_session(session_token, code)
            return
        except FxaApiError as exc:
            print(f"Verification failed: {exc}")


class VerificationRequired(PerchVPNError):
    """A fresh password login needs out-of-band confirmation from Firefox
    Accounts before an OAuth token can be minted.

    Carries the (in-memory) session token and the requested verification
    method so callers can complete the flow without a console: numeric code
    via :func:`verify_session`, or the emailed link, confirmed by polling
    :func:`complete_link_verification` from a browser separately.
    """

    def __init__(self, email: str, session_token: str, method: Optional[str]) -> None:
        self.email = email
        self.session_token = session_token
        self.method = method  # "email-2fa" | "email" | None
        super().__init__("sign-in confirmation required")


class UnblockRequired(PerchVPNError):
    """FxA's anti-bot filter blocked a password login (errno 125) and emailed
    an unblock/authorization code. The caller must collect that code and
    repeat the password login with ``unblock_code``; no session exists yet,
    so this is deliberately distinct from :class:`VerificationRequired`."""

    def __init__(self, email: str, method: Optional[str]) -> None:
        self.email = email
        self.method = method or "email-captcha"
        super().__init__("sign-in blocked pending an emailed unblock code")


def login_with_password(
    email: str,
    password: str,
    token_path: Optional[Path] = None,
    unblock_code: Optional[str] = None,
) -> fxa.TokenResponse:
    """Authenticate with email+password and persist tokens.

    The console-free core of the interactive login (same FxA protocol, same
    recording endpoint): raises :class:`VerificationRequired` instead of
    prompting when Firefox Accounts requires out-of-band confirmation, and
    :class:`UnblockRequired` when the anti-bot filter wants an emailed
    unblock code (retry with ``unblock_code``).
    ``password`` is consumed in-register only; never returned in exceptions.
    """
    try:
        login_resp = fxa.login(email, password, unblock_code=unblock_code or None)
    except FxaUnblockCodeRequired as exc:
        raise UnblockRequired(email, exc.verification_method) from exc
    if not login_resp.verified:
        raise VerificationRequired(email, login_resp.session_token, login_resp.verification_method)
    token = fxa.oauth_token(login_resp.session_token)
    tokens.save_tokens(token, token_path)
    return token


def send_unblock_code(email: str) -> None:
    """(Re)send the FxA login authorization code to the account email."""
    fxa.send_unblock_code(email)


def resend_verification_code(session_token: str) -> None:
    """(Re)send the confirmation code/link for an awaiting sign-in."""
    fxa.resend_session_code(session_token)


def verify_with_code(
    session_token: str, code: str, token_path: Optional[Path] = None
) -> fxa.TokenResponse:
    """Complete an ``email-2fa`` confirmation with the emailed numeric code."""
    fxa.verify_session(session_token, code)
    token = fxa.oauth_token(session_token)
    tokens.save_tokens(token, token_path)
    return token


def verify_with_totp(
    session_token: str, code: str, token_path: Optional[Path] = None
) -> fxa.TokenResponse:
    """Complete a TOTP 2FA confirmation."""
    fxa.verify_totp(session_token, code)
    token = fxa.oauth_token(session_token)
    tokens.save_tokens(token, token_path)
    return token


def complete_link_verification(
    session_token: str, token_path: Optional[Path] = None
) -> fxa.TokenResponse:
    """Finish an ``email``-link confirmation after the user opened the link:
    only succeeds once Firefox Accounts marks the session verified."""
    return fxa.oauth_token(session_token)


def _login_interactively(
    email: str, password: Optional[str] = None, token_path: Optional[Path] = None
) -> fxa.TokenResponse:
    if password is None:
        password = getpass.getpass(f"Firefox Accounts password for {email}: ")
    try:
        return login_with_password(email, password, token_path)
    except VerificationRequired as pending:
        _verify_session_interactively(pending.email, pending.session_token, pending.method)
        token = fxa.oauth_token(pending.session_token)
        tokens.save_tokens(token, token_path)
        return token


def _refresh(saved: tokens.SavedTokens, token_path: Optional[Path] = None) -> fxa.TokenResponse:
    token = fxa.refresh_token(saved.refresh_token)
    tokens.save_tokens(token, token_path)
    return token


def _from_single_session_token(session_token: str, token_path: Optional[Path] = None) -> fxa.TokenResponse:
    token = fxa.oauth_token(session_token)
    tokens.save_tokens(token, token_path)
    return token


def login_with_session_token(
    session_token: str, token_path: Optional[Path] = None
) -> fxa.TokenResponse:
    """Sign in by exchanging a pasted Firefox Accounts session token.

    Used by the Account panel's Session Token import, which is the fallback
    when password and browser sign-in are both unavailable. The token is
    validated by FxA before anything is persisted.
    """
    session_token = (session_token or "").strip()
    if len(session_token) < 32:
        raise FxaApiError("Session token is not valid", errno=None, status_code=400)
    try:
        bytes.fromhex(session_token)
    except ValueError as exc:
        raise FxaApiError("Session token is not valid", errno=None, status_code=400) from exc
    return _from_single_session_token(session_token, token_path)


def refresh_runtime_auth(auth: RuntimeAuth) -> RuntimeAuth:
    """Renew ``auth``'s access token with its stored refresh token, persisting
    the result to the same ``token_path`` (existing token storage only, never a
    second format). Never prompts and never falls back to a different token
    file. Raises :class:`AccessTokenExpiredError` when no usable token can be
    produced, so callers do not proceed with a known-expired token."""
    if not auth.token.refresh_token:
        raise AccessTokenExpiredError(
            "no refresh token available to renew the access token", permanent=True
        )
    try:
        token = fxa.refresh_token(auth.token.refresh_token)
    except FxaApiError as exc:
        if _is_permanent_refresh_rejection(exc):
            raise AccessTokenExpiredError(
                f"Firefox Accounts rejected the refresh token: {exc}", permanent=True
            ) from exc
        raise AccessTokenExpiredError(
            f"could not renew the access token right now: {exc}", permanent=False
        ) from exc
    if not token.access_token:
        raise AccessTokenExpiredError(
            "FxA refresh response did not contain an access token", permanent=False
        )
    if not token.expires_in:
        token.expires_in = DEFAULT_ACCESS_TOKEN_TTL_SECONDS
    tokens.save_tokens(token, auth.token_path)
    return RuntimeAuth(
        token=token,
        session_token_pool=auth.session_token_pool,
        token_path=auth.token_path,
    )


def obtain_auth(
    *,
    email: Optional[str] = None,
    password: Optional[str] = None,
    force_login: bool = False,
    session_token_or_path: Optional[str] = None,
    token_path: Optional[Path] = None,
    interactive: bool = True,
) -> RuntimeAuth:
    """Resolve a valid access token following the same precedence as the
    original CLI: explicit session token(s) > forced fresh login > cached
    tokens (refreshing if needed) > fresh interactive login."""
    if session_token_or_path:
        pool: Optional[SessionTokenPool] = None
        try:
            pool = SessionTokenPool.load(session_token_or_path)
            session_token = pool.current()
        except (OSError, ValueError):
            session_token = session_token_or_path.strip()
        token = _from_single_session_token(session_token, token_path)
        return RuntimeAuth(token=token, session_token_pool=pool, token_path=token_path)

    if not force_login:
        saved = tokens.load_tokens(token_path)
        if saved is not None:
            if saved.access_token_valid():
                return RuntimeAuth(
                    token=fxa.TokenResponse(
                        access_token=saved.access_token,
                        refresh_token=saved.refresh_token,
                        scope=saved.scope,
                        expires_in=saved.expires_in,
                    ),
                    token_path=token_path,
                    obtained_at=saved.obtained_at,
                )
            if saved.refresh_token:
                try:
                    return RuntimeAuth(token=_refresh(saved, token_path), token_path=token_path)
                except FxaApiError as exc:
                    if not _is_permanent_refresh_rejection(exc):
                        # Transient control-plane failure: do not throw away a
                        # probably-good session by forcing a fresh sign-in.
                        logger.warning(
                            "could not renew the session right now (%s); keeping the stored "
                            "session and asking the caller to retry",
                            exc,
                        )
                        raise
                    logger.warning("refresh token rejected (%s), falling back to fresh login", exc)

    if not email:
        if not interactive:
            raise InteractiveLoginRequired("interactive login is required but disabled")
        email = input("Firefox Accounts email: ").strip()
    return RuntimeAuth(token=_login_interactively(email, password, token_path), token_path=token_path)


def rotate_session_token(auth: RuntimeAuth, token_path: Optional[Path] = None) -> Optional[RuntimeAuth]:
    """Advance through the session token pool, matching the original Go
    client's activateNextPoolToken: each remaining token's OAuth exchange is
    tried in turn, silently skipping any token Firefox Accounts itself
    rejects, until one succeeds or the pool is exhausted.

    Returns ``None`` when the pool is exhausted (or absent) without ever
    finding a usable token.
    """
    if auth.session_token_pool is None:
        return None
    pool = auth.session_token_pool
    # Keep the application's configured token path: without this, a rotation
    # triggered from the controller (which passes no explicit path) would save
    # to the default home-directory token file instead of the configured one.
    effective_path = token_path if token_path is not None else auth.token_path
    while True:
        next_token = pool.rotate()
        if next_token is None:
            return None
        try:
            token = _from_single_session_token(next_token, effective_path)
        except FxaApiError as exc:
            logger.warning("session token rejected by Firefox Accounts; trying next token: %s", exc)
            continue
        return RuntimeAuth(token=token, session_token_pool=pool, token_path=effective_path)
