"""Exception hierarchy used across the package."""

from __future__ import annotations

from typing import Optional


class PerchVPNError(Exception):
    """Base class for all PerchVPN errors."""


class FastlyChallengeError(PerchVPNError):
    """Raised when the Fastly anti-bot challenge could not be solved."""


class FxaApiError(PerchVPNError):
    """Raised for Firefox Accounts API errors."""

    def __init__(
        self,
        message: str,
        *,
        errno: Optional[int] = None,
        status_code: Optional[int] = None,
        verification_method: Optional[str] = None,
    ):
        super().__init__(message)
        self.errno = errno
        self.status_code = status_code
        self.verification_method = verification_method


class FxaUnblockCodeRequired(FxaApiError):
    """Raised when FxA blocks a login (errno 125) until an emailed unblock
    code is supplied. ``verification_method`` is normally ``email-captcha``;
    the caller must prompt for the code and retry ``account/login`` with
    ``unblockCode`` in the body."""

    def __init__(self, message: str, *, verification_method: str = "email-captcha"):
        super().__init__(
            message, errno=125, status_code=400, verification_method=verification_method
        )


class GuardianHTTPError(PerchVPNError):
    """Raised for Mozilla VPN Guardian control-plane HTTP errors."""

    def __init__(self, message: str, *, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class QuotaExceededError(GuardianHTTPError):
    """Raised when the account has exhausted its proxy quota."""


class TokenInvalidError(GuardianHTTPError):
    """Raised when the access token was rejected by Guardian."""


class ProxyError(PerchVPNError):
    """Raised for upstream proxy/tunnel errors."""
