"""FxA OAuth authorization-code flow with PKCE (real browser sign-in).

The Fastly edge hard-blocks HTTP `POST /v1/account/login` for non-browser
clients (probe-verified 2026-10-31), so first-time sign-in uses the
supported OAuth browser flow: the app window opens the FxA authorization
page, the user signs in there (browser-grade TLS, never 406s), FxA
redirects to a loopback callback and the code is exchanged server-side.

Security model:
- ``state`` and PKCE ``code_verifier`` come from ``secrets``; only the
  S256 challenge travels in the authorization URL.
- The callback listener binds 127.0.0.1 with an ephemeral port, accepts
  exactly one request, and compares ``state`` with `hmac.compare_digest`.
- The authorization ``code`` never reaches the web UI, logs or fragments:
  the callback redirects to the app root with the opaque state only, and
  the exchange happens server-side through the existing FxA token
  endpoint wrapper (same honest UA / proxy / timeout stack).
- A state is single-use; replays and cancellations are surfaced as
  explicit errors through the account panel's inline messages.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import os
import secrets
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple
from urllib.parse import quote, urlencode

from perchvpn import fxa, fxa_pkce, guardian_login
from perchvpn.exceptions import FxaApiError

AUTHORIZATION_ENDPOINT = "https://accounts.firefox.com/oauth"
# The Firefox/VPN OAuth client only registers the out-of-band redirect
# (probe-verified: a loopback redirect_uri is rejected with "Incorrect
# redirect_uri"). OOB mode makes FxA show the authorization code after
# sign-in; the user pastes it back into the app.
OOB_REDIRECT_URI = "urn:ietf:wg:oauth:2.0:oob"
OAUTH_SCOPE = "profile https://identity.mozilla.com/apps/vpn"
STATE_TTL_SECONDS = 600.0
_APP_ROOT_URL = "http://127.0.0.1:8765/"

_oauth_lock = threading.Lock()
_pending: Optional["PendingFlow"] = None


class OAuthError(Exception):
    """Detailed, user-presentable failure of one OAuth flow stage."""

    def __init__(self, kind: str, message: str, status_code: int = 400) -> None:
        self.kind = kind
        self.message = message
        self.status_code = status_code
        super().__init__(message)


@dataclass
class _CallbackServer:
    """One-shot loopback HTTP listener for the FxA redirect."""

    port: int
    sock: socket.socket
    thread: threading.Thread
    active: bool = True

    @classmethod
    def create(cls) -> "_CallbackServer":
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        port = int(sock.getsockname()[1])
        sock.listen(1)
        sock.settimeout(1.0)
        server = cls(port=port, sock=sock, thread=threading.Thread())
        server.thread = threading.Thread(target=cls._serve, args=(server,), daemon=True)
        server.thread.start()
        try:
            from . import diagnostics
            diagnostics.emit("INFO", "oauth", "authorization", "listening",
                             outcome="pending", detail=f"port={port}", )
        except Exception:  # noqa: BLE001
            pass
        return server

    def _serve(self) -> None:
        while self.active:
            try:
                conn, _addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                request = conn.recv(8192).decode("utf-8", "replace")
                method, path, query = _parse_request_line(request)
                status, headers, body = _process_callback(method, path, query)
                response = (
                    f"HTTP/1.1 {status} \r\n{headers}"
                    "Content-Type: text/html; charset=utf-8\r\n"
                    "Content-Length: %d\r\nConnection: close\r\n\r\n%s"
                    % (len(body.encode("utf-8")), body)
                )
                conn.sendall(response.encode("utf-8"))
            except Exception:  # noqa: BLE001
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass
            return  # one-shot: a single request completes the listener

    def close(self) -> None:
        self.active = False
        try:
            self.sock.close()
        except OSError:
            pass


def _parse_request_line(request: str) -> Tuple[str, str, str]:
    line = request.splitlines()[0] if request else ""
    parts = line.split(" ")
    method = parts[0] if parts else ""
    target = parts[1] if len(parts) > 1 else ""
    path, _, query = target.partition("?")
    return method.upper(), path, query


def _process_callback(method: str, path: str, query: str):
    try:
        from . import diagnostics
        diagnostics.emit("INFO", "oauth", "authorization", "callback",
                         outcome="received", detail=f"method={method} path={path}")
    except Exception:  # noqa: BLE001
        pass

    global _pending
    with _oauth_lock:
        pending = _pending
    if method != "GET" or pending is None:
        return 400, "", "<p>Unexpected callback request.</p>"
    params = _parse_query(query)

    if pending.provider == "guardian":
        code = params.get("code", "")
        if path not in ("/", "/oauth/callback") or params.get("error"):
            pending.record_result("error", {"kind": "provider_denied"})
        elif not guardian_login.is_valid_callback_code(code):
            pending.record_result("error", {"kind": "invalid_callback"})
        else:
            pending.record_result("ok", {"code": code.strip().lower()})
        location = f"{_APP_ROOT_URL}#oauth_dispatch={quote(pending.state, safe='')}"
        return 303, f"Location: {location}\r\n", "<p>Returning to the app…</p>"

    if not path.startswith("/oauth/callback"):
        return 400, "", "<p>Unexpected callback request.</p>"
    state = params.get("state", "")
    if not hmac.compare_digest(state, pending.state):
        return 400, "", "<p>This link does not match an active sign-in request.</p>"

    error_kind = params.get("error", "")
    code = params.get("code", "")
    if error_kind:
        pending.record_result("error", {"kind": "provider_denied"}
                              if error_kind in ("access_denied", "user_cancelled") else {"kind": "provider_error"})
    elif not code or len(code) > 1024 or "\x00" in code:
        pending.record_result("error", {"kind": "invalid_callback"})
    else:
        pending.record_result("ok", {"code": code})

    location = f"{_APP_ROOT_URL}#oauth_dispatch={quote(pending.state, safe='')}"
    return 303, f"Location: {location}\r\n", "<p>Returning to the app\u2026</p>"


def _parse_query(query: str) -> Dict[str, str]:
    from urllib.parse import parse_qs

    flat: Dict[str, str] = {}
    for key, values in parse_qs(query, keep_blank_values=True).items():
        if values:
            flat[key] = values[0]
    return flat


@dataclass
class PendingFlow:
    state: str
    verifier: str
    redirect_uri: str
    callback: Optional[_CallbackServer]
    provider: str = "fxa"
    created_at: float = field(default_factory=time.monotonic)
    result: Optional[Tuple[str, Dict[str, Any]]] = None
    consumed: bool = False

    def record_result(self, status: str, data: Dict[str, Any]) -> None:
        if self.result is None:
            self.result = (status, dict(data))

    def age(self) -> float:
        return time.monotonic() - self.created_at


def _generate_pkce() -> Tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).decode().rstrip("=")
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()).decode().rstrip("=")
    return verifier, challenge


def _begin_flow(*, loopback: bool) -> Dict[str, Any]:
    """Allocate a fresh PKCE flow and return the authorization URL + state."""
    global _pending
    with _oauth_lock:
        _prune_expired_locked()
        previous = _pending
        if previous is not None:
            if previous.callback is not None:
                previous.callback.close()
            _pending = None

    state = fxa_pkce.new_state()
    verifier, challenge = fxa_pkce.generate_pkce()
    if loopback:
        callback: Optional[_CallbackServer] = _CallbackServer.create()
    else:
        callback = None
    redirect_uri = fxa_pkce.SUCCESS_REDIRECT
    flow = PendingFlow(state=state, verifier=verifier, redirect_uri=redirect_uri,
                       callback=callback, provider="fxa_pkce")
    authorization_url = fxa_pkce.build_authorization_url(challenge, state)
    with _oauth_lock:
        _pending = flow
    try:
        from . import diagnostics
        diagnostics.emit("INFO", "oauth", "authorization", "start", outcome="pending",
                         detail="loopback" if loopback else "oob")
    except Exception:  # noqa: BLE001
        pass
    return {"authorization_url": authorization_url, "state": state,
            "redirect_uri": redirect_uri, "loopback": loopback}


def _begin_guardian_flow() -> Dict[str, Any]:
    """Guardian v2 desktop PKCE: loopback listener + current FxA client."""
    global _pending
    with _oauth_lock:
        _prune_expired_locked()
        previous = _pending
        if previous is not None:
            if previous.callback is not None:
                previous.callback.close()
            _pending = None

    state = secrets.token_urlsafe(24)
    verifier, challenge = _generate_pkce()
    callback = _CallbackServer.create()
    redirect_uri = f"http://127.0.0.1:{callback.port}/"
    try:
        info = guardian_login.request_login_url(challenge, callback.port)
    except Exception:
        callback.close()
        raise
    flow = PendingFlow(state=state, verifier=verifier, redirect_uri=redirect_uri,
                       callback=callback, provider="guardian")
    with _oauth_lock:
        _pending = flow
    try:
        from . import diagnostics
        diagnostics.emit("INFO", "oauth", "authorization", "start",
                         outcome="pending", detail="guardian-loopback")
    except Exception:  # noqa: BLE001
        pass
    return {"authorization_url": info["authorization_url"], "state": state,
            "redirect_uri": redirect_uri, "loopback": True, "port": callback.port}


def start_guardian_flow() -> Dict[str, Any]:
    return _begin_guardian_flow()


def start_oauth_flow() -> Dict[str, Any]:
    return _begin_flow(loopback=True)


def start_oauth_oob_flow() -> Dict[str, Any]:
    """Start the registered out-of-band flow (no local listener)."""
    return _begin_flow(loopback=False)


def cancel_oauth_flow(state: str) -> bool:
    global _pending
    with _oauth_lock:
        pending = _pending
        if not pending or not hmac.compare_digest(state, pending.state):
            return False
        if pending.callback is not None:
            pending.callback.close()
        pending.record_result("cancelled", {"kind": "cancelled"})
        _pending = None
    return True


def _prune_expired_locked() -> None:
    global _pending
    pending = _pending
    if pending is not None and pending.age() > STATE_TTL_SECONDS:
        if pending.callback is not None:
            pending.callback.close()
        _pending = None


def get_flow(state: str) -> Optional[PendingFlow]:
    with _oauth_lock:
        _prune_expired_locked()
        pending = _pending
    if not pending or not hmac.compare_digest(state, pending.state):
        return None
    return pending


def complete_oauth_flow(state: str) -> fxa.TokenResponse:
    """Exchange the callback code (single-use state) for tokens."""
    flow = get_flow(state)
    if flow is None:
        raise OAuthError("unknown_or_expired",
                         "No active sign-in request; start the browser sign-in again",
                         status_code=404)
    with _oauth_lock:
        if flow.consumed:
            raise OAuthError("replayed",
                             "This browser sign-in was already completed; open the form again",
                             status_code=409)
        result = flow.result
        if result is None:
            raise OAuthError("not_completed",
                             "The browser signed-in has not finished yet",
                             status_code=409)
        flow.consumed = True
        if result[0] == "cancelled":
            raise OAuthError("cancelled", "Browser sign-in was cancelled", status_code=400)
        if result[0] != "ok":
            kind = result[1].get("kind") or "provider_error"
            message = {
                "provider_denied": "Sign-in was not completed in the browser",
                "invalid_callback": "The browser response was malformed; try again",
            }.get(kind, "The browser sign-in did not complete; try again")
            terminal = (kind, message)
    if result[0] != "ok":
        # Terminal failure: release the listener and the single-flow slot
        # so the user can immediately retry.
        if flow.callback is not None:
            flow.callback.close()
        _reset_pending(state)
        raise OAuthError(terminal[0], terminal[1], status_code=400)
    code = result[1]["code"]
    try:
        if flow.provider == "guardian":
            guardian_token = guardian_login.exchange_login_code(code, flow.verifier)
            guardian_login.install_login_token(guardian_token)
            token = fxa.TokenResponse(
                access_token=guardian_token, scope=fxa.OAUTH_SCOPE, token_type="bearer"
            )
        elif flow.provider == "fxa_pkce":
            token = fxa.exchange_pkce_code(code, flow.verifier)
        else:
            token = fxa.exchange_authorization_code(code, flow.verifier, flow.redirect_uri)
    except fxa.FxaApiError as exc:
        try:
            from . import diagnostics
            diagnostics.emit(
                "WARN", "oauth", "authorization", "failed",
                outcome="exchange_error",
                detail=diagnostics.redact_exception(exc),
            )
        except Exception:  # noqa: BLE001
            pass
        if flow.callback is not None:
            flow.callback.close()
        _reset_pending(state)
        if exc.status_code in (400, 401):
            raise OAuthError(
                "invalid_code",
                "The access verification window expired; open the form and sign in again",
                status_code=400,
            ) from exc
        raise OAuthError("exchange_failed",
                         "The token exchange is unavailable right now; try again shortly",
                         status_code=502) from exc
    except Exception as exc:  # noqa: BLE001
        if flow.callback is not None:
            flow.callback.close()
        _reset_pending(state)
        raise OAuthError("exchange_failed",
                         "The token exchange is unavailable right now; try again shortly",
                         status_code=502) from exc

    try:
        from . import diagnostics
        diagnostics.emit("INFO", "oauth", "authorization", "complete", outcome="signed_in")
    except Exception:  # noqa: BLE001
        pass
    if flow.callback is not None:
        flow.callback.close()
    oauth = _reset_pending(state)
    del oauth
    return token


async def complete_oauth_flow_async(state: str) -> fxa.TokenResponse:
    return await asyncio.get_running_loop().run_in_executor(
        None, complete_oauth_flow, state)


def record_external_callback(state: str, url: str) -> bool:
    """Record a WebView2/external-browser oauth/success navigation."""
    flow = get_flow(state)
    if flow is None:
        return False
    try:
        parsed = fxa_pkce.parse_success_url(url, state)
    except FxaApiError:
        flow.record_result("error", {"kind": "invalid_callback"})
        return False
    flow.record_result("ok", {"code": parsed["code"]})
    return True


def reset_oauth_flow(state: str = "") -> bool:
    """Cancel a pending attempt and free the single-flow slot."""
    global _pending
    with _oauth_lock:
        current = _pending
        if current is None:
            return False
        if state and not hmac.compare_digest(state, current.state):
            return False
        if current.callback is not None:
            current.callback.close()
        _pending = None
    return True


def submit_oauth_code(state: str, code: str) -> fxa.TokenResponse:
    """Complete a flow with the code FxA displayed after login.

    Accepts either the raw code or the full oauth/success redirect URL.
    The PKCE verifier never leaves the process.
    """
    flow = get_flow(state)
    if flow is None:
        raise OAuthError(
            "unknown_or_expired",
            "No active browser sign-in; start it again",
            status_code=404,
        )
    code = (code or "").strip()
    if code.startswith("https://") and flow.provider == "fxa_pkce":
        try:
            code = fxa_pkce.parse_success_url(code, state)["code"]
        except FxaApiError as exc:
            raise OAuthError("invalid_callback", str(exc), status_code=400) from exc
    if flow.provider == "guardian":
        if not guardian_login.is_valid_callback_code(code):
            raise OAuthError("invalid_callback", "Paste the code Guardian displayed", 400)
        code = code.lower()
    elif not code or len(code) > 1024 or "\x00" in code:
        raise OAuthError("invalid_callback", "Paste the authorization code FxA displayed", 400)
    flow.record_result("ok", {"code": code})
    return complete_oauth_flow(state)


async def submit_oauth_code_async(state: str, code: str) -> fxa.TokenResponse:
    return await asyncio.get_running_loop().run_in_executor(
        None, submit_oauth_code, state, code)


def open_authorization_url(url: str) -> bool:
    """Open the FxA authorization page in the user's real browser.

    PyWebView cannot host the FxA login page (the edge rejects embedded
    non-browser clients), so browser sign-in hands the page to the default
    system browser. Returns False instead of raising when no handler exists.
    """
    try:
        if sys.platform == "win32":
            os.startfile(url)  # type: ignore[attr-defined]  # noqa: S606
            return True
        import webbrowser

        return bool(webbrowser.open(url))
    except Exception:  # noqa: BLE001 - surfaced to the UI as "did not open"
        return False


def _reset_pending(state: str) -> Optional[PendingFlow]:
    global _pending
    with _oauth_lock:
        pending = _pending
        if pending and hmac.compare_digest(state, pending.state):
            _pending = None
            return pending
    return None


def oauth_flow_status(state: str) -> Dict[str, Any]:
    """Polling view for the UI: pending / completed-with-error etc."""
    flow = get_flow(state)
    if flow is None:
        return {"status": "unknown_or_expired"}
    result = flow.result
    if result is None:
        return {"status": "pending"}
    status, data = result
    if status == "error":
        return {"status": "error", "kind": data.get("kind") or "provider_error"}
    if status == "cancelled":
        return {"status": "cancelled"}
    return {"status": "waiting_for_exchange"}
