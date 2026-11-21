"""WebView2 host for the PerchVPN Windows desktop frontend.

Starts the FastAPI backend on loopback and opens the web frontend in a
native WebView2 window via pywebview. On non-Windows platforms (or when
pywebview/WebView2 is unavailable) this falls back to logging the URL so
the ANSI dashboard or a browser can be used instead.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger("perchvpn_windows.webview")

API_HOST = "127.0.0.1"
API_PORT = 8765
STARTUP_TIMEOUT = 30.0  # seconds
STARTUP_POLL_INTERVAL = 0.5  # seconds
AUTH_TIMEOUT = 300.0  # seconds (5 minutes for interactive auth)
AUTH_POLL_INTERVAL = 1.0  # seconds
# Wait long enough for TunHelperClient.stop() to confirm child termination
# and journaled /32 route removal (20s) before the process exits.
SHUTDOWN_JOIN_TIMEOUT = 30.0  # seconds to wait for the API server thread




from .winconsole import (
    ensure_interactive_console as _ensure_interactive_console,
    restore_streams as _restore_streams,
)


def start_api_server() -> tuple:
    """Start the FastAPI app on loopback in a background thread.

    Returns (server_thread, uvicorn server) so the caller can signal
    ``server.should_exit`` and join the thread for a deterministic
    lifespan shutdown on exit.
    """
    import uvicorn
    from .api import app as fastapi_app

    # One ASGI event loop is intentional: the app/config objects and the
    # transactional mode/country state are process-global, so multiple uvicorn
    # workers would fork inconsistent state.  Concurrency comes from async
    # handlers plus the bounded API worker pool in api.py (blocking Remote
    # Settings/disk work never runs on the event loop).
    config = uvicorn.Config(
        fastapi_app,
        host=API_HOST,
        port=API_PORT,
        log_level="warning",
        lifespan="on",
        workers=1,
    )
    server = uvicorn.Server(config)

    thread = threading.Thread(target=server.run, daemon=True, name="perchvpn-api")
    thread.start()
    logger.info("FastAPI backend started on http://%s:%s", API_HOST, API_PORT)
    return thread, server


def _get_token_path() -> Path:
    """Get the Windows token storage path."""
    base = os.environ.get("APPDATA")
    if not base:
        base = str(Path.home() / "AppData" / "Roaming")
    return Path(base) / "PerchVPN" / "tokens.json"


def _has_valid_token() -> bool:
    """Check if a valid (non-expired) access token exists."""
    token_path = _get_token_path()
    if not token_path.exists():
        return False
    try:
        data = json.loads(token_path.read_text(encoding="utf-8"))
        access_token = data.get("access_token", "")
        if not access_token:
            return False
        obtained_at = data.get("obtained_at", 0.0)
        expires_in = data.get("expires_in", 0)
        if not expires_in:
            return False
        # Check if token is still valid (with 120s lead time like tokens.py)
        import time
        expires_at = obtained_at + expires_in
        return time.time() < (expires_at - 120.0)
    except (json.JSONDecodeError, OSError, KeyError):
        return False


def _spawn_auth_helper() -> Optional[subprocess.Popen]:
    """Spawn the CLI auth-only helper in a new Windows Terminal window.
    Returns the process handle, or None if launch failed.
    """
    try:
        import shutil

        from perchvpn_windows.app import auth_helper_command

        wt_path = shutil.which("wt")
        if not wt_path:
            logger.warning("Windows Terminal (wt.exe) not found in PATH; cannot launch interactive auth")
            return None

        env = os.environ.copy()
        env["PERCHVPN_DASHBOARD_WINDOW"] = "1"

        # CREATE_NEW_PROCESS_GROUP is Windows-specific
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)

        process = subprocess.Popen(
            [wt_path, "-w", "0", "new-tab", "--", *auth_helper_command(sys.executable, env=env)],
            env=env,
            creationflags=creationflags,
        )
        logger.info("Launched authentication helper in Windows Terminal (PID=%s)", process.pid)
        return process
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to launch authentication helper: %s", exc)
        return None


def _wait_for_token_ready(timeout: float = AUTH_TIMEOUT) -> bool:
    """Wait for a valid token to appear after auth helper completes."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _has_valid_token():
            logger.info("Valid token detected after authentication")
            return True
        time.sleep(AUTH_POLL_INTERVAL)
    logger.error("Timed out waiting for valid token after authentication")
    return False


def _run_auth_flow() -> bool:
    """Run the authentication flow if needed. Returns True if ready to proceed."""
    if _has_valid_token():
        logger.info("Valid token already exists; skipping interactive authentication")
        return True

    if getattr(sys, "frozen", False):
        # Packaged executable: sys.executable is the app itself, so re-invoking
        # it as "python -m ..." would recursively relaunch the exe. Run the
        # auth-only flow in-process instead.
        logger.info("No valid token found; running authentication in-process")
        import asyncio
        from perchvpn_windows.cli import _run_auth_only

        original = _ensure_interactive_console()
        try:
            result = asyncio.run(_run_auth_only())
        finally:
            _restore_streams(original)
        if result != 0:
            logger.error("Authentication failed with exit code %d", result)
            return False
        return _wait_for_token_ready()

    logger.info("No valid token found; launching interactive authentication")
    process = _spawn_auth_helper()
    if process is None:
        logger.error("Cannot proceed without interactive authentication")
        return False

    try:
        # Wait for auth to complete (process exits)
        logger.info("Waiting for authentication to complete...")
        try:
            exit_code = process.wait(timeout=AUTH_TIMEOUT)
        except subprocess.TimeoutExpired:
            logger.error("Authentication timed out after %.1fs", AUTH_TIMEOUT)
            try:
                process.terminate()
                process.wait(timeout=5.0)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass
            return False

        if exit_code == 130:
            logger.info("Authentication cancelled by user")
            return False
        if exit_code != 0:
            logger.error("Authentication failed with exit code %d", exit_code)
            return False

        # Verify token was persisted
        if not _wait_for_token_ready():
            logger.error("Token not persisted after successful authentication")
            return False

        logger.info("Authentication completed successfully")
        return True
    except Exception as exc:  # noqa: BLE001
        logger.error("Authentication flow failed: %s", exc)
        return False


def _wait_for_api_ready() -> bool:
    """Poll /api/status until the API answers with a valid status payload.

    A controller-less backend (proxy-only mode) reports uptime == 0.0 while
    fully live and serving, so readiness keys on the JSON payload carrying a
    recognized non-empty 'status' value — never on uptime alone.
    """
    import httpx

    url = f"http://{API_HOST}:{API_PORT}/api/status"
    deadline = time.monotonic() + STARTUP_TIMEOUT

    while time.monotonic() < deadline:
        try:
            resp = httpx.get(url, timeout=1.0)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, dict) and isinstance(data.get("status"), str) and data["status"]:
                    uptime = float(data.get("uptime") or 0.0)
                    logger.info(
                        "API ready (status=%s, uptime=%.2fs)", data["status"], uptime
                    )
                    return True
                # No recognized status yet: app still initializing.
            elif resp.status_code == 503:
                # App not initialized yet (lifespan may have failed)
                pass
        except httpx.RequestError:
            # Server not accepting connections yet
            pass
        except Exception as exc:  # noqa: BLE001
            logger.debug("Readiness check error: %s", exc)

        time.sleep(STARTUP_POLL_INTERVAL)

    logger.error("API server did not become ready within %.1fs", STARTUP_TIMEOUT)
    return False


def _preflight_interactive_auth() -> bool:
    """Decide whether GUI launch must run the interactive auth flow.

    The interactive flow still gates the GUI when a previous session
    exists but is no longer valid (expired/revoked tokens): the user must
    re-authenticate before the app can connect. A brand-new signed-out
    user (no tokens at all) must instead reach the GUI directly so the
    onboarding prompt can guide them to sign in — the sign-in button and
    the terminal helper handle the interactive flow from inside the app.
    """
    if _has_valid_token():
        logger.info("Valid token already exists; skipping interactive authentication")
        return False
    if _get_token_path().exists():
        # Tokens exist but are unusable; re-authentication is required up
        # front before anything can connect.
        return True
    logger.info(
        "No credentials yet: opening the GUI signed out; "
        "sign in from the app (Network tab / onboarding prompt)"
    )
    return False


def _web_icon_path() -> Optional[str]:
    """Resolve the packaged window/taskbar icon (editable and frozen)."""
    base = getattr(sys, "_MEIPASS", None)
    root = Path(base) if base else Path(__file__).resolve().parent
    candidate = root / "web" / "assets" / "perch.ico"
    return str(candidate) if candidate.is_file() else None


def launch_webview() -> int:
    """Launch the WebView2 window. Returns exit code."""
    url = f"http://{API_HOST}:{API_PORT}/"

    try:
        import webview
    except ImportError:
        logger.warning("pywebview not installed; WebView2 GUI unavailable")
        logger.info("Open %s in a browser, or use --no-dashboard", url)
        # Keep API alive so the browser can talk to it
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            return 0

    # Authentication first — but only when re-authentication is genuinely
    # required. A signed-out first run opens the GUI directly (see
    # _preflight_interactive_auth) and the GUI drives sign-in.
    if _preflight_interactive_auth() and not _run_auth_flow():
        return 1

    # Start the API before opening the window. The finally block below
    # guarantees the uvicorn lifespan shutdown (FastAPI app.shutdown —
    # frontend/controller teardown) executes on every exit path: ready
    # timeout, WebView2 failure, or normal window close.
    api_thread, api_server = start_api_server()
    try:
        # Wait for application initialization to complete
        if not _wait_for_api_ready():
            return 1

        # Create the WebView2 window
        window = webview.create_window(
            title="Perch VPN",
            url=url,
            width=1100,
            height=720,
            min_size=(900, 600),
            text_select=False,
        )

        try:
            webview.start(icon=_web_icon_path())
        except Exception as exc:  # noqa: BLE001
            logger.error("WebView2 failed to start: %s", exc)
            return 1

        return 0
    finally:
        api_server.should_exit = True
        if api_thread.is_alive():
            api_thread.join(timeout=SHUTDOWN_JOIN_TIMEOUT)
        if api_thread.is_alive():
            # The bounded app shutdown should have finished by now.  Force
            # uvicorn past graceful lifespan shutdown so the process can exit
            # and release 127.0.0.1:1080 instead of lingering as a ghost.
            api_server.force_exit = True
            api_thread.join(timeout=5.0)
        if api_thread.is_alive():
            logger.warning(
                "API server thread did not stop within %.1fs", SHUTDOWN_JOIN_TIMEOUT
            )


def main() -> int:
    return launch_webview()


if __name__ == "__main__":
    sys.exit(main())