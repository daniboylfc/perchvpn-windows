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
# First launch from a downloaded ZIP/MSI can sit in a Defender scan of
# _internal\ for 5-15 s, so a slow start is logged with timing marks instead
# of looking hung; the budget below already covers that window.
STARTUP_TIMEOUT = 30.0  # seconds
SLOW_START_WARNING = 10.0  # seconds before the wait is reported as slow
# Monotonic reference for the startup timing marks in perchvpn.log.
_PROCESS_STARTED = time.monotonic()
# 50 ms while the API is expected imminently, then 250 ms: the coarse 500 ms
# grid used to add an average of ~250 ms to every window launch (the API is
# ready, the window just had not noticed).
STARTUP_POLL_INTERVAL = 0.05  # seconds
STARTUP_POLL_BACKOFF_AFTER = 3.0  # seconds
STARTUP_POLL_INTERVAL_SLOW = 0.25  # seconds
AUTH_TIMEOUT = 300.0  # seconds (5 minutes for interactive auth)
AUTH_POLL_INTERVAL = 1.0  # seconds
# Wait long enough for TunHelperClient.stop() to confirm child termination
# and journaled /32 route removal (20s) before the process exits.
SHUTDOWN_JOIN_TIMEOUT = 30.0  # seconds to wait for the API server thread




from .startup_diagnostics import (
    append_startup_log as _append_startup_log,
    install_excepthook as _install_excepthook,
    install_startup_logging as _install_startup_logging,
    report_startup_failure as _report_startup_failure,
    show_info_dialog as _show_info_dialog,
    startup_log_path as _startup_log_path,
)
from .winconsole import (
    ensure_interactive_console as _ensure_interactive_console,
    restore_streams as _restore_streams,
)


def _mark(stage: str, detail: str = "", *, elapsed: Optional[float] = None) -> None:
    """Record one startup timing mark in the durable startup log.

    The windowed build has no console, so cold-start behaviour (Defender
    scanning ``_internal``, slow WebView2 environment init) is only observable
    through this log.  Best effort: never raise from a timing mark.
    """
    if elapsed is None:
        elapsed = time.monotonic() - _PROCESS_STARTED
    message = "startup %s at %.2fs%s" % (
        stage,
        elapsed,
        (" (%s)" % detail) if detail else "",
    )
    try:
        _append_startup_log("INFO", message)
    except Exception:  # noqa: BLE001
        pass
    # Debug only: the root file handler already captures INFO records, and
    # writing both produced duplicate lines in perchvpn.log.
    logger.debug(message)


def _ensure_writable_cwd() -> Path:
    """Move the process CWD off the install directory.

    An MSI install lives in ``Program Files`` and the shortcuts launch with the
    install folder as CWD, which a standard user cannot write.  Anything that
    resolves a relative path would then fail (or worse, look like a missing
    asset).  Point CWD at our own writable data root instead.
    """
    from perchvpn_windows.platform import get_local_app_data_dir

    target = get_local_app_data_dir()
    try:
        target.mkdir(parents=True, exist_ok=True)
        os.chdir(target)
    except OSError as exc:
        logger.warning("could not move CWD to %s: %s", target, exc)
    return target


def _uvicorn_log_config() -> dict:
    """uvicorn logging that never touches the (possibly absent) console.

    uvicorn's default formatter calls ``sys.stdout.isatty()``; a
    ``--windowed`` PyInstaller build has ``sys.stdout is None``, so the default
    config raises ``AttributeError: 'NoneType' object has no attribute
    'isatty'`` inside ``uvicorn.Config()`` and the API never starts.  Launched
    from Explorer or an MSI shortcut there is no console to show that, which is
    exactly the "silent exit" class of failure.  Propagate to the root handler
    installed by ``install_startup_logging`` instead of owning stream handlers.
    """
    return {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {"plain": {"format": "%(levelname)s:     %(message)s"}},
        "handlers": {},
        "loggers": {
            "uvicorn": {"handlers": [], "level": "WARNING", "propagate": True},
            "uvicorn.error": {"handlers": [], "level": "WARNING", "propagate": True},
            "uvicorn.access": {"handlers": [], "level": "WARNING", "propagate": True},
        },
    }


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
        log_config=_uvicorn_log_config(),
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
    started = time.monotonic()
    deadline = started + STARTUP_TIMEOUT
    slow_warned = False

    while True:
        now = time.monotonic()
        if now >= deadline:
            break
        waited = now - started
        if not slow_warned and waited >= SLOW_START_WARNING:
            slow_warned = True
            # Typical first launch from a downloaded archive: Defender is
            # still scanning _internal\.  Say so instead of looking hung.
            _mark(
                "api_wait_slow",
                "still waiting after %.0fs (antivirus scan of the bundle?)" % waited,
                elapsed=now - _PROCESS_STARTED,
            )
        try:
            resp = httpx.get(url, timeout=1.0)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, dict) and isinstance(data.get("status"), str) and data["status"]:
                    uptime = float(data.get("uptime") or 0.0)
                    logger.info(
                        "API ready (status=%s, uptime=%.2fs)", data["status"], uptime
                    )
                    _mark(
                        "api_ready",
                        "status=%s" % data["status"],
                        elapsed=now - _PROCESS_STARTED,
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

        time.sleep(
            STARTUP_POLL_INTERVAL
            if waited < STARTUP_POLL_BACKOFF_AFTER
            else STARTUP_POLL_INTERVAL_SLOW
        )

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


def _start_auth_preflight() -> Optional[threading.Thread]:
    """Run the interactive auth gate off the launch path.

    Returns the daemon thread when re-authentication is required, else None.
    Blocking window creation on an interactive console helper made a slow or
    failed sign-in indistinguishable from a crash: no window, no message.  The
    window now always appears and the app simply stays signed out when the
    preflight does not complete.
    """
    if not _preflight_interactive_auth():
        return None

    def _run() -> None:
        try:
            ok = _run_auth_flow()
        except Exception as exc:  # noqa: BLE001 - never kill the GUI
            logger.error("Authentication preflight failed: %s", exc)
            ok = False
        if ok:
            logger.info("Authentication preflight completed")
            return
        logger.error("Authentication preflight did not complete; staying signed out")
        _show_info_dialog(
            "Sign-in did not complete, so PerchVPN opened signed out.\n"
            "Use the Sign in button in the window to try again.\n\n"
            f"Log file: {_startup_log_path()}"
        )

    thread = threading.Thread(
        target=_run, daemon=True, name="perchvpn-auth-preflight"
    )
    thread.start()
    return thread


def _web_icon_path() -> Optional[str]:
    """Resolve the packaged window/taskbar icon (editable and frozen)."""
    base = getattr(sys, "_MEIPASS", None)
    root = Path(base) if base else Path(__file__).resolve().parent
    candidate = root / "web" / "assets" / "perch.ico"
    return str(candidate) if candidate.is_file() else None


WEBVIEW2_DOWNLOAD_URL = "https://go.microsoft.com/fwlink/p/?LinkId=2124703"


def _port_available(host: str = API_HOST, port: int = API_PORT) -> bool:
    """Return True when a loopback listener can bind ``host:port``.

    A hardcoded port with no preflight turned a collision into a 30 s silent
    wait and a windowless exit.  No ``SO_REUSEADDR``: on Windows that would
    make the probe succeed while another process is listening.
    """
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((host, int(port)))
        except OSError:
            return False
    return True


def _webview2_runtime_available() -> bool:
    """Best-effort check for the WebView2 Evergreen Runtime.

    pywebview logs a missing runtime on its own logger, which the windowed
    build never shows; the user sees a blank window or nothing at all.  Check
    the Edge Update client entries (machine and per-user) and the installed
    runtime directories before creating the window.
    """
    if sys.platform != "win32":
        return True
    try:
        import winreg
    except ImportError:  # pragma: no cover - win32 always has winreg
        return True
    registry_paths = (
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\EdgeUpdate\Clients"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\EdgeUpdate\Clients"),
    )
    for root, path in registry_paths:
        try:
            with winreg.OpenKey(root, path) as clients:
                count = winreg.QueryInfoKey(clients)[0]
                for index in range(count):
                    try:
                        key_name = winreg.EnumKey(clients, index)
                        with winreg.OpenKey(clients, key_name) as client:
                            display_name, _ = winreg.QueryValueEx(client, "name")
                    except OSError:
                        continue
                    if "webview2" in str(display_name).lower():
                        return True
        except OSError:
            continue
    for env in ("ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"):
        base = os.environ.get(env)
        if base and (Path(base) / "Microsoft" / "EdgeWebView" / "Application").is_dir():
            return True
    return False


def launch_webview() -> int:
    """Launch the WebView2 window. Returns exit code.

    Durable logging and an exception hook are installed before any GUI import:
    the frozen build has no console, so an unlogged failure used to exit the
    process silently.  Every non-zero path now surfaces a native dialog with
    the reason and the log file location.
    """
    _install_startup_logging()
    _install_excepthook()
    _mark("process_start", "gui launch requested")
    try:
        return _launch_webview()
    except Exception as exc:  # noqa: BLE001 - last-resort visibility
        _report_startup_failure(
            "PerchVPN could not start the desktop window.",
            f"{type(exc).__name__}: {exc}",
        )
        return 1


def _launch_webview() -> int:
    url = f"http://{API_HOST}:{API_PORT}/"
    # Must happen before anything resolves a relative path: the MSI shortcuts
    # start us inside Program Files, which is read-only.
    _ensure_writable_cwd()

    if not _port_available():
        logger.error("port %s:%s is already in use", API_HOST, API_PORT)
        _report_startup_failure(
            f"Port {API_PORT} on {API_HOST} is already in use.",
            "PerchVPN's local service cannot start, so the window was not opened.",
            hint=(
                "Close whatever is using that port (often another PerchVPN.exe) "
                "and start PerchVPN again."
            ),
        )
        return 1

    if not _webview2_runtime_available():
        logger.error("Microsoft Edge WebView2 Runtime is not installed")
        _report_startup_failure(
            "Microsoft Edge WebView2 Runtime is missing.",
            "PerchVPN needs the free WebView2 Evergreen Runtime to draw its window.",
            hint=f"Install it from {WEBVIEW2_DOWNLOAD_URL} and start PerchVPN again.",
        )
        return 1

    try:
        import webview
    except ImportError as exc:
        logger.error("pywebview not installed; WebView2 GUI unavailable: %s", exc)
        _report_startup_failure(
            "The desktop GUI backend (pywebview) is not available.",
            f"{type(exc).__name__}: {exc}",
            hint=(
                "Reinstall PerchVPN. To use the browser dashboard instead, run "
                f"{url} while `PerchVPN.exe --dashboard` is running from a terminal."
            ),
        )
        return 1

    # Start the API before opening the window. The finally block below
    # guarantees the uvicorn lifespan shutdown (FastAPI app.shutdown —
    # frontend/controller teardown) executes on every exit path: ready
    # timeout, WebView2 failure, or normal window close.
    api_thread, api_server = start_api_server()
    # Interactive re-authentication runs in the background so the window can
    # open immediately; the app serves a signed-out UI until it completes.
    _start_auth_preflight()
    tray = None
    try:
        # Wait for application initialization to complete
        if not _wait_for_api_ready():
            _report_startup_failure(
                "The local PerchVPN service did not start in time.",
                f"http://{API_HOST}:{API_PORT}/api/status did not answer within "
                f"{STARTUP_TIMEOUT:.0f}s.",
                hint=(
                    f"Another program may already be using port {API_PORT}, or "
                    "security software is blocking the app."
                ),
            )
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
        _mark("window_created", "webview2 window queued")

        tray = _start_tray(window)

        try:
            webview.start(
                icon=_web_icon_path(),
                private_mode=False,
                storage_path=_webview2_storage_path(),
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("WebView2 failed to start: %s", exc)
            _report_startup_failure(
                "The WebView2 window could not be created.",
                f"{type(exc).__name__}: {exc}",
                hint=(
                    "Install the free Microsoft Edge WebView2 Evergreen Runtime "
                    f"({WEBVIEW2_DOWNLOAD_URL}), then start PerchVPN again."
                ),
            )
            return 1

        return 0
    finally:
        if tray is not None:
            tray.stop()
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


def _api_status(timeout: float = 1.5) -> tuple:
    """Return ``(status, is_active)`` from the local API, best effort."""
    import json
    import urllib.request

    url = f"http://{API_HOST}:{API_PORT}/api/status"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
    except Exception:  # noqa: BLE001 - the menu must render even if the API stalls
        return "Disconnected", False
    status = str(data.get("status") or "disconnected").strip().lower()
    active = status in ("connected", "connecting")
    return status.capitalize(), active


def _tray_toggle() -> None:
    """Connect or disconnect from the tray menu without blocking the icon."""

    def _work() -> None:
        import urllib.request

        _label, active = _api_status()
        path = "/api/disconnect" if active else "/api/connect"
        url = f"http://{API_HOST}:{API_PORT}{path}"
        request = urllib.request.Request(url, data=b"", method="POST")
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                response.read()
        except Exception as exc:  # noqa: BLE001 - the UI shows the real error
            logger.warning("tray %s failed: %s", path, exc)

    thread = threading.Thread(target=_work, daemon=True, name="perchvpn-tray-toggle")
    thread.start()
    return thread


def _start_tray(window):
    """Attach a tray icon and hide (instead of close) on the X button.

    Returns the tray icon, or None when unsupported or unavailable; a machine
    without a notification area still gets a normal window.
    """
    from perchvpn_windows import tray as tray_module

    if not tray_module.is_supported():
        return None
    state = {"quitting": False}

    def _open() -> None:
        window.show()
        window.restore()

    def _quit() -> None:
        state["quitting"] = True
        try:
            window.destroy()
        except Exception as exc:  # noqa: BLE001
            logger.warning("tray quit could not close the window: %s", exc)

    def _menu() -> list:
        _label, active = _api_status()
        return [
            (tray_module.MENU_OPEN, "Open Perch VPN", True),
            (tray_module.MENU_TOGGLE, "Disconnect" if active else "Connect", True),
            (0, "", False),
            (tray_module.MENU_QUIT, "Quit", True),
        ]

    icon = tray_module.TrayIcon(
        on_open=_open,
        on_toggle=_tray_toggle,
        on_quit=_quit,
        icon_path=_web_icon_path(),
        menu_provider=_menu,
    )

    def _on_closing(*_args):
        if state["quitting"]:
            return True
        try:
            window.hide()
        except Exception as exc:  # noqa: BLE001 - never trap the user
            logger.warning("could not hide the window: %s", exc)
            return True
        _mark("window_hidden", "close button sent the window to the tray")
        return False

    # The close handler must only exist once there is a tray icon to restore
    # the window from; otherwise the X button would hide it for good.
    if not icon.start():
        return None
    try:
        window.events.closing += _on_closing
    except Exception as exc:  # noqa: BLE001 - never trap the user
        logger.warning("close-to-tray unavailable: %s", exc)
        return None
    return icon


def _webview2_storage_path() -> Optional[str]:
    """Return (and create) the persistent WebView2 user-data folder.

    ``private_mode=True`` (pywebview's default) allocates a throwaway temp
    profile per launch, so WebView2 re-initialises its environment from
    scratch every time.  A stable folder under ``%LOCALAPPDATA%`` removes that
    multi-second cold-start penalty on clean machines.
    """
    from perchvpn_windows.platform import get_webview2_data_dir

    path = get_webview2_data_dir()
    try:
        path.mkdir(parents=True, exist_ok=True)
        return str(path)
    except OSError as exc:
        logger.warning("WebView2 profile directory %s unavailable: %s", path, exc)
        return None


def launch_api_smoke() -> int:
    """Boot the API only, prove it answers, then shut it down cleanly.

    Used by CI and by ``PerchVPN.exe --api-smoke``: a windowed build cannot
    open or close a GUI in a headless runner, but the release smoke test still
    needs to prove that the frozen bundle imports, writes nothing beside the
    executable, serves ``/api/status`` and exits 0.
    """
    _install_startup_logging()
    _install_excepthook()
    _mark("process_start", "api smoke test")
    _ensure_writable_cwd()
    if not _port_available():
        _report_startup_failure(
            f"Port {API_PORT} on {API_HOST} is already in use.",
            "The smoke test could not start PerchVPN's local service.",
        )
        return 1
    api_thread, api_server = start_api_server()
    try:
        if not _wait_for_api_ready():
            _report_startup_failure(
                "The local PerchVPN service did not start in time.",
                f"http://{API_HOST}:{API_PORT}/api/status did not answer within "
                f"{STARTUP_TIMEOUT:.0f}s.",
            )
            return 1
        _mark("api_smoke_ready", "status endpoint answered")
        return 0
    finally:
        api_server.should_exit = True
        if api_thread.is_alive():
            api_thread.join(timeout=SHUTDOWN_JOIN_TIMEOUT)
        if api_thread.is_alive():
            api_server.force_exit = True
            api_thread.join(timeout=5.0)
        _mark("api_smoke_stopped")


def main() -> int:
    return launch_webview()


if __name__ == "__main__":
    sys.exit(main())