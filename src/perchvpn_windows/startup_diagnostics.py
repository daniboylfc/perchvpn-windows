"""Durable startup logging and native error dialogs for the windowed build.

The frozen GUI is built with PyInstaller ``--windowed``: ``sys.stderr`` is
``None``, so every ``StreamHandler`` (including logging's last-resort handler)
silently discards output.  A startup failure therefore used to be invisible —
the EXE could exit with no window, no dialog and no trace of the reason.

This module installs a rotating log file before any GUI import and reports
fatal startup errors through a native ``MessageBoxW``.  It deliberately has no
third-party imports so it can run before the backend, the auth stack or
pywebview are loaded.
"""

from __future__ import annotations

import faulthandler
import logging
import os
import sys
import tempfile
import threading
import time
import traceback
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

LOG_MAX_BYTES = 1_000_000
LOG_BACKUP_COUNT = 3
DIALOG_TITLE = "PerchVPN"
_NO_DIALOG_ENV = "PERCHVPN_NO_GUI_DIALOG"

_MB_OK = 0x00000000
_MB_ICONERROR = 0x00000010
_MB_ICONINFORMATION = 0x00000040
_MB_SETFOREGROUND = 0x00010000
_MB_TOPMOST = 0x00040000

_installed = False
_log_path: Optional[Path] = None
_fault_stream = None  # kept alive for the process lifetime


def _local_appdata() -> Optional[Path]:
    """Return the per-user local data directory, or None off-Windows."""
    base = os.environ.get("LOCALAPPDATA")
    if base:
        return Path(base)
    if os.name == "nt":
        return Path.home() / "AppData" / "Local"
    return None


def _base_dir() -> Path:
    base = _local_appdata()
    if base is None:
        base = Path(tempfile.gettempdir())
    return base / "PerchVPN"


def startup_log_path() -> Path:
    """Path of the startup log: ``%LOCALAPPDATA%\\PerchVPN\\perchvpn.log``.

    Off-Windows (tests, CI) the same relative layout is rooted in the temp
    directory so unit tests never touch a real user profile.
    """
    return _base_dir() / "perchvpn.log"


def crash_log_path() -> Path:
    """Path of a timestamped crash log: ``crash-<YYYYmmdd-HHMMSS>.log``."""
    stamp = time.strftime("%Y%m%d-%H%M%S")
    path = _base_dir() / f"crash-{stamp}.log"
    counter = 1
    while path.exists():
        path = _base_dir() / f"crash-{stamp}-{counter}.log"
        counter += 1
    return path


def append_crash_log(text: str) -> Optional[Path]:
    """Write a fatal report to a fresh timestamped crash log.

    The rotating startup log is not enough for a post-mortem: it is capped and
    may be reconfigured by the backend.  A dedicated crash file survives the
    session and is what the dialog points the user at.
    """
    path = crash_log_path()
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"{stamp}\n{text}\n", encoding="utf-8")
    except OSError:
        return None
    return path


def append_startup_log(level: str, message: str) -> Optional[Path]:
    """Append one line directly to the startup log, bypassing logging.

    Used for fatal paths where handlers may already have been reconfigured or
    never installed at all.  Returns the log path, or None when unwritable.
    """
    path = startup_log_path()
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(f"{stamp} {level.lower():<5} {message}\n")
    except OSError:
        return None
    return path


def install_startup_logging(level: int = logging.INFO) -> Path:
    """Attach a rotating file handler to the root logger (idempotent).

    The root logger is used on purpose: ``configure_logger`` later clears the
    ``perchvpn`` namespace handlers, while the root handler keeps capturing
    ``perchvpn_windows`` records for the whole session.
    """
    global _installed, _log_path, _fault_stream
    path = startup_log_path()
    if _installed:
        return _log_path or path
    _installed = True
    _log_path = path
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        handler: logging.Handler = RotatingFileHandler(
            path,
            maxBytes=LOG_MAX_BYTES,
            backupCount=LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
    except OSError:
        handler = logging.NullHandler()
    from perchvpn.logging_config import _TextFormatter

    handler.setFormatter(_TextFormatter())
    handler.setLevel(level)
    root = logging.getLogger()
    root.addHandler(handler)
    if root.level == logging.NOTSET or root.level > level:
        root.setLevel(level)
    if sys.stderr is not None:
        stderr = logging.StreamHandler(stream=sys.stderr)
        stderr.setFormatter(_TextFormatter())
        stderr.setLevel(level)
        root.addHandler(stderr)
    # Native crashes (access violations in the WebView2/TUN layers) bypass the
    # Python exception hooks entirely; faulthandler writes the C-level stack.
    try:
        fault_path = path.with_name("faulthandler.log")
        _fault_stream = open(fault_path, "a", buffering=1, encoding="utf-8")
        faulthandler.enable(_fault_stream)
    except Exception:  # noqa: BLE001 - diagnostics must never block startup
        _fault_stream = None
    return path


def _message_box(message: str, *, title: str = DIALOG_TITLE, error: bool = True) -> bool:
    """Show a native dialog.  No-op off-Windows or when dialogs are disabled."""
    if os.environ.get(_NO_DIALOG_ENV, "").strip().lower() in ("1", "true", "yes"):
        return False
    if sys.platform != "win32":
        return False
    if "--tun-helper" in sys.argv:
        # The UAC-launched helper runs hidden; a modal box would hang it (and
        # with it every later Connect).  It logs to the crash file instead.
        return False
    try:
        import ctypes

        flags = _MB_OK | _MB_SETFOREGROUND | _MB_TOPMOST
        flags |= _MB_ICONERROR if error else _MB_ICONINFORMATION
        ctypes.windll.user32.MessageBoxW(None, str(message), str(title), flags)
        return True
    except Exception:  # noqa: BLE001 - a dialog failure must never crash startup
        return False


def show_error_dialog(message: str, *, title: str = DIALOG_TITLE) -> bool:
    return _message_box(message, title=title, error=True)


def show_info_dialog(message: str, *, title: str = DIALOG_TITLE) -> bool:
    return _message_box(message, title=title, error=False)


def report_startup_failure(
    summary: str, detail: str = "", *, hint: str = ""
) -> Path:
    """Log a fatal startup failure and surface it in a native dialog.

    Returns the crash log path so callers/tests can point the user at the
    trace.
    """
    detail = str(detail or "").strip()
    message = f"{summary}: {detail}" if detail else summary
    append_startup_log("ERROR", message)
    crash_path = append_crash_log(message)
    target = crash_path or startup_log_path()
    parts = [summary]
    if detail:
        parts.append(detail)
    if hint:
        parts.append(hint)
    parts.append(f"Log file: {target}")
    show_error_dialog("\n\n".join(parts))
    return target


def install_excepthook() -> None:
    """Report uncaught main-thread and worker-thread exceptions.

    Main-thread failures get a dialog (the window may never have appeared);
    background-thread failures are logged only, because the GUI is usually
    already visible and a modal box from a worker would be disruptive.
    """
    if not getattr(sys.excepthook, "_perchvpn_startup_hook", False):
        previous = sys.excepthook

        def _hook(exc_type, exc, tb):
            if issubclass(exc_type, KeyboardInterrupt):
                previous(exc_type, exc, tb)
                return
            text = "".join(traceback.format_exception(exc_type, exc, tb)).strip()
            append_startup_log("ERROR", f"uncaught exception:\n{text}")
            crash_path = append_crash_log(f"uncaught exception:\n{text}")
            show_error_dialog(
                "PerchVPN hit an unexpected error and will close.\n\n"
                f"{exc_type.__name__}: {exc}\n\n"
                f"Log file: {crash_path or startup_log_path()}"
            )
            previous(exc_type, exc, tb)

        _hook._perchvpn_startup_hook = True  # type: ignore[attr-defined]
        sys.excepthook = _hook

    if not getattr(threading.excepthook, "_perchvpn_startup_hook", False):
        previous_thread_hook = threading.excepthook

        def _thread_hook(args):
            if args.exc_type is SystemExit:
                return
            text = "".join(
                traceback.format_exception(args.exc_type, args.exc_value, args.exc_traceback)
            ).strip()
            name = getattr(args.thread, "name", "?")
            append_startup_log(
                "ERROR", f"uncaught exception in thread {name}:\n{text}"
            )
            append_crash_log(f"uncaught exception in thread {name}:\n{text}")
            previous_thread_hook(args)

        _thread_hook._perchvpn_startup_hook = True  # type: ignore[attr-defined]
        threading.excepthook = _thread_hook


def focus_existing_instance(title: str = "Perch VPN") -> bool:
    """Bring an already-running PerchVPN window to the foreground.

    Returns False when no matching visible window exists or Windows refuses
    the foreground change (foreground lock); callers then show a hint dialog.
    """
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        matches: list[int] = []
        enum_proc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

        def _callback(hwnd, _lparam):
            length = user32.GetWindowTextLengthW(hwnd)
            if length:
                buffer = ctypes.create_unicode_buffer(length + 1)
                user32.GetWindowTextW(hwnd, buffer, length + 1)
                if title.lower() in buffer.value.lower() and user32.IsWindowVisible(hwnd):
                    matches.append(int(hwnd))
            return True

        user32.EnumWindows(enum_proc(_callback), 0)
        if not matches:
            return False
        hwnd = matches[0]
        user32.ShowWindow(hwnd, 9)  # SW_RESTORE
        return bool(user32.SetForegroundWindow(hwnd))
    except Exception:  # noqa: BLE001 - best effort only
        return False


def report_second_instance() -> None:
    """Log that a GUI instance already owns the mutex and try to focus it."""
    log_path = install_startup_logging()
    append_startup_log(
        "INFO",
        "another PerchVPN desktop instance is already running; "
        "not starting a second window",
    )
    if focus_existing_instance():
        return
    show_info_dialog(
        "PerchVPN is already running.\n\n"
        "If no window is visible, end the existing PerchVPN.exe process in "
        "Task Manager and start it again.\n\n"
        f"Log file: {log_path}"
    )
