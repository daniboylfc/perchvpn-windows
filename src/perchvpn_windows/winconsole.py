"""Windows interactive console attachment for windowed frozen builds.

PyInstaller ``--windowed`` exes have no usable stdin/stdout: interactive
credentials prompts (``input()`` / ``getpass``) hit EOF immediately and the
helper exits before doing anything. ``AllocConsole()`` creates a visible
console window and rebinds the std streams to ``CONIN$`` / ``CONOUT$`` for
the duration of the authentication flow.

Used by both the frozen in-process webview auth path and the spawned
``<exe> --auth-only`` helper, so clicking Sign In always shows an usable
interactive prompt.
"""

from __future__ import annotations

import logging
import sys

logger = logging.getLogger("perchvpn_windows.winconsole")

# Keep the module importable on every platform: outside win32 the helpers are
# no-ops (POSIX dev/test runs always have real std streams).


def ensure_interactive_console():
    """Attach an interactive console in a windowed frozen build.

    PyInstaller --windowed exes have no usable stdin/stdout, so the
    interactive FxA prompts would hit EOF immediately. AllocConsole()
    creates a visible console window for the duration of the prompts.
    Returns a tuple of the original (stdin, stdout, stderr) values that
    the caller must restore, or None when no console was attached.
    """
    if sys.platform != "win32":
        return None
    if sys.stdin is not None and sys.stdout is not None:
        return None
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        if not kernel32.AllocConsole():
            return None
        original = (sys.stdin, sys.stdout, sys.stderr)
        try:
            sys.stdin = open("CONIN$", "r", encoding="utf-8")  # noqa: SIM115
            sys.stdout = open("CONOUT$", "w", encoding="utf-8")  # noqa: SIM115
            sys.stderr = sys.stdout
        except OSError:
            (sys.stdin, sys.stdout, sys.stderr) = original
            return None
        logger.info("Attached interactive console for authentication prompts")
        return original
    except Exception as exc:  # noqa: BLE001
        logger.error("Cannot attach an interactive console: %s", exc)
        return None


def restore_streams(original) -> None:
    """Restore original std streams captured by ensure_interactive_console."""
    if original is None:
        return
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        try:
            if stream is not None and not stream.closed:
                stream.close()
        except Exception:  # noqa: BLE001
            pass
    (sys.stdin, sys.stdout, sys.stderr) = original
    try:
        import ctypes
        ctypes.windll.kernel32.FreeConsole()
    except Exception:  # noqa: BLE001
        pass
