"""Windows process-spawn helpers for background work.

GUI builds have no console of their own, so every console child must be
created with both ``CREATE_NO_WINDOW`` and a hidden ``STARTUPINFO``.  Using
only one of the two still lets some launchers (``taskkill``, ``pnputil``,
``powershell.exe``) briefly create a console window on screen.
"""

from __future__ import annotations

import subprocess
import sys
from typing import Any, Dict, Optional, Sequence

CREATE_NO_WINDOW = 0x08000000
CREATE_NEW_PROCESS_GROUP = 0x00000200
STARTF_USESHOWWINDOW = 0x00000001
SW_HIDE = 0


def hidden_startupinfo() -> Optional[subprocess.STARTUPINFO]:
    """Return a STARTUPINFO that requests a hidden window, or None off Windows."""
    if sys.platform != "win32" or not hasattr(subprocess, "STARTUPINFO"):
        return None
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = SW_HIDE
    return startupinfo


def hidden_process_kwargs(*, new_process_group: bool = False) -> Dict[str, Any]:
    """Keyword arguments for a background subprocess on Windows."""
    if sys.platform != "win32":
        return {}
    creationflags = CREATE_NO_WINDOW
    if new_process_group:
        creationflags |= CREATE_NEW_PROCESS_GROUP
    kwargs: Dict[str, Any] = {"creationflags": creationflags}
    startupinfo = hidden_startupinfo()
    if startupinfo is not None:
        kwargs["startupinfo"] = startupinfo
    return kwargs


def run_hidden(args: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess:
    """Run a console child without ever showing its window."""
    new_process_group = bool(kwargs.pop("new_process_group", False))
    hidden = hidden_process_kwargs(new_process_group=new_process_group)
    kwargs.update(hidden)
    return subprocess.run(list(args), **kwargs)


def popen_hidden(args: Sequence[str], **kwargs: Any) -> subprocess.Popen:
    """Start a background console child without ever showing its window."""
    new_process_group = bool(kwargs.pop("new_process_group", False))
    hidden = hidden_process_kwargs(new_process_group=new_process_group)
    kwargs.update(hidden)
    return subprocess.Popen(list(args), **kwargs)


def powershell_argv(script: str, executable: str = "powershell.exe") -> list[str]:
    """Build a non-interactive, hidden PowerShell command line."""
    return [
        executable,
        "-NoProfile",
        "-NonInteractive",
        "-WindowStyle",
        "Hidden",
        "-Command",
        script,
    ]
