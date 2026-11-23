"""Process-wide guard against launching two PerchVPN desktop instances.

Two GUI processes race for 127.0.0.1:1080 and the elevated TUN helper.  A
failed shutdown used to leave the first process holding the SOCKS listener
while a second launch reported ``WinError 10048``.  The mutex is per-session
(``Local\\``) so it does not block a helper or a test process in another
session.
"""

from __future__ import annotations

import ctypes
import sys
from typing import Optional

_ERROR_ALREADY_EXISTS = 183
_MUTEX_NAME = "Local\\PerchVPN-Desktop-Instance"
_handle: Optional[int] = None


def _kernel32():
    """Kernel32 with ctypes-managed last-error state.

    ``ctypes.windll`` saves/restores the thread's last-error around every call,
    so a separate ``GetLastError()`` call reads the *pre-call* value.  Only a
    library created with ``use_last_error=True`` paired with
    ``ctypes.get_last_error()`` reports the result of ``CreateMutexW``.
    """
    return ctypes.WinDLL("kernel32", use_last_error=True)


def acquire() -> bool:
    """Return False when another GUI instance already owns the mutex."""
    global _handle
    if sys.platform != "win32":
        return True
    if _handle:
        return True
    kernel32 = _kernel32()
    kernel32.CreateMutexW.restype = ctypes.c_void_p
    kernel32.CreateMutexW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_bool,
        ctypes.c_wchar_p,
    ]
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_bool
    handle = kernel32.CreateMutexW(None, False, _MUTEX_NAME)
    last_error = ctypes.get_last_error()
    if not handle:
        return True
    if last_error == _ERROR_ALREADY_EXISTS:
        kernel32.CloseHandle(handle)
        return False
    _handle = handle
    return True


def release() -> None:
    """Release the mutex owned by this process, if any."""
    global _handle
    if not _handle or sys.platform != "win32":
        _handle = None
        return
    try:
        close = ctypes.windll.kernel32.CloseHandle
        close.argtypes = [ctypes.c_void_p]
        close.restype = ctypes.c_bool
        close(_handle)
    finally:
        _handle = None
