"""System-tray icon and close-to-tray support (Win32, ctypes only).

The window's X button hides PerchVPN into the notification area instead of
tearing down the tunnel, which is what a VPN client is expected to do: closing
the window must not silently drop the connection.  Quitting is explicit (tray
menu, or ``--quit``) and goes through the normal ``webview.start()`` return
path so the API shutdown in ``webview._launch_webview`` still runs.

Implemented with ``Shell_NotifyIconW`` on a dedicated message-only window, so
it needs no extra dependency and no thread of the GUI toolkit.  Every Win32
call is failure-tolerant: a machine where the notification area is unavailable
must still get a working window, just without a tray icon.
"""

from __future__ import annotations

import logging
import sys
import threading
from typing import Callable, Optional

logger = logging.getLogger("perchvpn_windows.tray")

TRAY_TITLE = "Perch VPN"
_TIP_MAX = 127

MENU_OPEN = 1001
MENU_TOGGLE = 1002
MENU_QUIT = 1003


def is_supported() -> bool:
    return sys.platform == "win32"


class TrayIcon:
    """A tray icon whose menu drives three callbacks.

    ``on_open`` shows the window, ``on_toggle`` connects or disconnects, and
    ``on_quit`` must end the GUI loop.  Callbacks run on the tray thread, so
    they must be thread-safe (pywebview marshals window calls via Invoke).
    """

    def __init__(
        self,
        *,
        on_open: Callable[[], None],
        on_toggle: Callable[[], None],
        on_quit: Callable[[], None],
        title: str = TRAY_TITLE,
        icon_path: Optional[str] = None,
        backend_factory: Optional[Callable[..., object]] = None,
        menu_provider: Optional[Callable[[], list]] = None,
    ) -> None:
        self._on_open = on_open
        self._on_toggle = on_toggle
        self._on_quit = on_quit
        self._title = title
        self._icon_path = icon_path
        self._backend_factory = backend_factory or _Win32Tray
        self._menu_provider = menu_provider or self.menu_items
        self._backend = None
        self._thread: Optional[threading.Thread] = None
        self._ready = threading.Event()
        self._error: Optional[BaseException] = None
        self._lock = threading.Lock()
        self._status = "Disconnected"
        self._toggle_label = "Connect"
        self._started = False

    # -- lifecycle ---------------------------------------------------------
    def start(self, timeout: float = 5.0) -> bool:
        """Create the icon on its own thread.  False when unsupported."""
        if not is_supported() and self._backend_factory is _Win32Tray:
            return False
        with self._lock:
            if self._started:
                return True
            self._started = True
        try:
            self._backend = self._backend_factory(
                title=self._title,
                icon_path=self._icon_path,
                on_message=self._handle_message,
                menu_provider=self._menu_items_snapshot,
            )
        except Exception as exc:  # noqa: BLE001 - tray is best effort
            logger.warning("tray backend unavailable: %s", exc)
            self._started = False
            return False
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="perchvpn-tray"
        )
        self._thread.start()
        if not self._ready.wait(timeout):
            logger.warning("tray icon did not appear within %.1fs", timeout)
            self.stop()
            return False
        if self._error is not None or not getattr(self._backend, "ready", True):
            logger.warning("tray icon unavailable: %s", self._error or "backend not ready")
            self.stop()
            return False
        logger.info("Tray icon ready")
        return True

    def _run(self) -> None:
        try:
            self._backend.run(self._ready)
        except Exception as exc:  # noqa: BLE001
            self._error = exc
            logger.warning("tray message loop stopped: %s", exc)
        finally:
            self._ready.set()

    def stop(self) -> None:
        with self._lock:
            started, backend = self._started, self._backend
            self._started = False
        if not started or backend is None:
            return
        try:
            backend.close()
        except Exception as exc:  # noqa: BLE001
            logger.debug("tray close failed: %s", exc)
        self._backend = None

    # -- state -------------------------------------------------------------
    def set_state(self, status: str, toggle_label: str) -> None:
        """Update the tooltip and the Connect/Disconnect menu entry."""
        with self._lock:
            self._status = str(status or "").strip() or "Disconnected"
            self._toggle_label = str(toggle_label or "").strip() or "Connect"
            backend = self._backend
            tip = self._tooltip()
        if backend is not None:
            try:
                backend.update_tooltip(tip)
            except Exception as exc:  # noqa: BLE001
                logger.debug("tray tooltip update failed: %s", exc)

    def _tooltip(self) -> str:
        return f"{self._title} — {self._status}"[:_TIP_MAX]

    def _menu_items_snapshot(self) -> list:
        try:
            items = self._menu_provider()
        except Exception as exc:  # noqa: BLE001 - fall back to the cached menu
            logger.debug("tray menu provider failed: %s", exc)
            items = None
        return list(items) if items else self.menu_items()

    def menu_items(self) -> list:
        """Menu snapshot as ``(id, label, enabled)`` triples."""
        with self._lock:
            return [
                (MENU_OPEN, "Open Perch VPN", True),
                (MENU_TOGGLE, self._toggle_label, True),
                (0, "", False),
                (MENU_QUIT, "Quit", True),
            ]

    # -- events ------------------------------------------------------------
    def _handle_message(self, kind: str) -> None:
        if kind == "open":
            self._dispatch(self._on_open, "open")
        elif kind == "toggle":
            self._dispatch(self._on_toggle, "toggle")
        elif kind == "quit":
            self.stop()
            self._dispatch(self._on_quit, "quit")

    @staticmethod
    def _dispatch(callback: Callable[[], None], name: str) -> None:
        try:
            callback()
        except Exception as exc:  # noqa: BLE001 - a menu action must not kill the loop
            logger.warning("tray %s action failed: %s", name, exc)


class _Win32Tray:
    """ctypes facade: one message-only window plus a Shell_NotifyIcon entry."""

    WM_APP = 0x8000
    WM_TRAY = WM_APP + 1
    WM_COMMAND = 0x0111
    WM_CLOSE = 0x0010
    WM_DESTROY = 0x0002
    WM_NULL = 0x0000
    WM_LBUTTONUP = 0x0202
    WM_RBUTTONUP = 0x0205
    WM_CONTEXTMENU = 0x007B
    NIM_ADD, NIM_MODIFY, NIM_DELETE = 0, 1, 2
    NIF_MESSAGE, NIF_ICON, NIF_TIP = 0x1, 0x2, 0x4
    MF_STRING, MF_SEPARATOR, MF_GRAYED = 0x0, 0x800, 0x1
    TPM_RIGHTBUTTON, TPM_RETURNCMD, TPM_NONOTIFY = 0x2, 0x100, 0x80
    HWND_MESSAGE = -3
    IDI_APPLICATION = 32512
    IMAGE_ICON, LR_LOADFROMFILE, LR_DEFAULTSIZE = 1, 0x10, 0x40
    ICON_SMALL = 0
    GWLP_USERDATA = -21

    def __init__(self, *, title: str, icon_path, on_message, menu_provider=None) -> None:
        import ctypes
        from ctypes import wintypes

        self._ctypes = ctypes
        self._wintypes = wintypes
        self._on_message = on_message
        self._menu_provider = menu_provider
        self._title = title
        self._icon_path = icon_path
        self._hwnd = None
        self._icon = None
        self._ready = None
        self._wndproc_ref = None

        user32 = ctypes.WinDLL("user32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        self._user32, self._kernel32, self._shell32 = user32, kernel32, shell32

        LRESULT = ctypes.c_ssize_t
        WNDPROC = ctypes.WINFUNCTYPE(
            LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM
        )

        class WNDCLASSW(ctypes.Structure):
            _fields_ = [
                ("style", wintypes.UINT),
                ("lpfnWndProc", WNDPROC),
                ("cbClsExtra", ctypes.c_int),
                ("cbWndExtra", ctypes.c_int),
                ("hInstance", wintypes.HINSTANCE),
                ("hIcon", wintypes.HICON),
                ("hCursor", wintypes.HANDLE),
                ("hbrBackground", wintypes.HBRUSH),
                ("lpszMenuName", wintypes.LPCWSTR),
                ("lpszClassName", wintypes.LPCWSTR),
            ]

        class NOTIFYICONDATAW(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.DWORD),
                ("hWnd", wintypes.HWND),
                ("uID", wintypes.UINT),
                ("uFlags", wintypes.UINT),
                ("uCallbackMessage", wintypes.UINT),
                ("hIcon", wintypes.HICON),
                ("szTip", wintypes.WCHAR * 128),
                ("dwState", wintypes.DWORD),
                ("dwStateMask", wintypes.DWORD),
                ("szInfo", wintypes.WCHAR * 256),
                ("uVersion", wintypes.UINT),
                ("szInfoTitle", wintypes.WCHAR * 64),
                ("dwInfoFlags", wintypes.DWORD),
                ("guidItem", ctypes.c_byte * 16),
                ("hBalloonIcon", wintypes.HICON),
            ]

        class POINT(ctypes.Structure):
            _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]

        self._WNDCLASSW = WNDCLASSW
        self._NOTIFYICONDATAW = NOTIFYICONDATAW
        self._POINT = POINT
        self._WNDPROC = WNDPROC

        user32.CreateWindowExW.restype = wintypes.HWND
        user32.CreateWindowExW.argtypes = [
            wintypes.DWORD,
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.DWORD,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            wintypes.HWND,
            wintypes.HMENU,
            wintypes.HINSTANCE,
            wintypes.LPVOID,
        ]
        user32.RegisterClassW.restype = wintypes.ATOM
        user32.RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASSW)]
        user32.CreatePopupMenu.restype = wintypes.HMENU
        user32.AppendMenuW.restype = wintypes.BOOL
        user32.AppendMenuW.argtypes = [
            wintypes.HMENU,
            wintypes.UINT,
            ctypes.c_size_t,
            wintypes.LPCWSTR,
        ]
        user32.TrackPopupMenu.restype = ctypes.c_int
        user32.TrackPopupMenu.argtypes = [
            wintypes.HMENU,
            wintypes.UINT,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            wintypes.HWND,
            wintypes.LPVOID,
        ]
        user32.DestroyMenu.argtypes = [wintypes.HMENU]
        user32.SetForegroundWindow.argtypes = [wintypes.HWND]
        user32.PostMessageW.argtypes = [
            wintypes.HWND,
            wintypes.UINT,
            wintypes.WPARAM,
            wintypes.LPARAM,
        ]
        user32.GetMessageW.argtypes = [
            ctypes.POINTER(wintypes.MSG),
            wintypes.HWND,
            wintypes.UINT,
            wintypes.UINT,
        ]
        user32.GetCursorPos.argtypes = [ctypes.POINTER(POINT)]
        user32.DefWindowProcW.restype = LRESULT
        user32.DefWindowProcW.argtypes = [
            wintypes.HWND,
            wintypes.UINT,
            wintypes.WPARAM,
            wintypes.LPARAM,
        ]
        user32.DispatchMessageW.restype = LRESULT
        user32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
        user32.TranslateMessage.restype = wintypes.BOOL
        user32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
        user32.PostQuitMessage.restype = None
        user32.PostQuitMessage.argtypes = [ctypes.c_int]
        user32.DestroyWindow.restype = wintypes.BOOL
        user32.DestroyWindow.argtypes = [wintypes.HWND]
        user32.SetForegroundWindow.restype = wintypes.BOOL
        user32.LoadImageW.restype = wintypes.HANDLE
        user32.LoadImageW.argtypes = [
            wintypes.HINSTANCE,
            wintypes.LPCWSTR,
            wintypes.UINT,
            ctypes.c_int,
            ctypes.c_int,
            wintypes.UINT,
        ]
        user32.LoadIconW.restype = wintypes.HICON
        user32.LoadIconW.argtypes = [wintypes.HINSTANCE, ctypes.c_void_p]
        user32.DestroyIcon.argtypes = [wintypes.HICON]
        user32.DestroyWindow.argtypes = [wintypes.HWND]
        kernel32.GetModuleHandleW.restype = wintypes.HMODULE
        kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        shell32.Shell_NotifyIconW.restype = wintypes.BOOL
        shell32.Shell_NotifyIconW.argtypes = [
            wintypes.DWORD,
            ctypes.POINTER(NOTIFYICONDATAW),
        ]

    # -- window ------------------------------------------------------------
    def _load_icon(self):
        if self._icon_path:
            handle = self._user32.LoadImageW(
                None,
                str(self._icon_path),
                self.IMAGE_ICON,
                0,
                0,
                self.LR_LOADFROMFILE | self.LR_DEFAULTSIZE,
            )
            if handle:
                return handle
        return self._user32.LoadIconW(None, self._ctypes.c_void_p(self.IDI_APPLICATION))

    def run(self, ready: threading.Event) -> None:
        ctypes, wintypes = self._ctypes, self._wintypes
        self._ready = ready
        hinstance = self._kernel32.GetModuleHandleW(None)
        class_name = "PerchVPNTrayWindow"

        def _wndproc(hwnd, msg, wparam, lparam):
            try:
                if msg == self.WM_TRAY:
                    event = int(lparam) & 0xFFFF
                    if event in (self.WM_LBUTTONUP,):
                        self._on_message("open")
                    elif event in (self.WM_RBUTTONUP, self.WM_CONTEXTMENU):
                        self._popup(hwnd)
                    return 0
                if msg == self.WM_COMMAND:
                    self._command(int(wparam) & 0xFFFF)
                    return 0
                if msg == self.WM_CLOSE:
                    self._user32.DestroyWindow(hwnd)
                    return 0
                if msg == self.WM_DESTROY:
                    self._user32.PostQuitMessage(0)
                    return 0
            except Exception as exc:  # noqa: BLE001 - never break the loop
                logger.warning("tray window message failed: %s", exc)
            return self._user32.DefWindowProcW(hwnd, msg, wparam, lparam)

        self._wndproc_ref = self._WNDPROC(_wndproc)
        wc = self._WNDCLASSW()
        wc.lpfnWndProc = self._wndproc_ref
        wc.hInstance = hinstance
        wc.lpszClassName = class_name
        if not self._user32.RegisterClassW(ctypes.byref(wc)):
            raise OSError("RegisterClassW failed")
        hwnd = self._user32.CreateWindowExW(
            0, class_name, self._title, 0, 0, 0, 0, 0,
            wintypes.HWND(self.HWND_MESSAGE), None, hinstance, None,
        )
        if not hwnd:
            raise OSError("CreateWindowExW failed")
        self._hwnd = hwnd
        self.ready = False
        self._icon = self._load_icon()
        self._nid = self._NOTIFYICONDATAW()
        self._nid.cbSize = ctypes.sizeof(self._NOTIFYICONDATAW)
        self._nid.hWnd = hwnd
        self._nid.uID = 1
        self._nid.uFlags = self.NIF_MESSAGE | self.NIF_ICON | self.NIF_TIP
        self._nid.uCallbackMessage = self.WM_TRAY
        self._nid.hIcon = self._icon
        self._nid.szTip = self._title[:_TIP_MAX]
        if not self._shell32.Shell_NotifyIconW(self.NIM_ADD, ctypes.byref(self._nid)):
            self._user32.DestroyWindow(hwnd)
            raise OSError("Shell_NotifyIconW(NIM_ADD) failed")
        logger.info("tray icon added (hwnd=%s)", hwnd)
        self.ready = True
        ready.set()

        msg = wintypes.MSG()
        while True:
            result = self._user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
            if result in (0, -1):
                break
            self._user32.TranslateMessage(ctypes.byref(msg))
            self._user32.DispatchMessageW(ctypes.byref(msg))
        self._remove_icon()

    # -- shell integration -------------------------------------------------
    def _popup(self, hwnd) -> None:
        items = None
        if self._menu_provider is not None:
            try:
                items = self._menu_provider()
            except Exception as exc:  # noqa: BLE001
                logger.debug("tray menu provider failed: %s", exc)
        items = list(items) if items else [
            (MENU_OPEN, "Open Perch VPN", True),
            (MENU_TOGGLE, "Connect", True),
            (0, "", False),
            (MENU_QUIT, "Quit", True),
        ]
        menu = self._user32.CreatePopupMenu()
        if not menu:
            return
        try:
            for item_id, label, enabled in items:
                if item_id == 0:
                    self._user32.AppendMenuW(menu, self.MF_SEPARATOR, 0, None)
                    continue
                flags = self.MF_STRING if enabled else (self.MF_STRING | self.MF_GRAYED)
                self._user32.AppendMenuW(menu, flags, item_id, label)
            point = self._POINT()
            self._user32.GetCursorPos(self._ctypes.byref(point))
            # Required by the shell: foreground first, then a null message
            # after the menu closes, or the menu stays on screen.
            self._user32.SetForegroundWindow(hwnd)
            choice = self._user32.TrackPopupMenu(
                menu,
                self.TPM_RIGHTBUTTON | self.TPM_RETURNCMD | self.TPM_NONOTIFY,
                point.x,
                point.y,
                0,
                hwnd,
                None,
            )
            self._user32.PostMessageW(hwnd, self.WM_NULL, 0, 0)
        finally:
            self._user32.DestroyMenu(menu)
        if choice:
            self._command(int(choice))

    def _command(self, item_id: int) -> None:
        if item_id == MENU_OPEN:
            self._on_message("open")
        elif item_id == MENU_TOGGLE:
            self._on_message("toggle")
        elif item_id == MENU_QUIT:
            self._on_message("quit")

    def update_tooltip(self, text: str) -> None:
        if self._hwnd is None:
            return
        self._nid.szTip = text[:_TIP_MAX]
        self._shell32.Shell_NotifyIconW(self.NIM_MODIFY, self._ctypes.byref(self._nid))

    def close(self) -> None:
        hwnd = self._hwnd
        if hwnd is None:
            return
        self._user32.PostMessageW(hwnd, self.WM_CLOSE, 0, 0)

    def _remove_icon(self) -> None:
        if getattr(self, "_nid", None) is not None:
            try:
                self._shell32.Shell_NotifyIconW(
                    self.NIM_DELETE, self._ctypes.byref(self._nid)
                )
            except Exception:  # noqa: BLE001
                pass
            self._nid = None
        if self._icon:
            try:
                self._user32.DestroyIcon(self._icon)
            except Exception:  # noqa: BLE001
                pass
            self._icon = None
        self._hwnd = None
