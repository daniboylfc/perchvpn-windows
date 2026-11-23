"""System tray and close-to-tray behaviour.

The Win32 backend is replaced by a recorder: these tests pin the menu shape,
the callback wiring and the close-to-tray contract without touching a real
notification area (the CI runner has none).
"""

from __future__ import annotations

import threading
import types

import pytest

from perchvpn_windows import tray as tray_module
from perchvpn_windows import webview as webview_module


class _FakeBackend:
    instances = []

    def __init__(self, *, title, icon_path, on_message, menu_provider=None):
        self.title = title
        self.icon_path = icon_path
        self.on_message = on_message
        self.menu_provider = menu_provider
        self.tooltips = []
        self.closed = False
        self.ran = threading.Event()
        _FakeBackend.instances.append(self)

    def run(self, ready):
        ready.set()
        self.ran.wait(5)

    def update_tooltip(self, text):
        self.tooltips.append(text)

    def close(self):
        self.closed = True
        self.ran.set()


@pytest.fixture()
def backend():
    _FakeBackend.instances.clear()
    return _FakeBackend


def _icon(backend, calls, **kwargs):
    return tray_module.TrayIcon(
        on_open=lambda: calls.append("open"),
        on_toggle=lambda: calls.append("toggle"),
        on_quit=lambda: calls.append("quit"),
        backend_factory=backend,
        **kwargs,
    )


def test_start_requires_a_supported_platform(monkeypatch):
    monkeypatch.setattr(tray_module, "is_supported", lambda: False)
    icon = tray_module.TrayIcon(
        on_open=lambda: None, on_toggle=lambda: None, on_quit=lambda: None
    )
    assert icon.start(timeout=1) is False


def test_start_creates_the_backend_and_reports_ready(backend):
    icon = _icon(backend, [])
    assert icon.start(timeout=2) is True
    assert backend.instances[-1].title == tray_module.TRAY_TITLE
    icon.stop()
    assert backend.instances[-1].closed is True


def test_menu_exposes_open_toggle_and_quit(backend):
    icon = _icon(backend, [])
    icon.start(timeout=2)
    items = icon.menu_items()
    assert [item[0] for item in items] == [
        tray_module.MENU_OPEN,
        tray_module.MENU_TOGGLE,
        0,
        tray_module.MENU_QUIT,
    ]
    assert items[1][1] == "Connect"
    icon.set_state("Connected", "Disconnect")
    assert icon.menu_items()[1][1] == "Disconnect"
    assert "Connected" in icon._tooltip()
    icon.stop()


def test_messages_dispatch_to_the_callbacks(backend):
    calls = []
    icon = _icon(backend, calls)
    icon.start(timeout=2)
    icon._handle_message("open")
    icon._handle_message("toggle")
    icon._handle_message("quit")
    assert calls == ["open", "toggle", "quit"]
    icon.stop()


def test_a_failing_callback_does_not_break_the_loop(backend):
    def _boom():
        raise RuntimeError("nope")

    icon = tray_module.TrayIcon(
        on_open=_boom,
        on_toggle=lambda: None,
        on_quit=lambda: None,
        backend_factory=backend,
    )
    icon.start(timeout=2)
    icon._handle_message("open")
    icon._handle_message("toggle")
    icon.stop()


def test_menu_provider_failure_falls_back_to_the_cached_menu(backend):
    def _boom():
        raise RuntimeError("api down")

    icon = _icon(backend, [], menu_provider=_boom)
    icon.start(timeout=2)
    items = icon._menu_items_snapshot()
    assert [item[0] for item in items][0] == tray_module.MENU_OPEN
    icon.stop()


def test_tooltip_is_truncated_for_the_shell(backend):
    icon = _icon(backend, [], title="Perch VPN")
    icon.start(timeout=2)
    icon.set_state("x" * 400, "Disconnect")
    assert len(backend.instances[-1].tooltips[-1]) <= tray_module._TIP_MAX
    icon.stop()


def test_a_tray_that_cannot_start_leaves_the_x_button_alone(tray_env, monkeypatch):
    """No icon means no way back: do not intercept the close button."""
    class _DeadIcon(tray_module.TrayIcon):
        def start(self, timeout=5.0):
            return False

    monkeypatch.setattr(tray_module, "TrayIcon", _DeadIcon)
    window = _FakeWindow()
    assert webview_module._start_tray(window) is None
    assert window.events.closing.handlers == []


def test_a_failing_backend_reports_that_the_icon_is_unavailable(backend):
    class _BrokenBackend(backend):
        def run(self, ready):
            raise OSError("no notification area")

    icon = _icon(_BrokenBackend, [])
    assert icon.start(timeout=2) is False


class _FakeEvent:
    def __init__(self):
        self.handlers = []

    def __iadd__(self, handler):
        self.handlers.append(handler)
        return self

    def fire(self):
        return [handler() for handler in self.handlers]


class _FakeWindow:
    def __init__(self):
        self.events = types.SimpleNamespace(closing=_FakeEvent())
        self.calls = []

    def show(self):
        self.calls.append("show")

    def restore(self):
        self.calls.append("restore")

    def hide(self):
        self.calls.append("hide")

    def destroy(self):
        self.calls.append("destroy")


@pytest.fixture()
def tray_env(monkeypatch, backend):
    """Make _start_tray use the recorder backend on any platform."""
    class _Icon(tray_module.TrayIcon):
        def __init__(self, **kwargs):
            kwargs["backend_factory"] = backend
            super().__init__(**kwargs)

    monkeypatch.setattr(tray_module, "is_supported", lambda: True)
    monkeypatch.setattr(tray_module, "TrayIcon", _Icon)
    monkeypatch.setattr(
        webview_module, "_api_status", lambda timeout=1.5: ("Disconnected", False)
    )
    return _Icon


def test_close_hides_the_window_instead_of_quitting(tray_env, monkeypatch):
    marks = []
    monkeypatch.setattr(webview_module, "_mark", lambda stage, detail="", **kw: marks.append(stage))
    window = _FakeWindow()
    icon = webview_module._start_tray(window)
    assert icon is not None
    try:
        assert window.events.closing.fire() == [False]
        assert window.calls == ["hide"]
        assert marks == ["window_hidden"]
    finally:
        icon.stop()


def test_tray_open_restores_the_hidden_window(tray_env):
    window = _FakeWindow()
    icon = webview_module._start_tray(window)
    assert icon is not None
    try:
        icon._handle_message("open")
        assert window.calls == ["show", "restore"]
    finally:
        icon.stop()


def test_tray_quit_closes_the_window_and_allows_it(tray_env):
    window = _FakeWindow()
    icon = webview_module._start_tray(window)
    assert icon is not None
    try:
        icon._handle_message("quit")
        assert window.calls == ["destroy"]
        assert window.events.closing.fire() == [True]
    finally:
        icon.stop()


def test_tray_menu_label_follows_the_api_state(tray_env, monkeypatch):
    monkeypatch.setattr(webview_module, "_api_status", lambda timeout=1.5: ("Connected", True))
    window = _FakeWindow()
    icon = webview_module._start_tray(window)
    assert icon is not None
    try:
        labels = {item[0]: item[1] for item in icon._menu_items_snapshot()}
        assert labels[tray_module.MENU_TOGGLE] == "Disconnect"
    finally:
        icon.stop()


def test_api_status_defaults_to_disconnected_when_unreachable(monkeypatch):
    monkeypatch.setattr(webview_module, "API_PORT", 9)

    def _boom(*args, **kwargs):
        raise OSError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", _boom)
    assert webview_module._api_status(timeout=0.1) == ("Disconnected", False)


def test_tray_toggle_posts_disconnect_when_connected(monkeypatch):
    seen = {}

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return b"{}"

    def _urlopen(request, timeout=None):
        seen["url"] = request.full_url
        seen["method"] = request.get_method()
        return _Response()

    monkeypatch.setattr(webview_module, "_api_status", lambda timeout=1.5: ("Connected", True))
    monkeypatch.setattr("urllib.request.urlopen", _urlopen)
    webview_module._tray_toggle().join(timeout=5)
    assert seen["url"].endswith("/api/disconnect")
    assert seen["method"] == "POST"


def test_tray_toggle_posts_connect_when_idle(monkeypatch):
    seen = {}

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return b"{}"

    def _urlopen(request, timeout=None):
        seen["url"] = request.full_url
        return _Response()

    monkeypatch.setattr(webview_module, "_api_status", lambda timeout=1.5: ("Disconnected", False))
    monkeypatch.setattr("urllib.request.urlopen", _urlopen)
    webview_module._tray_toggle().join(timeout=5)
    assert seen["url"].endswith("/api/connect")


def test_launch_webview_stops_the_tray_on_exit(monkeypatch):
    """The tray thread must not outlive webview.start()."""
    import webview as pywebview

    stopped = []

    class _Icon:
        def start(self):
            return True

        def stop(self):
            stopped.append(True)

    class _TrayModule:
        MENU_OPEN, MENU_TOGGLE, MENU_QUIT = 1, 2, 3

        @staticmethod
        def is_supported():
            return True

        @staticmethod
        def TrayIcon(**_kwargs):
            return _Icon()

    window = _FakeWindow()
    monkeypatch.setattr(pywebview, "create_window", lambda **kwargs: window)
    monkeypatch.setattr(pywebview, "start", lambda **kwargs: None)
    monkeypatch.setattr(webview_module, "_start_tray", lambda win: _TrayModule.TrayIcon())
    monkeypatch.setattr(webview_module, "_port_available", lambda *a, **k: True)
    monkeypatch.setattr(webview_module, "_webview2_runtime_available", lambda: True)
    monkeypatch.setattr(webview_module, "_wait_for_api_ready", lambda: True)
    monkeypatch.setattr(webview_module, "_ensure_writable_cwd", lambda: None)
    monkeypatch.setattr(webview_module, "_start_auth_preflight", lambda: None)
    monkeypatch.setattr(
        webview_module,
        "start_api_server",
        lambda: (threading.Thread(target=lambda: None, daemon=True), types.SimpleNamespace(should_exit=False, force_exit=False)),
    )

    assert webview_module._launch_webview() == 0
    assert stopped == [True]
