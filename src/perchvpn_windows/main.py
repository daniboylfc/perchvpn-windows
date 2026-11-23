"""Entry-point for PerchVPN Windows.

When launched with any arguments the full CLI is dispatched (version,
help, auth-only, proxy-only, etc.). With no arguments the WebView2 GUI
starts. `--dashboard` is a legacy launcher flag: it is a no-op accepted by
the CLI parser, and on its own it still opens the WebView2 GUI (the
frozen desktop shortcut targets `PerchVPN.exe --dashboard`). The exit code
of the chosen path is always propagated so the process exit status
reflects reality (windowed frozen builds included).
"""

import sys

_GUI_ONLY_FLAGS = frozenset({"--dashboard"})
# Headless bundle smoke test: start the API, prove it answers, exit 0.  A
# windowed build cannot open and close a GUI on a headless CI runner, so the
# release workflow uses this instead of launching the window.
_API_SMOKE_FLAGS = frozenset({"--api-smoke"})


def _install_startup_reporting() -> None:
    """Install durable logging + exception hooks before any fallible import.

    A ``--windowed`` build has no console: without this, a failure in the
    GUI/API/auth imports exits the process with no window, no dialog and no
    trace.  Import failures here must never block the real dispatch.
    """
    try:
        from perchvpn_windows.startup_diagnostics import (
            install_excepthook,
            install_startup_logging,
        )

        install_startup_logging()
        install_excepthook()
    except Exception:  # noqa: BLE001 - last-resort reporter must not break launch
        pass


def _helper_spec(argv) -> str:
    """Return the ``--tun-helper`` spec path, or ``""`` when not requested.

    The elevated helper is launched as ``PerchVPN.exe --tun-helper <spec>``.
    Dispatching it before the CLI import keeps the UAC-launched process from
    importing argparse, the controller, FastAPI, and the GUI stack just to
    run the sidecar lifecycle.
    """
    if not argv:
        return ""
    first = argv[0]
    if first == "--tun-helper":
        return str(argv[1]) if len(argv) > 1 else ""
    if first.startswith("--tun-helper="):
        return first.split("=", 1)[1]
    return ""


def _dispatch(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    spec_path = _helper_spec(argv)
    if spec_path or (argv and argv[0].split("=", 1)[0] == "--tun-helper"):
        from perchvpn_windows.tun_helper import helper_main
        return helper_main(spec_path)
    if argv and set(argv) <= _API_SMOKE_FLAGS:
        from perchvpn_windows.webview import launch_api_smoke

        return launch_api_smoke()
    if argv and not set(argv) <= _GUI_ONLY_FLAGS:
        from perchvpn_windows.cli import main as cli_main
        return cli_main(argv)
    from perchvpn_windows.instance_guard import acquire, release
    from perchvpn_windows.webview import launch_webview

    if not acquire():
        # A second GUI instance used to exit silently (exit 0, no window, no
        # log) which looks like a broken double-click.  Record it durably and
        # bring the existing window forward when Windows allows it.
        from perchvpn_windows.startup_diagnostics import report_second_instance

        report_second_instance()
        return 0
    try:
        return launch_webview()
    finally:
        release()


if __name__ == "__main__":
    _install_startup_reporting()
    sys.exit(_dispatch())
