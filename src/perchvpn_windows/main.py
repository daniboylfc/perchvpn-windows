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
    if argv and not set(argv) <= _GUI_ONLY_FLAGS:
        from perchvpn_windows.cli import main as cli_main
        return cli_main(argv)
    from perchvpn_windows.instance_guard import acquire, release
    from perchvpn_windows.webview import launch_webview

    if not acquire():
        return 0
    try:
        return launch_webview()
    finally:
        release()


if __name__ == "__main__":
    sys.exit(_dispatch())
