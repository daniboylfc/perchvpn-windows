"""Compatibility coverage for the legacy ``--dashboard`` launcher flag.

The frozen desktop shortcut historically targeted ``PerchVPN.exe
--dashboard``. The flag is a no-op (the dashboard is enabled by default),
``--no-dashboard`` overrides it, and a bare ``--dashboard`` still opens
the WebView2 GUI.
"""

from __future__ import annotations

import perchvpn.cli as core_cli
import perchvpn_windows
import perchvpn_windows.cli as win_cli
import perchvpn_windows.main as main_module
import perchvpn_windows.webview as webview_module


class TestWindowsCliDashboardFlag:
    def test_dashboard_enabled_by_default(self):
        assert win_cli.build_parser().parse_args([]).dashboard is True

    def test_dashboard_flag_is_accepted_as_noop(self):
        assert win_cli.build_parser().parse_args(["--dashboard"]).dashboard is True

    def test_no_dashboard_overrides_dashboard(self):
        args = win_cli.build_parser().parse_args(["--dashboard", "--no-dashboard"])
        assert args.dashboard is False

    def test_dashboard_after_no_dashboard_reenables(self):
        args = win_cli.build_parser().parse_args(["--no-dashboard", "--dashboard"])
        assert args.dashboard is True

    def test_dashboard_flag_does_not_break_dispatch(self, capsys):
        assert win_cli.main(["--dashboard", "--version"]) == 0
        out = capsys.readouterr().out.strip()
        assert out == f"perchvpn {perchvpn_windows.__version__}"


class TestCoreCliDashboardFlag:
    def test_dashboard_is_accepted(self):
        assert core_cli.build_parser().parse_args(["--dashboard"]).dashboard is True

    def test_no_dashboard_is_accepted(self):
        args = core_cli.build_parser().parse_args(["--dashboard", "--no-dashboard"])
        assert args.dashboard is False


class TestEntrypointDashboardDispatch:
    def test_bare_dashboard_flag_launches_webview(self, monkeypatch):
        called = {}

        def fake_launch_webview():
            called["webview"] = True
            return 42

        monkeypatch.setattr(webview_module, "launch_webview", fake_launch_webview)
        assert main_module._dispatch(["--dashboard"]) == 42
        assert called == {"webview": True}

    def test_no_dashboard_routes_to_cli(self, monkeypatch):
        received = {}

        def fake_cli_main(argv):
            received["argv"] = list(argv)
            return 7

        monkeypatch.setattr(win_cli, "main", fake_cli_main)
        assert main_module._dispatch(["--no-dashboard"]) == 7
        assert received["argv"] == ["--no-dashboard"]
