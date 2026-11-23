"""Install-path and cold-start parity between local candidates and releases.

The published MSI installs into ``Program Files`` (read-only) while the local
candidate runs from a user-writable folder.  Every runtime write must therefore
land under ``%LOCALAPPDATA%``/``%APPDATA%``, the WebView2 profile must be
persistent, and the frozen bundle must be smoke-testable without a desktop.
"""

from __future__ import annotations

import os
import sys
import types
from pathlib import Path

import pytest

from perchvpn_windows import platform as platform_module
from perchvpn_windows import startup_diagnostics, tun_helper, webview


@pytest.fixture()
def user_dirs(tmp_path, monkeypatch):
    roaming = tmp_path / "Roaming"
    local = tmp_path / "Local"
    roaming.mkdir()
    local.mkdir()
    monkeypatch.setenv("APPDATA", str(roaming))
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    return roaming / "PerchVPN", local / "PerchVPN"


@pytest.fixture()
def install_dir(tmp_path, monkeypatch):
    """Pretend the frozen EXE lives in a read-only Program Files folder."""
    install = tmp_path / "Program Files" / "PerchVPN"
    install.mkdir(parents=True)
    exe = install / "PerchVPN.exe"
    exe.write_bytes(b"MZ")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(exe), raising=False)
    return install


class TestRuntimeWriteRoots:
    def test_every_runtime_path_is_outside_the_install_dir(
        self, user_dirs, install_dir
    ):
        roaming, local = user_dirs
        spec = tun_helper.TunHelperSpec(
            proxy_host="127.0.0.1", proxy_port=1080, executable="sing-box.exe"
        )
        paths = {
            "startup_log": startup_diagnostics.startup_log_path(),
            "crash_log": startup_diagnostics.crash_log_path(),
            "config_dir": platform_module.get_config_dir(),
            "proxy_state": platform_module.get_proxy_state_path(),
            "status": platform_module.get_status_path(),
            "ownership": platform_module.get_tun_ownership_path(),
            "webview2": platform_module.get_webview2_data_dir(),
            "runtime": platform_module.get_runtime_dir(),
            "journal": tun_helper.journal_path(),
            "sidecar_config": tun_helper._default_config_path(spec),
        }
        install_resolved = install_dir.resolve()
        for name, path in paths.items():
            resolved = Path(path).resolve()
            assert install_resolved not in resolved.parents, (name, resolved)
            assert resolved != install_resolved, (name, resolved)
            roots = (roaming.resolve(), local.resolve())
            assert resolved in roots or any(root in resolved.parents for root in roots), (
                name,
                resolved,
            )

    def test_sidecar_config_is_written_under_local_appdata(
        self, user_dirs, monkeypatch, tmp_path
    ):
        _, local = user_dirs
        written: list[Path] = []
        monkeypatch.setattr(
            tun_helper.singbox_config, "write_config", lambda path, cfg: written.append(Path(path))
        )
        spec = tun_helper.TunHelperSpec(
            proxy_host="127.0.0.1", proxy_port=1080, executable="sing-box.exe"
        )
        cmd = tun_helper.build_sidecar_command(spec)
        assert written, "config was not written"
        assert local.resolve() in written[0].resolve().parents
        assert str(written[0]) in cmd

    def test_webview2_profile_is_persistent_and_under_local_appdata(
        self, user_dirs
    ):
        _, local = user_dirs
        path = webview._webview2_storage_path()
        assert path is not None
        assert Path(path) == local / "webview2"
        assert Path(path).is_dir()


class TestWritableCwd:
    def test_chdir_moves_cwd_off_a_read_only_directory(self, user_dirs, tmp_path):
        _, local = user_dirs
        read_only = tmp_path / "readonly"
        read_only.mkdir()
        original = Path.cwd()
        os.chmod(read_only, 0o555)
        try:
            os.chdir(read_only)
            webview._ensure_writable_cwd()
            assert Path.cwd() == local
            assert Path.cwd().is_dir()
            # A relative write now succeeds instead of failing in Program Files.
            (Path.cwd() / "relative-probe.txt").write_text("ok", encoding="utf-8")
        finally:
            os.chdir(original)
            os.chmod(read_only, 0o755)


class TestPersistentWebviewProfile:
    def test_start_uses_storage_path_and_disables_private_mode(
        self, user_dirs, monkeypatch, tmp_path
    ):
        _, local = user_dirs
        captured: dict = {}
        fake_mod = types.ModuleType("webview")
        fake_mod.create_window = lambda **kwargs: captured.setdefault("window", kwargs)
        fake_mod.start = lambda **kwargs: captured.setdefault("start", kwargs)
        monkeypatch.setitem(sys.modules, "webview", fake_mod)
        monkeypatch.setattr(webview, "_port_available", lambda: True)
        monkeypatch.setattr(webview, "_webview2_runtime_available", lambda: True)
        monkeypatch.setattr(webview, "_preflight_interactive_auth", lambda: False)
        monkeypatch.setattr(webview, "_wait_for_api_ready", lambda: True)
        monkeypatch.setattr(
            webview,
            "start_api_server",
            lambda: (types.SimpleNamespace(is_alive=lambda: False), types.SimpleNamespace()),
        )
        monkeypatch.setattr(webview, "_ensure_writable_cwd", lambda: local)

        assert webview._launch_webview() == 0
        start = captured["start"]
        assert start["private_mode"] is False
        assert start["storage_path"] == str(local / "webview2")


class TestStartupTimingMarks:
    def test_marks_are_appended_to_the_startup_log(self, user_dirs):
        _, local = user_dirs
        webview._mark("api_ready", "status=proxy_active")
        webview._mark("window_created")
        text = (local / "perchvpn.log").read_text(encoding="utf-8")
        assert "startup api_ready" in text
        assert "status=proxy_active" in text
        assert "startup window_created" in text


class TestApiSmokeMode:
    def test_smoke_boots_api_and_stops_it(self, user_dirs, monkeypatch):
        server = types.SimpleNamespace(should_exit=False, force_exit=False)
        thread = types.SimpleNamespace(
            is_alive=lambda: False, join=lambda timeout=None: None
        )
        monkeypatch.setattr(webview, "_port_available", lambda: True)
        monkeypatch.setattr(webview, "start_api_server", lambda: (thread, server))
        monkeypatch.setattr(webview, "_wait_for_api_ready", lambda: True)

        assert webview.launch_api_smoke() == 0
        assert server.should_exit is True

    def test_smoke_fails_when_api_never_answers(self, user_dirs, monkeypatch):
        server = types.SimpleNamespace(should_exit=False, force_exit=False)
        thread = types.SimpleNamespace(
            is_alive=lambda: False, join=lambda timeout=None: None
        )
        dialogs: list[str] = []
        monkeypatch.setattr(webview, "_port_available", lambda: True)
        monkeypatch.setattr(webview, "start_api_server", lambda: (thread, server))
        monkeypatch.setattr(webview, "_wait_for_api_ready", lambda: False)
        monkeypatch.setattr(
            webview, "_report_startup_failure", lambda *a, **k: dialogs.append(a[0])
        )

        assert webview.launch_api_smoke() == 1
        assert dialogs, "a failed smoke run must report the reason"

    def test_entrypoint_dispatches_api_smoke(self, monkeypatch):
        from perchvpn_windows import main as main_module

        calls: list[str] = []
        monkeypatch.setitem(
            sys.modules,
            "perchvpn_windows.webview",
            types.SimpleNamespace(launch_api_smoke=lambda: calls.append("smoke") or 0),
        )
        assert main_module._dispatch(["--api-smoke"]) == 0
        assert calls == ["smoke"]


class TestConsolelessStartup:
    def test_api_server_starts_without_std_streams(self, monkeypatch, user_dirs):
        """A --windowed build has no stdout/stderr.

        uvicorn's default formatter calls ``sys.stdout.isatty()``, which raised
        AttributeError inside ``uvicorn.Config()`` and aborted the API start
        with no window and no message on a clean install.
        """
        import uvicorn

        monkeypatch.setattr(sys, "stdout", None)
        monkeypatch.setattr(sys, "stderr", None)
        monkeypatch.setattr(uvicorn.Server, "run", lambda self: None)

        thread, server = webview.start_api_server()
        thread.join(timeout=5)
        assert not thread.is_alive()
        assert server.should_exit is False


class TestReleaseParityFiles:
    def _read(self, relative: str) -> str:
        root = Path(__file__).resolve().parents[1]
        return (root / relative).read_text(encoding="utf-8")

    def test_installer_requires_the_webview2_runtime(self):
        wxs = self._read("installer/PerchVPN.wxs")
        assert "F3017226-FE2A-4295-8BDF-00C3A9A7E4C5" in wxs
        assert "<Launch" in wxs
        assert "WEBVIEW2_MACHINE" in wxs and "WEBVIEW2_USER" in wxs
        assert "go.microsoft.com/fwlink/p/?LinkId=2124703" in wxs

    def test_release_workflow_builds_through_the_shared_script(self):
        workflow = self._read(".github/workflows/release-windows.yml")
        assert "scripts\\build-candidate.ps1" in workflow
        assert "--api-smoke" in workflow
        assert "Build-flag parity guard" in workflow

    def test_build_script_keeps_the_release_flags(self):
        script = self._read("scripts/build-candidate.ps1")
        for flag in (
            "--noconfirm",
            "--onedir",
            "--windowed",
            "--clean",
            "--collect-all",
            "curl_cffi",
            "--add-data",
            "--noupx",
        ):
            assert flag in script, flag
