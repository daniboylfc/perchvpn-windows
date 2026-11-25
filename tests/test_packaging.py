"""Package integrity tests: web asset resolution, CLI surface, metadata."""

from __future__ import annotations

import os
import sys

import perchvpn
import perchvpn_windows
import perchvpn_windows.cli as cli_module


class TestPackageIdentity:
    def test_version_matches_metadata(self):
        assert perchvpn.__version__ == "2.0.4"
        assert perchvpn_windows.__version__ == "2.0.4"

    def test_project_name_is_perchvpn(self):
        import importlib.metadata as md

        dist = md.distribution("perchvn-windows") if False else md.distribution("perchvpn-windows")
        assert dist.version == "2.0.4"
        assert dist.metadata["Name"] == "perchvpn-windows"


class TestWebAssetResolution:
    def test_web_dir_resolves_inside_package(self):
        pkg_web = os.path.join(
            os.path.dirname(os.path.abspath(perchvpn_windows.__file__)), "web"
        )
        assert os.path.isdir(pkg_web), pkg_web
        assert os.path.isfile(os.path.join(pkg_web, "index.html"))

    def test_package_ships_web_ui(self):
        pkg_web = os.path.join(os.path.dirname(os.path.abspath(perchvpn_windows.__file__)), "web")
        assert os.path.isfile(os.path.join(pkg_web, "index.html"))
        assert os.path.isfile(os.path.join(pkg_web, "app.js"))
        assert os.path.isfile(os.path.join(pkg_web, "styles.css"))


class TestCliSurface:
    def test_prog_is_perchvpn(self):
        parser = cli_module.build_parser()
        assert parser.prog == "perchvpn"

    def test_version_flag_prints_version(self, capsys):
        assert cli_module.main(["--version"]) == 0
        out = capsys.readouterr().out.strip()
        assert out == "perchvpn 2.0.4"

    def test_console_script_target_exists(self):
        from perchvpn_windows import cli

        assert callable(cli.main)
