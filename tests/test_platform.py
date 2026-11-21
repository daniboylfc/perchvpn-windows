"""Tests for Windows platform path abstractions."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from src.perchvpn_windows.platform import (
    get_config_dir,
    get_token_path,
    get_proxy_state_path,
    get_status_path,
    ensure_config_dir,
)


class TestPlatformPaths:
    def test_get_config_dir_uses_appdata(self, monkeypatch):
        monkeypatch.setenv("APPDATA", "C:\\Users\\Test\\AppData\\Roaming")
        path = get_config_dir()
        assert path == Path("C:\\Users\\Test\\AppData\\Roaming") / "PerchVPN"

    def test_get_config_dir_fallback(self, monkeypatch):
        monkeypatch.delenv("APPDATA", raising=False)
        path = get_config_dir()
        assert path.name == "PerchVPN"
        assert "AppData" in str(path)

    def test_get_token_path(self, monkeypatch):
        monkeypatch.setenv("APPDATA", "C:\\Users\\Test\\AppData\\Roaming")
        path = get_token_path()
        assert path.name == "tokens.json"
        assert "PerchVPN" in str(path)

    def test_get_proxy_state_path(self, monkeypatch):
        monkeypatch.setenv("APPDATA", "C:\\Users\\Test\\AppData\\Roaming")
        path = get_proxy_state_path()
        assert path.name == "proxy-state.json"
        assert "PerchVPN" in str(path)

    def test_get_status_path(self, monkeypatch):
        monkeypatch.setenv("APPDATA", "C:\\Users\\Test\\AppData\\Roaming")
        path = get_status_path()
        assert path.name == "status.json"
        assert "PerchVPN" in str(path)

    def test_ensure_config_dir_creates_directory(self, tmp_path, monkeypatch):
        test_dir = tmp_path / "TestPerchVPN"
        monkeypatch.setattr("src.perchvpn_windows.platform.get_config_dir", lambda: test_dir)
        ensure_config_dir()
        assert test_dir.exists()
        assert test_dir.is_dir()