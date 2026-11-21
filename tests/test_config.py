"""Tests for WindowsConfig defaults and serialization."""

from __future__ import annotations

import json
import tempfile
import os
from pathlib import Path

import pytest

from src.perchvpn_windows.config import WindowsConfig, load_config, save_config, _config_path
from src.perchvpn_windows.platform import get_config_dir


class TestWindowsConfigDefaults:
    def test_defaults(self):
        cfg = WindowsConfig()
        assert cfg.listen_host == "127.0.0.1"
        assert cfg.listen_port == 1080
        assert cfg.country is None
        assert cfg.explicit_proxy is None
        assert cfg.upstream_conns == 1
        assert cfg.use_http3 is False
        assert cfg.handshake_timeout == 10.0
        assert cfg.idle_timeout == 0.0
        assert cfg.max_conns == 256
        assert cfg.verify_exit is True
        assert cfg.guardian_endpoint == "https://vpn.mozilla.org"
        assert cfg.log_level == "info"
        assert cfg.log_format == "text"

    def test_listen_address_property(self):
        cfg = WindowsConfig(listen_host="127.0.0.1", listen_port=1080)
        assert cfg.listen_address == "127.0.0.1:1080"

    def test_validation_upstream_conns(self):
        with pytest.raises(ValueError):
            WindowsConfig(upstream_conns=0)

    def test_validation_max_conns_negative(self):
        with pytest.raises(ValueError):
            WindowsConfig(max_conns=-1)

    def test_validation_idle_timeout_negative(self):
        with pytest.raises(ValueError):
            WindowsConfig(idle_timeout=-1)

    def test_validation_handshake_timeout_zero(self):
        with pytest.raises(ValueError):
            WindowsConfig(handshake_timeout=0)


class TestConfigPersistence:
    def test_save_and_load_roundtrip(self, tmp_path):
        original = WindowsConfig(
            listen_host="127.0.0.1",
            listen_port=1081,
            country="US",
            upstream_conns=4,
            use_http3=True,
            handshake_timeout=15.0,
            idle_timeout=300.0,
            max_conns=100,
            verify_exit=False,
            guardian_endpoint="https://custom.example.com",
            session_token_path="/custom/path",
            log_level="debug",
            log_format="json",
        )

        config_dir = tmp_path / "config"
        config_dir.mkdir()
        config_file = config_dir / "config.json"

        import src.perchvpn_windows.config as config_module
        original_config_path = config_module._config_path
        config_module._config_path = lambda: config_file

        try:
            save_config(original)
            loaded = load_config()
            assert loaded.listen_host == original.listen_host
            assert loaded.listen_port == original.listen_port
            assert loaded.country == original.country
            assert loaded.upstream_conns == original.upstream_conns
            assert loaded.use_http3 == original.use_http3
            assert loaded.handshake_timeout == original.handshake_timeout
            assert loaded.idle_timeout == original.idle_timeout
            assert loaded.max_conns == original.max_conns
            assert loaded.verify_exit == original.verify_exit
            assert loaded.guardian_endpoint == original.guardian_endpoint
            assert loaded.session_token_path == original.session_token_path
            assert loaded.log_level == original.log_level
            assert loaded.log_format == original.log_format
        finally:
            config_module._config_path = original_config_path

    def test_load_missing_returns_defaults(self, tmp_path):
        config_dir = tmp_path / "config"
        config_file = config_dir / "config.json"

        import src.perchvpn_windows.config as config_module
        original_config_path = config_module._config_path
        config_module._config_path = lambda: config_file

        try:
            loaded = load_config()
            assert isinstance(loaded, WindowsConfig)
            assert loaded.listen_host == "127.0.0.1"
            assert loaded.listen_port == 1080
        finally:
            config_module._config_path = original_config_path

    def test_load_invalid_json_returns_defaults(self, tmp_path):
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        config_file = config_dir / "config.json"
        config_file.write_text("{ invalid json }", encoding="utf-8")

        import src.perchvpn_windows.config as config_module
        original_config_path = config_module._config_path
        config_module._config_path = lambda: config_file

        try:
            loaded = load_config()
            assert isinstance(loaded, WindowsConfig)
            assert loaded.listen_host == "127.0.0.1"
        finally:
            config_module._config_path = original_config_path