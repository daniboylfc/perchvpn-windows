"""Tests for upstream v2.0.3 parity configuration fields."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.perchvpn_windows import config as config_module
from src.perchvpn_windows.config import WindowsConfig, load_config, save_config
from src.perchvpn_windows.api import is_newer_version


class TestParityDefaults:
    def test_defaults(self):
        cfg = WindowsConfig()
        assert cfg.latency_probe_url == "https://www.gstatic.com/generate_204"
        assert cfg.ip_mode == "dual_stack"
        assert cfg.bootstrap_dns_provider == "automatic"
        assert cfg.custom_bootstrap_doh_url == ""
        assert cfg.relayer_provider == "automatic"
        assert cfg.custom_relayer_url == ""
        assert cfg.relayed_endpoints == ["guardian"]
        assert cfg.bypass_local_network is True
        assert cfg.local_proxy_auth_enabled is False
        assert cfg.local_proxy_username == ""
        assert cfg.transport_version == "h2"
        assert cfg.multiplex_streams == 8
        assert cfg.utls_fingerprint == "disabled"
        assert cfg.always_on is False
        assert cfg.kill_switch is False
        assert cfg.automatic_recovery is True
        assert cfg.update_checks is True


class TestParityValidation:
    def test_invalid_ip_mode(self):
        with pytest.raises(ValueError, match="ip_mode"):
            WindowsConfig(ip_mode="prefer_both")

    def test_invalid_bootstrap_provider(self):
        with pytest.raises(ValueError, match="bootstrap_dns_provider"):
            WindowsConfig(bootstrap_dns_provider="cloudflare-dns")

    @pytest.mark.parametrize(
        "kwargs, match",
        [
            ({"bootstrap_dns_provider": "custom"}, "custom_bootstrap_doh_url"),
            (
                {"bootstrap_dns_provider": "custom", "custom_bootstrap_doh_url": "http://x.test"},
                "HTTPS",
            ),
        ],
    )
    def test_bootstrap_doh_rules(self, kwargs, match):
        with pytest.raises(ValueError, match=match):
            WindowsConfig(**kwargs)

    def test_custom_relayer_requires_url(self):
        with pytest.raises(ValueError, match="custom_relayer_url"):
            WindowsConfig(relayer_provider="custom")

    def test_custom_relayer_https_only(self):
        with pytest.raises(ValueError, match="HTTPS"):
            WindowsConfig(
                relayer_provider="custom",
                custom_relayer_url="http://relayer.example.com",
            )

    def test_relayer_url_only_with_custom(self):
        with pytest.raises(ValueError, match="custom_relayer_url requires"):
            WindowsConfig(custom_relayer_url="https://relayer.example.com")

    def test_relayed_endpoints_stripped(self):
        cfg = WindowsConfig(relayed_endpoints=["  guardian  ", "", "fxa"])
        assert cfg.relayed_endpoints == ["guardian", "fxa"]

    def test_local_proxy_auth_requires_credentials(self):
        with pytest.raises(ValueError, match="username and password"):
            WindowsConfig(local_proxy_auth_enabled=True, local_proxy_username="u")

    def test_local_proxy_username_colon_forbidden(self):
        with pytest.raises(ValueError, match="must not contain"):
            WindowsConfig(
                local_proxy_auth_enabled=True,
                local_proxy_username="u:s",
                local_proxy_password="p",
            )

    @pytest.mark.parametrize("value", ["h4", "http2", ""])
    def test_invalid_transport_version(self, value):
        with pytest.raises(ValueError, match="transport_version"):
            WindowsConfig(transport_version=value)

    def test_invalid_multiplex_streams(self):
        with pytest.raises(ValueError, match="multiplex_streams"):
            WindowsConfig(multiplex_streams=24)

    def test_invalid_utls_fingerprint(self):
        with pytest.raises(ValueError, match="utls_fingerprint"):
            WindowsConfig(utls_fingerprint="wget")

    def test_latency_probe_url_https_only(self):
        with pytest.raises(ValueError, match="latency_probe_url"):
            WindowsConfig(latency_probe_url="http://www.gstatic.com/generate_204")


class TestEffectiveUseHttp3:
    def test_h2_disables_http3(self):
        cfg = WindowsConfig(use_http3=True, transport_version="h2")
        assert cfg.effective_use_http3 is False

    def test_h3_overrides_legacy_flag(self):
        cfg = WindowsConfig(use_http3=False, transport_version="h3")
        assert cfg.effective_use_http3 is True

    def test_h1_keeps_legacy_flag(self):
        cfg = WindowsConfig(use_http3=True, transport_version="h1")
        assert cfg.effective_use_http3 is True
        cfg = WindowsConfig(use_http3=False, transport_version="h1")
        assert cfg.effective_use_http3 is False


class TestParityPersistence:
    def test_save_and_load_roundtrip(self, tmp_path: Path):
        original = WindowsConfig(
            latency_probe_url="https://probe.example.com/generate_204",
            ip_mode="prefer_ipv6",
            bootstrap_dns_provider="quad9",
            relayer_provider="direct",
            relayed_endpoints=["guardian", "fxa"],
            bypass_local_network=False,
            transport_version="h3",
            multiplex_streams=32,
            utls_fingerprint="chrome",
            always_on=True,
            kill_switch=True,
            automatic_recovery=False,
            update_checks=False,
        )

        config_file = tmp_path / "config.json"
        original_config_path = config_module._config_path
        config_module._config_path = lambda: config_file
        original_config_dir = config_module.ensure_config_dir
        config_module.ensure_config_dir = lambda: None
        try:
            save_config(original)
            data = json.loads(config_file.read_text(encoding="utf-8"))
            assert data["ip_mode"] == "prefer_ipv6"
            assert data["multiplex_streams"] == 32
            loaded = load_config()
            assert loaded.latency_probe_url == original.latency_probe_url
            assert loaded.ip_mode == "prefer_ipv6"
            assert loaded.bootstrap_dns_provider == "quad9"
            assert loaded.relayer_provider == "direct"
            assert loaded.relayed_endpoints == ["guardian", "fxa"]
            assert loaded.bypass_local_network is False
            assert loaded.transport_version == "h3"
            assert loaded.multiplex_streams == 32
            assert loaded.utls_fingerprint == "chrome"
            assert loaded.always_on is True
            assert loaded.kill_switch is True
            assert loaded.automatic_recovery is False
            assert loaded.update_checks is False
        finally:
            config_module._config_path = original_config_path
            config_module.ensure_config_dir = original_config_dir

    def test_legacy_config_loads_with_defaults(self, tmp_path: Path):
        config_file = tmp_path / "config.json"
        config_file.write_text(
            json.dumps({"listen_port": 1099}), encoding="utf-8"
        )
        original_config_path = config_module._config_path
        config_module._config_path = lambda: config_file
        try:
            loaded = load_config()
        finally:
            config_module._config_path = original_config_path
        assert loaded.listen_port == 1099
        assert loaded.ip_mode == "dual_stack"
        assert loaded.latency_probe_url == config_module.DEFAULT_LATENCY_PROBE_URL


class TestUpdateVersionCompare:
    @pytest.mark.parametrize(
        "tag,current,expected",
        [
            ("v2.0.4", "1.0.7", True),
            ("2.0.3", "1.0.7", True),
            ("v1.0.7", "1.0.7", False),
            ("v1.0.6", "1.0.7", False),
            ("v2.0.10", "2.0.9", True),
            ("not-a-version", "1.0.7", False),
        ],
    )
    def test_is_newer_version(self, tag, current, expected):
        assert is_newer_version(tag, current) is expected


class TestTlsFragmentParity:
    def test_defaults(self):
        cfg = WindowsConfig()
        assert cfg.tls_fragment_mode == "disabled"
        assert cfg.tls_fragment_fallback_delay_ms == 300

    def test_all_modes_accepted(self):
        for mode in ("disabled", "record", "packet", "combined"):
            assert WindowsConfig(tls_fragment_mode=mode).tls_fragment_mode == mode

    def test_invalid_mode_rejected(self):
        with pytest.raises(ValueError, match="tls_fragment_mode"):
            WindowsConfig(tls_fragment_mode="faketls")

    def test_delay_bounds(self):
        assert WindowsConfig(tls_fragment_fallback_delay_ms=0).tls_fragment_fallback_delay_ms == 0
        with pytest.raises(ValueError, match="tls_fragment_fallback_delay_ms"):
            WindowsConfig(tls_fragment_fallback_delay_ms=-1)
        with pytest.raises(ValueError, match="tls_fragment_fallback_delay_ms"):
            WindowsConfig(tls_fragment_fallback_delay_ms=10_001)

    def test_extended_utls_fingerprints(self):
        for fp in ("chrome", "firefox", "edge", "safari", "ios", "randomized", "disabled"):
            assert WindowsConfig(utls_fingerprint=fp).utls_fingerprint == fp
        with pytest.raises(ValueError, match="utls_fingerprint"):
            WindowsConfig(utls_fingerprint="wget")
