"""Tests for upstream v2.0.3 parity in the sing-box configuration builder."""

from __future__ import annotations

import pytest

from src.perchvpn_windows import singbox_config


class TestIpModeParity:
    def test_legacy_default_is_ipv4_only_addresses(self):
        cfg = singbox_config.build_config()
        tun = cfg["inbounds"][0]
        assert tun["address"] == [singbox_config.DEFAULT_TUN_ADDRESS_V4]
        assert cfg["dns"]["strategy"] == "prefer_ipv4"

    def test_legacy_ipv6_flag_adds_addresses(self):
        cfg = singbox_config.build_config(ipv6=True)
        tun = cfg["inbounds"][0]
        assert singbox_config.DEFAULT_TUN_ADDRESS_V6 in tun["address"]

    def test_explicit_ip_mode_controls_addresses(self):
        cfg = singbox_config.build_config(ip_mode="ipv6_only")
        tun = cfg["inbounds"][0]
        assert tun["address"] == [singbox_config.DEFAULT_TUN_ADDRESS_V6]
        assert cfg["dns"]["strategy"] == "ipv6_only"

    def test_ipv4_only_rejects_ipv6_destinations(self):
        cfg = singbox_config.build_config(ip_mode="ipv4_only")
        assert {"ip_version": 6, "action": "reject"} in cfg["route"]["rules"]

    def test_ipv6_only_rejects_ipv4_destinations(self):
        cfg = singbox_config.build_config(ip_mode="ipv6_only")
        assert {"ip_version": 4, "action": "reject"} in cfg["route"]["rules"]

    def test_dual_stack_has_no_family_reject(self):
        cfg = singbox_config.build_config(ip_mode="dual_stack")
        assert not any(
            rule.get("ip_version") in (4, 6) for rule in cfg["route"]["rules"]
        )

    def test_invalid_ip_mode_rejected(self):
        with pytest.raises(ValueError, match="ip_mode"):
            singbox_config.build_config(ip_mode="both")

    def test_dual_stack_requires_ipv6_mtu(self):
        with pytest.raises(ValueError, match="1280"):
            singbox_config.build_config(ip_mode="dual_stack", mtu=1000)

    def test_ipv4_only_allows_small_mtu(self):
        cfg = singbox_config.build_config(ip_mode="ipv4_only", mtu=1000)
        assert cfg["inbounds"][0]["mtu"] == 1000


class TestLocalNetworkBypass:
    def test_default_bypasses_local_networks(self):
        cfg = singbox_config.build_config()
        rules = [rule for rule in cfg["route"]["rules"] if "ip_cidr" in rule]
        assert any(
            singbox_config.LOCAL_NETWORKS[0] in rule["ip_cidr"] for rule in rules
        )

    def test_disabled_bypass_drops_local_rule(self):
        cfg = singbox_config.build_config(bypass_local_network=False)
        rules = [rule for rule in cfg["route"]["rules"] if "ip_cidr" in rule]
        assert not any(
            singbox_config.LOCAL_NETWORKS[0] in rule["ip_cidr"] for rule in rules
        )


class TestLocalProxyAuth:
    def test_users_emitted_on_mixed_inbound(self):
        cfg = singbox_config.build_config(
            local_proxy_users={"alice": "secret"}
        )
        mixed = next(
            item for item in cfg["inbounds"] if item.get("tag") == "mixed-in"
        )
        assert mixed["users"] == [{"username": "alice", "password": "secret"}]

    def test_no_users_by_default(self):
        cfg = singbox_config.build_config()
        mixed = next(
            item for item in cfg["inbounds"] if item.get("tag") == "mixed-in"
        )
        assert "users" not in mixed

    def test_empty_credential_rejected(self):
        with pytest.raises(ValueError, match="username and password"):
            singbox_config.build_config(local_proxy_users={"alice": ""})


class TestKillSwitch:
    def test_kill_switch_forces_strict_route(self):
        cfg = singbox_config.build_config(kill_switch=True, strict_route=False)
        assert cfg["inbounds"][0]["strict_route"] is True

    def test_no_kill_switch_keeps_requested_route(self):
        cfg = singbox_config.build_config(strict_route=False)
        assert cfg["inbounds"][0]["strict_route"] is False


class TestUtlsParity:
    def test_disabled_by_default(self):
        cfg = singbox_config.build_config()
        server_tls = cfg["dns"]["servers"][0]["tls"]
        assert "utls" not in server_tls

    def test_fingerprint_emitted_on_doh_tls(self):
        cfg = singbox_config.build_config(utls_fingerprint="firefox")
        utls = cfg["dns"]["servers"][0]["tls"]["utls"]
        assert utls == {"enabled": True, "fingerprint": "firefox"}

    def test_ios_and_randomized_supported(self):
        for fp in ("ios", "randomized"):
            cfg = singbox_config.build_config(utls_fingerprint=fp)
            assert cfg["dns"]["servers"][0]["tls"]["utls"]["fingerprint"] == fp

    def test_unknown_fingerprint_rejected(self):
        with pytest.raises(ValueError, match="utls_fingerprint"):
            singbox_config.build_config(utls_fingerprint="wget")

    def test_fingerprint_map_matches_config_constants(self):
        from src.perchvpn_windows.config import UTLS_FINGERPRINTS

        assert singbox_config.SINGBOX_UTLS_FINGERPRINTS.keys() == set(UTLS_FINGERPRINTS) - {"disabled"}
