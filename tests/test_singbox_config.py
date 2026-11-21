"""sing-box configuration and command construction tests."""

from __future__ import annotations

import ipaddress
import json
import socket
from pathlib import Path

import pytest

from perchvpn_windows import singbox_config, tun_helper
from perchvpn_windows.tun_helper import TunHelperSpec


def _spec(tmp_path: Path, **overrides) -> TunHelperSpec:
    values = dict(
        executable=str(tmp_path / "sing-box.exe"),
        adapter="PerchVPN",
        mtu=1400,
        proxy_host="127.0.0.1",
        proxy_port=1080,
        bypass=["203.0.113.9"],
        extra_args=[],
    )
    values.update(overrides)
    return TunHelperSpec(**values)


class TestBuildConfig:
    def test_tun_and_proxy_shape(self):
        cfg = singbox_config.build_config(bypass=("203.0.113.9",))
        tun = cfg["inbounds"][0]
        assert tun["type"] == "tun"
        assert tun["interface_name"] == "PerchVPN"
        assert tun["mtu"] == 1400
        assert tun["address"] == ["172.19.0.1/30"]
        assert tun["dns_address"] == ["172.19.0.2"]
        assert tun["auto_route"] is True
        assert tun["strict_route"] is True
        assert tun["stack"] == "system"

        mixed = cfg["inbounds"][1]
        assert mixed["type"] == "mixed"
        assert mixed["listen"] == "127.0.0.1"
        assert "listen_host" not in mixed
        assert mixed["listen_port"] == 10808

        socks = next(o for o in cfg["outbounds"] if o["type"] == "socks")
        assert socks["server"] == "127.0.0.1"
        assert socks["server_port"] == 1080
        assert socks["version"] == "5"
        assert socks["network"] == "tcp"
        assert cfg["route"]["final"] == socks["tag"]

    def test_bypass_entries_are_canonical_cidrs(self):
        cfg = singbox_config.build_config(
            bypass=("203.0.113.9", "198.51.100.0/24", "2001:db8::1")
        )
        excluded = cfg["inbounds"][0]["route_exclude_address"]
        assert "203.0.113.9/32" in excluded
        assert "198.51.100.0/24" in excluded
        assert "2001:db8::1/128" in excluded
        # Every entry must be a valid network, not a host string.
        for entry in excluded:
            ipaddress.ip_network(entry, strict=True)

    def test_duplicate_exclusions_are_collapsed(self):
        cfg = singbox_config.build_config(
            bypass=("203.0.113.9", "203.0.113.9/32")
        )
        excluded = cfg["inbounds"][0]["route_exclude_address"]
        assert excluded.count("203.0.113.9/32") == 1

    def test_local_networks_are_excluded(self):
        cfg = singbox_config.build_config()
        excluded = cfg["inbounds"][0]["route_exclude_address"]
        for expected in singbox_config.LOCAL_NETWORKS:
            assert expected in excluded

    def test_fastly_masque_networks_are_excluded(self):
        cfg = singbox_config.build_config()
        excluded = cfg["inbounds"][0]["route_exclude_address"]
        for expected in singbox_config.FASTLY_MASQUE_NETWORKS:
            assert expected in excluded

    def test_split_default_routes_are_explicit(self):
        cfg = singbox_config.build_config(bypass=("203.0.113.9",))
        tun = cfg["inbounds"][0]
        assert tun["route_address"] == list(singbox_config.DEFAULT_ROUTE_ADDRESS)
        assert tun["route_exclude_address"].count("203.0.113.9/32") == 1

    def test_setup_false_disables_auto_route(self):
        cfg = singbox_config.build_config(auto_route=False, strict_route=False)
        assert cfg["inbounds"][0]["auto_route"] is False
        assert cfg["inbounds"][0]["strict_route"] is False

    def test_ipv6_adds_addresses(self):
        cfg = singbox_config.build_config(ipv6=True)
        tun = cfg["inbounds"][0]
        assert tun["address"] == ["172.19.0.1/30", "fdfe:dcba:9876::1/126"]
        assert tun["dns_address"] == ["172.19.0.2", "fdfe:dcba:9876::2"]

    def test_invalid_bypass_is_rejected(self):
        with pytest.raises(ValueError, match="invalid exclude address"):
            singbox_config.build_config(bypass=("not-an-ip",))

    def test_invalid_ports_are_rejected(self):
        with pytest.raises(ValueError, match="proxy_port"):
            singbox_config.build_config(proxy_port=0)
        with pytest.raises(ValueError, match="mixed_port"):
            singbox_config.build_config(mixed_port=70000)
        with pytest.raises(ValueError, match="differ"):
            singbox_config.build_config(proxy_port=10808, mixed_port=10808)

    def test_invalid_mtu_is_rejected(self):
        with pytest.raises(ValueError, match="mtu"):
            singbox_config.build_config(mtu=0)

    def test_invalid_host_and_adapter_are_rejected(self):
        with pytest.raises(ValueError, match="proxy_host"):
            singbox_config.build_config(proxy_host=" ")
        with pytest.raises(ValueError, match="adapter"):
            singbox_config.build_config(adapter="")

    def test_dns_uses_direct_ip_literal_without_bootstrap_loop(self):
        cfg = singbox_config.build_config()
        servers = {item["tag"]: item for item in cfg["dns"]["servers"]}

        remote = servers[singbox_config.DNS_TUNNEL_TAG]
        assert remote["type"] == "https"
        assert remote["server"] == "1.1.1.1"
        assert remote["server_port"] == 443
        assert remote["path"] == "/dns-query"
        assert remote["tls"] == {
            "enabled": True,
            "server_name": "cloudflare-dns.com",
        }
        # An IP literal cannot need DNS to resolve itself, and the resolver
        # must ride the SOCKS tunnel: sing-box dials DNS transports directly
        # when no detour is set, which leaks queries out the physical adapter.
        # ``perch-socks`` points at an IP literal, so it cannot deadlock on the
        # resolver it bootstraps.
        ipaddress.ip_address(remote["server"])
        assert remote["detour"] == "perch-socks"

        direct = servers[singbox_config.DNS_DIRECT_TAG]
        assert direct["type"] == "local"
        assert direct["detour"] == "direct"
        assert cfg["dns"]["final"] == singbox_config.DNS_TUNNEL_TAG
        assert cfg["dns"]["strategy"] == "prefer_ipv4"
        assert cfg["dns"]["independent_cache"] is True
        assert (
            cfg["route"]["default_domain_resolver"]
            == singbox_config.DNS_DIRECT_TAG
        )
        assert (
            "1.1.1.1/32"
            in cfg["inbounds"][0]["route_exclude_address"]
        )

    def test_port_53_is_hijacked_into_the_tunnel_resolver(self):
        cfg = singbox_config.build_config()
        rules = cfg["route"]["rules"]
        assert any(rule.get("port") == 53 for rule in rules)
        assert any(rule.get("protocol") == "dns" for rule in rules)
        assert all(
            rule.get("action") == "hijack-dns"
            for rule in rules
            if rule.get("port") == 53 or rule.get("protocol") == "dns"
        )

    def test_non_dns_udp_is_rejected_after_local_direct(self):
        cfg = singbox_config.build_config()
        rules = cfg["route"]["rules"]
        udp_reject = next(
            rule for rule in rules if rule.get("network") == "udp"
        )
        assert udp_reject["action"] == "reject"
        direct_indexes = [
            index
            for index, rule in enumerate(rules)
            if rule.get("outbound") == "direct"
        ]
        assert direct_indexes
        assert rules.index(udp_reject) > max(direct_indexes)

    def test_dns_hijack_precedes_private_direct_route(self):
        cfg = singbox_config.build_config()
        rules = cfg["route"]["rules"]
        dns_indexes = [
            index
            for index, rule in enumerate(rules)
            if rule.get("protocol") == "dns" or rule.get("port") == 53
        ]
        direct_indexes = [
            index
            for index, rule in enumerate(rules)
            if rule.get("outbound") == "direct"
        ]
        assert dns_indexes
        assert direct_indexes
        assert max(dns_indexes) < min(direct_indexes)

        tun_reject = next(
            rule
            for rule in rules
            if rule.get("action") == "reject"
            and "172.19.0.0/30" in (rule.get("ip_cidr") or ())
        )
        assert rules.index(tun_reject) < min(direct_indexes)

    def test_loopback_is_bypassed_like_other_local_networks(self):
        assert "127.0.0.0/8" in singbox_config.LOCAL_NETWORKS
        cfg = singbox_config.build_config()
        assert "127.0.0.0/8" in cfg["inbounds"][0]["route_exclude_address"]
        direct_rule = next(
            rule
            for rule in cfg["route"]["rules"]
            if "127.0.0.0/8" in (rule.get("ip_cidr") or ())
        )
        assert direct_rule["outbound"] == "direct"

    def test_loopback_proxy_port_is_direct_before_the_socks_final(self):
        cfg = singbox_config.build_config(proxy_host="127.0.0.1", proxy_port=1080)
        rules = cfg["route"]["rules"]
        proxy_rule = next(
            rule
            for rule in rules
            if rule.get("port") == 1080
            and "127.0.0.0/8" in (rule.get("ip_cidr") or ())
        )
        assert proxy_rule["outbound"] == "direct"
        assert rules.index(proxy_rule) < len(rules) - 1

    def test_private_cidrs_are_direct_before_the_socks_final(self):
        cfg = singbox_config.build_config()
        rules = cfg["route"]["rules"]
        for cidr in (
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "127.0.0.0/8",
        ):
            matching = [
                index
                for index, rule in enumerate(rules)
                if cidr in (rule.get("ip_cidr") or ())
            ]
            assert matching, cidr
            for index in matching:
                assert rules[index]["outbound"] == "direct"
        final_rule = max(
            index
            for index, rule in enumerate(rules)
            if rule.get("outbound") == "direct"
        )
        assert final_rule < rules.index(
            next(rule for rule in rules if rule.get("network") == "udp")
        )

    def test_telegram_cidrs_route_to_the_tunnel_outbound(self):
        cfg = singbox_config.build_config()
        rules = cfg["route"]["rules"]
        telegram_rule = next(
            rule
            for rule in rules
            if set(singbox_config.TELEGRAM_NETWORKS).issubset(
                set(rule.get("ip_cidr") or ())
            )
        )
        assert telegram_rule["outbound"] == cfg["route"]["final"]
        # Telegram TCP must not fall into the generic UDP rejection rule.
        udp_reject = next(
            rule for rule in rules if rule.get("network") == "udp"
        )
        assert rules.index(telegram_rule) < rules.index(udp_reject)
        for cidr in singbox_config.TELEGRAM_NETWORKS:
            ipaddress.ip_network(cidr, strict=True)

    def test_bypass_process_names_route_direct_and_find_process_enabled(self):
        # Default config disables process bypass to avoid socket-table polling and allow egress checks
        cfg = singbox_config.build_config()
        assert cfg["route"]["find_process"] is False
        assert not any(
            "process_name" in rule for rule in cfg["route"]["rules"]
        )

        # When explicitly configured, process bypass routes direct and enables find_process
        custom_processes = ("PerchVPN.exe", "test.exe")
        cfg_proc = singbox_config.build_config(bypass_processes=custom_processes)
        assert cfg_proc["route"]["find_process"] is True
        process_rule = next(
            rule for rule in cfg_proc["route"]["rules"] if "process_name" in rule
        )
        assert process_rule["action"] == "route"
        assert process_rule["outbound"] == "direct"
        for name in custom_processes:
            assert name in process_rule["process_name"]


class TestWsl2Routing:
    """WSL2 NAT packets and WSL DNS must bypass the TUN even under strict_route."""

    WSL_SUBNET = "172.27.208.0/20"
    WSL_DNS = "172.27.208.1"

    def _config(self, monkeypatch, **overrides):
        monkeypatch.setattr(
            singbox_config, "_wsl2_exclude_addresses", lambda: [self.WSL_SUBNET]
        )
        return singbox_config.build_config(**overrides)

    def test_carve_out_keeps_default_route_and_strict_route(self, monkeypatch):
        cfg = self._config(monkeypatch)
        tun = cfg["inbounds"][0]
        assert tun["auto_route"] is True
        assert tun["strict_route"] is True
        assert tun["route_address"] == list(singbox_config.DEFAULT_ROUTE_ADDRESS)
        assert self.WSL_SUBNET in tun["route_exclude_address"]
        singbox_config.validate_config(cfg)

    def test_wsl_dns_gateway_is_not_hijacked_or_rejected(self, monkeypatch):
        cfg = self._config(monkeypatch)
        excluded = cfg["inbounds"][0]["route_exclude_address"]
        gateway = ipaddress.ip_address(self.WSL_DNS)
        assert any(gateway in ipaddress.ip_network(net) for net in excluded)
        # The TUN-subnet reject rule is scoped to the tunnel itself.
        assert gateway not in ipaddress.ip_network(
            singbox_config.DEFAULT_TUN_ADDRESS_V4, strict=False
        )
        # Hijack still applies to DNS that actually enters the TUN.
        assert {"protocol": "dns", "action": "hijack-dns"} in cfg["route"]["rules"]
        assert {"port": singbox_config.DNS_PORT, "action": "hijack-dns"} in cfg["route"]["rules"]

    def test_carve_out_survives_bypass_local_network_off(self, monkeypatch):
        cfg = self._config(monkeypatch, bypass_local_network=False)
        assert self.WSL_SUBNET in cfg["inbounds"][0]["route_exclude_address"]
        singbox_config.validate_config(cfg)


class TestMixedPortSelection:
    def test_returns_preferred_when_free(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        assert singbox_config.available_mixed_port(preferred=port) == port

    def test_returns_none_when_another_proxy_owns_the_port(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as owner:
            owner.bind(("127.0.0.1", 0))
            owner.listen(1)
            port = owner.getsockname()[1]
            assert singbox_config.available_mixed_port(preferred=port) is None

    def test_invalid_preferred_port_disables_listener(self):
        assert singbox_config.available_mixed_port(preferred=0) is None


class TestWriteAndValidate:
    def test_write_is_valid_json(self, tmp_path):
        target = tmp_path / "nested" / "sing-box.json"
        singbox_config.write_config(target, singbox_config.build_config())
        parsed = json.loads(target.read_text(encoding="utf-8"))
        assert parsed["inbounds"][0]["type"] == "tun"
        assert not target.with_suffix(".json.tmp").exists()

    def test_validate_rejects_unknown_route_final(self):
        cfg = singbox_config.build_config()
        cfg["route"]["final"] = "missing"
        with pytest.raises(ValueError, match="route.final"):
            singbox_config.validate_config(cfg)

    def test_validate_rejects_unknown_rule_outbound(self):
        cfg = singbox_config.build_config()
        cfg["route"]["rules"].append({"ip_cidr": ["10.0.0.0/8"], "outbound": "nope"})
        with pytest.raises(ValueError, match="unknown outbound"):
            singbox_config.validate_config(cfg)

    def test_tunnel_dns_provider_presets(self):
        # The provider/custom-URL settings were previously inert: every
        # config pinned Cloudflare 1.1.1.1 regardless of the user choice.
        from perchvpn_windows import singbox_config as sc

        cases = {
            "default": ("1.1.1.1", "cloudflare-dns.com"),
            "cloudflare": ("1.1.1.1", "cloudflare-dns.com"),
            "google": ("8.8.8.8", "dns.google"),
            "quad9": ("9.9.9.9", "dns.quad9.net"),
            "adguard": ("94.140.14.14", "dns.adguard-dns.com"),
        }
        for provider, (server, server_name) in cases.items():
            cfg = sc.build_config(tunnel_dns_provider=provider)
            remote = next(
                item for item in cfg["dns"]["servers"]
                if item["tag"] == sc.DNS_TUNNEL_TAG
            )
            assert remote["server"] == server, provider
            assert remote["tls"]["server_name"] == server_name, provider
            assert remote["detour"] == "perch-socks"
            assert "%s/32" % server in cfg["inbounds"][0]["route_exclude_address"]

    def test_auto_detect_interface_toggle(self):
        # The harness runs a local stand-in proxy: an interface-bound
        # outbound socket cannot reach it, so the knob must be honoured.
        from perchvpn_windows import singbox_config as sc

        assert sc.build_config()["route"]["auto_detect_interface"] is True
        cfg = sc.build_config(auto_detect_interface=False)
        assert cfg["route"]["auto_detect_interface"] is False
        sc.validate_config(cfg)

    def test_tunnel_dns_custom_url_requires_ip_literal(self):
        from perchvpn_windows import singbox_config as sc

        cfg = sc.build_config(
            tunnel_dns_provider="custom",
            custom_tunnel_doh_url="https://94.140.14.14:443/dns-query",
        )
        remote = next(
            item for item in cfg["dns"]["servers"]
            if item["tag"] == sc.DNS_TUNNEL_TAG
        )
        assert remote["server"] == "94.140.14.14"
        assert remote["path"] == "/dns-query"
        sc.validate_config(cfg)

        with pytest.raises(ValueError, match="https"):
            sc.build_config(
                tunnel_dns_provider="custom",
                custom_tunnel_doh_url="http://94.140.14.14/dns-query",
            )
        with pytest.raises(ValueError, match="IP literal"):
            sc.build_config(
                tunnel_dns_provider="custom",
                custom_tunnel_doh_url="https://dns.example.org/dns-query",
            )

    def test_validate_rejects_missing_tun(self):
        cfg = singbox_config.build_config()
        cfg["inbounds"] = [item for item in cfg["inbounds"] if item["type"] != "tun"]
        with pytest.raises(ValueError, match="tun inbound"):
            singbox_config.validate_config(cfg)

    def test_validate_rejects_domain_doh_endpoint(self):
        cfg = singbox_config.build_config()
        remote = next(
            item
            for item in cfg["dns"]["servers"]
            if item["tag"] == singbox_config.DNS_TUNNEL_TAG
        )
        remote["server"] = "dns.example"
        with pytest.raises(ValueError, match="IP literal"):
            singbox_config.validate_config(cfg)

    def test_validate_rejects_unknown_dns_final(self):
        cfg = singbox_config.build_config()
        cfg["dns"]["final"] = "missing"
        with pytest.raises(ValueError, match="dns.final"):
            singbox_config.validate_config(cfg)

    def test_validate_rejects_unknown_dns_detour(self):
        cfg = singbox_config.build_config()
        remote = next(
            item
            for item in cfg["dns"]["servers"]
            if item["tag"] == singbox_config.DNS_TUNNEL_TAG
        )
        remote["detour"] = "missing"
        with pytest.raises(ValueError, match="unknown outbound"):
            singbox_config.validate_config(cfg)

    def test_validate_rejects_legacy_listen_host_field(self):
        cfg = singbox_config.build_config()
        mixed = next(item for item in cfg["inbounds"] if item["type"] == "mixed")
        mixed["listen_host"] = mixed.pop("listen")
        with pytest.raises(ValueError, match="listen_host"):
            singbox_config.validate_config(cfg)


class TestSidecarCommand:
    def test_command_runs_singbox_with_config(self, tmp_path):
        spec = _spec(tmp_path)
        config_path = tmp_path / "sing-box.json"
        cmd = tun_helper.build_sidecar_command(
            spec, config_path=config_path, setup=True
        )
        assert cmd[0] == spec.executable
        assert cmd[-3:] == ["run", "-c", str(config_path)]
        cfg = json.loads(config_path.read_text(encoding="utf-8"))
        assert cfg["inbounds"][0]["auto_route"] is True
        assert "203.0.113.9/32" in cfg["inbounds"][0]["route_exclude_address"]

    def test_extra_args_precede_run(self, tmp_path):
        spec = _spec(tmp_path, extra_args=("--log-level", "debug"))
        cmd = tun_helper.build_sidecar_command(
            spec, config_path=tmp_path / "c.json"
        )
        assert cmd[1:3] == ["--log-level", "debug"]
        assert cmd[3:5] == ["run", "-c"]

    def test_setup_false_disables_auto_route(self, tmp_path):
        spec = _spec(tmp_path)
        config_path = tmp_path / "c.json"
        tun_helper.build_sidecar_command(spec, config_path=config_path, setup=False)
        cfg = json.loads(config_path.read_text(encoding="utf-8"))
        assert cfg["inbounds"][0]["auto_route"] is False
        assert cfg["inbounds"][0]["strict_route"] is False
