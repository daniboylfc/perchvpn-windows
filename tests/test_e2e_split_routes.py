"""Split-route assertion for the client E2E harness.

sing-box 1.14 with auto_route + route_exclude_address decomposes the literal
/1 split into a long exclusion-aware prefix list.  The harness must accept
that decomposed evidence without weakening the physical-exclusion guarantees.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "scripts" / "e2e" / "e2e_support.py"
)


def _load_support():
    spec = importlib.util.spec_from_file_location("e2e_support", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def support():
    return _load_support()


def _route(prefix: str, *, alias: str = "PerchVPN_test", next_hop: str = "172.19.0.2") -> dict:
    return {
        "DestinationPrefix": prefix,
        "NextHop": next_hop,
        "InterfaceAlias": alias,
    }


def test_literal_split_routes_satisfy_check(support):
    defaults = [
        _route("0.0.0.0/1", next_hop="172.19.0.2"),
        _route("128.0.0.0/1", next_hop="172.19.0.2"),
    ]
    evidence = support.split_route_evidence(defaults, [], "PerchVPN_test")
    assert evidence["ok"] is True
    assert evidence["via"] == "literal"


def test_decomposed_public_halves_satisfy_check(support):
    tun_routes = [
        _route("1.0.0.0/16"),
        _route("64.0.0.0/3"),
        _route("128.0.0.0/3"),
        _route("208.0.0.0/4"),
        _route("10.0.0.0/8"),
        _route("172.19.0.0/30"),
        _route("255.255.255.255/32"),
    ]
    evidence = support.split_route_evidence([], tun_routes, "PerchVPN_test")
    assert evidence["ok"] is True
    assert evidence["via"] == "decomposed"
    assert evidence["halves_covered"] == {"0.0.0.0/1": True, "128.0.0.0/1": True}


def test_single_half_is_not_enough(support):
    evidence = support.split_route_evidence(
        [], [_route("128.0.0.0/3")], "PerchVPN_test"
    )
    assert evidence["ok"] is False
    assert evidence["via"] == "missing"


def test_private_and_onlink_routes_do_not_count(support):
    tun_routes = [
        _route("10.0.0.0/8"),
        _route("172.19.0.0/30", next_hop="0.0.0.0"),
        _route("192.168.0.0/16"),
        _route("224.0.0.0/3"),
    ]
    evidence = support.split_route_evidence([], tun_routes, "PerchVPN_test")
    assert evidence["ok"] is False
    assert evidence["decomposed_count"] == 0


def test_other_adapter_routes_are_ignored(support):
    tun_routes = [
        _route("1.0.0.0/16", alias="Ethernet"),
        _route("128.0.0.0/3", alias="Ethernet"),
    ]
    evidence = support.split_route_evidence([], tun_routes, "PerchVPN_test")
    assert evidence["ok"] is False
