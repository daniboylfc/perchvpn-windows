"""Focused tests for custom edge-address parsing."""

from __future__ import annotations

from src.perchvpn_windows.app import PerchVPNApp


def test_parse_edge_address_host_only():
    assert PerchVPNApp._parse_edge_address("edge.example") == ("edge.example", None)


def test_parse_edge_address_host_port():
    assert PerchVPNApp._parse_edge_address("edge.example:8443") == ("edge.example", 8443)


def test_parse_edge_address_ipv6_with_port():
    assert PerchVPNApp._parse_edge_address("[2001:db8::1]:8443") == ("2001:db8::1", 8443)


def test_parse_edge_address_empty():
    assert PerchVPNApp._parse_edge_address("") == (None, None)
