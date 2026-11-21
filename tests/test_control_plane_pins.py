"""Control-plane dial pinning: hostname answers may never race into the TUN."""

from __future__ import annotations

import httpx
import pytest

from perchvpn import guardian, http_client


@pytest.fixture(autouse=True)
def _clear_overrides():
    http_client.set_control_plane_address_overrides(None)
    yield
    http_client.set_control_plane_address_overrides(None)


def test_rewrite_uses_the_pin_and_preserves_host_and_sni():
    http_client.set_control_plane_address_overrides(
        {"vpn.mozilla.org": "203.0.113.5"}
    )
    url, headers, extensions = http_client.rewrite_control_plane_url(
        "https://vpn.mozilla.org/api/v1/fpn/token"
    )
    assert url == "https://203.0.113.5/api/v1/fpn/token"
    assert headers == {"Host": "vpn.mozilla.org"}
    assert extensions == {"sni_hostname": b"vpn.mozilla.org"}


def test_rewrite_keeps_ports_and_leaves_unmapped_hosts_untouched():
    http_client.set_control_plane_address_overrides(
        {"vpn.mozilla.org": "203.0.113.5"}
    )
    url, headers, extensions = http_client.rewrite_control_plane_url(
        "https://vpn.mozilla.org:8443/x?y=1"
    )
    assert url == "https://203.0.113.5:8443/x?y=1"
    assert headers == {"Host": "vpn.mozilla.org:8443"}
    assert extensions == {"sni_hostname": b"vpn.mozilla.org"}

    assert http_client.rewrite_control_plane_url("https://api.accounts.firefox.com/v1") == (
        "https://api.accounts.firefox.com/v1",
        {},
        {},
    )


def test_authorized_request_dials_only_the_verified_pin(monkeypatch):
    http_client.set_control_plane_address_overrides(
        {"vpn.mozilla.org": "203.0.113.5"}
    )
    recorded = {}

    class FakeClient:
        def request(self, method, url, **kwargs):
            recorded.update(
                method=method,
                url=url,
                headers=kwargs.get("headers"),
                extensions=kwargs.get("extensions"),
                follow_redirects=kwargs.get("follow_redirects"),
            )
            return httpx.Response(200, json={"token": "t"})

    monkeypatch.setattr(guardian, "get_client", lambda: FakeClient())
    guardian._authorized_request(
        "GET", "https://vpn.mozilla.org/api/v1/fpn/token", "token"
    )

    assert recorded["url"] == "https://203.0.113.5/api/v1/fpn/token"
    assert recorded["headers"]["Host"] == "vpn.mozilla.org"
    assert recorded["headers"]["Authorization"] == "Bearer token"
    assert recorded["extensions"] == {"sni_hostname": b"vpn.mozilla.org"}
    # A redirect target would be dialed without a verified pin.
    assert recorded["follow_redirects"] is False


def test_clearing_overrides_restores_plain_hostname_dials(monkeypatch):
    http_client.set_control_plane_address_overrides(
        {"vpn.mozilla.org": "203.0.113.5"}
    )
    http_client.set_control_plane_address_overrides(None)
    assert http_client.rewrite_control_plane_url(
        "https://vpn.mozilla.org/api/v1/fpn/token"
    ) == ("https://vpn.mozilla.org/api/v1/fpn/token", {}, {})
