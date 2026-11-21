"""Shared test fixtures."""

from __future__ import annotations

import pytest

from perchvpn import doh_resolver


@pytest.fixture(autouse=True)
def _clear_dns_cache():
    """Keep the process-wide DoH cache from leaking between tests."""
    doh_resolver.clear_dns_cache()
    yield
    doh_resolver.clear_dns_cache()


@pytest.fixture(autouse=True)
def _isolate_tun_singbox_config(tmp_path, monkeypatch):
    """Keep the TUN frontend's default sing-box.json inside the test sandbox."""
    from perchvpn_windows import tun_frontend

    monkeypatch.setattr(
        tun_frontend,
        "get_config_dir",
        lambda: tmp_path / "PerchVPN",
        raising=False,
    )
