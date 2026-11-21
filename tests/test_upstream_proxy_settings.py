"""Focused tests for upstream-proxy settings persistence."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from pydantic import ValidationError

from src.perchvpn_windows import api as api_module
from src.perchvpn_windows.config import WindowsConfig, load_config, save_config
from src.perchvpn_windows.platform import get_config_dir


@pytest.fixture
def isolated_config(monkeypatch):
    config_dir = Path(tempfile.mkdtemp()) / "config"
    config_dir.mkdir()
    config_file = config_dir / "config.json"
    monkeypatch.setattr("src.perchvpn_windows.config._config_path", lambda: config_file)
    monkeypatch.setattr("src.perchvpn_windows.config._encrypt_password", lambda value: value)
    monkeypatch.setattr("src.perchvpn_windows.config._decrypt_password", lambda value: value)
    return config_file


@pytest.mark.asyncio
async def test_network_config_does_not_expose_password(isolated_config, monkeypatch):
    config = WindowsConfig(
        upstream_proxy_enabled=True,
        upstream_proxy=__import__("src.perchvpn_windows.config", fromlist=["UpstreamProxyConfig"]).UpstreamProxyConfig(
            host="proxy.example", port=1080, type="socks5", username="alice", password="secret"
        ),
    )
    save_config(config)
    loaded = load_config()
    monkeypatch.setattr(api_module, "_config", loaded)
    monkeypatch.setattr(api_module, "_app", None)

    response = await api_module.get_network_config()

    assert response.upstream_proxy_enabled is True
    assert response.upstream_proxy_host == "proxy.example"
    assert response.upstream_proxy_username == "alice"
    assert not hasattr(response, "upstream_proxy_password")


@pytest.mark.asyncio
async def test_set_network_config_saves_upstream_proxy(isolated_config, monkeypatch):
    config = WindowsConfig()
    monkeypatch.setattr("src.perchvpn_windows.config._config_path", lambda: isolated_config)
    monkeypatch.setattr(api_module, "_config", config)
    monkeypatch.setattr(api_module, "_app", None)

    from src.perchvpn_windows.api import NetworkConfig

    payload = NetworkConfig(
        upstream_proxy_enabled=True,
        upstream_proxy_type="http",
        upstream_proxy_host="proxy.example",
        upstream_proxy_port=8080,
        upstream_proxy_username="alice",
        upstream_proxy_password="secret",
    )
    await api_module.set_network_config(payload)

    loaded = load_config()
    assert loaded.upstream_proxy_enabled is True
    assert loaded.upstream_proxy is not None
    assert loaded.upstream_proxy.type == "http"
    assert loaded.upstream_proxy.host == "proxy.example"
    assert loaded.upstream_proxy.port == 8080
    assert loaded.upstream_proxy.username == "alice"
    assert loaded.upstream_proxy.password == "secret"


@pytest.mark.asyncio
async def test_set_network_config_preserves_password_when_blank(isolated_config, monkeypatch):
    from src.perchvpn_windows.config import UpstreamProxyConfig

    config = WindowsConfig(
        upstream_proxy=UpstreamProxyConfig(host="proxy.example", port=1080, username="alice", password="secret")
    )
    save_config(config)
    loaded = load_config()
    monkeypatch.setattr("src.perchvpn_windows.config._config_path", lambda: isolated_config)
    monkeypatch.setattr(api_module, "_config", loaded)
    monkeypatch.setattr(api_module, "_app", None)

    from src.perchvpn_windows.api import NetworkConfig

    payload = NetworkConfig(
        upstream_proxy_enabled=True,
        upstream_proxy_type="socks5",
        upstream_proxy_host="proxy.example",
        upstream_proxy_port=1080,
        upstream_proxy_username="alice",
        upstream_proxy_password="",
    )
    await api_module.set_network_config(payload)

    reloaded = load_config()
    assert reloaded.upstream_proxy is not None
    assert reloaded.upstream_proxy.password == "secret"


@pytest.mark.asyncio
async def test_disabling_upstream_proxy_preserves_settings(isolated_config, monkeypatch):
    from src.perchvpn_windows.config import UpstreamProxyConfig

    config = WindowsConfig(
        upstream_proxy_enabled=True,
        upstream_proxy=UpstreamProxyConfig(host="proxy.example", port=1080, username="alice", password="secret"),
    )
    save_config(config)
    loaded = load_config()
    monkeypatch.setattr("src.perchvpn_windows.config._config_path", lambda: isolated_config)
    monkeypatch.setattr(api_module, "_config", loaded)
    monkeypatch.setattr(api_module, "_app", None)

    from src.perchvpn_windows.api import NetworkConfig

    payload = NetworkConfig(upstream_proxy_enabled=False)
    await api_module.set_network_config(payload)

    reloaded = load_config()
    assert reloaded.upstream_proxy_enabled is False
    assert reloaded.upstream_proxy is not None
    assert reloaded.upstream_proxy.host == "proxy.example"
    assert reloaded.upstream_proxy.password == "secret"


def test_upstream_proxy_validation_requires_host_when_enabled():
    from src.perchvpn_windows.api import NetworkConfig
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        NetworkConfig(upstream_proxy_enabled=True)
    with pytest.raises(ValidationError):
        NetworkConfig(upstream_proxy_enabled=True, upstream_proxy_host="proxy.example", upstream_proxy_port=0)
    NetworkConfig(
        upstream_proxy_enabled=True,
        upstream_proxy_type="socks5",
        upstream_proxy_host="proxy.example",
        upstream_proxy_port=1080,
    )
