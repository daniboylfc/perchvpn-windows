"""Regression tests for the live DPAPI audit findings (2026-11-16).

Covers the four /api/network + DPAPI defects found by the bare-metal host audit:
- DPAPI ctypes wiring: CryptProtectData/CryptUnprotectData must receive the
  full 7-argument signature with DATA_BLOB structs (previously 5 c_char_p
  pointers with no pDataOut -> every save of a local-proxy password 500'd).
- LAN bind: socks_bind_address must accept 0.0.0.0 / :: (unspecified).
- custom_edge_address must be honored on POST /api/network.
- relayer_provider='custom' with an empty URL must be rejected.
"""

from __future__ import annotations

import ctypes
from types import SimpleNamespace

import pytest

from src.perchvpn_windows.config import (
    WindowsConfig,
    _cryptprotect,
    _cryptunprotect,
    load_config,
    save_config,
)


class _FakeCfunc:
    """Callable with ctypes function-object attributes (restype/argtypes)."""

    def __init__(self, impl) -> None:
        self._impl = impl
        self.restype = None
        self.argtypes = None

    def __call__(self, *args):
        return self._impl(*args)


class _FakeWindll:
    """Stands in for ctypes.windll; records crypt32/kernel32 calls."""

    def __init__(self) -> None:
        self.cryptprotect_calls: list[int] = []
        self.cryptunprotect_calls: list[int] = []
        self.localfree_calls: list[int] = []
        self.crypt32 = SimpleNamespace()
        self.kernel32 = SimpleNamespace()
        self.crypt32.CryptProtectData = _FakeCfunc(self._cryptprotect_impl)
        self.crypt32.CryptUnprotectData = _FakeCfunc(self._cryptunprotect_impl)
        self.kernel32.LocalFree = _FakeCfunc(self._localfree_impl)

    def _cryptprotect_impl(self, *args):
        self.cryptprotect_calls.append(len(args))
        in_ref, _descr, _ent, cb, _prompt, flags, out_ref = args
        assert cb == 0 and flags == 0
        in_blob = in_ref._obj
        data = ctypes.string_at(in_blob.pbData, in_blob.cbData)
        payload = b"enc:" + data
        buf = ctypes.create_string_buffer(payload, len(payload))
        out_blob = out_ref._obj
        out_blob.cbData = len(payload)
        out_blob.pbData = ctypes.cast(buf, ctypes.c_void_p).value
        return 1

    def _cryptunprotect_impl(self, *args):
        self.cryptunprotect_calls.append(len(args))
        in_ref, descr_ref, _ent, cb, _prompt, flags, out_ref = args
        assert cb == 0 and flags == 0
        in_blob = in_ref._obj
        data = ctypes.string_at(in_blob.pbData, in_blob.cbData)
        assert data.startswith(b"enc:")
        payload = data[4:]
        buf = ctypes.create_string_buffer(payload, len(payload))
        out_blob = out_ref._obj
        out_blob.cbData = len(payload)
        out_blob.pbData = ctypes.cast(buf, ctypes.c_void_p).value
        descr_ref._obj.value = "desc"
        return 1

    def _localfree_impl(self, pointer):
        self.localfree_calls.append(pointer.value or 0)
        return 0


@pytest.fixture
def fake_windll(monkeypatch):
    fake = _FakeWindll()
    monkeypatch.setattr(ctypes, "windll", fake, raising=False)
    return fake


def test_cryptprotect_uses_full_seven_arg_signature(fake_windll):
    encrypted = _cryptprotect(b"audit-pass-123")
    assert encrypted == b"enc:audit-pass-123"
    assert fake_windll.cryptprotect_calls == [7]


def test_cryptunprotect_uses_full_seven_arg_signature(fake_windll):
    decrypted = _cryptunprotect(b"enc:audit-pass-123")
    assert decrypted == b"audit-pass-123"
    assert fake_windll.cryptunprotect_calls == [7]
    assert fake_windll.localfree_calls  # output blob freed


def test_encrypt_password_roundtrip_through_fake_dpapi(fake_windll):
    from src.perchvpn_windows.config import _encrypt_password, _decrypt_password

    token = _encrypt_password("s3cret-value")
    assert _decrypt_password(token) == "s3cret-value"


def test_local_proxy_password_persists_with_real_dpapi_wrappers(
    fake_windll, monkeypatch, tmp_path
):
    config_file = tmp_path / "config.json"
    monkeypatch.setattr("src.perchvpn_windows.config._config_path", lambda: config_file)
    config = WindowsConfig(
        local_proxy_auth_enabled=True,
        local_proxy_username="audit",
        local_proxy_password="audit-pass-123",
    )
    save_config(config)
    raw = config_file.read_text(encoding="utf-8")
    assert "audit-pass-123" not in raw  # never plaintext on disk
    loaded = load_config()
    assert loaded.local_proxy_username == "audit"
    assert loaded.local_proxy_password == "audit-pass-123"


@pytest.mark.skipif(
    not hasattr(ctypes, "windll"), reason="DPAPI is Windows-only"
)
def test_dpapi_real_roundtrip_on_windows():
    token = _cryptprotect("roundtrip-value".encode("utf-8"))
    assert _cryptunprotect(token) == b"roundtrip-value"


def test_network_config_accepts_lan_bind():
    from src.perchvpn_windows.api import NetworkConfig

    # 0.0.0.0 requires local proxy authentication (auth-gated LAN bind).
    NetworkConfig(
        socks_bind_address="0.0.0.0",
        local_proxy_auth_enabled=True,
        local_proxy_username="audit",
        local_proxy_password="audit-pass-123",
    )
    NetworkConfig(
        socks_bind_address="::",
        local_proxy_auth_enabled=True,
        local_proxy_username="audit",
        local_proxy_password="audit-pass-123",
    )
    with pytest.raises(Exception):
        NetworkConfig(socks_bind_address="192.168.1.50")


def test_network_config_lan_bind_with_http_proxy():
    from src.perchvpn_windows.api import NetworkConfig

    creds = dict(
        local_proxy_auth_enabled=True,
        local_proxy_username="audit",
        local_proxy_password="audit-pass-123",
    )
    NetworkConfig(http_proxy_enabled=True, socks_bind_address="127.0.0.1", **creds)
    NetworkConfig(http_proxy_enabled=True, socks_bind_address="0.0.0.0", **creds)


def test_network_config_relayer_pair_validation():
    from src.perchvpn_windows.api import NetworkConfig
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        NetworkConfig(relayer_provider="custom", custom_relayer_url="")
    with pytest.raises(ValidationError):
        NetworkConfig(relayer_provider="automatic", custom_relayer_url="https://r.example")
    NetworkConfig(relayer_provider="custom", custom_relayer_url="https://r.example")
    NetworkConfig(relayer_provider="automatic")


@pytest.mark.asyncio
async def test_set_network_config_honors_custom_edge_address(tmp_path, monkeypatch):
    from src.perchvpn_windows import api as api_module
    from src.perchvpn_windows.api import NetworkConfig

    config_file = tmp_path / "config.json"
    monkeypatch.setattr("src.perchvpn_windows.config._config_path", lambda: config_file)
    config = WindowsConfig()
    monkeypatch.setattr(api_module, "_config", config)
    monkeypatch.setattr(api_module, "_app", None)

    await api_module.set_network_config(
        NetworkConfig(custom_edge_address="edge.example.com:2499")
    )
    loaded = load_config()
    assert loaded.edge_address == "edge.example.com:2499"

    await api_module.set_network_config(NetworkConfig())
    assert load_config().edge_address == ""


@pytest.mark.asyncio
async def test_set_network_config_lan_bind_persists(fake_windll, tmp_path, monkeypatch):
    from src.perchvpn_windows import api as api_module
    from src.perchvpn_windows.api import NetworkConfig

    config_file = tmp_path / "config.json"
    monkeypatch.setattr("src.perchvpn_windows.config._config_path", lambda: config_file)
    config = WindowsConfig()
    monkeypatch.setattr(api_module, "_config", config)
    monkeypatch.setattr(api_module, "_app", None)

    await api_module.set_network_config(
        NetworkConfig(
            socks_bind_address="0.0.0.0",
            local_proxy_auth_enabled=True,
            local_proxy_username="audit",
            local_proxy_password="audit-pass-123",
        )
    )
    assert load_config().listen_host == "0.0.0.0"
