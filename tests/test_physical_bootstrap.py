"""Pre-TUN control-plane bootstrap must stay on the physical adapter."""

from __future__ import annotations

import socket
import struct
from types import SimpleNamespace

import pytest

from perchvpn import http_client
from perchvpn_windows import app as app_module
from perchvpn_windows import tun_state_capture


@pytest.fixture(autouse=True)
def _reset_http_client():
    saved = (
        http_client._physical_interface,
        http_client._local_address,
        http_client._address_overrides,
        http_client._client,
    )
    yield
    http_client._physical_interface = saved[0]
    http_client._local_address = saved[1]
    http_client._address_overrides = saved[2]
    http_client._client = saved[3]


@pytest.fixture(autouse=True)
def _reset_https_and_overrides():
    http_client.set_control_plane_address_overrides(None)
    yield
    http_client.set_control_plane_address_overrides(None)


def _app(*, guardian="https://guardian.example/api", proxy="proxy.example"):
    instance = object.__new__(app_module.PerchVPNApp)
    instance.config = SimpleNamespace(
        tun_enabled=True,
        guardian_endpoint=guardian,
        upstream_proxy_enabled=bool(proxy),
        upstream_proxy=SimpleNamespace(host=proxy) if proxy else None,
    )
    instance._source_bind_ip = None
    instance._physical_index = None
    instance._control_plane_dial_ips = {}
    instance._upstream_proxy_pin = None
    return instance


def test_socket_options_carry_the_interface_index_on_windows(monkeypatch):
    monkeypatch.setattr(http_client.sys, "platform", "win32")
    assert http_client.physical_interface_socket_options(7) == [
        (socket.IPPROTO_IP, 31, struct.pack("!I", 7))
    ]


def test_socket_options_are_empty_off_windows(monkeypatch):
    monkeypatch.setattr(http_client.sys, "platform", "linux")
    assert http_client.physical_interface_socket_options(7) == []
    assert http_client.physical_interface_socket_options(None) == []


def test_set_physical_interface_rebuilds_the_client(monkeypatch):
    built = []
    monkeypatch.setattr(
        http_client, "_build_client", lambda use_doh=False: built.append(use_doh)
    )
    http_client.set_physical_interface(7)
    assert http_client.physical_interface() == 7
    assert built == [False]


def test_bootstrap_pins_both_endpoints_and_defers_binding_to_the_caller(monkeypatch):
    instance = _app()
    resolved = {"guardian.example": "203.0.113.10", "proxy.example": "203.0.113.20"}
    calls = []

    def fake_resolve(name, *, physical_ip, physical_index):
        calls.append((name, physical_ip, physical_index))
        return [resolved[name]]

    monkeypatch.setattr(app_module, "_is_windows", lambda: True)
    monkeypatch.setattr(
        tun_state_capture,
        "detect_physical_egress",
        lambda: ("192.168.1.5", 7),
    )
    monkeypatch.setattr(app_module, "_physical_ipv4_addresses", fake_resolve)
    monkeypatch.setattr(http_client, "set_physical_interface", lambda index: calls.append(("if", index)))
    monkeypatch.setattr(http_client, "set_local_address", lambda ip: calls.append(("src", ip)))

    egress = instance._bootstrap_physical_path()

    # The client binding is the caller's job: a possibly-orphaned worker
    # thread must never rebuild the shared control-plane client.
    assert egress == ("192.168.1.5", 7)
    assert instance._source_bind_ip is None
    assert instance._physical_index is None
    assert ("src", "192.168.1.5") not in calls
    assert ("if", 7) not in calls
    assert instance._upstream_proxy_pin == "203.0.113.20"
    assert http_client.control_plane_address_overrides() == {
        "guardian.example": "203.0.113.10",
        "proxy.example": "203.0.113.20",
    }
    assert instance._control_plane_dial_ips["proxy.example"] == ["203.0.113.20"]


@pytest.mark.asyncio
async def test_preflight_applies_binding_when_bootstrap_finishes_in_window(monkeypatch):
    instance = _app()
    bound = []

    monkeypatch.setattr(app_module, "_is_windows", lambda: True)

    def fast_bootstrap():
        return ("192.168.1.5", 7)

    monkeypatch.setattr(instance, "_bootstrap_physical_path", fast_bootstrap)
    monkeypatch.setattr(
        http_client, "set_physical_interface", lambda index: bound.append(("if", index))
    )
    monkeypatch.setattr(http_client, "set_local_address", lambda ip: bound.append(("src", ip)))

    import asyncio as aio

    async def fake_to_thread(func, *args, **kwargs):
        return func(*args, **kwargs)

    monkeypatch.setattr(aio, "to_thread", fake_to_thread)
    monkeypatch.setattr(app_module, "PREFLIGHT_TIMEOUT_SECONDS", 1.0)

    await instance._startup_physical_preflight()

    assert bound == [("src", "192.168.1.5"), ("if", 7)]
    assert instance._source_bind_ip == "192.168.1.5"
    assert instance._physical_index == 7


@pytest.mark.asyncio
async def test_preflight_orphaned_bootstrap_never_binds_the_client(monkeypatch):
    instance = _app()
    bound = []

    monkeypatch.setattr(app_module, "_is_windows", lambda: True)

    def slow_bootstrap():
        import time

        time.sleep(0.3)
        return ("192.168.1.5", 7)

    monkeypatch.setattr(
        http_client, "set_physical_interface", lambda index: bound.append(("if", index))
    )
    monkeypatch.setattr(http_client, "set_local_address", lambda ip: bound.append(("src", ip)))

    import asyncio as aio

    monkeypatch.setattr(aio, "to_thread", aio.to_thread)
    monkeypatch.setattr(app_module, "PREFLIGHT_TIMEOUT_SECONDS", 0.05)

    await instance._startup_physical_preflight()

    # The discovery thread outlived the window; binding must never happen.
    assert bound == []
    assert instance._source_bind_ip is None
    assert instance._physical_index is None


def test_bootstrap_fails_closed_when_the_guardian_cannot_be_resolved(monkeypatch):
    instance = _app()

    def boom(*args, **kwargs):
        raise RuntimeError("no DNS server leaves via the physical adapter")

    monkeypatch.setattr(app_module, "_is_windows", lambda: True)
    monkeypatch.setattr(
        tun_state_capture,
        "detect_physical_egress",
        lambda: ("192.168.1.5", 7),
    )
    monkeypatch.setattr(app_module, "_physical_ipv4_addresses", boom)

    with pytest.raises(RuntimeError, match="could not be resolved on the physical path"):
        instance._bootstrap_physical_path()
    assert http_client.control_plane_address_overrides() == {}


def test_bootstrap_fails_closed_without_a_physical_egress(monkeypatch):
    instance = _app()
    monkeypatch.setattr(app_module, "_is_windows", lambda: True)
    monkeypatch.setattr(tun_state_capture, "detect_physical_egress", lambda: None)

    with pytest.raises(RuntimeError, match="no physical egress"):
        instance._bootstrap_physical_path()


def test_bootstrap_refuses_a_configured_source_that_is_not_the_physical_egress(
    monkeypatch,
):
    instance = _app()
    instance._source_bind_ip = "10.8.0.2"
    monkeypatch.setattr(app_module, "_is_windows", lambda: True)
    monkeypatch.setattr(
        tun_state_capture,
        "detect_physical_egress",
        lambda: ("192.168.1.5", 7),
    )

    with pytest.raises(RuntimeError, match="is not the physical egress"):
        instance._bootstrap_physical_path()


def test_bootstrap_is_a_no_op_off_windows(monkeypatch):
    instance = _app()
    called = []
    monkeypatch.setattr(app_module, "_is_windows", lambda: False)
    monkeypatch.setattr(
        tun_state_capture,
        "detect_physical_egress",
        lambda: called.append(True) or ("192.168.1.5", 7),
    )

    assert instance._bootstrap_physical_path() is None

    assert called == []
    assert instance._physical_index is None
    assert http_client.control_plane_address_overrides() == {}


def test_bootstrap_skips_literal_endpoints(monkeypatch):
    instance = _app(guardian="https://203.0.113.10", proxy="203.0.113.20")
    monkeypatch.setattr(app_module, "_is_windows", lambda: True)
    monkeypatch.setattr(
        tun_state_capture,
        "detect_physical_egress",
        lambda: ("192.168.1.5", 7),
    )

    egress = instance._bootstrap_physical_path()

    assert egress == ("192.168.1.5", 7)
    assert instance._physical_index is None
    assert http_client.control_plane_address_overrides() == {}


def test_activation_installs_the_proxy_pin_and_tightens_the_controller(monkeypatch):
    instance = _app()
    instance._controller = SimpleNamespace(
        config=SimpleNamespace(upstream_proxy_host=None, require_pinned_upstream=False)
    )

    instance._install_control_plane_overrides({"proxy.example": ["203.0.113.20"]})

    assert instance._upstream_proxy_pin == "203.0.113.20"
    assert instance._controller.config.upstream_proxy_host == "203.0.113.20"
    assert instance._controller.config.require_pinned_upstream is True
