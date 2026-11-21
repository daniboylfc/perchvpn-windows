"""The upstream-proxy dial may only use a verified physical-underlay address."""

from __future__ import annotations

import socket
import struct
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from perchvpn.controller import ControllerConfig, ProxyController
from perchvpn.exceptions import ProxyError
from perchvpn.proxystate import ProxyCandidate
from perchvpn.proxy import upstream_proxy as upstream_module
from perchvpn.proxy.upstream_proxy import (
    UpstreamProxyConfig,
    connect_through_upstream_proxy,
)


class _FakeSocket:
    instances: list["_FakeSocket"] = []

    def __init__(self, *args, **kwargs):
        self.connect_target = None
        self.bind_target = None
        self.options: list[tuple] = []
        self.sent: list[bytes] = []
        self.closed = False
        self._responses = [b"\x05\x00", b"\x05\x00\x00\x01" + b"\x00" * 6]
        _FakeSocket.instances.append(self)

    def settimeout(self, value):
        pass

    def setsockopt(self, level, option, value):
        self.options.append((level, option, value))

    def bind(self, address):
        self.bind_target = address

    def connect(self, address):
        self.connect_target = address

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, size):
        return self._responses.pop(0)

    def close(self):
        self.closed = True


@pytest.fixture
def fake_socket(monkeypatch):
    _FakeSocket.instances = []
    monkeypatch.setattr(
        upstream_module.socket, "socket", lambda *a, **k: _FakeSocket()
    )
    return _FakeSocket


def test_proxy_connection_dials_the_pin_and_keeps_the_target_name(fake_socket):
    proxy = UpstreamProxyConfig(host="proxy.example", port=1080, type="socks5")

    connect_through_upstream_proxy(
        proxy,
        "edge.example",
        443,
        dial_host="203.0.113.9",
    )

    sock = fake_socket.instances[0]
    assert sock.connect_target == ("203.0.113.9", 1080)
    request = b"".join(sock.sent)
    assert b"edge.example" in request
    assert b"proxy.example" not in request


def test_proxy_connection_target_is_never_the_configured_name_when_pinned(fake_socket):
    proxy = UpstreamProxyConfig(host="proxy.example", port=1080, type="socks5")

    connect_through_upstream_proxy(
        proxy,
        "edge.example",
        443,
        dial_host="203.0.113.9",
    )

    sock = fake_socket.instances[0]
    assert sock.connect_target == ("203.0.113.9", 1080)


def test_interface_pin_sets_ip_unicast_if_before_connect(fake_socket, monkeypatch):
    monkeypatch.setattr(upstream_module.sys, "platform", "win32")
    proxy = UpstreamProxyConfig(host="proxy.example", port=1080, type="socks5")

    connect_through_upstream_proxy(
        proxy, "edge.example", 443, dial_host="203.0.113.9", interface_index=7
    )

    sock = fake_socket.instances[0]
    assert (socket.IPPROTO_IP, 31, struct.pack("!I", 7)) in sock.options


def test_no_interface_pin_means_no_socket_option(fake_socket, monkeypatch):
    monkeypatch.setattr(upstream_module.sys, "platform", "win32")
    proxy = UpstreamProxyConfig(host="proxy.example", port=1080, type="socks5")

    connect_through_upstream_proxy(
        proxy, "edge.example", 443, dial_host="203.0.113.9"
    )

    assert fake_socket.instances[0].options == []


def _controller(**overrides) -> ProxyController:
    candidate = ProxyCandidate(
        host="edge.example", port=443, country_code="US", country_name="United States"
    )
    config = ControllerConfig(
        guardian_endpoint="https://guardian.example",
        candidate=candidate,
        upstream_conns=1,
        handshake_timeout=0.01,
        **overrides,
    )
    controller = ProxyController(config, MagicMock())
    controller.proxy_pass = SimpleNamespace(
        raw_token="tok",
        expires_at=lambda: datetime.now(timezone.utc) + timedelta(hours=1),
    )
    return controller


class _RecordingSession:
    dialled: list[dict] = []

    def __init__(self, host, port, token, **kwargs):
        self.host = host
        self.port = port
        _RecordingSession.dialled.append(dict(host=host, port=port, **kwargs))

    async def connect(self, timeout=None):
        return None

    async def close(self):
        return None


@pytest.mark.asyncio
async def test_unpinned_upstream_proxy_hostname_fails_before_dialling(monkeypatch):
    _RecordingSession.dialled = []
    monkeypatch.setattr(
        "perchvpn.controller.H2ProxySession", _RecordingSession, raising=True
    )
    controller = _controller(
        upstream_proxy=UpstreamProxyConfig(host="proxy.example", port=1080),
        require_pinned_upstream=True,
    )

    with pytest.raises(ProxyError, match="no verified physical-underlay address pin"):
        await controller._connect_candidate(controller.current_candidate)
    assert _RecordingSession.dialled == []


@pytest.mark.asyncio
async def test_non_literal_pin_is_not_accepted_as_verified(monkeypatch):
    _RecordingSession.dialled = []
    monkeypatch.setattr(
        "perchvpn.controller.H2ProxySession", _RecordingSession, raising=True
    )
    controller = _controller(
        upstream_proxy=UpstreamProxyConfig(host="proxy.example", port=1080),
        require_pinned_upstream=True,
        upstream_proxy_host="proxy.example",
    )

    with pytest.raises(ProxyError, match="no verified physical-underlay address pin"):
        await controller._connect_candidate(controller.current_candidate)
    assert _RecordingSession.dialled == []


@pytest.mark.asyncio
async def test_verified_pin_dials_the_address_while_the_name_is_preserved(monkeypatch):
    _RecordingSession.dialled = []
    monkeypatch.setattr(
        "perchvpn.controller.H2ProxySession", _RecordingSession, raising=True
    )
    controller = _controller(
        upstream_proxy=UpstreamProxyConfig(host="proxy.example", port=1080),
        require_pinned_upstream=True,
        upstream_proxy_host="203.0.113.9",
        physical_interface=7,
    )

    await controller._connect_candidate(controller.current_candidate)

    dialled = _RecordingSession.dialled[0]
    assert dialled["upstream_proxy"].host == "proxy.example"
    assert dialled["upstream_proxy_host"] == "203.0.113.9"
    assert dialled["physical_interface"] == 7


@pytest.mark.asyncio
async def test_literal_proxy_ip_needs_no_pin(monkeypatch):
    _RecordingSession.dialled = []
    monkeypatch.setattr(
        "perchvpn.controller.H2ProxySession", _RecordingSession, raising=True
    )
    controller = _controller(
        upstream_proxy=UpstreamProxyConfig(host="203.0.113.9", port=1080),
        require_pinned_upstream=True,
    )

    await controller._connect_candidate(controller.current_candidate)

    dialled = _RecordingSession.dialled[0]
    assert dialled["upstream_proxy_host"] is None


@pytest.mark.asyncio
async def test_pinning_requirement_is_off_without_the_tunnel(monkeypatch):
    _RecordingSession.dialled = []
    monkeypatch.setattr(
        "perchvpn.controller.H2ProxySession", _RecordingSession, raising=True
    )
    controller = _controller(
        upstream_proxy=UpstreamProxyConfig(host="proxy.example", port=1080),
        require_pinned_upstream=False,
    )

    await controller._connect_candidate(controller.current_candidate)

    assert _RecordingSession.dialled[0]["upstream_proxy_host"] is None
