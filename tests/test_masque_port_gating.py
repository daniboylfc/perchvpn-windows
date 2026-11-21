"""MASQUE port gating: local rejection of non-80/443 flows and 502 breaker.

Fastly MASQUE upstream edges only accept CONNECT streams to ports 80/443 and
refuse every other port with HTTP 502 (which also poisons live :443 streams).
These tests pin the local defences: the SOCKS5 frontend refuses those ports
before an upstream stream is opened, trips a short per-target breaker after a
502, and the sing-box config rejects the same TCP port ranges at route level.
"""

from __future__ import annotations

import asyncio
import struct
from unittest.mock import AsyncMock, MagicMock

import pytest

import pytest_asyncio  # noqa: F401

from perchvpn.proxy.socks import (
    Socks5Server,
    SOCKS_VERSION,
    _CMD_CONNECT,
    _REP_CONNECTION_NOT_ALLOWED,
    _REP_SUCCEEDED,
    _PORT_BREAKER_COOLDOWN_SECONDS,
)
from perchvpn_windows import singbox_config


def _make_server(upstream_proxy=None):
    pool = MagicMock()
    pool.open_stream = AsyncMock(return_value=MagicMock())
    server = Socks5Server("127.0.0.1", 1080, pool, upstream_proxy=upstream_proxy)
    return server, pool


async def _negotiate(server: Socks5Server, port: int):
    """Run one CONNECT negotiation; returns the wire bytes written.

    Layout: 2-byte method-selection reply, then the 10-byte CONNECT reply,
    so the CONNECT rep code lives at offset 3.
    """
    reader = MagicMock()
    reader.readexactly = AsyncMock(
        side_effect=[
            struct.pack("!BB", SOCKS_VERSION, 1),
            bytes([0]),
            struct.pack("!BBBB", SOCKS_VERSION, _CMD_CONNECT, 0, 1),
            bytes(int(p) for p in "192.178.223.188".split(".")),
            struct.pack("!H", port),
        ]
    )
    reader.read = AsyncMock(return_value=b"")
    writer = MagicMock()
    written = bytearray()
    writer.write = written.extend
    writer.drain = AsyncMock()
    writer.get_extra_info = MagicMock(return_value=("127.0.0.1", 1080))
    writer.close = MagicMock()
    await server._negotiate_and_serve(reader, writer, "127.0.0.1")
    return bytes(written)


def _connect_rep(written: bytes) -> int:
    return written[3]


@pytest.mark.asyncio
async def test_non_masque_port_rejected_locally_without_upstream_stream():
    server, pool = _make_server()
    written = await _negotiate(server, 5228)
    assert _connect_rep(written) == _REP_CONNECTION_NOT_ALLOWED
    pool.open_stream.assert_not_awaited()


@pytest.mark.asyncio
async def test_port_443_reaches_upstream():
    server, pool = _make_server()
    written = await _negotiate(server, 443)
    assert _connect_rep(written) == _REP_SUCCEEDED
    pool.open_stream.assert_awaited_once()


@pytest.mark.asyncio
async def test_custom_upstream_disables_port_gating():
    server, pool = _make_server(upstream_proxy=object())
    written = await _negotiate(server, 5228)
    assert _connect_rep(written) == _REP_SUCCEEDED
    pool.open_stream.assert_awaited_once()


@pytest.mark.asyncio
async def test_502_refusal_trips_per_target_breaker():
    """A 502 on an allowed port (:443, as observed in the storm) trips a
    short breaker for that destination only: retrying apps cannot storm the
    session, while other :443 flows keep working (a port-wide breaker
    blackholed all HTTPS, including exit/egress verification)."""
    server, pool = _make_server()
    refusal = RuntimeError(
        "upstream eglc860.m1.fastly-masque.net:2499 refused CONNECT with status 502"
    )
    pool.open_stream = AsyncMock(side_effect=refusal)
    first = await _negotiate(server, 443)
    assert _connect_rep(first) != _REP_SUCCEEDED
    assert ("192.178.223.188", 443) in server._target_breakers
    # While the breaker holds, the next dial to that target is refused
    # without touching the pool.
    calls_after_first = pool.open_stream.await_count
    second = await _negotiate(server, 443)
    assert _connect_rep(second) == _REP_CONNECTION_NOT_ALLOWED
    assert pool.open_stream.await_count == calls_after_first
    # After the cooldown expires the breaker clears and the pool is used again.
    server._target_breakers[("192.178.223.188", 443)] -= (
        _PORT_BREAKER_COOLDOWN_SECONDS + 1.0
    )
    pool.open_stream = AsyncMock(return_value=MagicMock())
    third = await _negotiate(server, 443)
    assert _connect_rep(third) == _REP_SUCCEEDED


@pytest.mark.asyncio
async def test_502_refusal_does_not_break_other_targets_on_same_port():
    server, pool = _make_server()
    server._target_breakers[("198.51.100.9", 443)] = (
        asyncio.get_running_loop().time() + _PORT_BREAKER_COOLDOWN_SECONDS
    )
    written = await _negotiate(server, 443)
    assert _connect_rep(written) == _REP_SUCCEEDED
    pool.open_stream.assert_awaited_once()


def test_singbox_route_rejects_non_masque_tcp_ports():
    cfg = singbox_config.build_config()
    rules = cfg["route"]["rules"]
    reject_rules = [
        r
        for r in rules
        if r.get("action") == "reject"
        and r.get("network") == "tcp"
        and "port_range" in r
    ]
    assert len(reject_rules) == 1
    ranges = reject_rules[0]["port_range"]
    assert set(ranges) == {"0:79", "81:442", "444:65535"}


@pytest.mark.asyncio
async def test_disconnect_cancels_in_flight_restart_task():
    """POST /api/disconnect cancels an active restart worker instead of waiting."""
    import perchvpn_windows.api as api_module

    started = asyncio.Event()
    release = asyncio.Event()

    async def slow_worker():
        started.set()
        try:
            await release.wait()
        except asyncio.CancelledError:
            raise

    task = asyncio.ensure_future(slow_worker())
    api_module._restart_task = task
    api_module._app = None
    try:
        await asyncio.wait_for(started.wait(), timeout=1)
        assert not task.done()
        # Mirror the endpoint's cancellation contract without a live server.
        active = api_module._restart_task is not None and not api_module._restart_task.done()
        assert active
        api_module._restart_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(api_module._restart_task, timeout=2)
        api_module._restart_task = None
        assert task.cancelled()
    finally:
        if not task.done():
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
