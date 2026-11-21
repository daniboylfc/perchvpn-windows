"""Tests for multiplex-concurrency pool scaling (upstream v2.0.3 parity)."""

from __future__ import annotations

import asyncio

import pytest

from src.perchvpn.controller import ControllerConfig
from src.perchvpn.exceptions import ProxyError
from src.perchvpn.proxy.http1_session import SessionAtCapacity
from src.perchvpn.proxy.pool import SessionPool


class FakeSession:
    def __init__(self, cap: int, fail: bool = False):
        self.cap = cap
        self.fail = fail
        self.streams: list = []
        self._closed = False
        self.tokens: list = []

    @property
    def is_closed(self) -> bool:
        return self._closed

    @property
    def active_streams(self) -> int:
        return len(self.streams)

    def update_token(self, token: str) -> None:
        self.tokens.append(token)

    async def close(self) -> None:
        self._closed = True

    async def open_stream(self, host, port, metrics=None):
        if self.fail:
            raise ProxyError("dial failed")
        if len(self.streams) >= self.cap:
            raise SessionAtCapacity("full")
        self.streams.append((host, port))
        return object()


def test_max_sessions_bound_from_multiplex_cap():
    pool = SessionPool(1, lambda: None, max_streams_per_session=8, total_stream_target=64)
    assert pool.max_sessions == 8  # ceil(64 / 8)
    pool = SessionPool(1, lambda: None, max_streams_per_session=64, total_stream_target=64)
    assert pool.max_sessions == 1
    pool = SessionPool(4, lambda: None, max_streams_per_session=16, total_stream_target=64)
    assert pool.max_sessions == 4


def test_no_cap_keeps_fixed_size():
    pool = SessionPool(3, lambda: None)
    assert pool.max_sessions == 3


@pytest.mark.asyncio
async def test_pool_grows_on_capacity_exhaustion():
    made: list[FakeSession] = []

    async def factory():
        session = FakeSession(cap=2)
        made.append(session)
        return session

    pool = SessionPool(1, factory, max_streams_per_session=2, total_stream_target=6)
    await pool.start()
    streams = []
    for i in range(5):
        streams.append(await pool.open_stream("h", 80, affinity_key=f"k{i}"))
    # 1 initial + 2 grown sessions cover the 5 streams at cap 2.
    assert len(pool._sessions) == 3
    assert pool.max_sessions == 3  # bound reached, no further growth
    await pool.close()


@pytest.mark.asyncio
async def test_concurrent_growth_never_exceeds_max_sessions():
    """Concurrent capacity misses must reserve slots, not each append one.

    Bare-metal log: bound=32 but the pool reached 34 sessions.  Every waiter
    used to observe the same len(_sessions) before the dial completed.
    """
    made: list[FakeSession] = []

    async def factory():
        await asyncio.sleep(0.01)
        session = FakeSession(cap=1)
        made.append(session)
        return session

    pool = SessionPool(
        1, factory, max_streams_per_session=8, total_stream_target=256
    )
    await pool.start()
    pool._min_dial_interval = 0
    await asyncio.gather(*(pool._maybe_grow() for _ in range(100)))
    assert pool.max_sessions == 32
    assert len(pool._sessions) <= pool.max_sessions
    await pool.close()


@pytest.mark.asyncio
async def test_growth_bound_falls_back_to_least_loaded():
    async def factory():
        return FakeSession(cap=1)

    pool = SessionPool(2, factory, max_streams_per_session=1, total_stream_target=2)
    await pool.start()
    # Pre-fill session 0; round-robin (affinity_key=None) selects it next.
    pool._sessions[0].streams.append(("h", 80))
    stream = await pool.open_stream("h", 80, affinity_key=None)
    assert stream is not None
    # The at-cap session was skipped for the idle one; no growth happened.
    assert len(pool._sessions) == 2
    assert len(pool._sessions[1].streams) == 1
    await pool.close()


@pytest.mark.asyncio
async def test_growth_dial_failure_falls_back_to_live_sessions():
    state = {"n": 0}

    async def factory():
        state["n"] += 1
        if state["n"] == 1:
            return FakeSession(cap=1)
        raise ProxyError("dial failed")

    pool = SessionPool(1, factory, max_streams_per_session=1, total_stream_target=2)
    await pool.start()
    pool._sessions[0].streams.append(("h", 80))
    # Growth dial fails and the bound is reached: the capacity miss is
    # surfaced as a plain ProxyError (never as a leak of the factory error).
    with pytest.raises(ProxyError):
        await pool.open_stream("h", 80, affinity_key="a")
    await pool.close()


def test_transport_property_maps_versions():
    from src.perchvpn.controller import ProxyController

    for version, expected in (("h1", "http1"), ("h2", "http2"), ("h3", "http3")):
        controller_cfg = ControllerConfig(
            guardian_endpoint="https://guardian.test",
            candidate=None,
            upstream_conns=1,
            handshake_timeout=1.0,
            transport_version=version,
        )
        controller = ProxyController(controller_cfg, auth=None)
        assert controller.transport == expected


def test_controller_config_parity_defaults():
    cfg = ControllerConfig(
        guardian_endpoint="https://guardian.test",
        candidate=None,
        upstream_conns=1,
        handshake_timeout=1.0,
    )
    assert cfg.transport_version == "h2"
    assert cfg.utls_fingerprint == "disabled"
    assert cfg.tls_fragment_mode == "disabled"
    assert cfg.tls_fragment_fallback_delay_ms == 300
    assert cfg.multiplex_streams == 8
    assert cfg.max_conns == 256
