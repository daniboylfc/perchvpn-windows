"""F1/F2: bounded H1 dial churn and clean HTTP/2 fallback.

F1: replacement and growth dials share a rate-limited gate so a burst of
short-lived flows (each finished HTTP/1.1 CONNECT tears its dedicated
session down) cannot storm the edge with parallel TLS handshakes, and a
close-storm signal detects edge-side churn.

F2: the controller falls back cleanly to HTTP/2 on the close-storm signal
or on HTTP/3 QUIC handshake timeouts, unless the transport is pinned.
"""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.perchvpn import controller as controller_module
from src.perchvpn.controller import ControllerConfig, ProxyController, _is_quic_timeout
from src.perchvpn.exceptions import ProxyError
from src.perchvpn.proxy.http1_session import SessionAtCapacity
from src.perchvpn.proxy.pool import SessionPool
from src.perchvpn.proxystate import ProxyCandidate


class _Session:
    def __init__(self):
        self._closed = False

    @property
    def is_closed(self) -> bool:
        return self._closed

    async def close(self) -> None:
        self._closed = True


class _DyingSession(_Session):
    """Mimics the h1 behavior after an edge close: the session marks itself
    dead, then open_stream raises the transport-death error."""

    def __init__(self):
        super().__init__()
        self.open_calls = 0

    def die(self):
        self._closed = True

    async def open_stream(self, host, port, metrics=None):
        self.open_calls += 1
        self._closed = True  # _mark_connection_lost
        raise ProxyError(
            "upstream e:2499 connection closed before CONNECT response"
        )


class _HealthySession(_Session):
    def __init__(self):
        super().__init__()
        self.open_calls = 0

    async def open_stream(self, host, port, metrics=None):
        self.open_calls += 1
        return object()


class _AtCapSession(_Session):
    """Session at its multiplex cap: raises SessionAtCapacity forever."""

    def __init__(self):
        super().__init__()
        self.open_calls = 0

    async def open_stream(self, host, port, metrics=None):
        self.open_calls += 1
        raise SessionAtCapacity("at cap")


# ---------------------------------------------------------------------------
# F1: dial gate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_replacement_dials_are_rate_limited():
    made = []

    async def factory():
        made.append(time.monotonic())
        return _Session()

    pool = SessionPool(2, factory)
    await pool.start()
    made.clear()
    pool._min_dial_interval = 0.1

    # Close every session, then demand streams repeatedly: each demand
    # replaces a closed session through the gate.
    for session in pool._sessions:
        session._closed = True
    for index in range(3):
        await pool._session_for(None)
        pool._sessions[index % len(pool._sessions)]._closed = True

    assert len(made) == 3
    for first, second in zip(made, made[1:]):
        assert second - first >= 0.09
    await pool.close()


@pytest.mark.asyncio
async def test_growth_dials_share_the_gate():
    made = []

    async def factory():
        made.append(time.monotonic())
        return _Session()

    pool = SessionPool(1, factory, max_streams_per_session=2, total_stream_target=4)
    await pool.start()
    made.clear()
    pool._min_dial_interval = 0.1

    assert await pool._maybe_grow() is True
    assert len(made) == 1
    assert made[0] - 0 >= 0  # gate passes the first dial straight through
    await pool.close()


# ---------------------------------------------------------------------------
# F1: dead sessions feed the storm detector (live-prod finding: the edge
# closes h1 sessions whose deaths never reached _session_for; the pool
# grew silently to 40+ sessions with no storm signal)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dead_session_open_stream_records_close_and_retries():
    clock = _FakeClock()
    dying = _DyingSession()
    queue = [dying]
    fresh = []

    async def factory():
        if queue:
            return queue.pop(0)
        session = _HealthySession()
        fresh.append(session)
        return session

    pool = SessionPool(1, factory, clock=clock)
    await pool.start()

    stream = await pool.open_stream("dns.example", 443)

    assert stream is not None
    assert dying.open_calls == 1
    assert len(fresh) == 1 and fresh[0].open_calls == 1  # served by fresh dial
    # Both the mid-use death and the replacement were recorded: two events
    # within the window means 4 such deaths trip the storm.
    assert len(pool._close_events) == 2
    await pool.close()


def _affinity_with_hash_mod(mod: int) -> str:
    # str hash is randomized per process, so probe for a key mapping to the
    # wanted session index.
    key = "x"
    while hash(key) % 2 != mod:
        key += "x"
    return key


@pytest.mark.asyncio
async def test_post_growth_retry_death_records_close_event():
    # Live h1_combined run2 signature: attempt 0 hits a capped session,
    # growth dials a fresh one, and the attempt-1 CONNECT on it dies mid
    # handshake. That death must be recorded even though the retry raises.
    clock = _FakeClock()
    capped = _AtCapSession()
    dying = _DyingSession()

    async def factory():
        return dying

    pool = SessionPool(1, factory, clock=clock)
    pool._sessions = [capped]
    pool.max_sessions = 2

    with pytest.raises(ProxyError):
        await pool.open_stream("dns.example", 443, affinity_key=_affinity_with_hash_mod(1))

    assert dying.open_calls == 1
    assert len(pool._close_events) == 1
    await pool.close()


@pytest.mark.asyncio
async def test_least_loaded_retry_death_records_close_event():
    # Same burst, alternate arm: after growth the affinity maps back to the
    # capped session, so selection falls to the least-loaded live session
    # whose CONNECT dies. That death must be recorded too.
    clock = _FakeClock()
    capped = _AtCapSession()
    capped.active_streams = 1
    dying = _DyingSession()

    async def factory():
        return dying

    pool = SessionPool(1, factory, clock=clock)
    pool._sessions = [capped]
    pool.max_sessions = 2

    with pytest.raises(ProxyError):
        await pool.open_stream("dns.example", 443, affinity_key=_affinity_with_hash_mod(0))

    assert dying.open_calls == 1
    assert len(pool._close_events) == 1
    await pool.close()


@pytest.mark.asyncio
async def test_four_edge_kills_trip_the_close_storm():
    clock = _FakeClock()
    storms = []

    async def on_storm():
        storms.append(clock.now)

    queue = [_DyingSession()]
    fresh = []

    async def factory():
        if queue:
            return queue.pop(0)
        session = _DyingSession()
        fresh.append(session)
        return session

    pool = SessionPool(1, factory, clock=clock, on_close_storm=on_storm)
    await pool.start()

    # Every open_stream is served by a session the edge kills mid-CONNECT;
    # the client call fails (all dials die), but every death is recorded and
    # after 4 deaths inside the window the storm must signal.
    for _ in range(5):
        with pytest.raises(ProxyError):
            await pool.open_stream("dns.example", 443)
    await asyncio.sleep(0)
    assert len(storms) == 1
    await pool.close()


@pytest.mark.asyncio
async def test_born_dead_growth_dial_records_close_event():
    clock = _FakeClock()

    async def factory():
        session = _Session()
        session._closed = True  # edge killed the dial instantly
        return session

    pool = SessionPool(1, factory, max_streams_per_session=2, total_stream_target=4, clock=clock)
    await pool.start()
    assert await pool._maybe_grow() is False
    assert len(pool._close_events) == 1
    await pool.close()


# ---------------------------------------------------------------------------
# F1: close-storm detection
# ---------------------------------------------------------------------------


class _FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


async def _factory_ok():
    return _Session()


@pytest.mark.asyncio
async def test_close_storm_fires_once_within_renotify_window():
    clock = _FakeClock()
    storms = []

    async def on_storm():
        storms.append(clock.now)

    pool = SessionPool(1, _factory_ok, clock=clock, on_close_storm=on_storm)
    await pool.start()
    assert len(pool._sessions) == 1

    # Four closes inside the 10 s window: one notification.
    for _ in range(4):
        pool._record_close_event()
    await asyncio.sleep(0)
    assert len(storms) == 1
    assert pool.close_storm_active is True

    # More churn inside the renotify window stays silent.
    clock.now += 5.0
    for _ in range(4):
        pool._record_close_event()
    await asyncio.sleep(0)
    assert len(storms) == 1

    # Past the renotify window the signal fires again.
    clock.now += 61.0
    for _ in range(4):
        pool._record_close_event()
    await asyncio.sleep(0)
    assert len(storms) == 2
    await pool.close()


@pytest.mark.asyncio
async def test_scattered_closes_do_not_signal_storm():
    clock = _FakeClock()
    storms = []

    async def on_storm():
        storms.append(clock.now)

    pool = SessionPool(1, _factory_ok, clock=clock, on_close_storm=on_storm)
    await pool.start()
    for _ in range(4):
        pool._record_close_event()
        clock.now += 11.0  # each close ages out of the window
    await asyncio.sleep(0)
    assert storms == []
    assert pool.close_storm_active is False
    assert len(pool._sessions) == 1  # no replacement/growth dial happened
    await pool.close()


@pytest.mark.asyncio
async def test_storm_callback_failure_does_not_break_serving():
    clock = _FakeClock()

    async def broken():
        raise RuntimeError("callback blew up")

    pool = SessionPool(1, _factory_ok, clock=clock, on_close_storm=broken)
    await pool.start()
    for _ in range(4):
        pool._record_close_event()
    await asyncio.sleep(0)  # notification task completes despite the failure
    await pool.close()


# ---------------------------------------------------------------------------
# F2: controller transport fallback
# ---------------------------------------------------------------------------


def _controller_config(**overrides) -> ControllerConfig:
    candidate = ProxyCandidate("203.0.113.7", 443, "us", "United States")
    defaults = dict(
        guardian_endpoint="https://guardian.example",
        candidate=candidate,
        upstream_conns=2,
        handshake_timeout=5.0,
    )
    defaults.update(overrides)
    return ControllerConfig(**defaults)


def _bare_controller(config) -> ProxyController:
    controller = object.__new__(ProxyController)
    controller.config = config
    controller.proxy_pass = None
    controller.auth = MagicMock(access_token_expired=MagicMock(return_value=False))
    controller.pool = None
    controller.accepting = False
    controller._reason = "starting"
    controller._tasks = []
    controller._stopped = asyncio.Event()
    controller._started_at = None
    controller._metrics = None
    controller._candidates = [config.candidate]
    controller._candidate_index = 0
    controller._auth_lock = asyncio.Lock()
    controller._effective_transport = config.transport_version
    controller._effective_use_http3 = config.use_http3
    controller._transport_fallback_in_progress = False
    controller.on_pool_replaced = None
    return controller


class _FakePool:
    def __init__(self, *, start_error: Exception | None = None):
        self.start = AsyncMock(side_effect=start_error)
        self.close = AsyncMock()
        self.update_token = MagicMock()


@pytest.mark.asyncio
async def test_close_storm_falls_back_to_http2_and_repoints_frontend():
    config = _controller_config(transport_version="h1")
    controller = _bare_controller(config)
    old_pool = _FakePool()
    controller.pool = old_pool
    replacement = _FakePool()
    repointed = []

    async def on_pool_replaced(pool):
        repointed.append(pool)

    controller.on_pool_replaced = on_pool_replaced
    with patch.object(controller_module, "SessionPool", lambda *a, **kw: replacement):
        await controller._handle_close_storm()

    assert controller._effective_transport == "h2"
    assert controller.pool is replacement
    assert repointed == [replacement]
    old_pool.close.assert_awaited_once()
    # The fallback pool was started before the old pool was torn down.
    assert replacement.start.await_count == 1


@pytest.mark.asyncio
async def test_pinned_transport_never_falls_back():
    config = _controller_config(transport_version="h1", transport_pinned=True)
    controller = _bare_controller(config)
    old_pool = _FakePool()
    controller.pool = old_pool

    with patch.object(controller_module, "SessionPool") as pool_cls:
        await controller._handle_close_storm()

    assert controller._effective_transport == "h1"
    assert controller.pool is old_pool
    pool_cls.assert_not_called()
    old_pool.close.assert_not_awaited()


@pytest.mark.asyncio
async def test_http2_pool_does_not_react_to_close_storms():
    config = _controller_config(transport_version="h2")
    controller = _bare_controller(config)
    old_pool = _FakePool()
    controller.pool = old_pool

    with patch.object(controller_module, "SessionPool") as pool_cls:
        await controller._handle_close_storm()

    assert controller._effective_transport == "h2"
    assert controller.pool is old_pool
    pool_cls.assert_not_called()


@pytest.mark.asyncio
async def test_fallback_failure_keeps_the_current_pool():
    config = _controller_config(transport_version="h1")
    controller = _bare_controller(config)
    old_pool = _FakePool()
    controller.pool = old_pool
    broken = _FakePool(start_error=ProxyError("edge refused the h2 dial"))

    with patch.object(controller_module, "SessionPool", lambda *a, **kw: broken):
        await controller._handle_close_storm()

    assert controller._effective_transport == "h1"
    assert controller.pool is old_pool
    broken.close.assert_not_awaited()
    old_pool.close.assert_not_awaited()


def test_quic_timeout_detection():
    quic_timeout = ProxyError(
        "upstream e.example:443 QUIC handshake failed for all 1 resolved "
        "address(es); last error: TimeoutError()"
    )
    assert _is_quic_timeout(quic_timeout) is True
    assert _is_quic_timeout(ProxyError("connect failed: refused")) is False
    assert _is_quic_timeout(ProxyError("QUIC handshake failed: cert error")) is False


@pytest.mark.asyncio
async def test_start_falls_back_to_http2_on_quic_timeout():
    config = _controller_config(transport_version="h3")
    controller = _bare_controller(config)
    quic_pool = _FakePool(
        start_error=ProxyError(
            "upstream e.example:443 QUIC handshake failed for all 1 resolved "
            "address(es); last error: TimeoutError()"
        )
    )
    h2_pool = _FakePool()
    repointed = []

    async def on_pool_replaced(pool):
        repointed.append(pool)

    controller.on_pool_replaced = on_pool_replaced

    class _Pass:
        @staticmethod
        def not_before():
            import datetime

            return datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)

        @staticmethod
        def expires_at():
            import datetime

            return datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)

    controller.proxy_pass = _Pass()

    pools = [quic_pool, h2_pool]

    def make_pool(*args, **kwargs):
        return pools.pop(0)

    with patch.object(controller_module, "SessionPool", make_pool):
        try:
            started = await controller.start(initial_pass=_Pass())
        finally:
            await controller.stop()

    assert started is h2_pool
    assert controller._effective_transport == "h2"
    assert repointed == [h2_pool]
    quic_pool.close.assert_awaited_once()
