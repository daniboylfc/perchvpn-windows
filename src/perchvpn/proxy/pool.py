"""A small pool of upstream proxy sessions (HTTP/2 or HTTP/3).

When more than one upstream connection is configured, SOCKS5 clients are
assigned to a session using a stable hash of an affinity key (typically the
client's source IP), so repeated connections from the same client route
through the same upstream session/IP.
"""

from __future__ import annotations

import asyncio
import itertools
import logging
import time
from collections import deque
from typing import Awaitable, Callable, List, Optional, Union

from ..exceptions import ProxyError
from .h3_session import H3ProxySession, H3Stream
from .http1_session import H1ProxySession, H1Stream, SessionAtCapacity
from .session import H2ProxySession, H2Stream

logger = logging.getLogger("perchvpn.proxy.pool")

# Both session classes expose the same duck-typed interface (connect,
# update_token, open_stream, close, is_closed, active_streams); which one a
# given pool uses is decided by ProxyController based on transport_version.
ProxySession = Union[H2ProxySession, H3ProxySession, H1ProxySession]
ProxyStream = Union[H2Stream, H3Stream, H1Stream]
SessionFactory = Callable[[], Awaitable[ProxySession]]
CloseStormCallback = Callable[[], Awaitable[None]]

# A burst of short-lived client flows (DNS, telemetry) makes every finished
# HTTP/1.1 CONNECT tear its dedicated session down; without a dial gate the
# resulting replacement/growth dials storm the edge with parallel TLS
# handshakes (observed live: 30+ sessions inside ~90 s).  Replacement and
# growth dials therefore share one gate with a minimum spacing.
_MIN_DIAL_INTERVAL_SECONDS = 0.25

# Upstream closing/replacing this many sessions within the window is an
# edge-side churn signature (or stream-EOF churn), not ordinary load; the
# controller uses it to trigger a clean HTTP/2 fallback.
_CLOSE_STORM_THRESHOLD = 4
_CLOSE_STORM_WINDOW_SECONDS = 10.0
_STORM_RENOTIFY_SECONDS = 60.0


class SessionPool:
    def __init__(
        self,
        size: int,
        factory: SessionFactory,
        metrics: Optional["TrafficMetrics"] = None,
        max_streams_per_session: Optional[int] = None,
        total_stream_target: Optional[int] = None,
        on_close_storm: Optional[CloseStormCallback] = None,
        clock: Optional[Callable[[], float]] = None,
    ):
        self.size = max(1, size)
        self._factory = factory
        self._sessions: List[ProxySession] = []
        self._rr = itertools.count()
        self._lock = asyncio.Lock()
        # Reserve a growth slot before dialing.  Without this, concurrent
        # capacity misses all observe the same len(_sessions) and each append
        # one session, overshooting max_sessions (observed: bound=32, 34
        # sessions on the bare-metal reconnect test).
        self._growing = 0
        self._metrics = metrics
        # Dial gate: replacement and growth dials share one slot with a
        # minimum spacing so a burst of short-lived flows (each finished
        # HTTP/1.1 CONNECT tears its dedicated session down) cannot storm
        # the edge with parallel TLS handshakes.
        self._dial_gate = asyncio.Lock()
        self._last_dial_at: Optional[float] = None
        self._min_dial_interval = _MIN_DIAL_INTERVAL_SECONDS
        # Session-close churn tracking (drives the HTTP/2 fallback signal).
        self._close_events: deque = deque(maxlen=64)
        self._close_storm_threshold = _CLOSE_STORM_THRESHOLD
        self._close_storm_window = _CLOSE_STORM_WINDOW_SECONDS
        self._storm_notified_at: Optional[float] = None
        self._on_close_storm = on_close_storm
        self._clock = clock or time.monotonic
        # Multiplex-concurrency mapping: each session carries at most
        # ``max_streams_per_session`` tunnels; the pool grows on demand up
        # to the session count that can carry ``total_stream_target``
        # concurrent tunnels (defaults to the controller's max_conns).
        self._cap = max_streams_per_session if (max_streams_per_session or 0) > 0 else None
        target = total_stream_target if (total_stream_target and total_stream_target > 0) else 256
        if self._cap:
            self.max_sessions = max(self.size, -(-target // self._cap))
        else:
            self.max_sessions = self.size

    async def _dial_through_gate(self) -> ProxySession:
        """One replacement/growth dial at a time, minimum spacing apart."""
        async with self._dial_gate:
            if self._last_dial_at is not None:
                wait = self._last_dial_at + self._min_dial_interval - self._clock()
                if wait > 0:
                    await asyncio.sleep(wait)
            self._last_dial_at = self._clock()
            return await self._factory()

    def _record_close_event(self) -> None:
        """Record an observed session close; notify the controller once the
        close rate looks like an edge churn signature, not ordinary load."""
        now = self._clock()
        self._close_events.append(now)
        if self._on_close_storm is None:
            return
        if not self.close_storm_active:
            return
        last = self._storm_notified_at
        if last is not None and (now - last) < _STORM_RENOTIFY_SECONDS:
            return
        self._storm_notified_at = now
        asyncio.ensure_future(self._notify_close_storm())

    async def _notify_close_storm(self) -> None:
        callback = self._on_close_storm
        if callback is None:
            return
        try:
            await callback()
        except Exception:  # noqa: BLE001 - the storm signal must never break serving
            logger.exception("close-storm callback failed")

    @property
    def close_storm_active(self) -> bool:
        """True when sessions have been closing faster than normal load."""
        if not self._close_events:
            return False
        now = self._clock()
        recent = [t for t in self._close_events if (now - t) <= self._close_storm_window]
        return len(recent) >= self._close_storm_threshold

    async def start(self) -> None:
        tasks = [asyncio.ensure_future(self._factory()) for _ in range(self.size)]
        try:
            results = await asyncio.gather(*tasks, return_exceptions=True)
        except asyncio.CancelledError:
            for task in tasks:
                if not task.done():
                    task.cancel()
            results = await asyncio.gather(*tasks, return_exceptions=True)
            await self._close_sessions([r for r in results if not isinstance(r, BaseException)])
            raise
        errors = [r for r in results if isinstance(r, BaseException)]
        sessions = [r for r in results if not isinstance(r, BaseException)]
        if errors:
            # Partial failure: close whatever connected so sibling sessions and
            # their reader/keepalive tasks are never leaked.
            await self._close_sessions(sessions)
            raise errors[0]
        self._sessions = sessions

    @staticmethod
    async def _close_sessions(sessions: List[ProxySession]) -> None:
        if sessions:
            await asyncio.gather(*(s.close() for s in sessions), return_exceptions=True)

    def update_token(self, token: str) -> None:
        for session in self._sessions:
            session.update_token(token)

    async def _session_for(self, affinity_key: Optional[str]) -> ProxySession:
        async with self._lock:
            if affinity_key is not None:
                index = hash(affinity_key) % len(self._sessions)
            else:
                index = next(self._rr) % len(self._sessions)
            session = self._sessions[index]
            if session.is_closed:
                logger.warning("upstream session %d closed, reconnecting", index)
                self._record_close_event()
                session = await self._dial_through_gate()
                self._sessions[index] = session
            return session

    async def open_stream(
        self, target_host: str, target_port: int, affinity_key: Optional[str] = None
    ) -> ProxyStream:
        # A client request can race a session teardown: ``_session_for`` may
        # replace a closed session, but that fresh dial can itself fail once.
        # Retry a single time only when the failure is a dead/missing session;
        # a live session refusing a specific CONNECT (for example 502) is not
        # retried, because that would just duplicate the same upstream refusal.
        for attempt in range(2):
            session: Optional[ProxySession] = None
            try:
                session = await self._session_for(affinity_key)
                return await session.open_stream(
                    target_host, target_port, self._metrics
                )
            except SessionAtCapacity:
                # The selected session is at its multiplex cap. Grow the pool
                # with a fresh session (bounded by max_sessions) and retry on
                # it; when the growth bound is reached, pick the least-loaded
                # live session instead.
                grown = await self._maybe_grow()
                if attempt == 0 and grown:
                    continue
                session = await self._least_loaded_session()
                try:
                    return await session.open_stream(
                        target_host, target_port, self._metrics
                    )
                except SessionAtCapacity as exc:
                    raise ProxyError(str(exc)) from exc
                except Exception:
                    if session is not None and getattr(
                        session, "is_closed", False
                    ):
                        self._record_close_event()
                    raise
            except Exception as exc:
                # A session that died mid-use is churn evidence regardless of
                # which attempt surfaced it (the post-growth retry at
                # attempt==1 sees most edge closes on busy h1 pools).
                if session is not None and getattr(session, "is_closed", False):
                    self._record_close_event()
                if attempt == 1 or (session is not None and not session.is_closed):
                    raise
                logger.warning(
                    "upstream session unavailable for %s:%s; retrying with a "
                    "fresh session: %s",
                    target_host,
                    target_port,
                    exc,
                )
        raise RuntimeError("unreachable")

    async def _reserve_growth_slot(self) -> bool:
        """Reserve one session slot without holding the lock during dialing."""
        async with self._lock:
            if len(self._sessions) + self._growing >= self.max_sessions:
                return False
            self._growing += 1
            return True

    def _release_growth_slot(self) -> None:
        if self._growing > 0:
            self._growing -= 1

    async def _maybe_grow(self) -> bool:
        """Dial one extra session if the growth bound allows it.

        A failed growth dial is swallowed (the caller falls back to the
        least-loaded live session) so a broken factory never escalates a
        capacity miss into a hard failure beyond the original dial error.
        """
        if not await self._reserve_growth_slot():
            return False
        try:
            try:
                session = await self._dial_through_gate()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                logger.warning("pool growth dial failed: %s", exc)
                return False
            if session is None or getattr(session, "is_closed", False):
                if session is not None:
                    # Born dead: the edge killed the dial immediately.  Record
                    # the close so the churn detector sees the signature.
                    self._record_close_event()
                    try:
                        await session.close()
                    except Exception:  # noqa: BLE001
                        pass
                return False
            self._sessions.append(session)
            logger.info(
                "multiplex cap reached; pool scaled out to %d sessions "
                "(cap=%s/session, bound=%d)",
                len(self._sessions),
                self._cap,
                self.max_sessions,
            )
            return True
        finally:
            self._release_growth_slot()

    async def _least_loaded_session(self) -> ProxySession:
        live = [s for s in self._sessions if not s.is_closed]
        if not live:
            session = await self._dial_through_gate()
            async with self._lock:
                closed = next(
                    (i for i, s in enumerate(self._sessions) if s.is_closed),
                    None,
                )
                if closed is not None:
                    self._sessions[closed] = session
                elif (
                    len(self._sessions) + self._growing
                    < self.max_sessions
                ):
                    self._sessions.append(session)
                else:
                    # Bound reached and every slot is occupied: never append
                    # past max_sessions.  The caller retries or surfaces the
                    # capacity error.
                    try:
                        await session.close()
                    except Exception:  # noqa: BLE001
                        pass
                    raise ProxyError("no upstream session available")
            return session
        return min(live, key=lambda s: getattr(s, "active_streams", 0))

    async def close(self) -> None:
        await asyncio.gather(*(s.close() for s in self._sessions), return_exceptions=True)
