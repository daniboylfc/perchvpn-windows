"""Focused tests for bounded upstream candidate failover (P1-2).

Wholly offline: candidates are synthesised, sessions are fakes, and no real
sockets or state files are used outside ``tmp_path``.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import perchvpn.controller as controller_module
from perchvpn.controller import (
    INITIAL_DIAL_MAX_ATTEMPTS,
    ControllerConfig,
    ProxyController,
)
from perchvpn.exceptions import ProxyError
from perchvpn.proxy.pool import SessionPool
from perchvpn.proxystate import (
    ProxyCandidate,
    ProxyStateStore,
    alternate_candidates,
    resolve_proxy,
)
from perchvpn.serverlist import City, Country, Protocol, Server


def _server(hostname: str, port: int = 443) -> Server:
    return Server(hostname=hostname, port=port, protocols=[Protocol(name="connect", host=hostname, port=port)])


def _countries() -> list[Country]:
    servers = [_server("a"), _server("b"), _server("c"), _server("d")]
    return [Country(name="United Kingdom", code="GB", cities=[City(name="London", code="LON", servers=servers)])]


def _candidate(host: str) -> ProxyCandidate:
    return ProxyCandidate(host=host, port=443, country_code="GB", country_name="United Kingdom")


class FakeSession:
    def __init__(self, name: str = "s", is_closed: bool = False) -> None:
        self.name = name
        self.is_closed = is_closed
        self.close_calls = 0

    async def connect(self, timeout: float | None = None) -> None:
        return None

    async def close(self) -> None:
        self.close_calls += 1

    def update_token(self, token: str) -> None:
        return None

    async def open_stream(self, host: str, port: int, metrics=None):
        return SimpleNamespace(session=self.name, host=host, port=port)


def _fake_pass() -> SimpleNamespace:
    return SimpleNamespace(
        raw_token="tok",
        expires_at=lambda: datetime.now(timezone.utc) + timedelta(hours=1),
    )


def _controller(candidates: list[ProxyCandidate], *, upstream_conns: int = 1) -> ProxyController:
    config = ControllerConfig(
        guardian_endpoint="https://guardian.example",
        candidate=candidates[0],
        upstream_conns=upstream_conns,
        handshake_timeout=0.01,
        alternates=candidates[1:],
    )
    return ProxyController(config, MagicMock())


class TestSessionPoolStart:
    @pytest.mark.asyncio
    async def test_partial_failure_closes_the_successes(self):
        good = FakeSession("good")
        calls = {"n": 0}

        async def factory():
            index = calls["n"]
            calls["n"] += 1
            if index == 0:
                return good
            raise ProxyError("refused")

        pool = SessionPool(2, factory, None)
        with pytest.raises(ProxyError):
            await pool.start()
        assert good.close_calls == 1
        assert pool._sessions == []

    @pytest.mark.asyncio
    async def test_cancellation_closes_created_sessions(self):
        good = FakeSession("good")
        blocked = asyncio.Event()
        calls = {"n": 0}

        async def factory():
            index = calls["n"]
            calls["n"] += 1
            if index == 0:
                return good
            blocked.set()
            await asyncio.Event().wait()

        pool = SessionPool(2, factory, None)
        task = asyncio.create_task(pool.start())
        await asyncio.wait_for(blocked.wait(), timeout=1.0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert good.close_calls == 1
        assert pool._sessions == []


class TestAlternateCandidates:
    def test_same_country_alternates_exclude_primary(self):
        countries = _countries()
        alts = alternate_candidates(countries, _candidate("a"))
        assert [c.host for c in alts] == ["b", "c", "d"]

    def test_limit_applied(self):
        countries = _countries()
        alts = alternate_candidates(countries, _candidate("a"), limit=2)
        assert [c.host for c in alts] == ["b", "c"]

    def test_explicit_proxy_has_no_alternates(self):
        countries = _countries()
        explicit = ProxyCandidate(host="x", port=8443, country_code="", country_name="")
        assert alternate_candidates(countries, explicit) == []


class TestControllerFailover:
    def _install(
        self,
        monkeypatch,
        *,
        connect,
    ) -> ProxyController:
        async def fake_initial(self):
            self.proxy_pass = _fake_pass()

        monkeypatch.setattr(ProxyController, "_acquire_initial_pass", fake_initial)
        monkeypatch.setattr(ProxyController, "_connect_candidate", connect)
        monkeypatch.setattr(controller_module, "_initial_dial_backoff", lambda attempt: 0.0)

    @pytest.mark.asyncio
    async def test_initial_failover_selects_alternate(self, monkeypatch):
        attempts: list[str] = []

        async def connect(self, candidate):
            attempts.append(candidate.host)
            if candidate.host == "a":
                raise ProxyError("dead")
            return FakeSession(candidate.host)

        self._install(monkeypatch, connect=connect)
        controller = _controller([_candidate("a"), _candidate("b")])
        pool = await controller.start()
        try:
            assert attempts == ["a", "b"]
            assert controller.current_candidate.host == "b"
            assert [s.name for s in pool._sessions] == ["b"]
        finally:
            await controller.stop()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("upstream_conns", [2, 4])
    async def test_initial_failover_with_concurrent_pool(self, monkeypatch, upstream_conns):
        """A pool dials all N slots at once, each starting on the dead primary.

        Regression: rotating the candidate once per failed slot moved the index
        by N and, for even N, landed back on the dead primary every round, so a
        live alternate was never reached (start() failed after all attempts).
        """
        attempts: list[str] = []

        async def connect(self, candidate):
            attempts.append(candidate.host)
            # Yield so every slot reads current_candidate before any dial
            # completes, mirroring a real connect() that awaits the network.
            await asyncio.sleep(0)
            if candidate.host == "a":
                raise ProxyError("dead")
            return FakeSession(candidate.host)

        self._install(monkeypatch, connect=connect)
        controller = _controller(
            [_candidate("a"), _candidate("b")], upstream_conns=upstream_conns
        )
        pool = await controller.start()
        try:
            assert attempts == ["a"] * upstream_conns + ["b"] * upstream_conns
            assert controller.current_candidate.host == "b"
            assert [s.name for s in pool._sessions] == ["b"] * upstream_conns
        finally:
            await controller.stop()

    @pytest.mark.asyncio
    async def test_initial_failover_is_bounded(self, monkeypatch):
        attempts: list[str] = []

        async def connect(self, candidate):
            attempts.append(candidate.host)
            raise ProxyError("dead")

        self._install(monkeypatch, connect=connect)
        controller = _controller([_candidate("a"), _candidate("b")])
        with pytest.raises(ProxyError):
            await controller.start()
        assert len(attempts) == INITIAL_DIAL_MAX_ATTEMPTS
        assert attempts == ["a", "b", "a", "b"]

    @pytest.mark.asyncio
    async def test_runtime_reconnect_rotates_candidate(self, monkeypatch):
        connects: list[str] = []
        state = {"n": 0}

        async def connect(self, candidate):
            state["n"] += 1
            connects.append(candidate.host)
            if state["n"] == 1:
                raise ProxyError("dead")
            return FakeSession(candidate.host)

        self._install(monkeypatch, connect=connect)
        controller = _controller([_candidate("a"), _candidate("b")])
        controller.proxy_pass = _fake_pass()
        controller.pool = SessionPool(1, controller._session_factory, None)
        controller.pool._sessions = [FakeSession("a", is_closed=True)]

        stream = await controller.pool.open_stream("example.test", 80)
        assert connects == ["a", "b"]
        assert stream.session == "b"
        assert controller.pool._sessions[0].name == "b"
        assert controller.current_candidate.host == "b"

    @pytest.mark.asyncio
    async def test_live_session_refusal_is_not_retried(self):
        session = FakeSession("a")
        calls = {"n": 0}

        async def refuse(host: str, port: int, metrics=None):
            calls["n"] += 1
            raise ProxyError("refused CONNECT with status 502")

        session.open_stream = refuse
        pool = SessionPool(1, lambda: session, None)
        pool._sessions = [session]

        with pytest.raises(ProxyError, match="status 502"):
            await pool.open_stream("example.test", 80)
        assert calls["n"] == 1


class TestSavedPrimaryPreserved:
    def test_alternates_never_replace_persisted_primary(self, tmp_path):
        countries = _countries()
        store = ProxyStateStore(str(tmp_path / "state.json"))
        primary, _ = resolve_proxy(countries, country_code="GB", state_store=store)

        alts = alternate_candidates(countries, primary)
        assert primary.host not in [c.host for c in alts]

        controller = _controller([primary, *alts])
        # The controller holds no state store, so failover cannot rewrite the
        # persisted selection; it only reports current_candidate.
        assert not hasattr(controller, "state_store")
        assert store.load().host == primary.host
        assert controller.current_candidate.host == primary.host
