"""Cached country-list loading (/api/countries, /api/country validation).

In the buggy build the endpoint called serverlist.fetch_server_list() with
no cache path: a live Remote Settings HTTPS fetch fired on every dashboard
or countries tab visit and on every country selection, making the lists
open slowly. Now a short-lived in-process snapshot is shared by both
endpoints, backed by the core client's configured disk cache.
"""

from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import src.perchvpn_windows.api as api_module
from src.perchvpn_windows.api import CountryResponse
from src.perchvpn_windows.config import WindowsConfig


@pytest.fixture(autouse=True)
def _reset_globals():
    api_module._serverlist_cache = {"countries": None, "at": 0.0}
    api_module._serverlist_refresh_inflight = False
    original_app = api_module._app
    original_config = api_module._config
    yield
    api_module._app = original_app
    api_module._config = original_config
    api_module._serverlist_cache = {"countries": None, "at": 0.0}
    api_module._serverlist_refresh_inflight = False


def _country(code: str) -> SimpleNamespace:
    return SimpleNamespace(
        code=code,
        name=f"Country {code}",
        cities=[SimpleNamespace(
            code=f"{code}x",
            name="City",
            servers=[SimpleNamespace(hostname=f"{code}edge.mpn", port=2499)],
        )],
    )


class TestAutoCountryFilter:
    def test_recommended_pseudo_country_is_not_a_listed_location(self, monkeypatch):
        """REC (\"automatically choose\") is resolved implicitly, not pickable.

        It has no flag, no cities of its own and produced a row with an empty
        data-code in the location list.
        """
        api_module._config = None
        monkeypatch.setattr(
            "perchvpn.serverlist.fetch_server_list",
            lambda path=None: [_country("REC"), _country("DE")],
        )
        result = asyncio.run(api_module.get_countries())
        assert [c.code for c in result] == ["DE"]


class TestCountriesCache:
    def test_countries_served_from_single_fetch(self, monkeypatch):
        # No config: the fetch runs without a disk cache path.
        api_module._config = None
        calls: list = []
        monkeypatch.setattr(
            "perchvpn.serverlist.fetch_server_list",
            lambda path=None: calls.append(path) or [_country("DE")],
        )

        first = asyncio.run(api_module.get_countries())
        second = asyncio.run(api_module.get_countries())

        assert len(calls) == 1  # one fetch, one snapshot
        assert first == second
        assert isinstance(first[0], CountryResponse)
        assert first[0].code == "DE"
        assert first[0].cities[0].hostname == "DEedge.mpn"
        assert first[0].cities[0].port == 2499

    def test_fetch_uses_configured_serverlist_cache_path(self, monkeypatch):
        config = WindowsConfig()
        api_module._config = config
        seen: list = []
        monkeypatch.setattr(
            "perchvpn.serverlist.fetch_server_list",
            lambda path=None: seen.append(path) or [_country("GB")],
        )

        asyncio.run(api_module.get_countries())
        assert seen == [config.serverlist_cache_path]

    def test_snapshot_expires_after_ttl(self, monkeypatch):
        api_module._config = None
        calls: list = []
        monkeypatch.setattr(
            "perchvpn.serverlist.fetch_server_list",
            lambda path=None: calls.append(path) or [_country("US")],
        )

        asyncio.run(api_module.get_countries())
        asyncio.run(api_module.get_countries())
        assert len(calls) == 1

        # Force expiry of the in-process snapshot.
        api_module._serverlist_cache = {"countries": None, "at": 0.0}
        asyncio.run(api_module.get_countries())
        assert len(calls) == 2

    def test_country_selection_reuses_snapshot(self, monkeypatch):
        """Validating a country via /api/country must not trigger a second
        live server-list fetch when the snapshot is fresh."""
        api_module._config = None
        calls: list = []

        def _fetch(path=None):
            calls.append(path)
            return [_country("GB")]

        monkeypatch.setattr("perchvpn.serverlist.fetch_server_list", _fetch)
        first = api_module._cached_countries()
        second = api_module._cached_countries()

        codes = {c.code.lower(): c.code for c in first if c.code}
        assert codes == {"gb": "GB"}
        assert codes == {c.code.lower(): c.code for c in second if c.code}
        assert len(calls) == 1  # snapshot reused, live fetch not repeated

    def test_stale_snapshot_returns_immediately_and_queues_refresh(
        self, monkeypatch
    ):
        old = [_country("DE")]
        api_module._serverlist_cache = {
            "countries": old,
            "at": time.monotonic() - (api_module._SERVERLIST_TTL_SECONDS + 10.0),
        }
        submitted = []

        class FakeExecutor:
            def submit(self, fn):
                submitted.append(fn)

        monkeypatch.setattr(api_module, "_SERVERLIST_EXECUTOR", FakeExecutor())

        started = time.monotonic()
        result = api_module._cached_countries()

        assert result is old
        assert time.monotonic() - started < 0.05
        assert submitted == [api_module._refresh_serverlist_worker]
        assert api_module._serverlist_refresh_inflight is True

    @pytest.mark.asyncio
    async def test_get_countries_keeps_event_loop_responsive(self, monkeypatch):
        def slow_cache():
            time.sleep(0.15)
            return []

        monkeypatch.setattr(api_module, "_cached_countries", slow_cache)

        loop = asyncio.get_running_loop()
        started = loop.time()
        ticks: list[float] = []

        async def ticker():
            await asyncio.sleep(0.02)
            ticks.append(loop.time() - started)

        task = asyncio.create_task(ticker())
        result = await api_module.get_countries()
        await task

        assert result == []
        assert ticks and ticks[0] < 0.1

    def test_fetch_failure_propagates_and_caches_nothing(self, monkeypatch):
        api_module._config = None

        def _boom(path=None):
            raise RuntimeError("offline")

        monkeypatch.setattr("perchvpn.serverlist.fetch_server_list", _boom)
        with pytest.raises(RuntimeError):
            api_module._cached_countries()
        assert api_module._serverlist_cache["countries"] is None
