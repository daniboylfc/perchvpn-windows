"""Tests for control-plane relayer routing and failover."""

from __future__ import annotations

import base64

import httpx
import pytest

from src.perchvpn import relayer
from src.perchvpn.relayer import RelayerState


@pytest.fixture(autouse=True)
def _reset_state():
    relayer.configure(provider="direct")
    yield
    relayer.configure(provider="direct")


class TestRelayerUrlBuilding:
    def test_appends_base64url_query_param(self):
        target = "https://vpn.mozilla.org/api/v1/fpn/token"
        url = relayer.build_relayer_url("https://relayer.foxyvpn.workers.dev", target)
        encoded = base64.urlsafe_b64encode(target.encode()).decode()
        assert url == f"https://relayer.foxyvpn.workers.dev/?url={encoded}"

    def test_schemeless_base_gets_https(self):
        url = relayer.build_relayer_url("relayer.example", "https://t.test/")
        assert url.startswith("https://relayer.example/?url=")

    def test_base_with_existing_query(self):
        url = relayer.build_relayer_url("https://w.test/?a=1", "https://t.test/")
        assert "/?a=1&url=" in url

    def test_base_ending_with_url_param(self):
        url = relayer.build_relayer_url("https://w.test/?url=", "https://t.test/")
        assert url == "https://w.test/?url=" + base64.urlsafe_b64encode(b"https://t.test/").decode()


class TestCandidateRelayers:
    def test_direct_never_relays(self):
        assert relayer.candidate_relayers("direct") == []

    def test_automatic_lists_default_workers(self):
        candidates = relayer.candidate_relayers("automatic")
        assert candidates == [
            "https://relayer.foxyvpn.workers.dev",
            "https://relayer.foxyvpn.vercel.app",
        ]

    def test_explicit_provider_pins_one(self):
        assert relayer.candidate_relayers("cloudflare") == ["https://relayer.foxyvpn.workers.dev"]
        assert relayer.candidate_relayers("vercel") == ["https://relayer.foxyvpn.vercel.app"]

    def test_custom_requires_https(self):
        assert relayer.candidate_relayers("custom", "https://mine.test") == ["https://mine.test"]
        assert relayer.candidate_relayers("custom", "http://mine.test") == []


class TestCategoryMatching:
    def test_guardian(self):
        assert relayer.match_category("https://vpn.mozilla.org/api/v1/fpn/token", "guardian")
        assert not relayer.match_category("https://example.com/", "guardian")

    def test_fxa(self):
        assert relayer.match_category("https://api.accounts.firefox.com/v1/finish", "fxa")
        assert relayer.match_category("https://vpn.mozilla.org/oauth/token", "fxa")

    def test_server_list_and_config(self):
        assert relayer.match_category("https://vpn.mozilla.org/vpn-serverlist", "server_list")
        assert relayer.match_category("https://firefox.settings/FoxyConfig", "config")


class TestShouldRelay:
    def test_direct_state_never_relays(self):
        assert not relayer.should_relay("https://vpn.mozilla.org/api/v1/fpn/token")

    def test_routed_endpoints_gate(self):
        state = RelayerState(provider="automatic", routed_endpoints=("guardian",))
        assert relayer.should_relay("https://vpn.mozilla.org/api/v1/fpn/token", state)
        assert not relayer.should_relay("https://vpn.mozilla.org/vpn-serverlist", state)


class _StubResponse:
    def __init__(self, status: int):
        self.status_code = status


class _StubClient:
    def __init__(self, script):
        self.script = list(script)
        self.calls: list = []

    def request(self, method, url, **kwargs):
        self.calls.append(url)
        action = self.script.pop(0)
        if isinstance(action, Exception):
            raise action
        return _StubResponse(action)


class TestFailoverFlow:
    def test_direct_success_never_relays(self):
        client = _StubClient([200])
        response = relayer.request_with_relayer(
            client, "GET", "https://vpn.mozilla.org/api/v1/fpn/token",
            state=RelayerState(provider="automatic", routed_endpoints=("guardian",)),
        )
        assert response.status_code == 200
        assert len(client.calls) == 1

    def test_451_fails_over_to_relayer(self):
        client = _StubClient([451, 200])
        response = relayer.request_with_relayer(
            client, "GET", "https://vpn.mozilla.org/api/v1/fpn/token",
            state=RelayerState(provider="automatic", routed_endpoints=("guardian",)),
        )
        assert response.status_code == 200
        assert len(client.calls) == 2
        assert client.calls[1].startswith("https://relayer.foxyvpn.workers.dev/?url=")
        # The original URL is base64url-encoded into the relayed request.
        encoded = client.calls[1].split("?url=", 1)[1]
        assert base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)).decode() == (
            "https://vpn.mozilla.org/api/v1/fpn/token"
        )

    def test_connection_error_fails_over(self):
        client = _StubClient([httpx.ConnectError("blocked"), 200])
        response = relayer.request_with_relayer(
            client, "GET", "https://vpn.mozilla.org/api/v1/fpn/token",
            state=RelayerState(provider="automatic", routed_endpoints=("guardian",)),
        )
        assert response.status_code == 200

    def test_all_failures_re_raise_direct_error(self):
        client = _StubClient([
            httpx.ConnectError("blocked"),
            httpx.ConnectError("r1"),
            httpx.ConnectError("r2"),
        ])
        with pytest.raises(httpx.ConnectError, match="blocked"):
            relayer.request_with_relayer(
                client, "GET", "https://vpn.mozilla.org/api/v1/fpn/token",
                state=RelayerState(provider="automatic", routed_endpoints=("guardian",)),
            )
        assert len(client.calls) == 3  # direct + both relayers

    def test_custom_provider_uses_single_worker(self):
        client = _StubClient([451, 200])
        response = relayer.request_with_relayer(
            client, "GET", "https://vpn.mozilla.org/api/v1/fpn/token",
            state=RelayerState(provider="custom", custom_url="https://mine.test", routed_endpoints=("guardian",)),
        )
        assert response.status_code == 200
        assert client.calls[1].startswith("https://mine.test/?url=")

    def test_relayed_451_walks_to_next_relayer(self):
        client = _StubClient([451, 451, 200])
        response = relayer.request_with_relayer(
            client, "GET", "https://vpn.mozilla.org/api/v1/fpn/token",
            state=RelayerState(provider="automatic", routed_endpoints=("guardian",)),
        )
        assert response.status_code == 200
        assert client.calls[2].startswith("https://relayer.foxyvpn.vercel.app/?url=")


class TestLatencyProbe:
    def test_measures_rtt_per_candidate(self):
        class _TimedClient:
            def request(self, method, url, **kwargs):
                if "workers.dev" in url:
                    return _StubResponse(200)
                raise httpx.ConnectError("down")

        results = relayer.measure_relayer_rtt(
            "automatic", client=_TimedClient(),
        )
        assert len(results) == 2
        assert results[0]["ok"] is True
        assert results[0]["rtt_ms"] >= 0
        assert results[1]["ok"] is False
        assert results[1]["rtt_ms"] is None

    def test_direct_provider_has_no_candidates(self):
        assert relayer.measure_relayer_rtt("direct", client=_StubClient([])) == []


class TestHttpClientHook:
    def test_default_state_passes_through(self):
        from src.perchvpn.http_client import _RelayingClient

        calls = []

        class _Inner:
            def request(self, method, url, **kwargs):
                calls.append((method, url))
                return _StubResponse(200)

        client = _RelayingClient.__new__(_RelayingClient)
        client.__dict__["_inner"] = _Inner()
        # _RelayingClient.request resolves state via relayer.current_state();
        # default state is "direct", so no relay path is exercised.
        import unittest.mock as mock

        with mock.patch.object(httpx.Client, "request", autospec=True) as mocked:
            mocked.return_value = _StubResponse(200)
            response = _RelayingClient.request(client, "GET", "https://vpn.mozilla.org/api/v1/fpn/token")
            assert response.status_code == 200
            assert mocked.call_count == 1

    def test_relaying_client_invokes_failover(self):
        from unittest.mock import patch

        from src.perchvpn.http_client import _RelayingClient
        from src.perchvpn import relayer as relayer_module

        relayer_module.configure(provider="automatic", routed_endpoints=("guardian",))
        try:
            client = _RelayingClient.__new__(_RelayingClient)
            with patch.object(httpx.Client, "request", autospec=True) as mocked:
                responses = [_StubResponse(451), _StubResponse(200)]
                mocked.side_effect = lambda self, method, url, **kw: responses.pop(0)
                response = client.request("GET", "https://vpn.mozilla.org/api/v1/fpn/token")
                assert response.status_code == 200
                assert mocked.call_count == 2
        finally:
            relayer_module.configure(provider="direct")
