"""API-level tests for upstream v2.0.3 parity endpoints."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from pydantic import ValidationError

from src.perchvpn_windows import api as api_module
from src.perchvpn_windows.api import NetworkConfig, NetworkConfigResponse, _network_response
from src.perchvpn_windows.config import WindowsConfig


class TestNetworkRequestValidation:
    def test_invalid_ip_mode_rejected(self):
        with pytest.raises(ValidationError, match="ip_mode"):
            NetworkConfig(ip_mode="both")

    def test_invalid_transport_version_rejected(self):
        with pytest.raises(ValidationError, match="transport_version"):
            NetworkConfig(transport_version="h4")

    def test_invalid_multiplex_streams_rejected(self):
        with pytest.raises(ValidationError, match="multiplex_streams"):
            NetworkConfig(multiplex_streams=24)

    def test_invalid_utls_fingerprint_rejected(self):
        with pytest.raises(ValidationError, match="utls_fingerprint"):
            NetworkConfig(utls_fingerprint="wget")

    def test_latency_probe_url_https_only(self):
        with pytest.raises(ValidationError, match="latency probe URL"):
            NetworkConfig(latency_probe_url="http://probe.example.com")

    def test_relayer_provider_validated(self):
        with pytest.raises(ValidationError, match="relayer_provider"):
            NetworkConfig(relayer_provider="relay")


class TestNetworkResponseParity:
    def test_response_includes_parity_fields(self):
        cfg = WindowsConfig(
            ip_mode="prefer_ipv6",
            transport_version="h3",
            multiplex_streams=64,
            utls_fingerprint="firefox",
            always_on=True,
            kill_switch=True,
        )
        response = _network_response(cfg)
        assert isinstance(response, NetworkConfigResponse)
        assert response.ip_mode == "prefer_ipv6"
        assert response.transport_version == "h3"
        assert response.multiplex_streams == 64
        assert response.utls_fingerprint == "firefox"
        assert response.always_on is True
        assert response.kill_switch is True
        assert response.automatic_recovery is True
        assert response.latency_probe_url == api_module.DEFAULT_LATENCY_PROBE_URL
        # The local proxy password must never be exposed through the API.
        assert not hasattr(response, "local_proxy_password")


class TestUpdatesEndpoint:
    @pytest.mark.asyncio
    async def test_update_available(self):
        from src.perchvpn_windows import __version__

        release = {
            "tag": "v2.0.5",
            "name": "FoxyVPN v2.0.5",
            "url": "https://github.com/daniboylfc/perchvpn-windows/releases/tag/v2.0.5",
            "body": "notes",
        }
        with patch.object(api_module, "_fetch_latest_release", return_value=release):
            result = await api_module.check_updates()
        assert result["update_available"] is True
        assert result["current_version"] == __version__
        assert result["latest_tag"] == "v2.0.5"

    @pytest.mark.asyncio
    async def test_up_to_date(self):
        from src.perchvpn_windows import __version__

        release = {"tag": "v1.0.0", "name": "", "url": "u", "body": ""}
        with patch.object(api_module, "_fetch_latest_release", return_value=release):
            result = await api_module.check_updates()
        assert result["update_available"] is False
        assert result["current_version"] == __version__

    @pytest.mark.asyncio
    async def test_fetch_failure_maps_to_502(self):
        with patch.object(
            api_module,
            "_fetch_latest_release",
            side_effect=OSError("network down"),
        ):
            import fastapi

            with pytest.raises(fastapi.HTTPException) as exc_info:
                await api_module.check_updates()
            assert exc_info.value.status_code == 502


class TestRelayerTestEndpoint:
    def test_request_provider_validated(self):
        with pytest.raises(ValidationError, match="provider"):
            api_module.RelayerTestRequest(provider="relay")

    def test_request_defaults(self):
        request = api_module.RelayerTestRequest()
        assert request.provider == "automatic"
        assert request.custom_url == ""
        assert request.routed_endpoints == []

    @pytest.mark.asyncio
    async def test_latency_probe_round_trip(self):
        stub_results = [
            {"relay": "https://relayer.foxyvpn.workers.dev", "ok": True, "rtt_ms": 12.0},
            {"relay": "https://relayer.foxyvpn.vercel.app", "ok": False, "rtt_ms": None},
        ]
        with patch(
            "perchvpn.relayer.measure_relayer_rtt", return_value=stub_results
        ) as mocked:
            result = await api_module.test_relayer_latency(
                api_module.RelayerTestRequest(provider="automatic")
            )
        assert result == {
            "provider": "automatic",
            "custom_url": "",
            "routed_endpoints": [],
            "results": stub_results,
        }
        mocked.assert_called_once()

    @pytest.mark.asyncio
    async def test_latency_probe_failure_maps_to_502(self):
        import fastapi

        with patch(
            "perchvpn.relayer.measure_relayer_rtt",
            side_effect=OSError("probe down"),
        ):
            with pytest.raises(fastapi.HTTPException) as exc_info:
                await api_module.test_relayer_latency(
                    api_module.RelayerTestRequest(provider="automatic")
                )
        assert exc_info.value.status_code == 502


class TestTlsFragmentApiFields:
    def test_invalid_mode_rejected(self):
        with pytest.raises(ValidationError, match="tls_fragment_mode"):
            api_module.NetworkConfig(tls_fragment_mode="faketls")

    def test_delay_bounds_validated(self):
        with pytest.raises(ValidationError):
            api_module.NetworkConfig(tls_fragment_fallback_delay_ms=10_001)

    def test_response_carries_fragment_fields(self):
        cfg = WindowsConfig(tls_fragment_mode="combined", tls_fragment_fallback_delay_ms=450)
        response = _network_response(cfg)
        assert response.tls_fragment_mode == "combined"
        assert response.tls_fragment_fallback_delay_ms == 450
