"""Tests for connection-state presentation: the /api/status contract and the
honest rendering of exit-verification results.

These tests assert that the UI-facing API never presents missing exit metadata
as a verified exit location, and that it never invents a server address,
country, or pool size.

The proxy controller, TLS configuration, DNS transport, SOCKS5 behaviour and
upstream chaining are intentionally out of scope here: only the status
reporting surface these states are read from is exercised.

The status endpoint is invoked directly (rather than through a TestClient with a
lifespan) because the real lifespan performs live authentication and network
calls, which are not available in a unit test.
"""

from __future__ import annotations

import asyncio
from typing import Optional
from unittest.mock import MagicMock

import pytest

import src.perchvpn_windows.api as api_module
from src.perchvpn_windows.api import StatusResponse
from src.perchvpn_windows.config import WindowsConfig


class _FakeMetrics:
    """Stand-in for TrafficMetrics with plain, deterministic values."""

    def __init__(self, downloaded=0, uploaded=0, download_speed=0.0,
                 upload_speed=0.0, active=0):
        self._values = {
            "downloaded": downloaded,
            "uploaded": uploaded,
            "download_speed": download_speed,
            "upload_speed": upload_speed,
            "active_connections": active,
        }

    def __getattr__(self, name):
        values = self.__dict__["_values"]
        if name in values:
            return values[name]
        raise AttributeError(name)


def _make_app_pair(controller_status: str, exit_verification_state: str,
                   exit_ip: str = "0.0.0.0", exit_country: str = "--",
                   candidate=None, tunnel=None) -> tuple:
    """Build an (app, config) pair like the real lifespan does."""
    config = WindowsConfig()

    controller = MagicMock()
    controller.status = controller_status
    controller.uptime = 12.5
    controller.transport = "http/2"
    controller.metrics = _FakeMetrics()

    app_obj = MagicMock()
    app_obj._controller = controller
    app_obj._exit_ip = exit_ip
    app_obj._exit_country = exit_country
    app_obj._exit_verification_state = exit_verification_state
    app_obj._candidate = candidate
    # Existing tests describe an operational system-wide tunnel; the honest
    # proxy-vs-TUN split is covered by TestStatusHonesty below.
    app_obj.tun_payload = lambda: (
        tunnel if tunnel is not None
        else {"enabled": True, "mode": "tun", "state": "traffic_verified",
              "detail": "System traffic exits through the VPN."}
    )

    return app_obj, config


def _get_status(app_obj, config) -> dict:
    """Invoke the status endpoint directly against a stubbed global app."""
    api_module._app = app_obj
    api_module._config = config
    result = asyncio.run(api_module.get_status())
    return result.model_dump()


@pytest.fixture(autouse=True)
def _reset_globals():
    """Ensure no test leaks global state into another."""
    original_app = api_module._app
    original_config = api_module._config
    original_restart = api_module._restart_task
    yield
    api_module._app = original_app
    api_module._config = original_config
    api_module._restart_task = original_restart


class TestStatusResponseContract:
    def test_new_fields_have_safe_defaults(self):
        """New fields must default safely so older callers still validate."""
        resp = StatusResponse(
            status="disconnected",
            uptime=0.0,
            socks5_addr="127.0.0.1:1080",
            exit_ip="0.0.0.0",
            country="--",
            transport="--",
            downloaded=0,
            uploaded=0,
            download_speed=0.0,
            upload_speed=0.0,
            active_connections=0,
        )
        assert resp.exit_verification_state == "not_applicable"

    def test_existing_field_names_preserved(self):
        resp = StatusResponse(
            status="connected",
            uptime=1.0,
            socks5_addr="127.0.0.1:1080",
            exit_ip="1.2.3.4",
            country="gb",
            transport="http/2",
            downloaded=10,
            uploaded=20,
            download_speed=1.0,
            upload_speed=2.0,
            active_connections=3,
        )
        for field in ("status", "uptime", "socks5_addr", "exit_ip", "country",
                      "transport", "downloaded", "uploaded", "download_speed",
                      "upload_speed", "active_connections", "exit_verification_state"):
            assert hasattr(resp, field)


class TestStatusDisconnected:
    def test_no_controller_reports_disconnected_without_server(self):
        app_obj, config = _make_app_pair("disconnected", "not_applicable")
        app_obj._controller = None
        body = _get_status(app_obj, config)

        assert body["status"] == "disconnected"
        assert body["exit_verification_state"] == "not_applicable"

    def test_restart_task_in_flight_reports_connecting(self):
        app_obj, config = _make_app_pair("disconnected", "not_applicable")
        app_obj._controller = None
        fake_task = MagicMock()
        fake_task.done.return_value = False
        api_module._restart_task = fake_task

        body = _get_status(app_obj, config)
        assert body["status"] == "connecting"
        assert body["uptime"] == 0.0

    def test_restart_task_done_reports_disconnected_when_no_controller(self):
        app_obj, config = _make_app_pair("disconnected", "not_applicable")
        app_obj._controller = None
        fake_task = MagicMock()
        fake_task.done.return_value = True
        api_module._restart_task = fake_task

        body = _get_status(app_obj, config)
        assert body["status"] == "disconnected"


class TestStatusConnectedVerified:
    def test_verified_state_and_real_exit_metadata(self):
        candidate = MagicMock()
        candidate.host = "p.m1.fastly-masque.net"
        candidate.port = 2499
        candidate.country_code = "GB"
        candidate.country_name = "United Kingdom"
        candidate.city_code = "lhr"

        app_obj, config = _make_app_pair(
            "connected", "verified",
            exit_ip="203.0.113.7", exit_country="GB", candidate=candidate,
        )
        body = _get_status(app_obj, config)

        assert body["status"] == "connected"
        assert body["exit_verification_state"] == "verified"
        assert body["exit_ip"] == "203.0.113.7"
        assert body["country"] == "gb"


class TestStatusConnectedExitVerificationPending:
    def test_connected_with_placeholder_exit_not_laundered(self):
        """A connected proxy with an unresolved exit check must still report
        connected with the placeholder values intact, so the UI can show
        'connected, verification pending' rather than a verified location."""
        app_obj, config = _make_app_pair("connected", "pending")
        body = _get_status(app_obj, config)

        assert body["status"] == "connected"
        assert body["exit_verification_state"] == "pending"
        # Placeholders must not be laundered into real-looking metadata.
        assert body["exit_ip"] == "0.0.0.0"
        assert body["country"] == "--"


class TestStatusConnectedExitVerificationFailed:
    def test_connected_exit_verification_failed(self):
        app_obj, config = _make_app_pair("connected", "failed")
        body = _get_status(app_obj, config)

        assert body["status"] == "connected"
        assert body["exit_verification_state"] == "failed"
        assert body["exit_ip"] == "0.0.0.0"
        assert body["country"] == "--"


class TestStatusConnectedExitVerificationNotApplicable:
    def test_connected_without_exit_check_is_not_a_failure(self):
        """Exit verification can be intentionally disabled; that is 'not
        applicable', not an error."""
        app_obj, config = _make_app_pair("connected", "not_applicable")
        body = _get_status(app_obj, config)

        assert body["status"] == "connected"
        assert body["exit_verification_state"] == "not_applicable"


class TestStatusConnecting:
    def test_connecting_state(self):
        app_obj, config = _make_app_pair("connecting", "not_applicable")
        body = _get_status(app_obj, config)

        assert body["status"] == "connecting"
        assert body["exit_verification_state"] == "not_applicable"
        assert body["uptime"] == 12.5  # controller reports its own uptime


class TestControllerReasonTranslation:
    """The core controller reports lifecycle reasons ("starting" while the
    initial dial is in flight, "ok" once the upstream accepts); the UI-facing
    status contract is connected/connecting/disconnected. The API must
    translate the core vocabulary, not leak reasons into the UI."""

    def test_controller_ok_translates_to_connected(self):
        app_obj, config = _make_app_pair("ok", "verified",
                                         exit_ip="203.0.113.7", exit_country="FI")
        body = _get_status(app_obj, config)

        assert body["status"] == "connected"
        with_placeholder = _make_app_pair("ok", "pending")
        assert _get_status(with_placeholder[0], with_placeholder[1])["status"] == "connected"

    def test_controller_starting_translates_to_connecting(self):
        app_obj, config = _make_app_pair("starting", "pending")
        body = _get_status(app_obj, config)

        assert body["status"] == "connecting"
        assert body["exit_verification_state"] == "pending"

    def test_connected_contract_value_passes_through(self):
        app_obj, config = _make_app_pair("connected", "verified")
        body = _get_status(app_obj, config)

        assert body["status"] == "connected"

    def test_unknown_reason_passes_through(self):
        app_obj, config = _make_app_pair("mystery", "not_applicable")
        body = _get_status(app_obj, config)

        assert body["status"] == "mystery"


class TestStatusTraffic:
    def test_metrics_and_uptime_reported(self):
        candidate = MagicMock()
        candidate.host = "edge.example.net"
        candidate.port = 443
        candidate.country_code = "DE"
        candidate.country_name = "Germany"
        candidate.city_code = "fra"

        app_obj, config = _make_app_pair(
            "connected", "verified",
            exit_ip="198.51.100.22", exit_country="DE",
            candidate=candidate,
        )
        app_obj._controller.metrics = _FakeMetrics(
            downloaded=1024, uploaded=2048,
            download_speed=512.0, upload_speed=256.0, active=5,
        )
        body = _get_status(app_obj, config)

        assert body["downloaded"] == 1024
        assert body["uploaded"] == 2048
        assert body["download_speed"] == 512.0
        assert body["upload_speed"] == 256.0
        assert body["active_connections"] == 5
        assert body["uptime"] == 12.5


class TestExitVerificationStateTransitions:
    """The exit-verification state machine lives in PerchVPNApp._run_exit_check;
    verify it records the outcomes the UI relies on."""

    def _state_after(self, verify_exit: bool, country_code: str,
                     verify_result: Optional[tuple] = None,
                     raises: Optional[Exception] = None) -> str:
        import src.perchvpn_windows.app as app_module

        original_verify = app_module.verify_exit_country
        app_module.verify_exit_country = self._fake_verify(verify_result, raises)

        try:
            cfg = WindowsConfig(verify_exit=verify_exit)
            app_obj = app_module.PerchVPNApp.__new__(app_module.PerchVPNApp)
            app_obj.config = cfg
            app_obj._exit_ip = "0.0.0.0"
            app_obj._exit_country = "--"
            app_obj._exit_verification_state = "not_applicable"

            candidate = MagicMock()
            candidate.country_code = country_code
            app_obj._candidate = candidate

            asyncio.run(app_obj._run_exit_check("socks5://127.0.0.1:1080"))
            return app_obj._exit_verification_state
        finally:
            app_module.verify_exit_country = original_verify

    @staticmethod
    def _fake_verify(result, raises):
        async def _verify(proxy_url, expected_country):
            if raises is not None:
                raise raises
            return result
        return _verify

    def test_successful_check_records_verified(self):
        assert self._state_after(True, "GB", verify_result=("203.0.113.7", "gb")) == "verified"

    def test_failed_check_records_failed(self):
        assert self._state_after(True, "GB", verify_result=None) == "failed"

    def test_raised_check_records_failed(self):
        assert self._state_after(True, "GB", raises=RuntimeError("boom")) == "failed"

    def test_no_country_code_stays_not_applicable(self):
        """Without a country code the probe must not run, so the state stays
        'not applicable' instead of claiming a verified exit."""
        assert self._state_after(True, "", verify_result=("203.0.113.7", "gb")) == "not_applicable"

    def test_verify_disabled_stays_not_applicable(self):
        assert self._state_after(False, "GB", verify_result=("203.0.113.7", "gb")) == "not_applicable"

    def test_verify_disabled_does_not_touch_exit_values(self):
        """A disabled exit check must leave the placeholder exit values alone."""
        import src.perchvpn_windows.app as app_module

        original_verify = app_module.verify_exit_country
        calls = []

        async def _verify(proxy_url, expected_country):
            calls.append(expected_country)
            return ("203.0.113.7", "gb")

        app_module.verify_exit_country = _verify
        try:
            cfg = WindowsConfig(verify_exit=False)
            app_obj = app_module.PerchVPNApp.__new__(app_module.PerchVPNApp)
            app_obj.config = cfg
            app_obj._exit_ip = "0.0.0.0"
            app_obj._exit_country = "--"
            app_obj._exit_verification_state = "not_applicable"

            candidate = MagicMock()
            candidate.country_code = "GB"
            app_obj._candidate = candidate

            asyncio.run(app_obj._run_exit_check("socks5://127.0.0.1:1080"))

            assert calls == []  # probe never invoked
            assert app_obj._exit_ip == "0.0.0.0"
            assert app_obj._exit_country == "--"
            assert app_obj._exit_verification_state == "not_applicable"
        finally:
            app_module.verify_exit_country = original_verify


class TestStateResolutionMapping:
    """The frontend resolves five UI states from (controller status,
    exit_verification_state). These mirrors keep the contract honest if the
    mapping is ever ported server-side."""

    @staticmethod
    def resolve(controller_status: str, exit_state: str) -> str:
        if controller_status == "connected":
            mapping = {
                "verified": "connected_verified",
                "failed": "connected_unverified",
                "pending": "connected_verifying",
                "not_applicable": "connected_unverified",
            }
            return mapping.get(exit_state, "connected_unverified")
        if controller_status == "connecting":
            return "connecting"
        return "disconnected"

    def test_every_backend_cell_maps_to_a_known_state(self):
        allowed = {
            "disconnected", "connecting",
            "connected_verifying", "connected_verified", "connected_unverified",
        }
        for controller_status in ("disconnected", "connecting", "connected"):
            for exit_state in ("not_applicable", "pending", "verified", "failed"):
                result = self.resolve(controller_status, exit_state)
                assert result in allowed, (controller_status, exit_state, result)

    def test_connected_with_pending_exit_is_not_verified(self):
        assert self.resolve("connected", "pending") == "connected_verifying"

    def test_connected_with_failed_exit_is_not_verified(self):
        assert self.resolve("connected", "failed") == "connected_unverified"

    def test_connected_with_unavailable_exit_is_not_verified(self):
        assert self.resolve("connected", "not_applicable") == "connected_unverified"

    def test_connecting_takes_precedence(self):
        assert self.resolve("connecting", "pending") == "connecting"

    def test_disconnected_regardless_of_exit_state(self):
        for exit_state in ("not_applicable", "pending", "verified", "failed"):
            assert self.resolve("disconnected", exit_state) == "disconnected"


class TestStatusHonesty:
    """TUN must never be reported Connected without system-traffic proof."""

    def test_no_tun_reports_proxy_active_not_connected(self):
        app_obj, config = _make_app_pair(
            "ok", "verified",
            tunnel={"enabled": False, "mode": "socks5", "state": "disabled",
                    "detail": "TUN is not enabled."},
        )
        body = _get_status(app_obj, config)

        assert body["status"] == "proxy_active"
        assert body["tunnel"]["enabled"] is False

    def test_tun_not_elevated_never_reports_connected(self):
        app_obj, config = _make_app_pair(
            "ok", "verified",
            tunnel={"enabled": True, "mode": "tun", "state": "not_elevated",
                    "detail": "Administrator privileges are required."},
        )
        body = _get_status(app_obj, config)

        assert body["status"] == "failed"
        assert body["status"] != "connected"
        assert "Administrator" in body["tunnel"]["detail"]

    def test_tun_routes_without_egress_proof_is_not_connected(self):
        app_obj, config = _make_app_pair(
            "ok", "verified",
            tunnel={"enabled": True, "mode": "tun", "state": "routes_configured",
                    "detail": "Routes active; egress not verified."},
        )
        body = _get_status(app_obj, config)

        assert body["status"] == "connecting"

    def test_tun_traffic_verified_is_connected(self):
        app_obj, config = _make_app_pair(
            "ok", "verified",
            tunnel={"enabled": True, "mode": "tun", "state": "traffic_verified",
                    "detail": "System egress matches the VPN exit."},
        )
        body = _get_status(app_obj, config)

        assert body["status"] == "connected"
        assert body["tunnel"]["state"] == "traffic_verified"


class TestCanonicalTunStatusContract:
    """The top-level /api/status values are canonical: degraded / failed."""

    def test_tunnel_failure_is_reported_as_failed(self):
        app_obj, config = _make_app_pair(
            "ok",
            "verified",
            tunnel={
                "enabled": True,
                "mode": "tun",
                "state": "failed",
                "detail": "tun2proxy exited unexpectedly",
            },
        )
        payload = _get_status(app_obj, config)
        assert payload["status"] == "failed"
        assert payload["status"] not in ("tun_failed", "tun_degraded")
        assert payload["tunnel"]["detail"] == "tun2proxy exited unexpectedly"

    def test_tunnel_degraded_is_reported_as_degraded(self):
        app_obj, config = _make_app_pair(
            "ok",
            "verified",
            tunnel={
                "enabled": True,
                "mode": "tun",
                "state": "degraded",
                "detail": "physical egress leak detected",
            },
        )
        payload = _get_status(app_obj, config)
        assert payload["status"] == "degraded"
        assert payload["status"] not in ("tun_failed", "tun_degraded")

    def test_legacy_tun_aliases_are_never_emitted(self):
        for tunnel_state in ("failed", "degraded", "starting", "traffic_verified"):
            app_obj, config = _make_app_pair(
                "ok",
                "verified",
                tunnel={"enabled": True, "mode": "tun", "state": tunnel_state},
            )
            payload = _get_status(app_obj, config)
            assert payload["status"] in (
                "connected",
                "connecting",
                "degraded",
                "failed",
            ), tunnel_state

    def test_recovery_state_is_failed_with_detail(self):
        app_obj, config = _make_app_pair(
            "ok",
            "verified",
            tunnel={
                "enabled": True,
                "mode": "tun",
                "state": "recovery_required",
                "detail": "journaled routes could not be reconciled",
            },
        )
        payload = _get_status(app_obj, config)
        assert payload["status"] == "failed"
        assert payload["tunnel"]["detail"]


class TestNodeStatusContractHarness:
    """The Node behaviour harness exercises the exact UI mapping table."""

    @staticmethod
    def _run(js: str):
        import json
        import shutil
        import subprocess
        from pathlib import Path

        node = shutil.which("node")
        if not node:
            pytest.skip("node is not available")
        module = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "perchvpn_windows"
            / "web"
            / "status-contract.js"
        )
        result = subprocess.run(
            [node, "-e", "const c = require(%s);\n%s" % (json.dumps(str(module)), js)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    def test_degraded_renders_the_tunnel_unverified_pill(self):
        data = self._run(
            """
const state = c.resolveUiState({status: 'degraded', tunnel: {enabled: true}});
const meta = c.META[state];
process.stdout.write(JSON.stringify({
  state,
  headerText: meta.headerText,
  headerClass: meta.headerClass,
  statusText: meta.statusText,
  stateClass: meta.stateClass,
  detail: c.detailText(state, {status: 'degraded', tunnel: {detail: 'leak reason'}}),
  button: c.buttonState(state)
}));
"""
        )
        assert data["state"] == "tun_degraded"
        assert data["headerText"] == "Tunnel unverified"
        assert data["headerClass"] == "status-indicator--connecting"
        assert data["statusText"] == "Tunnel unverified"
        assert data["stateClass"] == "is-connecting"
        assert data["detail"] == "leak reason"
        assert data["button"] == {
            "connected": False,
            "connecting": True,
            "error": False,
            "disabled": True,
            "pressed": False,
            "label": "Connect",
            "ariaLabel": "Connect to VPN",
        }

    def test_failed_renders_the_tunnel_failed_pill(self):
        data = self._run(
            """
const state = c.resolveUiState({status: 'failed', tunnel: {enabled: true}});
const meta = c.META[state];
process.stdout.write(JSON.stringify({
  state,
  headerText: meta.headerText,
  headerClass: meta.headerClass,
  statusText: meta.statusText,
  stateClass: meta.stateClass,
  detail: c.detailText(state, {status: 'failed', tunnel: {detail: 'helper crashed'}}),
  fallback: c.detailText(state, {status: 'failed'}),
  button: c.buttonState(state)
}));
"""
        )
        assert data["state"] == "tun_failed"
        assert data["headerText"] == "Tunnel failed"
        assert data["headerClass"] == "status-indicator--disconnected"
        assert data["statusText"] == "Tunnel failed"
        assert data["stateClass"] == "is-disconnected"
        assert data["detail"] == "helper crashed"
        assert data["fallback"] == "The system tunnel is not available."
        assert data["button"]["connected"] is False
        assert data["button"]["connecting"] is False
        assert data["button"]["disabled"] is False
        assert data["button"]["label"] == "Connect"

    def test_legacy_tun_aliases_resolve_identically(self):
        data = self._run(
            """
process.stdout.write(JSON.stringify({
  fromDegraded: c.resolveUiState({status: 'tun_degraded'}),
  fromFailed: c.resolveUiState({status: 'tun_failed'}),
  normalised: [c.normaliseStatus('TUN_DEGRADED'), c.normaliseStatus('tun_failed')],
  connecting: c.resolveUiState({status: 'connecting'}),
  proxy: c.resolveUiState({status: 'proxy_active'}),
  verified: c.resolveUiState({status: 'connected', exit_verification_state: 'verified'}),
  unverified: c.resolveUiState({status: 'connected', exit_verification_state: 'failed'}),
  verifying: c.resolveUiState({status: 'connected', exit_verification_state: 'pending'}),
  disconnected: c.resolveUiState({status: 'disconnected'})
}));
"""
        )
        assert data["fromDegraded"] == "tun_degraded"
        assert data["fromFailed"] == "tun_failed"
        assert data["normalised"] == ["degraded", "failed"]
        assert data["connecting"] == "connecting"
        assert data["proxy"] == "proxy_active"
        assert data["verified"] == "connected_verified"
        assert data["unverified"] == "connected_unverified"
        assert data["verifying"] == "connected_verifying"
        assert data["disconnected"] == "disconnected"

    def test_app_js_uses_the_shared_contract(self):
        from pathlib import Path

        source = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "perchvpn_windows"
            / "web"
            / "app.js"
        ).read_text(encoding="utf-8")
        assert "window.PerchStatusContract.resolveUiState(d)" in source
        assert "window.PerchStatusContract.buttonState(state)" in source
        assert "...window.PerchStatusContract.META" in source
        # resolveState no longer re-implements the mapping locally.
        assert "if (controller === UI_STATE.TUN_FAILED)" not in source
        assert "if (controller === UI_STATE.TUN_DEGRADED)" not in source
