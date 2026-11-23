"""Structural checks for the targeted UI pass:

* the complete Account & Allowance section lives in its own Account tab and
  is fully removed from the Network tab,
* the repository address is gone from the UI (no external link anywhere),
* the connection button redirects signed-out users to the Account tab
  instead of failing silently on a backend 409,
* country rows keep their DOM nodes across ping refreshes (no innerHTML
  teardown) and flags load eagerly with long-lived cache headers.
"""

from __future__ import annotations

from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WEB = PROJECT_ROOT / "src" / "perchvpn_windows" / "web"


def _read(name: str) -> str:
    return (WEB / name).read_text(encoding="utf-8")


def _panel(html: str, panel_id: str) -> str:
    start = html.index(f'id="{panel_id}"')
    markers = [html.find(marker, start + 1) for marker in ("<section class=\"tab-panel\"", "</main>")]
    return html[start:min(m for m in markers if m != -1)]


class TestAccountTabReorganization:
    def test_account_panel_hosts_the_full_section(self):
        html = _read("index.html")
        panel = _panel(html, "account-panel")
        for marker in (
            'id="account-status-pill"',
            'id="account-card"',
            'id="account-identifier"',
            'id="account-guardian-status"',
            'id="signin-form"',
            'id="signin-email"',
            'id="signin-password"',
            'id="signin-password-toggle"',
            'id="signin-submit"',
            'id="signin-verify"',
            'id="signin-code"',
            'id="verify-submit"',
            'id="verify-cancel"',
            'id="btn-logout"',
            'id="btn-clear-tokens"',
            'id="allowance-gauge"',
            'id="gauge-arc"',
        ):
            assert marker in panel, f"{marker} must live in the Account tab"

    def test_network_panel_no_longer_contains_account_section(self):
        html = _read("index.html")
        panel = _panel(html, "network-panel")
        for marker in (
            "Account &amp; Allowance",
            'id="account-status-pill"',
            'id="signin-form"',
            'id="allowance-gauge"',
            'id="account-card"',
        ):
            assert marker not in panel, f"{marker} must not remain in the Network tab"
        # No duplicate Account & Allowance title anywhere else either.
        assert html.count("Account &amp; Allowance") == 1

    def test_account_tab_navigation_exists(self):
        html = _read("index.html")
        assert 'data-tab="account"' in html
        assert 'aria-controls="account-panel"' in html

    def onboarding_references_account_tab(self):
        html = _read("index.html")
        assert "open the Account tab" in html
        assert "open the Network tab and sign in" not in html
        html_only = html
        assert html_only.count("github.com") == 0


class TestRepoAddressRemoved:
    def test_no_source_repo_link_in_markup(self):
        html = _read("index.html")
        assert "source-repo" not in html
        assert "github.com" not in html
        assert "app-footer__link" not in html

    def test_no_repo_address_in_frontend_script(self):
        source = _read("app.js")
        assert "github.com" not in source
        assert "vauth" not in source


class TestConnectionButtonSignedOutFlow:
    def test_connect_redirects_signed_out_users_to_account_tab(self):
        source = _read("app.js")
        # Clear user feedback + navigation instead of a silent fast-fail.
        assert "Connect blocked: not signed in" in source
        assert "Sign in to your account before connecting the VPN." in source
        assert "this.switchTab('account')" in source
        assert "this.beginSignIn()" in source

    def test_restart_failures_surface_the_auth_redirect_too(self):
        source = _read("app.js")
        assert "/not signed in/i.test(message)" in source
        assert "Not signed in: enter your credentials on the Account tab" in source

    def test_backend_gates_restart_on_signed_out_state(self):
        from pathlib import Path as P

        api = (PROJECT_ROOT / "src" / "perchvpn_windows" / "api.py").read_text(encoding="utf-8")
        assert "Not signed in: sign in first, then connect" in api
        assert 'status_code=409' in api


class TestCountryListRendering:
    def test_ping_updates_are_in_place(self):
        source = _read("app.js")
        assert "setTextIfChanged" in source
        assert "In-place surgical update" in source
        # Latency writes go through the dirty-checked helper.
        assert "applyLatencyText(t.els," in source

    def test_country_rows_are_not_rebuilt_on_tab_switches(self):
        source = _read("app.js")
        assert "if (!this._countries || !this._countries.length) this.loadCountries();" in source

    def test_country_sort_moves_existing_rows_batched_in_a_raf(self):
        source = _read("app.js")
        assert "scheduleCountrySort" in source
        assert "requestAnimationFrame" in source
        assert "if (changed) decorated.forEach(d => list.appendChild(d.row));" in source

    def test_selection_refresh_is_per_row_dirty_checked(self):
        source = _read("app.js")
        assert "item.dataset.sel === key" in source

    def test_flags_load_eagerly_with_zero_layout_shift(self):
        source = _read("app.js")
        assert 'loading="eager"' in source
        assert 'decoding="sync"' in source
        assert "width=\"21\" height=\"15\"" in source
        assert "prewarmFlags" in source

    def test_flag_assets_are_served_immutable(self):
        from pathlib import Path as P

        api = (PROJECT_ROOT / "src" / "perchvpn_windows" / "api.py").read_text(encoding="utf-8")
        assert "_ImmutableAssets" in api
        assert '"Cache-Control", "public, max-age=31536000, immutable"' in api
        # App pages keep ETag revalidation (no immutable caching at /).
        assert 'app.mount("/assets", _ImmutableAssets' in api


class TestRenderingPerformance:
    def test_poll_writes_are_dirty_checked(self):
        source = _read("app.js")
        assert "function setTextIfChanged(el, text)" in source
        assert "el.textContent === text" in source

    def test_log_render_reuses_rows_instead_of_rebuilding(self):
        source = _read("app.js")
        assert "LOG_RENDER_MAX" in source
        assert "cachedLogRow" in source
        assert "container.replaceChildren(" in source
        # The old full innerHTML teardown must be gone.
        assert "container.innerHTML = ''" not in source

    def test_datalist_rebuilds_only_for_new_components(self):
        source = _read("app.js")
        assert "!this._seenComponents.has(ev.component)" in source

    def test_cards_and_rows_are_layout_contained(self):
        css = _read("styles.css")
        assert css.count("contain: layout style") >= 3


class TestUnifiedDelaySweep:
    def test_probe_favors_handshakedebiased_rtt(self):
        source = _read("app.js")
        # The surgical Stage-2 RTT field first, legacy TTFB as fallback.
        assert "result.latency_ms != null ? result.latency_ms : result.elapsed_ms" in source

    def test_bounded_concurrent_sweep_of_three(self):
        source = _read("app.js")
        assert "Math.min(3, queue.length)" in source

    def test_badge_writes_batched_inside_one_requestanimationframe(self):
        source = _read("app.js")
        assert "_latencyWrites" in source
        assert "_latencyFlushRaf" in source
        assert "requestAnimationFrame" in source

    def test_backend_two_stage_probe(self):
        api = (PROJECT_ROOT / "src" / "perchvpn_windows" / "api.py").read_text(encoding="utf-8")
        assert "cp.cloudflare.com/generate_204" in api or "_URLTEST_FALLBACK_HOST" in api
        assert "Connection: keep-alive" in api
        assert "time.perf_counter()" in api
        assert "latency_ms = max(1, round((time.perf_counter() - t0) * 1000))" in api
        # Guardian pass TTL-honoured in memory (never inside a ping).
        assert "_URLTEST_PASS_TTL_SECONDS" in api
        assert "_pass_ttl_seconds" in api


class TestTacticalRadar:
    def test_canvas_scope_and_hud_exist(self):
        html = _read("index.html")
        assert 'id="radar-canvas"' in html
        assert 'id="radar-scope"' in html
        assert 'id="radar-hud"' in html
        for hud_id in ("radar-hud-range", "radar-hud-contacts",
                       "radar-hud-exit", "radar-hud-bearing"):
            assert f'id="{hud_id}"' in html

    def test_tactical_reticle_markup(self):
        source = _read("app.js")
        # Range rings 25/50/75/100 % + cardinal bearing labels with degree sign.
        assert "[0.25, 0.5, 0.75, 1]" in source
        assert "\u00b0" in source or "°" in source
        assert "radarAzimuthForCode" in source
        # One rAF paint loop drives the sweep.
        assert "RADAR_SWEEP_PERIOD_MS" in source
        assert "startRadarLoop" in source
        assert "requestAnimationFrame" in source
        assert "getContext('2d')" in source

    def test_sweep_is_unconditional(self):
        # The sweep is the instrument, not decoration: it must keep moving
        # even when the OS asks for reduced motion.
        source = _read("app.js")
        radar = source[source.index("Tactical sonar scope"):source.index("        startDevWatch() {")]
        assert "reduced-motion is" in radar and "not honoured" in radar
        assert "prefers-reduced-motion" not in radar
        assert "matchMedia" not in radar

    def test_echo_blips_come_from_real_measurements(self):
        source = _read("app.js")
        # Real /api/urltest values mapped to radius; no invented telemetry.
        assert "_countryLatency" in source
        assert "Number.isFinite(ms) && ms > 0" in source

    def test_no_random_in_radar(self):
        source = _read("app.js")
        assert "Math.random" not in source

    def test_canvas_and_hud_css(self):
        css = _read("styles.css")
        assert "#radar-canvas" in css
        assert "aspect-ratio: 1 / 1" in css
        assert ".radar-hud" in css
        # Above-the-fold compaction for 1100x720 / 1366x768.
        assert "@media (max-height: 820px)" in css
        assert "width: min(252px, 100%)" in css


class TestDebugSubsection:
    def test_no_debug_top_level_tab(self):
        html = _read("index.html")
        assert 'data-tab="debug"' not in html
        assert 'id="debug-panel"' not in html

    def test_debug_lives_inside_live_logs_card(self):
        html = _read("index.html")
        card = html[html.index('id="log-container"'):html.index("</main>")]
        assert 'id="logs-debug"' in card
        assert 'id="logs-debug-state"' in card
        assert 'id="logs-debug-events"' in card
        assert "Debug / Diagnostics" in card

    def test_debug_renders_real_state_only(self):
        source = _read("app.js")
        assert "renderDebugEvents" in source
        assert "webui debug streaming" in source
        # De-duplicated: DEBUG events come from the same shared buffer.
        assert "this._eventLog.filter((ev) => ev.severity === 'DEBUG')" in source


class TestDashboardStackedInfoRows:
    """The narrow left-rail cards must stack key-above-value rows so long
    values never squeeze beside their uppercase key, and the SOCKS5
    endpoint must always render in full on one tabular-nums line."""

    def test_info_rows_are_stacked_grid(self):
        css = _read("styles.css")
        assert ".info-item {\n    /* Stacked key-above-value rows" in css
        assert "grid-template-columns: minmax(0, 1fr);" in css

    def test_no_ellipsis_clamping_on_status_slots(self):
        css = _read("styles.css")
        # The info-list section (dashboard status slots) must contain no
        # line clamping or ellipsis: long values wrap in the full-width
        # stacked row instead.
        section_start = css.index("Info Lists (key/value)")
        section_end = css.index("/* Slots that carry raw backend error strings")
        section = css[section_start:section_end]
        assert "-webkit-line-clamp" not in section
        assert "text-overflow: ellipsis" not in section

    def test_socks5_addr_line_contract(self):
        css = _read("styles.css")
        rule_start = css.index("#socks5-addr {")
        rule = css[rule_start:css.index("}", rule_start)]
        assert "white-space: nowrap" in rule
        assert "font-variant-numeric: tabular-nums" in rule
        assert "overflow: hidden" not in rule

    def test_values_left_aligned_in_stacked_rows(self):
        css = _read("styles.css")
        rule_start = css.index(".info-value {")
        rule = css[rule_start:css.index("}", rule_start)]
        assert "text-align: left" in rule


class TestStatusWebSocketPush:
    """The dashboard consumes /ws/status frames immediately; the 2 s poll
    remains only as a fallback while the socket is down."""

    def test_ws_status_endpoint_exists(self):
        api = (PROJECT_ROOT / "src" / "perchvpn_windows" / "api.py").read_text(
            encoding="utf-8"
        )
        assert '@app.websocket("/ws/status")' in api
        assert "broadcast_status" in api
        assert "_status_monitor_loop" in api

    def test_frontend_connects_status_socket(self):
        source = _read("app.js")
        assert "connectStatusWebSocket" in source
        assert "/ws/status" in source
        assert "applyStatusFrame" in source
        # The poll timer is stopped while the socket is live.
        assert "stopStatusPolling" in source

    def test_radar_loop_has_fps_cap_and_visibility_pause(self):
        source = _read("app.js")
        assert "RADAR_FRAME_MS" in source
        assert "this._radarNextDraw" in source
        assert "this._radarLastDraw" in source
        assert "document.hidden" in source


class TestParitySettingsControls:
    """Upstream v2.0.3 parity controls in the Network panel."""

    @pytest.fixture(scope="class")
    def network_panel(self) -> str:
        return _panel(_read("index.html"), "network-panel")

    def test_parity_selects_present(self, network_panel: str):
        for element_id in (
            "ip-mode",
            "transport-version",
            "multiplex-streams",
            "utls-fingerprint",
            "bootstrap-dns-provider",
            "relayer-provider",
            "latency-probe-url",
        ):
            assert f'id="{element_id}"' in network_panel, element_id

    def test_parity_toggles_present(self, network_panel: str):
        for element_id in (
            "bypass-local-network",
            "kill-switch",
            "automatic-recovery",
            "always-on",
            "update-checks",
            "local-proxy-auth-enabled",
        ):
            assert f'id="{element_id}"' in network_panel, element_id

    def test_update_check_button_in_footer(self):
        html = _read("index.html")
        assert 'id="btn-check-updates"' in html

    def test_js_wiring_for_new_toggles(self):
        js = _read("app.js")
        for fn in (
            "toggleBootstrapDoh",
            "toggleCustomRelayer",
            "toggleLocalProxyAuth",
            "checkForUpdates",
        ):
            assert fn in js, fn

    def test_save_payload_sends_parity_fields(self):
        js = _read("app.js")
        for field in (
            "ip_mode:",
            "transport_version:",
            "multiplex_streams:",
            "utls_fingerprint:",
            "latency_probe_url:",
            "bootstrap_dns_provider:",
            "relayer_provider:",
            "bypass_local_network:",
            "kill_switch:",
            "automatic_recovery:",
            "always_on:",
            "update_checks:",
            "local_proxy_auth_enabled:",
        ):
            assert field in js, field


class TestDatapathParityControls:
    """TLS fragmentation, relayer latency probe, and extended uTLS options."""

    @pytest.fixture(scope="class")
    def network_panel(self) -> str:
        return _panel(_read("index.html"), "network-panel")

    def test_tls_fragment_controls_present(self, network_panel: str):
        for element_id in ("tls-fragment-mode", "tls-fragment-delay"):
            assert f'id="{element_id}"' in network_panel, element_id

    def test_tls_fragment_mode_options(self, network_panel: str):
        for mode in ("disabled", "record", "packet", "combined"):
            assert f'value="{mode}"' in network_panel, mode

    def test_extended_utls_options(self, network_panel: str):
        for fingerprint in ("ios", "randomized"):
            assert f'value="{fingerprint}"' in network_panel, fingerprint

    def test_relayer_test_button_present(self, network_panel: str):
        assert 'id="btn-relayer-test"' in network_panel
        assert 'id="relayer-test-result"' in network_panel

    def test_relayer_provider_pin_options(self, network_panel: str):
        for provider in ("cloudflare", "vercel", "custom"):
            assert f'value="{provider}"' in network_panel, provider

    def test_js_wiring(self):
        js = _read("app.js")
        for fn in ("testRelayerLatency",):
            assert fn in js, fn
        for field in ("tls_fragment_mode:", "tls_fragment_fallback_delay_ms:"):
            assert field in js, field

    def test_reset_resets_fragment_fields(self):
        js = _read("app.js")
        assert "'tls-fragment-mode', 'disabled'" in js
        assert "'tls-fragment-delay', 300" in js
