"""Frontend static checks: sonar radar, allowance gauge and live logs UI.

Structural assertions matching the in-app sign-in test style: the markup,
CSS and JS implement real state mapping, and no fabricated data creeps in.
"""

from __future__ import annotations

from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WEB = PROJECT_ROOT / "src" / "perchvpn_windows" / "web"


def _read(name: str) -> str:
    return (WEB / name).read_text(encoding="utf-8")


class TestRadarMarkup:
    def test_radar_card_exists_below_connection(self):
        html = _read("index.html")
        radar_pos = html.find('id="radar-scope"')
        conn_pos = html.find('id="connection-toggle"')
        traffic_pos = html.find('id="traffic-heading"')
        assert radar_pos > conn_pos > 0
        assert radar_pos < traffic_pos

    def test_radar_structure(self):
        html = _read("index.html")
        assert 'id="radar-canvas"' in html
        assert 'id="radar-tooltip"' in html
        assert 'id="radar-state-label"' in html
        assert 'id="radar-legend"' in html
        assert 'id="radar-hud"' in html
        # Honest labeling: this is a local schematic, not packet capture.
        assert "local telemetry" in html

    def test_legend_colours_match_canvas_states(self):
        css = _read("styles.css")
        for state in ("ok", "degraded", "failed", "inactive"):
            assert f"radar-dot--{state}" in css
        source = _read("app.js")
        # The canvas palette must expose the same four canonical states.
        assert "degraded: '#e8b34a'" in source
        assert "failed: '#e5554d'" in source


class TestRadarStateLogic:
    def test_contacts_only_map_from_real_fields(self):
        source = _read("app.js")
        assert "exit_verification_state" in source
        assert "d.tunnel" in source
        assert "traffic_verified" in source
        assert "session_pool" in source
        assert "proxy_only_mode" in source
        assert "_radarContacts" in source
        assert "exit_verification_state || ''" in source

    def test_verified_contact_states(self):
        source = _read("app.js")
        # contacts derive one of the four canonical states from evidence
        for state in ("ok", "degraded", "failed", "inactive"):
            assert f"'{state}'" in source
        assert "RADAR_COLOURS[contact.state]" in source

    def test_self_sweep_with_no_false_contacts(self):
        source = _read("app.js")
        assert "instrument self-sweep" in source
        # A failed tunnel is labelled from its real detail, never "connected".
        assert "ATTENTION \u00b7 " in source or "ATTENTION · " in source
        assert "no false active contacts" not in source

    def test_no_random_or_dummy_data_in_radar(self):
        source = _read("app.js")
        assert "Math.random" not in source
        assert "setTimeout(Math" not in source

    def test_tooltip_content(self):
        source = _read("app.js")
        assert "showRadarTooltip" in source
        assert "Verified operational" in source
        assert "Last verified" in source


class TestAllowanceGauge:
    def test_gauge_markup(self):
        html = _read("index.html")
        assert 'id="allowance-gauge"' in html
        assert 'id="gauge-arc"' in html
        assert 'id="gauge-used"' in html
        assert 'id="gauge-allowance"' in html
        assert 'id="gauge-remaining"' in html
        assert 'id="gauge-percents"' in html
        assert 'id="gauge-reset"' in html
        assert 'id="gauge-source"' in html
        assert "allowance gauge" in html

    def test_css_gauge_structure(self):
        css = _read("styles.css")
        assert ".gauge-arc" in css
        assert "stroke-dasharray" in css
        assert "stroke-dashoffset" in css
        assert "gaugeArcGrad" in css
        # thresholds colour classes exist
        assert "gauge-arc--warn" in css
        assert "gauge-arc--crit" in css

    def test_threshold_colors(self):
        source = _read("app.js")
        assert "gauge-arc--ok" in source
        assert "gauge-arc--warn" in source
        assert "gauge-arc--crit" in source
        assert "remainingPercent <= 5" in source
        assert "remainingPercent <= 25" in source

    def test_used_values_come_from_quota_response(self):
        source = _read("app.js")
        assert "q.used_bytes" in source or "q.used_percent" in source
        assert "formatAllowance(q.max_bytes)" in source
        assert "q.max_bytes" in source

    def test_unavailable_state_is_honest(self):
        source = _read("app.js")
        assert "Usage unavailable" in source
        # reset date only when authoritative
        assert "if (q.reset_epoch)" in source
        assert "never invent one" in source

    def test_unlimited_account(self):
        source = _read("app.js")
        assert "gauge_state === 'unlimited'" in source


class TestLiveLogsUI:
    def test_dashboard_log_panel_structure(self):
        html = _read("index.html")
        assert 'id="log-severity-filter"' in html
        assert 'id="log-component-filter"' in html
        assert 'id="log-pause"' in html
        assert 'id="log-clear"' in html
        assert 'id="log-copy"' in html
        assert 'id="log-container"' in html

    def test_strip_exists(self):
        html = _read("index.html")
        assert 'id="diag-strip"' in html

    def test_rendering_uses_structure(self):
        source = _read("app.js")
        assert "renderLogEvents" in source
        assert "pollDiagnosticsEvents" in source
        assert "/api/events?after=" in source
        # Severity is classed dynamically from the structured event field
        assert "log-sev log-sev--${last.severity}" in source
        assert "log-sev log-sev--${ev.severity}" in source

    def test_pause_only_display(self):
        source = _read("app.js")
        assert "_eventPaused" in source
        assert "keep server buffer" in source

    def test_clear_only_clears_display(self):
        source = _read("app.js")
        assert "Clear the visible history only" in source

    def test_components_seeded_into_datalist(self):
        source = _read("app.js")
        assert "_seenComponents" in source
        assert "log-component-list" in source


class TestNoRegression:
    def test_onboarding_prompt_still_driven_by_definitive_state(self):
        source = _read("app.js")
        assert "updateOnboarding" in source
        assert "if (this._authenticated === false)" in source

    def test_in_app_signin_form_markup(self):
        html = _read("index.html")
        assert 'id="signin-form"' in html
        assert 'id="signin-email"' in html
        assert 'id="signin-password"' in html
        assert 'id="signin-password-toggle"' in html
        assert 'id="signin-submit"' in html
        assert 'id="signin-error"' in html
        assert 'id="signin-verify"' in html
        assert 'id="signin-code"' in html
        assert 'id="verify-submit"' in html
        assert 'id="verify-cancel"' in html

    def test_password_never_persisted_frontend(self):
        source = _read("app.js")
        # Never in localStorage
        assert "localStorage.setItem('perch" not in source
        # Cleared on completion and unmount
        assert "passwordInput.value = ''" in source
        assert "beforeunload" in source

    def test_show_hide_toggle(self):
        source = _read("app.js")
        assert "input.type = showing ? 'password' : 'text'" in source
