"""Static and API checks for mode switching and frame telemetry."""

from __future__ import annotations

import asyncio
from pathlib import Path

from perchvpn_windows import api as api_module

WEB = Path(__file__).resolve().parents[1] / "src" / "perchvpn_windows" / "web"


def _read(name: str) -> str:
    return (WEB / name).read_text(encoding="utf-8")


class TestRadarPerformance:
    def test_static_geometry_is_cached_offscreen(self):
        src = _read("app.js")
        assert "radarStaticLayer(" in src
        assert "drawImage(staticLayer" in src
        assert "_radarStaticKey" in src
        assert "_radarStaticRev" in src
        assert "radarTrailLayer(" in src
        assert "drawImage(trail" in src
        assert "radarContactSprite(" in src

    def test_frame_loop_pauses_when_hidden_and_is_dt_paced(self):
        src = _read("app.js")
        assert "document.hidden" in src
        assert "_radarPhaseMs" in src
        assert "visibilitychange" in src

    def test_fps_telemetry_is_measured_and_posted(self):
        src = _read("app.js")
        assert "window.__perchPerf" in src
        assert "/api/client-perf" in src
        assert "PerformanceObserver" in src

    def test_no_backdrop_filter_paint_storms(self):
        assert "backdrop-filter" not in _read("styles.css")


class TestIdleRepaintGuards:
    def test_train_loop_throttles_when_disconnected_and_pauses_when_hidden(self):
        src = _read("app.js")
        train = src[src.index("TICK_MIN_MS:"):src.index("window.GearCoreRef")]
        assert "TICK_MIN_MS_IDLE" in train
        assert "this.state === 'disconnected'" in train
        core_init = src[src.index("const GearCore ="):src.index("TICK_MIN_MS:")]
        assert "if (document.hidden) this.pause();" in core_init
        assert "window.addEventListener('blur', () => this.pause())" in core_init

    def test_status_state_transitions_render_while_hidden(self):
        src = _read("app.js")
        frame = src[src.index("applyStatusFrame(data) {"):src.index("async updateDashboard()")]
        assert "if (document.hidden)" in frame
        assert "this._statusRenderPending = true;" in frame
        # State transitions must never wait for visibility; traffic-only
        # frames still coalesce until the window returns.
        assert "if (stateChanged) this.renderDashboard(data);" in frame
        boot = src[src.index("async init() {"):src.index("bindTabEvents() {")]
        assert "this.resumeStatusUpdates()" in boot
        assert "window.addEventListener('focus'" in boot

    def test_status_poll_skips_hidden_windows(self):
        src = _read("app.js")
        polling = src[src.index("startStatusPolling() {"):src.index("stopStatusPolling() {")]
        assert "if (document.hidden) return;" in polling

    def test_radar_stops_on_hidden_other_tab_and_blur(self):
        src = _read("app.js")
        radar = src[src.index("startRadarLoop() {"):src.index("_startPerfTelemetry() {")]
        assert "document.hidden || this.currentTab !== 'dashboard'" in radar
        assert "window.addEventListener('blur'" in radar

    def test_radar_pauses_when_disconnected(self):
        src = _read("app.js")
        radar = src[src.index("startRadarLoop() {"):src.index("_startPerfTelemetry() {")]
        assert "this._uiState === UI_STATE.DISCONNECTED" in radar
        assert "this._uiState === UI_STATE.TUN_FAILED" in radar
        assert "this._radarIdleFrame = true;" in radar
        apply = src[src.index("applyState(state, d) {"):src.index("formatExitLabel(ip) {")]
        assert "const prevState = this._uiState;" in apply
        assert "this.startRadarLoop();" in apply

    def test_radar_active_cadence_is_30fps(self):
        src = _read("app.js")
        assert "TICK_MIN_MS: 50" in src
        assert "RADAR_FRAME_MS = 1000 / 30" in src
        assert "RADAR_MAX_DT_MS = 50" in src
        assert "_radarNextDraw" in src

    def test_radar_dt_is_clamped_after_stalls(self):
        src = _read("app.js")
        assert (
            "Math.min(Math.max(0, ts - this._radarLastTs), this.RADAR_MAX_DT_MS)"
            in src
        )

    def test_radar_draw_avoids_per_frame_layout_and_shadow(self):
        src = _read("app.js")
        draw = src[
            src.index("drawRadar(ts) {"):src.index("radarStaticLayer(size, dpr, px) {")
        ]
        assert "getBoundingClientRect" not in draw
        assert "createRadialGradient" not in draw
        assert "shadowBlur" not in draw
        assert "RADAR_COLOURS" in draw
        assert "_radarSize" in draw
        assert "_radarDpr" in draw

    def test_animated_svg_layers_are_composited(self):
        css = _read("styles.css")
        gear = css[css.index(".gear {"):css.index(".gear--c {")]
        assert "will-change: transform" in gear
        rays = css[css.index(".gearcore__rays {"):css.index(".gear--c {")]
        assert "will-change: transform" in rays
        assert "will-change: opacity" in css
        scope = css[css.index(".radar-scope {"):css.index(".radar-scope::after")]
        assert "contain: layout paint" in scope
        canvas = css[css.index("#radar-canvas {"):css.index("/* Heads-up readouts")]
        assert "will-change: transform" in canvas

    def test_state_apply_skips_identical_dom_writes(self):
        src = _read("app.js")
        apply = src[src.index("applyState(state, d) {"):src.index("formatExitLabel(ip) {")]
        assert "if (statusEl.textContent !== text)" in apply
        assert "if (header.className !== headerClass)" in apply
        assert "btnText.textContent !== buttonState.label" in apply

    def test_country_latency_backs_off_when_disconnected_idle(self):
        src = _read("app.js")
        gate = src[src.index("_latencyShouldProbe() {"):src.index("_syncCountriesLatencyTimer() {")]
        assert "state !== UI_STATE.DISCONNECTED" in gate
        assert "state !== UI_STATE.TUN_FAILED" in gate
        timer = src[src.index("_syncCountriesLatencyTimer() {"):src.index("_resumeCountriesLatency() {")]
        assert "this._latencyTimerWanted" in timer
        assert "window.clearInterval(this._latencyTimer)" in timer
        resume = src[src.index("_resumeCountriesLatency() {"):src.index("setCountriesLatencyTimer(on) {")]
        assert "this.countriesLatencyCycle(true)" in resume
        assert "document.hidden" in resume

    def test_unchanged_status_frames_skip_state_dom_writes(self):
        src = _read("app.js")
        key = src[src.index("_stateRenderKey(state, d) {"):src.index("formatExitLabel(ip) {")]
        assert "modes.selected" in key
        assert "tunnel.detail" in key
        assert "this._actionBusy" in key
        start = src.index("renderDashboard(d) {")
        render = src[start:src.index("const set = (id, text)", start)]
        assert "stateKey !== this._lastStateRenderKey" in render
        assert "this.applyState(state, d);" in render

    def test_country_latency_sweep_is_bounded(self):
        src = _read("app.js")
        cycle = src[src.index("countriesLatencyCycle(force = false) {"):src.index("async latencyWorker(queue, gen, force) {")]
        assert "Math.min(4, queue.length)" in cycle
        assert "this._authenticated !== true" in cycle
        measure = src[src.index("async measureLatency(target, gen, force = false) {"):src.index("latencyErrorLabel(message) {")]
        assert "(Date.now() - cached.at) < 60000" in measure

    def test_idle_poll_intervals_stay_bounded(self):
        src = _read("app.js")
        auth = src[src.index("startAuthPolling() {"):src.index("async refreshAuthState()")]
        assert "if (!document.hidden) this.refreshAuthState();" in auth
        assert "}, 4000);" in auth
        latency = src[src.index("_latencyShouldProbe() {"):src.index("updateSelectedCountry(d) {")]
        assert "if (document.hidden) return false;" in latency
        assert "this._authenticated !== true" in latency
        assert "}, 60000);" in latency
        # Disconnected-idle must stop the periodic timer entirely; a single
        # fresh sweep is still allowed when the selector regains focus.
        assert "_syncCountriesLatencyTimer()" in latency
        assert "_resumeCountriesLatency()" in latency
        assert "this.countriesLatencyCycle(true)" in latency
        diag = src[src.index("pollDiagnosticsEvents() {"):src.index("pushEvent(ev) {")]
        assert "if (document.hidden || this.currentTab !== 'dashboard') return;" in diag


class TestModeUi:
    def test_proxy_button_sends_real_proxy_mode(self):
        src = _read("app.js")
        assert "setConnectionMode('proxy')" in src
        assert "setConnectionMode('proxy_only')" not in src
        assert "mode === 'tun' ? 'TUN' : 'Proxy'" in src

    def test_mode_switch_applies_live_with_transition_lock(self):
        src = _read("app.js")
        assert "const live = this.isLiveConnection();" in src
        assert "JSON.stringify({ mode, apply: live })" in src
        assert "_uiTransition" in src
        # a mode switch must not trigger a whole-app restart any more
        start = src.index("setConnectionMode(mode) {")
        end = src.index("refreshAuthState()", start)
        assert "restartVPN()" not in src[start:end]

    def test_proxy_label_is_not_proxy_only(self):
        html = _read("index.html")
        assert 'id="mode-proxy-only"' in html
        assert ">Proxy</button>" in html


class TestClientPerfEndpoint:
    def test_route_is_registered(self):
        paths = {getattr(route, "path", "") for route in api_module.app.routes}
        assert "/api/client-perf" in paths

    def test_round_trip_sample(self):
        result = asyncio.run(
            api_module.post_client_perf(
                api_module.ClientPerfRequest(
                    fps=58, frames=58, longTasks=0, worstFrameMs=21.4, size="420px"
                )
            )
        )
        assert result["success"] is True
        stored = asyncio.run(api_module.get_client_perf())
        assert stored["sample"]["fps"] == 58
        assert stored["sample"]["size"] == "420px"
