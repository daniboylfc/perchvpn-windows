// Perch VPN — WebView2 frontend application
//
// Futuristic cyberpunk UI controller (crimson theme retained).
//
// Responsibilities:
//   • Left-rail navigation across Dashboard / Countries / Network / Account
//   • Accurate connection + exit-verification state presentation
//   • Settings load / save / reset with preserved validation and defaults
//   • Live traffic + status polling and WebSocket activity log
//
// No telemetry, no remote assets. All state comes from the local API.

(function() {
    'use strict';

    const API_BASE = window.location.origin;
    const POLL_MS = 2000;
    const EVENT_LOG_MAX = 400;
    // Legacy storage key retained so an existing rail-collapsed preference
    // survives the rebrand (renaming it would silently reset the UI state).
    const RAIL_STORAGE_KEY = 'perchvpn.rail.collapsed';

    // Country flags bundled locally from lipis/flag-icons (MIT) — see
    // web/assets/flags/LICENSE. Only these codes resolve to a local SVG;
    // anything else falls back to the regional-indicator emoji.
    const FLAGS_BUNDLED = new Set([
        'AR','AT','AU','BE','BG','BR','CA','CL','CO','DE','DK','ES','FI','FR','GB','GH','IE','IT','JP','KR','MX','MY','NL','NO','NZ','PE','PH','PT','SE','SG','TH','US','ZA'
    ]);

    function normaliseCountryCode(code) {
        if (!code) return '';
        const raw = String(code).trim().toUpperCase();
        if (raw.length !== 2 || raw === 'REC') return '';
        const a = raw.charCodeAt(0), b = raw.charCodeAt(1);
        if (a < 65 || a > 90 || b < 65 || b > 90) return '';
        return raw.toLowerCase();
    }

    // Presentation-only mapping of the backend's three controller states.
    // The controller reports one of: 'connected', 'connecting', 'disconnected'.
    const CONTROLLER_STATE = Object.freeze({
        CONNECTED: 'connected',
        CONNECTING: 'connecting',
        DISCONNECTED: 'disconnected'
    });

    // exit_verification_state values reported by the backend.
    //  not_applicable  — no exit check was started (disabled or no country code)
    //  pending         — check is in flight
    //  verified        — check succeeded; exit IP + country are real observations
    //  failed          — check ran but could not be completed / endpoint failed
    const EXIT_STATE = Object.freeze({
        NOT_APPLICABLE: 'not_applicable',
        PENDING: 'pending',
        VERIFIED: 'verified',
        FAILED: 'failed'
    });

    // Single source of truth for the distinguishable UI states.
    const UI_STATE = Object.freeze({
        DISCONNECTED: 'disconnected',
        CONNECTING: 'connecting',
        CONNECTED_VERIFYING: 'connected_verifying',   // proxy up, exit check pending
        CONNECTED_VERIFIED: 'connected_verified',      // proxy up, exit check succeeded
        CONNECTED_UNVERIFIED: 'connected_unverified',  // proxy up, exit check failed/unavailable
        PROXY_ACTIVE: 'proxy_active',                  // proxy-only mode: SOCKS5 proxy up, no tunnel
        TUN_DEGRADED: 'tun_degraded',                  // TUN up but system traffic not verified
        TUN_FAILED: 'tun_failed'                       // TUN requested but could not serve
    });

    const RADAR_COLOURS = Object.freeze({
        ok: '#52e58c',
        degraded: '#e8b34a',
        failed: '#e5554d',
        inactive: 'rgba(140, 158, 148, 0.32)',
    });

    const STATE_META = Object.freeze({
        [UI_STATE.DISCONNECTED]: {
            stateClass: 'is-disconnected',
            statusText: 'Disconnected',
            headerClass: 'status-indicator--disconnected',
            headerText: 'Disconnected',
            detail: 'Disconnected',
            detailClass: 'info-value--disconnected',
            verification: 'Not applicable',
            verificationClass: 'info-value--unavailable',
            subtext: 'The local proxy is not running. Connect to route traffic through the VPN.',
            exitIp: 'Not available',
            exitCountry: 'Not available'
        },
        [UI_STATE.CONNECTING]: {
            stateClass: 'is-connecting',
            statusText: 'Connecting',
            headerClass: 'status-indicator--connecting',
            headerText: 'Connecting',
            detail: 'Setting up tunnel',
            detailClass: 'info-value--connecting',
            verification: 'Pending',
            verificationClass: 'info-value--pending',
            subtext: 'Establishing the VPN connection; status updates automatically.',
            exitIp: 'Pending',
            exitCountry: 'Pending'
        },
        [UI_STATE.CONNECTED_VERIFYING]: {
            stateClass: 'is-connecting',
            statusText: 'Connected — verifying exit',
            headerClass: 'status-indicator--connected',
            headerText: 'Connected',
            detail: 'Connected — verifying exit',
            detailClass: 'info-value--connecting',
            verification: 'Verifying exit location',
            verificationClass: 'info-value--pending',
            subtext: 'The proxy is up. The exit location is still being verified.',
            exitIp: 'Verifying…',
            exitCountry: 'Verifying…'
        },
        [UI_STATE.CONNECTED_VERIFIED]: {
            stateClass: 'is-connected',
            statusText: 'Connected — exit verified',
            headerClass: 'status-indicator--connected',
            headerText: 'Connected',
            detail: 'Connected — exit verified',
            detailClass: 'info-value--connected',
            verification: 'Exit location verified',
            verificationClass: 'info-value--verified',
            subtext: 'The proxy is up and the exit location has been verified.',
            exitIp: null,
            exitCountry: null
        },
        [UI_STATE.CONNECTED_UNVERIFIED]: {
            stateClass: 'is-error',
            statusText: 'Connected — exit not verified',
            headerClass: 'status-indicator--error',
            headerText: 'Exit not verified',
            detail: 'Connected — exit not verified',
            detailClass: 'info-value--error',
            verification: 'Could not verify exit location',
            verificationClass: 'info-value--failed',
            subtext: 'The proxy is up, but the exit location could not be verified. Traffic may not match the expected country.',
            exitIp: 'Unavailable',
            exitCountry: 'Unavailable'
        },
        [UI_STATE.PROXY_ACTIVE]: {
            stateClass: 'is-connected',
            statusText: 'SOCKS5 only',
            headerClass: 'status-indicator--connected',
            headerText: 'SOCKS5 only',
            detail: 'SOCKS5 proxy active — system traffic not tunnelled',
            detailClass: 'info-value--connecting',
            verification: 'SOCKS5 exit',
            verificationClass: 'info-value--pending',
            subtext: 'Apps pointed at the local SOCKS5 proxy use the VPN; Windows system traffic is not tunnelled.',
            exitIp: null,
            exitCountry: null
        },
        // Tunnel degraded/failed presentation (header pill, chip, button
        // semantics) lives in status-contract.js so the Node behaviour
        // harness and this UI cannot drift.
        ...window.PerchStatusContract.META
    });

    // Neutral latency label while signed out: rows were one probe away from
    // "No pass" noise; until an authenticated cycle runs they stay candid.
    const SIGNED_OUT_LATENCY_LABEL = 'Sign in';

    const PLACEHOLDER = '—';

    // Dirty-checked text write: skip DOM writes when the rendered value is
    // already current (avoids text-node replacement + recalc every poll).
    function setTextIfChanged(el, text) {
        if (!el || el.textContent === text) return;
        el.textContent = text;
    }

    // ------------------------------------------------------------
    // Gear energy core (mechanical connection button centerpiece)
    //
    // Drives the three intermeshing SVG gears and the crimson glow. Syncs
    // strictly with the existing state machine by observing #connection-
    // state[data-state]; connection logic itself is untouched. Angles:
    // the side gears rotate at exactly -2x the central angle (36/18/18
    // teeth, geometry validated in the generator), so teeth stay meshed.
    // One lifecycle-managed rAF loop: runs only while the core is active
    // or decelerating, idles out when dormant, and pauses with the page.
    // Respects prefers-reduced-motion (no loop, static per-state glow).
    // ------------------------------------------------------------
    const GearCore = {
        pointer: null,
        scene: null,
        glow: null,
        sheen: null,
        gears: [],
        state: 'disconnected',
        angle: 0,          // central gear angle, degrees
        speed: 0,          // central gear speed, deg/s
        glowCur: 0.13,
        rafId: 0,
        running: false,
        lastTs: 0,
        reduced: false,

        // Central gear operating speed (deg/s): one turn in ~27s.
        OPERATING: 13.3,
        TAU_SPEED: 1150,   // ms, accel/decel time constant
        TAU_GLOW: 700,     // ms, glow ramp time constant
        TARGETS: {
            disconnected: 0.13,
            connecting: 0.55,
            connected_verifying: 0.78,
            connected_verified: 0.92,
            connected_unverified: 0.66,
            proxy_active: 0.92,
            tun_degraded: 0.66,
            tun_failed: 0.13
        },
        // Full-lifecycle presentation. The train idles when disconnected,
        // churns while connecting and runs faster once verified. Reduced
        // motion runs the same map at one-third speed (dials static when
        // disconnected and at rest, per the calm-presentation policy).
        SPEEDS: {
            disconnected: 4.7,
            connecting: 9.0,
            connected_verifying: 13.3,
            connected_verified: 20.0,
            connected_unverified: 13.3,
            proxy_active: 20.0,
            tun_degraded: 13.3,
            tun_failed: 4.7
        },
        PULSE_AMPLITUDE: {
            connecting: 0.07,
            connected_verified: 0.06
        },
        PULSE_PERIOD: {
            connecting: 3200,
            connected_verified: 7600
        },
        RADIANCE: {
            connected_verified: 0.85,
            connected_unverified: 0.68,
            proxy_active: 0.85,
            tun_degraded: 0.6
        },

        init() {
            const chip = document.getElementById('connection-state');
            const btn = document.getElementById('connection-toggle');
            this.scene = btn ? btn.querySelector('.gearcore') : null;
            if (!chip || !this.scene) return;
            this.glow = this.scene.querySelector('.gearcore__glow');
            this.sheen = this.scene.querySelector('.gearcore__sheen');
            this.radiance = this.scene.querySelector('.gearcore__radiance');
            this.rays = this.scene.querySelector('.gearcore__rays');
            this.gears = [
                this.scene.querySelector('.gear--c'),
                this.scene.querySelector('.gear--l'),
                this.scene.querySelector('.gear--r')
            ].filter(Boolean);
            if (!this.glow || this.gears.length !== 3) return;

            const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
            this.reduced = mq.matches;
            const mqChanged = () => {
                if (mq.matches !== this.reduced) {
                    this.reduced = mq.matches;
                    if (this.reduced) this.pause();
                    this.apply();
                }
            };
            if (mq.addEventListener) {
                mq.addEventListener('change', mqChanged);
            }
            this._mqChangedHandler = mqChanged;

            this.observer = new MutationObserver(() => this.apply());
            this.observer.observe(chip, { attributes: true, attributeFilter: ['data-state'] });
            document.addEventListener('visibilitychange', () => {
                if (document.hidden) this.pause();
                else this.apply();
            });
            // The train idles at 4.7 deg/s while disconnected and never
            // rests, so the loop used to write three transforms plus glow
            // opacities every display frame forever (~8-12% of a WebView2
            // renderer in task-manager terms).  Two cheap guards: cap the DOM
            // writes at 30 fps and stop entirely while the window is in the
            // background, resuming on focus.
            document.addEventListener('visibilitychange', () => {
                if (!document.hidden) this._lastTs = 0;
            });
            window.addEventListener('blur', () => this.pause());
            window.addEventListener('focus', () => this.apply());

            this.apply();
        },

        apply() {
            const chip = document.getElementById('connection-state');
            const state = chip ? (chip.getAttribute('data-state') || 'disconnected') : 'disconnected';
            this.state = state;
            this.scene.dataset.state = state;

            const target = this.TARGETS[state] != null ? this.TARGETS[state] : 0.13;
            if (this.reduced) {
                // Calm presentation: train turns at one-third operating
                // speed, state glow held flat (no pulse, no breath).
                const atRest = state === 'disconnected'
                    && this.angle === 0
                    && Math.abs(this.speed) < 0.05
                    && Math.abs(this.glowCur - target) < 0.01;
                this.glowCur = target;
                this.glow.style.opacity = String(target);
                this.sheen.style.opacity = String(target * 0.9);
                this.setRadiance(String(target * this.radianceFactor()));
                if (atRest) {
                    this.setTransforms(0);
                    this.pause();
                    return;
                }
                this.start();
                return;
            }
            // Full motion: the train never rests (disconnected idles at slow
            // speed); glow targets are reached inside the tick loop.
            this.start();
        },

        radianceFactor() {
            const f = this.RADIANCE[this.state];
            return f != null ? f : 0.75;
        },

        setTransforms(centerDeg) {
            // Side gears counter-rotate the central gear at exactly 2x its
            // angular velocity (36:18 teeth); both sides turn together.
            // The radiance rays drift gently against the train for parallax.
            this.gears[0].style.transform = 'rotate(' + centerDeg.toFixed(3) + 'deg)';
            const sideDeg = (-2 * centerDeg).toFixed(3);
            this.gears[1].style.transform = 'rotate(' + sideDeg + 'deg)';
            this.gears[2].style.transform = 'rotate(' + sideDeg + 'deg)';
            if (this.rays) this.rays.style.transform = 'rotate(' + (-0.3 * centerDeg).toFixed(3) + 'deg)';
        },

        setRadiance(v) {
            if (this.radiance) this.radiance.style.opacity = v;
        },

        pause() {
            this.running = false;
            if (this.rafId) {
                cancelAnimationFrame(this.rafId);
                this.rafId = 0;
            }
        },

        start() {
            if (this.running) return;
            this.running = true;
            this.lastTs = 0;
            this.rafId = requestAnimationFrame(ts => this.tick(ts));
        },

        TICK_MIN_MS: 50, // 20 fps DOM-write ceiling while active
        TICK_MIN_MS_IDLE: 100, // 10 fps is enough for the 4.7 deg/s idle drift

        tick(ts) {
            if (!this.running) return;
            if (!this.lastTs) this.lastTs = ts;
            const minMs = this.state === 'disconnected'
                ? this.TICK_MIN_MS_IDLE
                : this.TICK_MIN_MS;
            if (ts - this.lastTs < minMs) {
                this.rafId = requestAnimationFrame(t => this.tick(t));
                return;
            }
            const dt = Math.min(ts - this.lastTs, 120) / 1000;
            this.lastTs = ts;

            // Non-linear smoothing = seamless mechanical accel/decel.
            let targetSpeed;
            if (this.reduced) {
                targetSpeed = this.state === 'disconnected'
                    ? 0
                    : (this.SPEEDS[this.state] || this.OPERATING) / 3;
            } else {
                targetSpeed = this.SPEEDS[this.state] != null ? this.SPEEDS[this.state] : this.OPERATING;
            }
            this.speed += (targetSpeed - this.speed) * (1 - Math.exp(-dt * 1000 / this.TAU_SPEED));
            this.angle = (this.angle + this.speed * dt) % 360;

            // Crimson core: per-state pulse (connecting churn breathes fast,
            // verified breathes slowly). Reduced mode holds it flat.
            const target = this.TARGETS[this.state] != null ? this.TARGETS[this.state] : 0.13;
            let pulse = 0;
            const amp = this.PULSE_AMPLITUDE[this.state];
            if (!this.reduced && amp) {
                pulse = amp * Math.sin(Math.PI * 2 * ts / (this.PULSE_PERIOD[this.state] || 7600));
            }
            this.glowCur += (target + pulse - this.glowCur) * (1 - Math.exp(-dt * 1000 / this.TAU_GLOW));

            this.glow.style.opacity = this.glowCur.toFixed(3);
            this.sheen.style.opacity = (this.glowCur * 0.92).toFixed(3);
            this.setRadiance((this.glowCur * this.radianceFactor()).toFixed(3));
            this.setTransforms(this.angle);

            // Idle out of the background only in reduced mode, where a
            // disconnected core at rest stays fully static.
            if (this.reduced && this.state === 'disconnected'
                && Math.abs(this.speed) < 0.02
                && Math.abs(this.glowCur - target) < 0.005
                && Math.abs(this.angle) < 0.01) {
                this.angle = 0;
                this.speed = 0;
                this.setTransforms(0);
                this.glow.style.opacity = target.toFixed(3);
                this.sheen.style.opacity = (target * 0.9).toFixed(3);
                this.setRadiance((target * 0.75).toFixed(3));
                this.pause();
                return;
            }
            this.rafId = requestAnimationFrame(t => this.tick(t));
        }
    };
    window.GearCoreRef = GearCore;

    class PerchVPNApp {
        constructor() {
            this.currentTab = 'dashboard';
            this.pollTimer = null;
            this.ws = null;
            this.apiUp = false;
            // Authentication state: null while the first /api/account check
            // is in-flight (never treated as signed out), true/false once
            // known. Drives the onboarding prompt and latency probing.
            this._authenticated = null;
            this._authNotice = '';
            this._countryLatency = Object.create(null);
            this._countrySortRaf = 0;
            // In-flight lifecycle guards: keep optimistic state authoritative
            // until the request settles (the 2s poll must not re-enable the
            // button or start an overlapping connect/disconnect).
            this._actionBusy = false;
            this._modeBusy = false;
            this._uiTransition = null;
            // User's mode selection (proxy|tun). Kept explicitly so Connect
            // sends the button they picked, never a stale config flag.
            this._selectedMode = null;
            this.init();
        }

        // ------------------------------------------------------------
        // Boot
        // ------------------------------------------------------------

        async init() {
            this.bindTabEvents();
            this.bindFormEvents();
            this.bindNavExtras();
            GearCore.init();
            this.initRadar();
            this.restoreRailState();
            // Status frames keep arriving over the socket while the window is
            // hidden. State transitions are rendered immediately (they must
            // never wait for visibility); traffic-only frames are coalesced
            // and replayed on return, and every return resyncs /api/status
            // because the backend may have moved while the window was hidden
            // (UAC secure desktop, minimized window, WS reconnect).
            document.addEventListener('visibilitychange', () => {
                if (!document.hidden) this.resumeStatusUpdates();
            });
            window.addEventListener('focus', () => this.resumeStatusUpdates());
            this.startStatusPolling();
            this.startAuthPolling();
            this.loadCountries();
            this.prewarmFlags();
            this.setCountriesLatencyTimer(true);
            this.connectStatusWebSocket();
            this.connectLogWebSocket();
            this.bindDiagnostics();
            this.updateOnboarding();
        }

        // ------------------------------------------------------------
        // Navigation
        // ------------------------------------------------------------

        bindTabEvents() {
            const items = document.querySelectorAll('.rail__item');
            items.forEach(item => {
                item.addEventListener('click', () => {
                    this.switchTab(item.dataset.tab);
                });
            });

            // Keyboard navigation within the rail
            const rail = document.getElementById('rail');
            if (rail) {
                rail.addEventListener('keydown', (ev) => {
                    if (ev.key !== 'ArrowDown' && ev.key !== 'ArrowUp') return;
                    const tabs = Array.from(document.querySelectorAll('.rail__item'));
                    const idx = tabs.indexOf(document.activeElement);
                    if (idx === -1) return;
                    ev.preventDefault();
                    const next = ev.key === 'ArrowDown'
                        ? (idx + 1) % tabs.length
                        : (idx - 1 + tabs.length) % tabs.length;
                    tabs[next].focus();
                });
            }
        }

        switchTab(tabName) {
            document.querySelectorAll('.rail__item').forEach(t => {
                const active = t.dataset.tab === tabName;
                t.classList.toggle('rail__item--active', active);
                t.setAttribute('aria-selected', active ? 'true' : 'false');
            });

            document.querySelectorAll('.tab-panel').forEach(c => {
                const active = c.id === `${tabName}-panel`;
                c.classList.toggle('tab-panel--active', active);
                if (active) c.removeAttribute('hidden');
                else c.setAttribute('hidden', '');
            });

            this.currentTab = tabName;
            if (tabName === 'dashboard') {
                this._radarLastTs = 0;
                if (typeof this.startRadarLoop === 'function') this.startRadarLoop();
            }
            const title = document.getElementById('page-title');
            if (title) {
                title.textContent = tabName.charAt(0).toUpperCase() + tabName.slice(1);
            }

            if (tabName === 'dashboard' || tabName === 'countries') {
                // Prices of rebuilding rows: full innerHTML teardown recreates
                // every flag <img> and resets scroll. /api/countries data is
                // already in memory; only fetch when it has never loaded.
                if (!this._countries || !this._countries.length) this.loadCountries();
                this.setCountriesLatencyTimer(true);
                if (tabName === 'countries') this._resumeCountriesLatency();
            } else {
                this.setCountriesLatencyTimer(false);
            }
            if (tabName === 'network') {
                this.loadNetworkConfig();
            } else if (tabName === 'account') {
                this.loadAccount();
                this.refreshQuota();
            }
            if (tabName !== 'account' && tabName !== 'network' && this._quotaTimer) {
                clearInterval(this._quotaTimer);
                this._quotaTimer = null;
            }
        }

        // ------------------------------------------------------------
        // Rail collapse toggle
        // ------------------------------------------------------------

        bindNavExtras() {
            const collapse = document.getElementById('rail-collapse');
            const rail = document.getElementById('rail');
            if (!collapse || !rail) return;

            collapse.addEventListener('click', () => {
                const collapsed = rail.classList.toggle('is-collapsed');
                collapse.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
                collapse.setAttribute('aria-label', collapsed ? 'Expand navigation' : 'Collapse navigation');
                try {
                    localStorage.setItem(RAIL_STORAGE_KEY, collapsed ? '1' : '0');
                } catch (e) { /* storage may be unavailable */ }
            });
        }

        restoreRailState() {
            const rail = document.getElementById('rail');
            const collapse = document.getElementById('rail-collapse');
            if (!rail || !collapse) return;
            let stored = null;
            try {
                stored = localStorage.getItem(RAIL_STORAGE_KEY);
            } catch (e) { /* ignore */ }
            if (stored === '1') {
                rail.classList.add('is-collapsed');
                collapse.setAttribute('aria-expanded', 'false');
                collapse.setAttribute('aria-label', 'Expand navigation');
            }
        }

        // ------------------------------------------------------------
        // API helper
        // ------------------------------------------------------------

        async api(path, options = {}) {
            const res = await fetch(`${API_BASE}${path}`, {
                headers: { 'Content-Type': 'application/json' },
                // Never latch _actionBusy forever on a wedged backend: every
                // request aborts after 60s so the button state always settles.
                signal: AbortSignal.timeout(60000),
                ...options
            });
            if (!res.ok) {
                const err = await res.json().catch(() => ({ detail: res.statusText }));
                // FastAPI validation errors arrive as an array of detail
                // objects; a raw object would render as "[object Object]".
                let detail = err.detail;
                if (Array.isArray(detail)) {
                    const first = detail[0] || {};
                    detail = (typeof first.msg === 'string' && first.msg) || 'Request was rejected (invalid input)';
                } else if (detail && typeof detail === 'object') {
                    detail = (typeof detail.message === 'string' && detail.message) || 'Request was rejected';
                }
                throw new Error(detail || `HTTP ${res.status}`);
            }
            return res.json();
        }

        // ------------------------------------------------------------
        // Status polling
        // ------------------------------------------------------------

        startStatusPolling() {
            this._pollFailures = 0;
            this.updateDashboard();
            if (!this.pollTimer) {
                this.pollTimer = setInterval(() => {
                    if (document.hidden) return; // WS/poll fallback: no hidden fetches
                    this.updateDashboard();
                }, POLL_MS);
            }
        }

        stopStatusPolling() {
            if (this.pollTimer) {
                clearInterval(this.pollTimer);
                this.pollTimer = null;
            }
        }

        // Real-time state push: /ws/status delivers the same payload as
        // /api/status immediately on every backend transition (tunnel state,
        // exit verification, restart/disconnect). The 2 s poll is retained
        // only as a fallback while the socket is down.
        connectStatusWebSocket() {
            if (typeof WebSocket === 'undefined') return; // polling stays
            const proto = location.protocol === 'https:' ? 'wss' : 'ws';
            let ws;
            try {
                ws = new WebSocket(`${proto}://${location.host}/ws/status`);
            } catch (e) {
                return; // polling stays
            }
            this._statusWs = ws;
            this._statusWsOpen = false;
            ws.onopen = () => {
                this._statusWsOpen = true;
                // Live socket wins: stop the poll timer while connected.
                this.stopStatusPolling();
                // A reconnect may have missed transitions; resync now
                // instead of waiting for the next change-triggered frame.
                this.updateDashboard();
            };
            ws.onmessage = (ev) => {
                let data;
                try {
                    data = JSON.parse(ev.data);
                } catch (e) {
                    return; // malformed frame; the poll remains the fallback
                }
                this.applyStatusFrame(data);
            };
            ws.onclose = () => {
                this._statusWs = null;
                const wasOpen = this._statusWsOpen;
                this._statusWsOpen = false;
                // Fallback: poll again until the socket returns.
                this.startStatusPolling();
                if (wasOpen) {
                    setTimeout(() => this.connectStatusWebSocket(), 5000);
                } else {
                    // Never connected: server may be older — poll only.
                }
            };
            ws.onerror = () => {
                try { ws.close(); } catch (e) { /* already closing */ }
            };
        }

        // Cheap fingerprint of the fields the backend pushes immediately.
        // Mirrors api._status_state_signature so both transports agree on
        // what counts as a state transition (vs traffic-only).
        _statusStateSignature(data) {
            if (!data) return '';
            const tunnel = (data.tunnel && typeof data.tunnel === 'object') ? data.tunnel : {};
            const sw = (data.switch && typeof data.switch === 'object') ? data.switch : {};
            return [
                data.status,
                data.exit_verification_state,
                data.exit_ip,
                data.country,
                data.transport,
                data.proxy_only_mode,
                data.tun_frontend,
                data.session_pool,
                data.http_proxy_enabled_live,
                tunnel.enabled,
                tunnel.state,
                tunnel.detail,
                tunnel.process_alive,
                sw.state,
            ].join('|');
        }

        resumeStatusUpdates() {
            if (this._statusRenderPending && this._lastStatus) {
                this._statusRenderPending = false;
                this.applyStatusFrame(this._lastStatus);
            }
            // Resync even without a pending frame: the backend may have
            // transitioned while hidden and the socket frame may have been
            // delivered before this handler ran.
            this.updateDashboard();
            // Returning to the app is the one time a stale ping list is
            // worth a fresh sweep even when the periodic timer is paused.
            this._resumeCountriesLatency();
        }

        // One shared render path for both the poll timer and WS frames so
        // the two transports can never disagree about UI state.
        applyStatusFrame(data) {
            this.apiUp = true;
            this._pollFailures = 0;
            this._lastStatus = data;
            if (this._devWatch === undefined) {
                this._devWatch = data.webui_debug === '1';
                if (this._devWatch) this.startDevWatch();
            }
            const signature = this._statusStateSignature(data);
            const stateChanged = signature !== this._lastStatusSig;
            this._lastStatusSig = signature;
            if (document.hidden) {
                this._statusRenderPending = true;
                // Never defer a state transition: UAC secure desktop and
                // minimized windows must still reflect Up/verified. Only
                // traffic-only frames wait for visibility.
                if (stateChanged) this.renderDashboard(data);
                return;
            }
            this._statusRenderPending = false;
            this.renderDashboard(data);
            this.renderRadar(data);
        }

        async updateDashboard() {
            try {
                const data = await this.api('/api/status');
                this.applyStatusFrame(data);
            } catch (e) {
                this.apiUp = false;
                // A transient poll failure (slow host under load during the
                // TUN boot window) must not clobber the Connecting lock: two
                // consecutive failures are tolerated while a connection
                // attempt is believed to be running, then unknown-backend
                // rendering takes over honestly.
                const wasConnecting =
                    (this._lastStatus && this._lastStatus.status === 'connecting')
                    || this._actionBusy;
                this._pollFailures = (this._pollFailures || 0) + 1;
                if (wasConnecting && this._pollFailures <= 2) return;
                this.renderUnavailable();
                this.renderRadar(null);
            }
        }

        // ------------------------------------------------------------
        // Tactical sonar scope (canvas) — live telemetry only
        //
        // The scope is a single DPR-scaled canvas repainted from one
        // requestAnimationFrame loop. It always sweeps (reduced-motion is
        // deliberately not honoured here: the sweep is the instrument, not
        // decoration) and every blip maps to a real /api/status field or a
        // measured latency. Nothing is synthesised.
        // ------------------------------------------------------------

        RADAR_SWEEP_PERIOD_MS = 5200;
        RADAR_FRAME_MS = 1000 / 30; // ~33.33 ms active cadence (30 fps)
        RADAR_MAX_DT_MS = 50;       // clamp phase catch-up after stalls

        renderRadar(data) {
            if (!this._radarContacts) return;
            const d = data || {};
            const status = d.status || 'disconnected';
            const verified = (d.exit_verification_state || '') === 'verified';
            const pending = (d.exit_verification_state || '') === 'pending';
            const failed = (d.exit_verification_state || '') === 'failed';
            const proxyOnly = !!d.proxy_only_mode;
            const tunnel = d.tunnel || {};
            const tunEnabled = !!tunnel.enabled;
            const tunState = tunnel.state || (tunEnabled ? 'starting' : 'disabled');
            const pool = !!d.session_pool;
            const now = Date.now();

            const set = (contact, state) => {
                if (!contact || contact.state === state) return;
                contact.state = state;
                if (state === 'ok') contact.verifiedAt = now;
            };

            this._radarContacts.forEach((c) => {
                if (c.key === 'local') {
                    set(c, this.apiUp ? 'ok' : (pending ? 'degraded' : 'inactive'));
                } else if (c.key === 'socks') {
                    if (!this.apiUp) { set(c, 'inactive'); return; }
                    if (pool || proxyOnly) set(c, 'ok');
                    else if (status === 'connecting') set(c, 'degraded');
                    else set(c, 'inactive');
                } else if (c.key === 'tun') {
                    if (!this.apiUp || !tunEnabled) { set(c, 'inactive'); return; }
                    if (tunState === 'traffic_verified') set(c, 'ok');
                    else if (['failed', 'not_elevated', 'not_configured', 'recovery_required', 'degraded'].indexOf(tunState) >= 0) set(c, 'failed');
                    else set(c, 'degraded');
                } else if (c.key === 'pool') {
                    if (!this.apiUp) { set(c, 'inactive'); return; }
                    if (pool) set(c, verified ? 'ok' : 'degraded');
                    else if (status === 'connecting') set(c, 'degraded');
                    else set(c, 'inactive');
                } else if (c.key === 'upstream') {
                    if (!this.apiUp) { set(c, 'inactive'); return; }
                    if (status === 'failed') set(c, 'failed');
                    else if (status === 'connected' || status === 'proxy_active') set(c, verified ? 'ok' : (failed ? 'failed' : 'degraded'));
                    else if (status === 'connecting' || status === 'degraded') set(c, 'degraded');
                    else set(c, 'inactive');
                } else if (c.key === 'exit') {
                    if (!this.apiUp) { set(c, 'inactive'); return; }
                    if (status === 'failed' || failed) set(c, 'failed');
                    else if (verified) set(c, 'ok');
                    else if (pending || status === 'connecting' || status === 'degraded') set(c, 'degraded');
                    else set(c, 'inactive');
                }
            });

            const echoes = this.computeRadarEchoes();
            const echoKey = echoes.map((e) => e.code + ':' + e.ms + ':' + e.frac).join(',');
            if (echoKey !== this._radarEchoKey) {
                this._radarEchoKey = echoKey;
                this._radarEchoRev = (this._radarEchoRev || 0) + 1;
            }
            this._radarEchoes = echoes;
            this._radarExitCode = verified ? normaliseCountryCode(d.country) : '';

            const label = document.getElementById('radar-state-label');
            if (label) {
                let text;
                if (!this.apiUp) text = 'OFFLINE · instrument self-sweep';
                else if (status === 'failed') text = 'ATTENTION · ' + (tunnel.detail || 'tunnel failed');
                else if (tunEnabled && !verified) text = 'SYNC · TUN ' + String(tunState).replace(/_/g, ' ');
                else if (proxyOnly) text = 'LIVE · SOCKS5 only';
                else if (verified) text = 'LIVE · verified exit';
                else if (status === 'connecting' || pending) text = 'LIVE · verifying exit';
                else text = 'IDLE · ' + status;
                setTextIfChanged(label, text);
            }
        }

        // Real measured pings only: codes that have a live /api/urltest value
        // in this session. Distance maps measured ms; unmeasured countries are
        // never drawn.
        computeRadarEchoes() {
            const entries = Object.entries(this._countryLatency || {})
                .filter(([, ms]) => Number.isFinite(ms) && ms > 0)
                .sort(([, a], [, b]) => a - b);
            if (!entries.length) return [];
            const values = entries.map(([, ms]) => ms);
            const lo = values[0];
            const hi = values[values.length - 1];
            return entries.map(([code, ms]) => ({
                code: String(code).toUpperCase(),
                ms,
                azimuth: this.radarAzimuthForCode(code),
                frac: hi === lo ? 0.35 : 0.22 + 0.72 * ((ms - lo) / (hi - lo)),
            }));
        }

        initRadar() {
            const canvas = document.getElementById('radar-canvas');
            if (!canvas) return;
            const ctx = canvas.getContext('2d');
            if (!ctx) return;
            this._radarCanvas = canvas;
            this._radarCtx = ctx;
            this._radarPx = 0;
            this._radarRaf = null;
            this._radarAngle = 0;
            this._radarHudAt = 0;
            this._radarEchoes = [];
            this._radarExitCode = '';
            this._radarSweepStarted = performance.now();
            this._radarPhaseMs = 0;
            this._radarLastTs = 0;
            this._radarLastDraw = 0;
            this._radarNextDraw = 0;
            this._radarIdleFrame = false;
            this._radarSize = 0;
            this._radarDpr = 1;
            this._radarStatic = null;
            this._radarStaticKey = '';
            this._radarStaticPx = 0;
            this._radarStaticRev = -1;
            this._radarEchoRev = 0;
            this._radarEchoKey = '';
            this._radarTrail = null;
            this._radarTrailPx = 0;
            this._radarSprites = {};
            this._radarHudEls = null;
            this._radarResizeBound = false;
            this._radarVisibilityBound = false;
            this._perfFrames = 0;
            this._perfWindowStart = performance.now();
            this._perfWorstMs = 0;
            this._perfLongTasks = 0;
            this._perfPostedAt = 0;
            this._startPerfTelemetry();

            const contacts = [
                { key: 'local', angle: 0, radius: 0, name: 'Local client (API process)' },
                { key: 'socks', angle: 300, radius: 0.36, name: 'SOCKS5 listener' },
                { key: 'tun', angle: 235, radius: 0.58, name: 'System TUN adapter' },
                { key: 'pool', angle: 148, radius: 0.58, name: 'Session pool' },
                { key: 'upstream', angle: 78, radius: 0.80, name: 'Upstream H2/H3 relay' },
                { key: 'exit', angle: 28, radius: 0.94, name: 'Verified exit connection' },
            ];
            this._radarContacts = contacts.map((c) => ({
                ...c, state: 'inactive', verifiedAt: 0, pulseAt: 0,
            }));

            canvas.addEventListener('mousemove', (ev) => this.hitTestRadar(ev));
            canvas.addEventListener('mouseleave', () => this.hideRadarTooltip());
            this._measureRadar();
            this._bindRadarResize();
            this.startRadarLoop();
        }

        // Cache the CSS size and DPR once per layout change instead of reading
        // getBoundingClientRect() on every animation frame.
        _measureRadar() {
            const canvas = this._radarCanvas;
            if (!canvas) return false;
            const rect = canvas.getBoundingClientRect();
            const size = Math.floor(Math.min(rect.width, rect.height));
            const dpr = Math.min(window.devicePixelRatio || 1, 2.5);
            const changed = size !== this._radarSize || dpr !== this._radarDpr;
            this._radarSize = size;
            this._radarDpr = dpr;
            if (changed) {
                this._radarStatic = null;
                this._radarStaticKey = '';
                this._radarTrail = null;
                this._radarTrailPx = 0;
            }
            return changed;
        }

        _bindRadarResize() {
            const canvas = this._radarCanvas;
            if (!canvas || this._radarResizeBound) return;
            this._radarResizeBound = true;
            const onResize = () => {
                if (!this._measureRadar()) return;
                if (this._radarRaf || this._radarIdleFrame) this.drawRadar(performance.now());
            };
            if (typeof ResizeObserver === 'function') {
                this._radarResizeObserver = new ResizeObserver(onResize);
                this._radarResizeObserver.observe(canvas);
            } else {
                window.addEventListener('resize', onResize);
            }
        }

        // rAF loop: one canvas, one paint per frame. Runs regardless of the
        // reduced-motion preference, but stops entirely when the scope is not
        // visible (hidden window, unfocused, or another tab).
        startRadarLoop() {
            if (!this._radarCanvas || this._radarRaf) return;
            const step = (ts) => {
                // A zero-size canvas still costs a rect read and a callback
                // per frame; stop the loop entirely when the scope cannot be
                // seen (other tab, minimized, or window unfocused) instead of
                // spinning rAF against a hidden element.
                if (document.hidden || this.currentTab !== 'dashboard') {
                    this._radarRaf = null;
                    return;
                }
                const radarIdle = this._uiState === UI_STATE.DISCONNECTED
                    || this._uiState === UI_STATE.TUN_FAILED;
                if (radarIdle) {
                    // No live session: keep one painted scope, then stop the
                    // rAF/canvas loop entirely instead of sweeping at 20 fps.
                    this._radarRaf = null;
                    if (!this._radarIdleFrame) {
                        this._radarIdleFrame = true;
                        this.drawRadar(ts);
                    }
                    return;
                }
                this._radarIdleFrame = false;
                this._radarRaf = window.requestAnimationFrame(step);
                const dt = this._radarLastTs
                    ? Math.min(Math.max(0, ts - this._radarLastTs), this.RADAR_MAX_DT_MS)
                    : 16.7;
                this._radarLastTs = ts;
                if (dt <= 0) return; // duplicate timestamp: nothing to advance
                this._radarPhaseMs = (this._radarPhaseMs + dt) % this.RADAR_SWEEP_PERIOD_MS;
                // 30 fps average: a deadline accumulator draws every other
                // 60 Hz vsync instead of a 33.33 ms threshold (which would
                // collapse to 20 fps on a 60 Hz panel).
                if (!this._radarNextDraw) this._radarNextDraw = ts;
                if (ts + 0.5 < this._radarNextDraw) return;
                this._radarNextDraw += this.RADAR_FRAME_MS;
                if (this._radarNextDraw <= ts) this._radarNextDraw = ts + this.RADAR_FRAME_MS;
                this._radarLastDraw = ts;
                this._perfFrames += 1;
                if (dt > this._perfWorstMs) this._perfWorstMs = dt;
                this._flushPerfWindow(ts);
                this.drawRadar(ts);
            };
            this._radarLastTs = 0;
            this._radarNextDraw = 0;
            this._radarRaf = window.requestAnimationFrame(step);
            if (!this._radarVisibilityBound) {
                this._radarVisibilityBound = true;
                document.addEventListener('visibilitychange', () => {
                    if (document.hidden) {
                        if (this._radarRaf) window.cancelAnimationFrame(this._radarRaf);
                        this._radarRaf = null;
                        return;
                    }
                    this._radarLastTs = 0;
                    this.startRadarLoop();
                });
                window.addEventListener('blur', () => {
                    if (this._radarRaf) window.cancelAnimationFrame(this._radarRaf);
                    this._radarRaf = null;
                });
                window.addEventListener('focus', () => {
                    this._radarLastTs = 0;
                    this.startRadarLoop();
                });
            }
        }

        // Real frame telemetry for acceptance runs (no synthetic numbers):
        // exposed as window.__perchPerf and POSTed to /api/client-perf.
        _startPerfTelemetry() {
            if (this._perfBound) return;
            this._perfBound = true;
            this._perfWindowStart = performance.now();
            window.__perchPerf = { fps: 0, frames: 0, longTasks: 0, worstFrameMs: 0, size: '' };
            if (window.PerformanceObserver) {
                try {
                    const obs = new PerformanceObserver((list) => {
                        this._perfLongTasks += list.getEntries().length;
                    });
                    obs.observe({ entryTypes: ['longtask'] });
                    this._perfObserver = obs;
                } catch (e) { /* longtask unsupported */ }
            }
        }

        _flushPerfWindow(ts) {
            const elapsed = ts - this._perfWindowStart;
            if (elapsed < 1000) return;
            const fps = Math.round((this._perfFrames * 1000) / elapsed);
            const size = this._radarSize || 0;
            const longTasks = this._perfLongTasks - (this._perfLongTasksPosted || 0);
            this._perfLongTasksPosted = this._perfLongTasks;
            const sample = {
                fps,
                frames: this._perfFrames,
                longTasks,
                longTasksTotal: this._perfLongTasks,
                worstFrameMs: Math.round(this._perfWorstMs * 10) / 10,
                size: size + 'px',
            };
            window.__perchPerf = sample;
            this._perfFrames = 0;
            this._perfWorstMs = 0;
            this._perfWindowStart = ts;
            if (this.apiUp && ts - this._perfPostedAt > 5000) {
                this._perfPostedAt = ts;
                this.api('/api/client-perf', { method: 'POST', body: JSON.stringify(sample) })
                    .catch(() => {});
            }
        }

        radarPoint(contact, c, rMax) {
            const a = (contact.angle - 90) * Math.PI / 180;
            return {
                x: c + contact.radius * rMax * Math.cos(a),
                y: c + contact.radius * rMax * Math.sin(a),
            };
        }

        drawRadar(ts) {
            const canvas = this._radarCanvas;
            const ctx = this._radarCtx;
            if (!canvas || !ctx) return;
            if (!this._radarSize) this._measureRadar();
            const size = this._radarSize;
            if (!size || size < 80) return;
            const dprNow = Math.min(window.devicePixelRatio || 1, 2.5);
            if (dprNow !== this._radarDpr) {
                this._radarDpr = dprNow;
                this._radarStatic = null;
                this._radarStaticKey = '';
                this._radarTrail = null;
                this._radarTrailPx = 0;
            }
            const dpr = this._radarDpr;
            const px = Math.round(size * dpr);
            if (this._radarPx !== px) {
                this._radarPx = px;
                canvas.width = px;
                canvas.height = px;
            }
            ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
            ctx.clearRect(0, 0, size, size);

            const c = size / 2;
            const rMax = c - 9;
            const angle = (this._radarPhaseMs / this.RADAR_SWEEP_PERIOD_MS) * 360;
            const prev = this._radarAngle;
            this._radarAngle = angle;
            const rad = angle * Math.PI / 180;

            // Static geometry (bowl, rings, crosshair, ticks, echoes) is
            // cached on an offscreen canvas and blitted once per frame; only
            // the sweep, contacts and HUD are repainted live.
            const staticLayer = this.radarStaticLayer(size, dpr, px);
            if (staticLayer) ctx.drawImage(staticLayer, 0, 0, size, size);

            // Beam-over-contact crossings pulse the real state markers.
            this._radarContacts.forEach((contact) => {
                if (contact.state === 'inactive') return;
                const crossed = prev < angle
                    ? (contact.angle > prev && contact.angle <= angle)
                    : (contact.angle > prev || contact.angle <= angle);
                if (crossed) contact.pulseAt = ts;
            });

            // The 64° phosphor trail + leading edge is pre-rendered once per
            // size/DPR and rotated into place: one blit instead of 32 fills
            // and a per-frame shadow blur.
            const trail = this.radarTrailLayer(size, dpr, px);
            if (trail) {
                ctx.save();
                ctx.translate(c, c);
                ctx.rotate(rad);
                ctx.drawImage(trail, -c, -c, size, size);
                ctx.restore();
            }

            // Contact markers: colour = honest component state. The dot+glow
            // is a cached sprite, so no per-frame shadow blur is paid.
            this._radarContacts.forEach((contact) => {
                const a = (contact.angle - 90) * Math.PI / 180;
                const x = c + contact.radius * rMax * Math.cos(a);
                const y = c + contact.radius * rMax * Math.sin(a);
                const colour = RADAR_COLOURS[contact.state] || RADAR_COLOURS.inactive;
                const radius = contact.key === 'local' ? 4.2 : 3.2;
                const pulse = contact.pulseAt ? (ts - contact.pulseAt) : Infinity;
                if (pulse < 900) {
                    const p = pulse / 900;
                    ctx.beginPath();
                    ctx.arc(x, y, 5 + p * 16, 0, Math.PI * 2);
                    ctx.strokeStyle = 'rgba(150, 255, 195, ' + (0.45 * (1 - p)).toFixed(3) + ')';
                    ctx.lineWidth = 1;
                    ctx.stroke();
                }
                const sprite = this.radarContactSprite(colour, radius, dpr);
                if (sprite) {
                    const s = sprite._css;
                    ctx.drawImage(sprite, x - s / 2, y - s / 2, s, s);
                } else {
                    ctx.fillStyle = colour;
                    ctx.beginPath();
                    ctx.arc(x, y, radius, 0, Math.PI * 2);
                    ctx.fill();
                }
            });

            // Central origin pip.
            ctx.strokeStyle = 'rgba(190, 255, 215, 0.5)';
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.arc(c, c, 7, 0, Math.PI * 2);
            ctx.stroke();

            // HUD (throttled DOM writes, cached elements, real values only).
            if (!this._radarHudAt || ts - this._radarHudAt > 200) {
                this._radarHudAt = ts;
                const hud = this._radarHudEls || (this._radarHudEls = {
                    range: document.getElementById('radar-hud-range'),
                    contacts: document.getElementById('radar-hud-contacts'),
                    exit: document.getElementById('radar-hud-exit'),
                    bearing: document.getElementById('radar-hud-bearing'),
                });
                const active = this._radarContacts.filter((x) => x.state !== 'inactive').length;
                const echoes = this._radarEchoes || [];
                const slowest = echoes.length ? echoes[echoes.length - 1].ms : null;
                if (hud.range) setTextIfChanged(hud.range, slowest ? slowest + ' ms' : '—');
                if (hud.contacts) setTextIfChanged(hud.contacts, active + '/' + this._radarContacts.length);
                if (hud.exit) setTextIfChanged(hud.exit, this._radarExitCode ? this._radarExitCode.toUpperCase() : '—');
                if (hud.bearing) setTextIfChanged(hud.bearing, String(Math.round(angle) % 360).padStart(3, '0') + '°');
            }
        }

        radarStaticLayer(size, dpr, px) {
            const echoes = this._radarEchoes || [];
            if (this._radarStatic && this._radarStaticPx === px
                && this._radarStaticRev === this._radarEchoRev) return this._radarStatic;
            const layer = this._radarStatic || document.createElement('canvas');
            layer.width = px;
            layer.height = px;
            const g = layer.getContext('2d');
            if (!g) return null;
            const c = size / 2;
            const rMax = c - 9;
            const toRad = (deg) => deg * Math.PI / 180;
            g.setTransform(dpr, 0, 0, dpr, 0, 0);
            g.clearRect(0, 0, size, size);
            const bg = g.createRadialGradient(c, c, 0, c, c, rMax);
            bg.addColorStop(0, 'rgba(26, 58, 40, 0.55)');
            bg.addColorStop(0.7, 'rgba(10, 26, 17, 0.55)');
            bg.addColorStop(1, 'rgba(3, 9, 6, 0.3)');
            g.fillStyle = bg;
            g.beginPath();
            g.arc(c, c, rMax, 0, Math.PI * 2);
            g.fill();

            // Range rings + crosshair.
            g.lineWidth = 1;
            [0.25, 0.5, 0.75, 1].forEach((f, i) => {
                g.beginPath();
                g.arc(c, c, rMax * f, 0, Math.PI * 2);
                g.strokeStyle = i === 3 ? 'rgba(64, 220, 130, 0.30)' : 'rgba(64, 220, 130, 0.15)';
                g.stroke();
            });
            g.strokeStyle = 'rgba(64, 220, 130, 0.11)';
            g.beginPath();
            g.moveTo(c - rMax, c); g.lineTo(c + rMax, c);
            g.moveTo(c, c - rMax); g.lineTo(c, c + rMax);
            g.stroke();

            // Bearing ticks (15°), majors labelled every 90°.
            g.font = '8px ui-monospace, SFMono-Regular, Menlo, monospace';
            g.textAlign = 'center';
            g.textBaseline = 'middle';
            for (let deg = 0; deg < 360; deg += 15) {
                const a = toRad(deg - 90);
                const major = deg % 90 === 0;
                const r0 = rMax;
                const r1 = rMax - (major ? 10 : 5);
                g.beginPath();
                g.moveTo(c + r0 * Math.cos(a), c + r0 * Math.sin(a));
                g.lineTo(c + r1 * Math.cos(a), c + r1 * Math.sin(a));
                g.strokeStyle = major ? 'rgba(64, 220, 130, 0.38)' : 'rgba(64, 220, 130, 0.18)';
                g.stroke();
                if (major) {
                    g.fillStyle = 'rgba(120, 236, 168, 0.55)';
                    g.fillText(String(deg).padStart(3, '0') + '°',
                        c + (rMax - 20) * Math.cos(a),
                        c + (rMax - 20) * Math.sin(a));
                }
            }

            // Measured country echoes (faint diamonds).
            (this._radarEchoes || []).forEach((e) => {
                const a = toRad(e.azimuth - 90);
                const r = e.frac * rMax;
                const x = c + r * Math.cos(a);
                const y = c + r * Math.sin(a);
                g.save();
                g.translate(x, y);
                g.rotate(Math.PI / 4);
                g.fillStyle = 'rgba(120, 235, 165, 0.30)';
                g.fillRect(-2, -2, 4, 4);
                g.restore();
            });

            this._radarStatic = layer;
            this._radarStaticPx = px;
            this._radarStaticRev = this._radarEchoRev;
            this._radarStaticKey = px + '|' + this._radarEchoRev;
            return layer;
        }

        // 64° trail + leading edge, baked once per size/DPR. The caller
        // rotates this sprite around the scope centre and blits it.
        radarTrailLayer(size, dpr, px) {
            if (this._radarTrail && this._radarTrailPx === px) return this._radarTrail;
            const layer = this._radarTrail || document.createElement('canvas');
            layer.width = px;
            layer.height = px;
            const g = layer.getContext('2d');
            if (!g) return null;
            const c = size / 2;
            const rMax = c - 9;
            const trailRad = 64 * Math.PI / 180;
            g.setTransform(dpr, 0, 0, dpr, 0, 0);
            g.clearRect(0, 0, size, size);
            for (let i = 0; i < 32; i++) {
                const a0 = -trailRad * (i + 1) / 32;
                const a1 = -trailRad * i / 32;
                g.beginPath();
                g.moveTo(c, c);
                g.arc(c, c, rMax, a0, a1);
                g.closePath();
                g.fillStyle = 'rgba(64, 224, 132, ' + (0.30 * Math.pow(1 - i / 32, 2.1)).toFixed(3) + ')';
                g.fill();
            }
            g.beginPath();
            g.moveTo(c, c);
            g.lineTo(c + rMax, c);
            g.strokeStyle = 'rgba(176, 255, 210, 0.85)';
            g.lineWidth = 1.4;
            g.shadowColor = 'rgba(110, 255, 175, 0.9)';
            g.shadowBlur = 6;
            g.stroke();
            g.shadowBlur = 0;
            this._radarTrail = layer;
            this._radarTrailPx = px;
            return layer;
        }

        // Contact dot + soft glow baked per colour/radius/DPR.
        radarContactSprite(colour, radius, dpr) {
            const key = colour + '|' + radius + '|' + dpr;
            const cache = this._radarSprites || (this._radarSprites = {});
            if (cache[key]) return cache[key];
            const s = Math.ceil(radius * 4 + 10);
            const px = Math.max(1, Math.round(s * dpr));
            const layer = document.createElement('canvas');
            layer.width = px;
            layer.height = px;
            layer._css = s;
            const g = layer.getContext('2d');
            if (!g) return null;
            g.setTransform(dpr, 0, 0, dpr, 0, 0);
            const c = s / 2;
            if (colour !== RADAR_COLOURS.inactive) {
                const glow = g.createRadialGradient(c, c, 0, c, c, radius * 3.5);
                glow.addColorStop(0, colour);
                glow.addColorStop(0.35, colour);
                glow.addColorStop(1, 'rgba(0, 0, 0, 0)');
                g.globalAlpha = 0.35;
                g.fillStyle = glow;
                g.beginPath();
                g.arc(c, c, radius * 3.5, 0, Math.PI * 2);
                g.fill();
                g.globalAlpha = 1;
            }
            g.fillStyle = colour;
            g.beginPath();
            g.arc(c, c, radius, 0, Math.PI * 2);
            g.fill();
            cache[key] = layer;
            return layer;
        }

        hitTestRadar(ev) {
            const canvas = this._radarCanvas;
            if (!canvas) return;
            const rect = canvas.getBoundingClientRect();
            const size = Math.min(rect.width, rect.height);
            const c = size / 2;
            const rMax = c - 9;
            const x = ev.clientX - rect.left - (rect.width - size) / 2;
            const y = ev.clientY - rect.top - (rect.height - size) / 2;
            let best = null;
            let bestD = 16;
            (this._radarContacts || []).forEach((contact) => {
                const pt = this.radarPoint(contact, c, rMax);
                const dist = Math.hypot(pt.x - x, pt.y - y);
                if (dist < bestD) { bestD = dist; best = contact; }
            });
            if (!best) { this.hideRadarTooltip(); return; }
            this.showRadarTooltip(best, ev);
        }

        // Deterministic azimuth for a country code — a stable pure function
        // of the code itself (no randomness, no state).
        radarAzimuthForCode(code) {
            const upper = String(code).toUpperCase();
            let h = 7;
            for (let i = 0; i < upper.length; i++) {
                h = ((h * 31) + upper.charCodeAt(i)) >>> 0;
            }
            h = (h + ((upper.charCodeAt(1) || 7) * 12)) >>> 0;
            return h % 360;
        }

        showRadarTooltip(contact, ev) {
            const tip = document.getElementById('radar-tooltip');
            if (!tip) return;
            const stateText = {
                ok: 'Verified operational',
                degraded: 'Starting / unverified',
                failed: 'Failed',
                inactive: 'Inactive',
            }[contact.state] || 'Inactive';
            const nameEl = document.getElementById('radar-tooltip-name');
            if (nameEl) nameEl.textContent = contact.name;
            const stateEl = document.getElementById('radar-tooltip-state');
            if (stateEl) stateEl.textContent = stateText;
            const seenEl = document.getElementById('radar-tooltip-seen');
            if (seenEl) {
                if (contact.state === 'ok' && contact.verifiedAt) {
                    seenEl.textContent = 'Last verified ' + new Date(contact.verifiedAt).toLocaleTimeString();
                    seenEl.hidden = false;
                } else {
                    seenEl.hidden = true;
                }
            }
            tip.hidden = false;
            const scope = tip.closest('.radar-scope');
            if (scope && ev) {
                const rect = scope.getBoundingClientRect();
                let left = ev.clientX - rect.left + 14;
                let top = ev.clientY - rect.top - 10;
                if (left + 240 > rect.width) left -= 250;
                tip.style.left = Math.max(4, left) + 'px';
                tip.style.top = Math.max(4, top) + 'px';
            }
        }

        hideRadarTooltip() {
            const tip = document.getElementById('radar-tooltip');
            if (tip) tip.hidden = true;
        }

        startDevWatch() {
            // Env-gated diagnostics (PERCHVPN_WEBUI_DEBUG=1): mirror GearCore
            // state into the activity log so captures can read it.
            setInterval(() => {
                const g = window.GearCoreRef;
                if (!g) return;
                const rm = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
                this.api('/api/devwatch', {
                    method: 'POST',
                    body: JSON.stringify({
                        msg: `gc a=${g.angle.toFixed(2)} s=${g.speed.toFixed(3)} run=${g.running} rm=${rm} vs=${document.visibilityState}`
                    })
                }).catch(() => {});
            }, 2000);
        }

        renderUnavailable() {
            this.applyState(UI_STATE.DISCONNECTED, null);
        }

        // ------------------------------------------------------------
        // State resolution — the core of honest status presentation
        // ------------------------------------------------------------

        resolveState(d) {
            // An in-flight mode switch must not be clobbered by the 2s poll.
            if (this._uiTransition && this._uiTransition.type === 'mode') {
                return UI_STATE.CONNECTING;
            }
            // Canonical "degraded"/"failed" (with legacy tun_ aliases) and
            // exit-verification mapping: single shared implementation.
            return window.PerchStatusContract.resolveUiState(d);
        }

        applyState(state, d) {
            const prevState = this._uiState;
            this._uiState = state;
            const meta = STATE_META[state] || STATE_META[UI_STATE.DISCONNECTED];
            const set = (id, text) => {
                setTextIfChanged(document.getElementById(id), text);
            };
            const setIn = (containerId, selector, text) => {
                const container = document.getElementById(containerId);
                if (!container) return;
                setTextIfChanged(container.querySelector(selector), text);
            };

            // header pill + connection state chip
            const header = document.getElementById('global-status');
            if (header) {
                const headerClass = 'status-indicator ' + meta.headerClass;
                if (header.className !== headerClass) header.className = headerClass;
            }
            setIn('global-status', '.status-indicator__text', meta.headerText);

            const chip = document.getElementById('connection-state');
            if (chip) {
                const chipClass = 'connection-state ' + meta.stateClass;
                if (chip.className !== chipClass) chip.className = chipClass;
                if (chip.getAttribute('data-state') !== state) chip.setAttribute('data-state', state);
            }
            setIn('connection-state', '.connection-state__text', meta.statusText);

            // status card
            const statusEl = document.getElementById('status-value');
            if (statusEl) {
                const tunnelDetail = d && d.tunnel && d.tunnel.detail;
                const text = (meta.tunnelDetail && tunnelDetail) ? tunnelDetail : meta.detail;
                if (statusEl.textContent !== text) statusEl.textContent = text;
                // Long error strings are line-clamped in CSS; expose the full
                // value on hover/focus so elided text is still readable.
                if (statusEl.title !== text) statusEl.title = text;
                const statusClass = 'info-value ' + meta.detailClass;
                if (statusEl.className !== statusClass) statusEl.className = statusClass;
            }

            // exit verification card
            const verEl = document.getElementById('exit-verification');
            if (verEl) {
                const socksVerified = state === UI_STATE.PROXY_ACTIVE
                    && d && d.exit_verification_state === 'verified';
                const verText = socksVerified ? 'Verified (SOCKS5 only)' : meta.verification;
                if (verEl.textContent !== verText) verEl.textContent = verText;
                const verClass = 'info-value ' + (socksVerified ? 'info-value--connected' : meta.verificationClass);
                if (verEl.className !== verClass) verEl.className = verClass;
            }

            // exit IP / country — real values only when verified
            set('exit-ip', meta.exitIp === null ? this.formatExitLabel(d.exit_ip) : meta.exitIp);
            set('country-value', meta.exitCountry === null ? this.formatCountry(d.country) : meta.exitCountry);

            // connection button + card framing (shared contract semantics)
            const btn = document.getElementById('connection-toggle');
            const card = btn && btn.closest('.card--connection');
            const buttonState = window.PerchStatusContract.buttonState(state);
            const connected = buttonState.connected;
            const connecting = buttonState.connecting;

            if (btn) {
                btn.classList.toggle('is-connected', connected && !connecting);
                btn.classList.toggle('is-connecting', connecting);
                btn.classList.toggle('is-error', buttonState.error);
                const pressed = buttonState.pressed ? 'true' : 'false';
                if (btn.getAttribute('aria-pressed') !== pressed) btn.setAttribute('aria-pressed', pressed);
                if (btn.getAttribute('aria-label') !== buttonState.ariaLabel) btn.setAttribute('aria-label', buttonState.ariaLabel);
                // Keep the control clickable-looking while the UAC helper,
                // adapter, and routes are being prepared. The JS guards below
                // reject overlapping actions; a hard `disabled` here showed
                // the Windows "no symbol" cursor and made the UI feel frozen.
                const loading = this._actionBusy || connecting;
                if (btn.disabled) btn.disabled = false;
                btn.classList.toggle('is-loading', loading);
                const busy = loading ? 'true' : 'false';
                if (btn.getAttribute('aria-busy') !== busy) btn.setAttribute('aria-busy', busy);
                if (btn.getAttribute('aria-disabled') !== busy) btn.setAttribute('aria-disabled', busy);
            }
            if (!this._actionBusy && btn) {
                const btnText = btn.querySelector('.btn__text');
                if (btnText && btnText.textContent !== buttonState.label) btnText.textContent = buttonState.label;
            }

            if (card) {
                card.classList.toggle('is-connected', connected && !connecting);
                card.classList.toggle('is-connecting', connecting);
            }
            set('connection-subtext', meta.subtext);

            // Connection-mode selector (proxy-only vs TUN), from live status.
            const modeBtnOnly = document.getElementById('mode-proxy-only');
            const modeBtnTun = document.getElementById('mode-tun');
            if (modeBtnOnly && modeBtnTun && d) {
                const modes = d.modes || {};
                if (!this._uiTransition && modes.selected) {
                    this._selectedMode = modes.selected;
                }
                const transition = this._uiTransition;
                const target = (transition && transition.type === 'mode') ? transition.targetMode : '';
                const selected = this._selectedMode || modes.selected || '';
                let active = target || modes.active || '';
                // No live connection: show the user's selection, not the
                // historical active mode (which may still say "proxy").
                if (active === 'disconnected' || active === 'connecting') {
                    active = selected;
                }
                if (!active) active = selected || (d.proxy_only_mode ? 'proxy_only' : 'proxy');
                const proxyMode = active !== 'tun';
                modeBtnOnly.classList.toggle('is-active', proxyMode);
                modeBtnTun.classList.toggle('is-active', !proxyMode);
                modeBtnOnly.setAttribute('aria-pressed', proxyMode ? 'true' : 'false');
                modeBtnTun.setAttribute('aria-pressed', proxyMode ? 'false' : 'true');
                const modeBusy = !!this._modeBusy;
                for (const modeBtn of [modeBtnOnly, modeBtnTun]) {
                    modeBtn.disabled = false;
                    modeBtn.classList.toggle('is-loading', modeBusy);
                    modeBtn.setAttribute('aria-busy', modeBusy ? 'true' : 'false');
                    modeBtn.setAttribute('aria-disabled', modeBusy ? 'true' : 'false');
                }
                modeBtnOnly.classList.toggle('is-switching', modeBusy && proxyMode);
                modeBtnTun.classList.toggle('is-switching', modeBusy && !proxyMode);
            }

            // Idle sessions do not need a live sweep; keep the last painted
            // scope and stop the rAF/canvas loop (see startRadarLoop). Resume
            // only on a transition into an active state while focused.
            const radarIdle = state === UI_STATE.DISCONNECTED || state === UI_STATE.TUN_FAILED;
            if (radarIdle) {
                this._radarIdleFrame = false;
            } else if (prevState !== state) {
                this._radarIdleFrame = false;
                const focused = typeof document.hasFocus !== 'function' || document.hasFocus();
                if (focused && typeof this.startRadarLoop === 'function') this.startRadarLoop();
            }

            this._syncCountriesLatencyTimer();
            if (prevState !== state && !radarIdle) this._resumeCountriesLatency();
            this._lastStateRenderKey = this._stateRenderKey(state, d);
        }

        _stateRenderKey(state, d) {
            const modes = (d && d.modes) || {};
            const tunnel = (d && d.tunnel) || {};
            const transition = modes.transition || {};
            const uiTransition = this._uiTransition || {};
            return [
                state,
                d && d.exit_verification_state,
                d && d.exit_ip,
                d && d.country,
                tunnel.enabled,
                tunnel.state,
                tunnel.detail,
                modes.selected,
                modes.active,
                modes.verified,
                modes.failure_reason,
                modes.fallback_reason,
                transition.state,
                transition.detail,
                uiTransition.type,
                uiTransition.targetMode,
                this._selectedMode,
                this._actionBusy ? 1 : 0,
                this._modeBusy ? 1 : 0,
            ].join('|');
        }

        formatExitLabel(ip) {
            if (!ip || ip === '0.0.0.0') return 'Unavailable';
            return ip;
        }

        formatCountry(code) {
            if (!code || code === '--') return 'Unavailable';
            return String(code).toUpperCase();
        }

        countryFlag(code) {
            const lower = normaliseCountryCode(code);
            if (!lower) return '';
            if (FLAGS_BUNDLED.has(lower.toUpperCase())) {
                // eager + sync decode (never lazy): the archive is already
                // in the flat assets directory and prewarmed on boot, so
                // rows render instantly with zero pop-in; fixed dimensions
                // prevent any layout shift while the SVG paints.
                return `<img class="country-flag__img" src="/assets/flags/4x3/${lower}.svg" alt="" aria-hidden="true" draggable="false" width="21" height="15" decoding="sync" loading="eager" onerror="this.remove()">`;
            }
            // Windows WebView2 renders regional-indicator emoji as bare
            // letters (no colour flag font) — use an ISO code badge instead.
            return `<span class="country-flag__code">${lower.toUpperCase()}</span>`;
        }

        // Decode every bundled flag once at boot (idle-time) so the first
        // country-list render hits the browser image cache instead of
        // fetching + decoding all SVGs mid-scroll.
        prewarmFlags() {
            const start = () => {
                FLAGS_BUNDLED.forEach(code => {
                    const img = new Image();
                    img.decoding = 'sync';
                    img.width = 21;
                    img.height = 15;
                    img.src = `/assets/flags/4x3/${code.toLowerCase()}.svg`;
                });
            };
            if (window.requestIdleCallback) window.requestIdleCallback(start, { timeout: 2000 });
            else window.setTimeout(start, 200);
        }

        // ------------------------------------------------------------
        // Dashboard rendering
        // ------------------------------------------------------------

        renderDashboard(d) {
            const state = this.resolveState(d);
            const stateKey = this._stateRenderKey(state, d);
            if (stateKey !== this._lastStateRenderKey) {
                this._lastStateRenderKey = stateKey;
                this.applyState(state, d);
            }

            const set = (id, text) => {
                setTextIfChanged(document.getElementById(id), text);
            };

            set('uptime-value', this.formatUptime(d.uptime || 0));
            set('socks5-addr', d.socks5_addr || PLACEHOLDER);
            set('transport-value', (d.transport && d.transport !== '--') ? String(d.transport).toUpperCase() : PLACEHOLDER);
            set('server-transport', (d.transport && d.transport !== '--') ? String(d.transport).toUpperCase() : PLACEHOLDER);

            const tun = d.tunnel || {};
            const tunEl = document.getElementById('tunnel-value');
            if (tunEl) {
                let text;
                let cls = 'info-value';
                if (tun.enabled) {
                    text = String(tun.state || 'starting').replace(/_/g, ' ') + (tun.detail ? ' · ' + tun.detail : '');
                    cls += tun.state === 'traffic_verified'
                        ? ' info-value--connected'
                        : (tun.state === 'starting' || tun.state === 'adapter_ready' || tun.state === 'routes_configured'
                            ? ' info-value--connecting'
                            : ' info-value--disconnected');
                } else {
                    text = 'Not enabled (SOCKS5 only)';
                    cls += ' info-value--unavailable';
                }
                if (tunEl.textContent !== text) tunEl.textContent = text;
                // Match the status-value clamping: full text via tooltip.
                if (tunEl.title !== text) tunEl.title = text;
                if (tunEl.className !== cls) tunEl.className = cls;
            }

            set('download-total', this.formatBytes(d.downloaded || 0));
            set('upload-total', this.formatBytes(d.uploaded || 0));
            set('download-speed', this.formatSpeed(d.download_speed || 0));
            set('upload-speed', this.formatSpeed(d.upload_speed || 0));
            set('total-traffic', this.formatBytes((d.downloaded || 0) + (d.uploaded || 0)));
            set('connections', String(d.active_connections || 0));
            const sw = d.switch || {};
            if (sw.id && sw.id !== this._switchSeenId) {
                this._switchSeenId = sw.id;
                this._switchLogged = false;
            }
            if (sw.id && !this._switchLogged && (sw.state === 'complete' || sw.state === 'degraded' || sw.state === 'failed')) {
                this._switchLogged = true;
                const phases = (sw.phases || []).map((p) => `${p.phase} ${p.duration_ms}ms`).join(' · ');
                this.log(`Country switch ${sw.target}: ${sw.state} in ${Math.round(sw.duration_ms || 0)} ms${phases ? ' [' + phases + ']' : ''}`);
            }
            this.updateSelectedCountry(d);
        }

        // ------------------------------------------------------------
        // Countries
        // ------------------------------------------------------------

        async loadCountries() {
            const lists = ['countries-list', 'dashboard-countries-list']
                .map(id => document.getElementById(id))
                .filter(Boolean);
            if (!lists.length) return;
            const loading = '<div class="loading"><span class="spinner" aria-hidden="true"></span>Loading countries…</div>';
            lists.forEach(list => { list.innerHTML = loading; });
            // Fresh rows start unmeasured; stale readings from a previous
            // fetch must not influence the new ordering.
            this._countryLatency = Object.create(null);
            try {
                const countries = await this.api('/api/countries');
                lists.forEach(list => { list.innerHTML = ''; });
                if (!countries.length) {
                    lists.forEach(list => { list.innerHTML = '<div class="loading">No countries available.</div>'; });
                    return;
                }
                countries.forEach(c => {
                    const city = (c.cities && c.cities.length) ? c.cities[0] : null;
                    const hostname = city && city.hostname ? city.hostname : '—';
                    const cityCode = city && city.code ? city.code : '';
                    const port = city && city.port ? city.port : 2499;
                    const flag = this.countryFlag(c.code);
                    const codeLower = normaliseCountryCode(c.code);
                    lists.forEach(list => {
                        const row = document.createElement('div');
                        row.className = 'country-item';
                        row.dataset.code = codeLower || '';
                        row.setAttribute('role', 'listitem');
                        row.dataset.sel = 'none';
                        row.innerHTML = `
                            <span class="country-flag" aria-hidden="true">${flag}</span>
                            <div class="country-info">
                                <span class="country-name">${this.esc(c.name)}</span>
                                <span class="country-hostname">${this.esc(hostname)}</span>
                                <span class="country-meta"><span class="country-pin">${this.esc(cityCode || '')}</span><span class="country-latency" data-host="${this.esc(hostname)}" data-port="${port}">Measuring…</span></span>
                            </div>
                            <button class="country-action" data-code="${this.esc(c.code)}" aria-pressed="false">Select</button>`;
                        const btn = row.querySelector('.country-action');
                        btn.addEventListener('click', () => this.selectCountry(c.code));
                        list.appendChild(row);
                    });
                    // Live latency for every visible row is applied by the
                    // bounded scheduler (countriesLatencyCycle) below, which
                    // also refreshes periodically while the view is active.
                });
                this._countries = countries;
                // Deterministic starting order while measurements are pending.
                this.sortCountryLists();
                this.refreshCountrySelection();
                this.updateServerDetails(this._lastStatus || null);
                this.countriesLatencyCycle();
            } catch (e) {
                lists.forEach(list => { list.innerHTML = `<div class="loading">Failed to load countries: ${this.esc(e.message)}</div>`; });
            }
        }

        refreshCountrySelection() {
            const live = this._selectedExit || '';
            const chosen = this._userChoice || '';
            document.querySelectorAll('.country-item').forEach(item => {
                const code = (item.dataset.code || '').toLowerCase();
                const btn = item.querySelector('.country-action');
                const isLive = code && code === live;
                const isChosen = !isLive && code && code === chosen;
                // Per-row dirty state: the 2s status poll calls this, so only
                // touch rows whose selection actually changed (avoids text
                // nodes being replaced and class churn every poll).
                const key = isLive ? 'live' : (isChosen ? 'pending' : 'none');
                if (item.dataset.sel === key) return;
                item.dataset.sel = key;
                item.classList.toggle('is-selected', isLive);
                item.classList.toggle('is-selected--pending', isChosen);
                if (btn) {
                    btn.classList.toggle('is-selected', isLive || isChosen);
                    btn.setAttribute('aria-pressed', (isLive || isChosen) ? 'true' : 'false');
                    btn.textContent = isLive ? 'In use' : (isChosen ? 'Selected' : 'Select');
                }
            });
        }

        // ------------------------------------------------------------
        // Country latency scheduler
        //
        // Measured against the endpoint advertised for each city in the
        // Remote Settings server list (hostname:port rendered on the row,
        // from /api/countries). The probe is the unified-delay realtime URL
        // test: the backend warms a keyed H2 session + CONNECT tunnel to
        // the city's edge relay and then times the surgical /generate_204
        // round trip on the warm keep-alive connection (handshake-debiased;
        // pass minting is TTL-cached and never inside the ping). Results
        // are one of "Measuring…", "<n> ms" or "Unavailable" — a failed
        // probe is never reported as 0 ms — and the country lists are
        // ordered by the measured value.
        // Boundaries: max 3 in-flight probes (bounded concurrent batches so
        // a 34-country sweep cannot spike TLS/CPU on a low-power GPU/CPU and
        // can never occupy the API thread pool a disconnect needs),
        // ~9s per-probe client timeout (backend itself caps at ~8.0s), 60s
        // refresh interval only while a countries view/tab is active and
        // the page is not hidden, and a generation token so a newer refresh
        // discards results from an older overlapping cycle.
        // ------------------------------------------------------------

        collectLatencyTargets() {
            const seen = Object.create(null);
            document.querySelectorAll('.country-latency').forEach(el => {
                // Hidden panels have no layout parent; skip them entirely.
                if (!el.offsetParent || !el.isConnected) return;
                const host = el.dataset.host;
                const port = Number(el.dataset.port);
                if (!host || !Number.isFinite(port) || port <= 0) return;
                const key = host + ':' + port;
                if (!seen[key]) seen[key] = { hostname: host, port: port, key: key, els: [] };
                seen[key].els.push(el);
            });
            return Object.values(seen);
        }

        countriesLatencyCycle(force = false) {
            const gen = (this._latencyGen || 0) + 1;
            this._latencyGen = gen;
            const targets = this.collectLatencyTargets();
            if (!targets.length) return;
            if (this._authenticated === false) {
                // Signed out: every probe would 503 ("Not signed in") — or
                // worse, 401 on a stale token ("No pass") — before a single
                // real measurement. Do not fire per-row relay probes or
                // Guardian pass fetches; rows keep the neutral signed-out
                // label until an authenticated cycle runs.
                targets.forEach(t => this.applyLatencyText(t.els, gen, SIGNED_OUT_LATENCY_LABEL));
                return;
            }
            if (this._authenticated !== true) {
                // Auth state still being determined: leave the initial
                // "Measuring…" text alone rather than probing or labelling.
                return;
            }
            // Duplicate countries lists may carry the same host:port; keys
            // above are unique so each endpoint is probed at most once.
            const queue = targets.slice();
            // Bounded concurrent sweep: worker-pool of 3 keeps peak TLS
            // handshakes and canvas/CPU contention low on integrated GPUs.
            const workers = Math.min(3, queue.length);
            for (let i = 0; i < workers; i++) this.latencyWorker(queue, gen, force);
        }

        async latencyWorker(queue, gen, force) {
            while (queue.length) {
                if (gen !== this._latencyGen) return; // superseded refresh
                const target = queue.shift();
                await this.measureLatency(target, gen, force);
            }
        }

        async measureLatency(target, gen, force = false) {
            const { hostname, port, key, els } = target;
            this._latencyCache = this._latencyCache || {};
            const cached = this._latencyCache[key];
            if (!force && cached && (Date.now() - cached.at) < 60000) {
                this.applyLatencyText(els, gen, cached.valid ? `${cached.ms} ms` : (cached.label || 'Unavailable'));
                return;
            }
            this.applyLatencyText(els, gen, 'Measuring…');
            const ctrl = new AbortController();
            const timeout = setTimeout(() => ctrl.abort(), 9000);
            try {
                const result = await this.api(
                    `/api/urltest?host=${encodeURIComponent(hostname)}&port=${port}`,
                    { signal: ctrl.signal }
                );
                // Unified-delay response: prefer the handshake-debiased
                // Stage-2 RTT; fall back to the legacy TTFB field.
                const ms = Number(
                    result.latency_ms != null ? result.latency_ms : result.elapsed_ms
                );
                if (Number.isFinite(ms) && ms > 0) {
                    // > 0: a URL test measured below 1ms is treated as unreliable
                    // rather than fabricating a "0 ms" reading.
                    if (gen !== this._latencyGen) return; // superseded: never cache
                    this._latencyCache[key] = { at: Date.now(), ms: ms, valid: true };
                    this.applyLatencyText(els, gen, `${ms} ms`);
                } else {
                    if (gen !== this._latencyGen) return; // superseded: never cache
                    this._latencyCache[key] = { at: Date.now(), valid: false, label: 'Unavailable' };
                    this.applyLatencyText(els, gen, 'Unavailable');
                }
            } catch (e) {
                const label = this.latencyErrorLabel(e && e.message);
                if (gen !== this._latencyGen) return; // superseded: never cache
                this._latencyCache[key] = { at: Date.now(), valid: false, label: label };
                this.applyLatencyText(els, gen, label);
            } finally {
                clearTimeout(timeout);
            }
        }

        // Distinguish the honest failure modes of /api/urltest so the rows
        // say WHY a probe failed instead of a bare "Unavailable":
        // 503 "Application not initialized"/"Not signed in" -> auth state,
        // 502 "…proxy pass unavailable: …quota exceeded" -> account quota,
        // 502 "…proxy pass unavailable: …" -> pass/token problem,
        // 504 "URL test timed out …" -> relay timeout, anything else stays
        // "Unavailable". never fabricated latencies; text labels only.
        latencyErrorLabel(message) {
            const text = String(message || '');
            if (/Application not initialized|Not signed in/i.test(text)) return 'Sign in';
            if (/quota exceeded/i.test(text)) return 'Quota';
            if (/proxy pass/i.test(text)) return 'No pass';
            if (/timed out/i.test(text)) return 'Timeout';
            return 'Unavailable';
        }

        applyLatencyText(els, gen, text) {
            if (gen !== this._latencyGen) return; // stale result
            const match = /^(\d+(?:\.\d+)?)\s*ms$/.exec(text);
            const ms = match ? Number(match[1]) : null;
            // Rasterize badge writes on the next frame: the bounded 6-way
            // concurrent sweep can deliver several results within a couple
            // of ms; batching the textContent updates into ONE keyframe
            // keeps the country rows flash-free during the sweep.
            this._latencyWrites = this._latencyWrites || [];
            this._latencyWrites.push({ els, text, ms, gen });
            if (this._latencyFlushRaf) return;
            const raf = window.requestAnimationFrame || (cb => window.setTimeout(cb, 16));
            this._latencyFlushRaf = raf(() => {
                this._latencyFlushRaf = 0;
                const batch = this._latencyWrites || [];
                this._latencyWrites = [];
                batch.forEach(({ els: batchEls, text: batchText, ms: batchMs, gen: batchGen }) => {
                    if (batchGen !== this._latencyGen) return; // superseded cycle
                    this._writeLatencyBadges(batchEls, batchText, batchMs);
                });
            });
        }

        _writeLatencyBadges(els, text, ms) {
            let measured = false;
            els.forEach(el => {
                if (!el.isConnected) return;
                // In-place surgical update: never rebuild the row; keep the
                // existing text node when the value is unchanged so ping
                // refreshes don't flash or invalidate layout for nothing.
                setTextIfChanged(el, text);
                if (text === 'Measuring…') return; // keep the last known value
                const row = el.closest('.country-item');
                if (!row || !row.dataset.code) return;
                this._countryLatency[row.dataset.code] = ms;
                if (Number.isFinite(ms) && ms > 0) measured = true;
            });
            // Definitive readings (including Unavailable) re-rank the lists;
            // the transient Measuring… label never causes a reorder.
            if (text !== 'Measuring…') this.scheduleCountrySort();
            // New measured pings feed the sonar echo plot (real values only).
            if (measured) this._radarEchoesDirty = true;
        }

        // ------------------------------------------------------------
        // Country ordering
        //
        // Lowest measured ping first; rows without a usable measurement
        // (missing, invalid, Unavailable) follow every measured row. The
        // comparator lives in country-sort.js so the rules are unit-tested
        // directly. Reordering moves existing rows, so event listeners and
        // the current selection survive.
        // ------------------------------------------------------------

        scheduleCountrySort() {
            if (this._countrySortRaf) return;
            const raf = window.requestAnimationFrame || (cb => window.setTimeout(cb, 16));
            this._countrySortRaf = raf(() => {
                this._countrySortRaf = 0;
                this.sortCountryLists();
            });
        }

        sortCountryLists() {
            const comparator = window.PerchCountrySort && window.PerchCountrySort.compare;
            if (!comparator) return;
            ['countries-list', 'dashboard-countries-list'].forEach(id => {
                const list = document.getElementById(id);
                if (!list) return;
                const rows = Array.from(list.children).filter(el => el.classList.contains('country-item'));
                if (rows.length < 2) return;
                const decorated = rows.map((row, index) => {
                    const nameEl = row.querySelector('.country-name');
                    return {
                        row: row,
                        index: index,
                        name: nameEl ? nameEl.textContent : '',
                        ms: this._countryLatency[row.dataset.code || '']
                    };
                });
                decorated.sort(comparator);
                const changed = decorated.some((d, i) => d.row !== rows[i]);
                if (changed) decorated.forEach(d => list.appendChild(d.row));
            });
        }

        _latencyShouldProbe() {
            if (document.hidden) return false;
            if (this.currentTab !== 'dashboard' && this.currentTab !== 'countries') return false;
            if (this._authenticated !== true) return false;
            const state = this._uiState;
            return state !== UI_STATE.DISCONNECTED && state !== UI_STATE.TUN_FAILED;
        }

        _syncCountriesLatencyTimer() {
            const shouldRun = !!this._latencyTimerWanted && this._latencyShouldProbe();
            if (shouldRun && !this._latencyTimer) {
                this._latencyTimer = window.setInterval(() => {
                    if (!this._latencyShouldProbe()) {
                        this._syncCountriesLatencyTimer();
                        return;
                    }
                    this.countriesLatencyCycle();
                }, 60000);
            } else if (!shouldRun && this._latencyTimer) {
                window.clearInterval(this._latencyTimer);
                this._latencyTimer = null;
            }
        }

        _resumeCountriesLatency() {
            // A single fresh sweep on focus/visibility regain or when the
            // server selector opens. The periodic timer stays paused while
            // disconnected; this is a one-shot resync, not a polling restart.
            if (document.hidden) return;
            if (this.currentTab !== 'dashboard' && this.currentTab !== 'countries') return;
            if (this._authenticated !== true) return;
            this.countriesLatencyCycle(true);
            this._syncCountriesLatencyTimer();
        }

        setCountriesLatencyTimer(on) {
            this._latencyTimerWanted = !!on;
            this._syncCountriesLatencyTimer();
        }

        updateSelectedCountry(d) {
            this._lastStatus = d;
            const verified = d && d.exit_verification_state === 'verified';
            const code = verified ? normaliseCountryCode(d.country) : '';
            this._selectedExit = code;
            if (code && this._userChoice === code) this._userChoice = '';
            this.refreshCountrySelection();
            this.updateServerDetails(d);
        }

        updateServerDetails(d) {
            // The 2s status poll calls this for every frame; skip identical
            // rewrites so connected panels don't repaint each poll.
            const cache = this._serverDetailRendered = this._serverDetailRendered || {};
            const setEl = (id, html, unavailable) => {
                const el = document.getElementById(id);
                if (!el) return;
                const key = unavailable ? '\0u' : html;
                if (cache[id] === key) return;
                cache[id] = key;
                if (unavailable) {
                    el.textContent = 'Unavailable';
                    el.classList.add('info-value--unavailable');
                } else {
                    el.innerHTML = html;
                    el.classList.remove('info-value--unavailable');
                }
            };
            const verified = d && d.exit_verification_state === 'verified';
            const code = verified ? normaliseCountryCode(d.country) : '';
            if (!verified || !code) {
                ['server-country', 'server-city', 'server-latency'].forEach(id => setEl(id, '', true));
                return;
            }
            const country = (this._countries || []).find(c => normaliseCountryCode(c.code) === code);
            const city = country && country.cities && country.cities.length ? country.cities[0] : null;
            const name = country ? country.name : String(d.country).toUpperCase();
            setEl('server-country', `<span class="server-detail__label">${this.esc(name)}</span><span class="country-pin">${this.esc(code.toUpperCase())}</span>`);
            if (city) {
                const hostPort = `${city.hostname}:${city.port}`;
                setEl('server-city', `${this.esc(city.name)}<span class="country-pin">${this.esc(city.code || '')}</span><span class="server-detail__host">${this.esc(hostPort)}</span>`);
            } else {
                setEl('server-city', '', true);
            }
            if (city && city.hostname) {
                const key = `${city.hostname}:${city.port}`;
                const cached = this._latencyCache && this._latencyCache[key];
                const fresh = cached && (Date.now() - cached.at) < 30000;
                if (fresh) {
                    this.renderServerLatency(cached.valid ? `${cached.ms} ms` : (cached.label || null));
                } else if (this._authenticated !== true) {
                    // No probe relay traffic for unauthenticated visitors:
                    // show the neutral signed-out label deterministically.
                    this.renderServerLatency(SIGNED_OUT_LATENCY_LABEL);
                } else {
                    setEl('server-latency', '<span class="country-latency">checking…</span>');
                    this.api(`/api/urltest?host=${encodeURIComponent(city.hostname)}&port=${city.port}`)
                        .then(result => {
                            this._latencyCache = this._latencyCache || {};
                            this._latencyCache[key] = { at: Date.now(), ms: result.elapsed_ms, valid: true };
                            this.renderServerLatency(`${result.elapsed_ms} ms`);
                        })
                        .catch(e => {
                            this._latencyCache = this._latencyCache || {};
                            this._latencyCache[key] = { at: Date.now(), valid: false, label: this.latencyErrorLabel(e && e.message) };
                            this.renderServerLatency(null);
                        });
                }
            } else {
                setEl('server-latency', '', true);
            }
        }

        renderServerLatency(text) {
            const el = document.getElementById('server-latency');
            if (!el) return;
            const cache = this._serverDetailRendered = this._serverDetailRendered || {};
            const key = String(text || 'unreachable');
            if (cache['server-latency'] === key) return;
            cache['server-latency'] = key;
            el.classList.remove('info-value--unavailable');
            el.innerHTML = text
                ? `<span class="server-latency__value">${this.esc(text)}</span>`
                : '<span class="server-latency__value server-latency__value--unreachable">unreachable</span>';
        }

        async selectCountry(code) {
            if (this._switchBusy) return;
            this._switchBusy = true;
            const target = String(code).toUpperCase();
            const previousChoice = this._userChoice;
            const previousExit = this._selectedExit;
            // Paint the choice on frame 1: the switch can take seconds (DoH
            // resolve + hot-swap) and the row must acknowledge the click
            // immediately. The 2s status poll promotes it to "in use" only
            // once the new exit is verified; a failed request rolls it back.
            this._userChoice = normaliseCountryCode(code);
            this._selectedExit = '';
            this.refreshCountrySelection();
            this.log(`Switching to ${target}…`);
            try {
                const result = await this.api('/api/country', {
                    method: 'POST',
                    body: JSON.stringify({ country_code: code })
                });
                if (result && result.mode === 'hot_swap') {
                    this.log(`Switching to ${target} (upstream hot-swap)…`);
                } else {
                    this.log(`Country set to ${target}.`);
                }
                await this.loadCountries();
                this.updateDashboard();
            } catch (e) {
                // Roll the optimistic row back so the UI never claims a
                // country the backend refused.
                this._userChoice = previousChoice;
                this._selectedExit = previousExit;
                this.refreshCountrySelection();
                this.log(`Failed to set country: ${e.message}`);
            } finally {
                this._switchBusy = false;
            }
        }

        prewarmCountry(code) {
            const key = String(code || '').toLowerCase();
            if (key.length !== 2) return;
            this._prewarmSeen = this._prewarmSeen || new Set();
            if (this._prewarmSeen.has(key)) return;
            this._prewarmSeen.add(key);
            this.api('/api/prewarm', {
                method: 'POST',
                body: JSON.stringify({ country_code: key })
            }).catch(() => { this._prewarmSeen.delete(key); });
        }

        bindCountrySearch() {
            ['countries-list', 'dashboard-countries-list'].forEach(listId => {
                const list = document.getElementById(listId);
                if (!list || list.dataset.prewarmBound === '1') return;
                list.dataset.prewarmBound = '1';
                const warm = (ev) => {
                    const row = ev.target && ev.target.closest ? ev.target.closest('.country-item') : null;
                    if (row) this.prewarmCountry(row.dataset.code);
                };
                list.addEventListener('pointerover', warm);
                list.addEventListener('focusin', warm);
            });

            ['country-search', 'dashboard-country-search'].forEach(searchId => {
                const search = document.getElementById(searchId);
                if (!search) return;
                const listId = searchId === 'dashboard-country-search' ? 'dashboard-countries-list' : 'countries-list';
                search.addEventListener('input', () => {
                    const q = search.value.toLowerCase();
                    const list = document.getElementById(listId);
                    if (!list) return;
                    list.querySelectorAll('.country-item').forEach(item => {
                        const name = item.querySelector('.country-name').textContent.toLowerCase();
                        item.style.display = name.includes(q) ? 'flex' : 'none';
                    });
                });
            });
        }

        // ------------------------------------------------------------
        // Network settings
        // ------------------------------------------------------------

        async loadNetworkConfig() {
            try {
                const cfg = await this.api('/api/network');
                this._netCfg = cfg;
                this.set('dns-mode', cfg.dns_mode || 'auto');
                this.set('dns-custom', cfg.dns_custom || '');
                this.set('edge-address', cfg.edge_address || '');
                this.set('socks-bind-address', cfg.socks_bind_address || '127.0.0.1');
                this.set('socks-port', cfg.socks_port || 1080);
                const httpProxyEnabled = document.getElementById('http-proxy-enabled'); if (httpProxyEnabled) httpProxyEnabled.checked = !!cfg.http_proxy_enabled;
                this.set('http-proxy-port', cfg.http_proxy_port || 8080);
                this.set('mtu', cfg.mtu || 1400);
                const upstreamProxyEnabled = document.getElementById('upstream-proxy-enabled'); if (upstreamProxyEnabled) upstreamProxyEnabled.checked = !!cfg.upstream_proxy_enabled;
                this.set('upstream-proxy-type', cfg.upstream_proxy_type || 'socks5');
                this.set('upstream-proxy-host', cfg.upstream_proxy_host || '');
                this.set('upstream-proxy-port', cfg.upstream_proxy_port || 1080);
                this.set('upstream-proxy-username', cfg.upstream_proxy_username || '');
                this.set('upstream-proxy-password', '');
                this.set('tunnel-dns-provider', cfg.tunnel_dns_provider || 'default');
                this.set('custom-tunnel-doh-url', cfg.custom_tunnel_doh_url || '');
                this.set('resolver-dns-provider', cfg.resolver_dns_provider || 'automatic');
                this.set('custom-resolver-ip', cfg.custom_resolver_ip || '');
                this.set('tls-split-mode', cfg.tls_split_mode || 'off');
                this.set('ip-mode', cfg.ip_mode || 'dual_stack');
                this.set('transport-version', cfg.transport_version || 'h2');
                this.set('multiplex-streams', String(cfg.multiplex_streams || 8));
                this.set('utls-fingerprint', cfg.utls_fingerprint || 'disabled');
                this.set('tls-fragment-mode', cfg.tls_fragment_mode || 'disabled');
                this.set('tls-fragment-delay', cfg.tls_fragment_fallback_delay_ms ?? 300);
                this.set('latency-probe-url', cfg.latency_probe_url || 'https://www.gstatic.com/generate_204');
                this.set('bootstrap-dns-provider', cfg.bootstrap_dns_provider || 'automatic');
                this.set('custom-bootstrap-doh-url', cfg.custom_bootstrap_doh_url || '');
                this.set('relayer-provider', cfg.relayer_provider || 'automatic');
                this.set('custom-relayer-url', cfg.custom_relayer_url || '');
                const bypassLocal = document.getElementById('bypass-local-network'); if (bypassLocal) bypassLocal.checked = cfg.bypass_local_network !== false;
                const killSwitch = document.getElementById('kill-switch'); if (killSwitch) killSwitch.checked = !!cfg.kill_switch;
                const autoRecovery = document.getElementById('automatic-recovery'); if (autoRecovery) autoRecovery.checked = cfg.automatic_recovery !== false;
                const alwaysOn = document.getElementById('always-on'); if (alwaysOn) alwaysOn.checked = !!cfg.always_on;
                const updateChecks = document.getElementById('update-checks'); if (updateChecks) updateChecks.checked = cfg.update_checks !== false;
                const localAuth = document.getElementById('local-proxy-auth-enabled'); if (localAuth) localAuth.checked = !!cfg.local_proxy_auth_enabled;
                this.set('local-proxy-username', cfg.local_proxy_username || '');
                this.set('local-proxy-password', '');
                this.toggleCustomDns();
                this.toggleCustomTunnelDoh();
                this.toggleCustomResolverIp();
                this.toggleBootstrapDoh();
                this.toggleCustomRelayer();
                this.toggleLocalProxyAuth();
                this.clearErrors('dns-custom', 'edge-address', 'listen-port', 'socks-bind-address', 'socks-port', 'http-proxy-port', 'mtu', 'custom-tunnel-doh-url', 'custom-resolver-ip', 'upstream-proxy-host', 'upstream-proxy-port');
            } catch (e) {
                this.log(`Failed to load network config: ${e.message}`);
            }
        }

        toggleCustomDns() {
            const mode = document.getElementById('dns-mode');
            const group = document.getElementById('custom-dns-group');
            if (mode && group) {
                if (mode.value === 'custom') group.removeAttribute('hidden');
                else group.setAttribute('hidden', '');
            }
        }

        toggleCustomTunnelDoh() {
            const mode = document.getElementById('tunnel-dns-provider');
            const group = document.getElementById('custom-tunnel-doh-group');
            if (mode && group) {
                if (mode.value === 'custom') group.removeAttribute('hidden');
                else group.setAttribute('hidden', '');
            }
        }

        toggleCustomResolverIp() {
            const mode = document.getElementById('resolver-dns-provider');
            const group = document.getElementById('custom-resolver-ip-group');
            if (mode && group) {
                if (mode.value === 'custom') group.removeAttribute('hidden');
                else group.setAttribute('hidden', '');
            }
        }

        toggleBootstrapDoh() {
            const mode = document.getElementById('bootstrap-dns-provider');
            const input = document.getElementById('custom-bootstrap-doh-url');
            if (mode && input) {
                if (mode.value === 'custom') input.removeAttribute('hidden');
                else input.setAttribute('hidden', '');
            }
        }

        toggleCustomRelayer() {
            const mode = document.getElementById('relayer-provider');
            const input = document.getElementById('custom-relayer-url');
            if (mode && input) {
                if (mode.value === 'custom') input.removeAttribute('hidden');
                else input.setAttribute('hidden', '');
            }
        }

        toggleLocalProxyAuth() {
            const enabled = document.getElementById('local-proxy-auth-enabled');
            const username = document.getElementById('local-proxy-username');
            const password = document.getElementById('local-proxy-password');
            if (enabled && username && password) {
                if (enabled.checked) {
                    username.removeAttribute('hidden');
                    password.removeAttribute('hidden');
                } else {
                    username.setAttribute('hidden', '');
                    password.setAttribute('hidden', '');
                }
            }
        }

        async saveNetworkConfig() {
            const dnsMode = this.val('dns-mode');
            const dnsCustom = this.val('dns-custom');
            const edgeAddress = this.val('edge-address');
            const socksBindAddress = this.val('socks-bind-address');
            const socksPort = this.val('socks-port');
            const httpProxyEnabled = !!document.getElementById('http-proxy-enabled')?.checked;
            const httpProxyPort = this.val('http-proxy-port');
            const mtu = this.val('mtu');
            const upstreamProxyEnabled = !!document.getElementById('upstream-proxy-enabled')?.checked;
            const upstreamProxyType = this.val('upstream-proxy-type');
            const upstreamProxyHost = this.val('upstream-proxy-host');
            const upstreamProxyPort = this.val('upstream-proxy-port');
            const upstreamProxyUsername = this.val('upstream-proxy-username');
            const upstreamProxyPassword = this.val('upstream-proxy-password');
            const tunnelDnsProvider = this.val('tunnel-dns-provider');
            const customTunnelDohUrl = this.val('custom-tunnel-doh-url');
            const resolverDnsProvider = this.val('resolver-dns-provider');
            const customResolverIp = this.val('custom-resolver-ip');
            const tlsSplitMode = this.val('tls-split-mode');
            const ipMode = this.val('ip-mode');
            const transportVersion = this.val('transport-version');
            const multiplexStreams = Number(this.val('multiplex-streams') || 8);
            const utlsFingerprint = this.val('utls-fingerprint');
            const tlsFragmentMode = this.val('tls-fragment-mode');
            const tlsFragmentDelay = Number(this.val('tls-fragment-delay') || 300);
            const latencyProbeUrl = this.val('latency-probe-url');
            const bootstrapDnsProvider = this.val('bootstrap-dns-provider');
            const customBootstrapDohUrl = this.val('custom-bootstrap-doh-url');
            const relayerProvider = this.val('relayer-provider');
            const customRelayerUrl = this.val('custom-relayer-url');
            const bypassLocalNetwork = !!document.getElementById('bypass-local-network')?.checked;
            const killSwitch = !!document.getElementById('kill-switch')?.checked;
            const automaticRecovery = !!document.getElementById('automatic-recovery')?.checked;
            const alwaysOn = !!document.getElementById('always-on')?.checked;
            const updateChecks = !!document.getElementById('update-checks')?.checked;
            const localProxyAuthEnabled = !!document.getElementById('local-proxy-auth-enabled')?.checked;
            const localProxyUsername = this.val('local-proxy-username');
            const localProxyPassword = this.val('local-proxy-password');

            if (localProxyAuthEnabled && (!localProxyUsername || !localProxyPassword)) {
                this.log('Local proxy authentication requires a username and password');
                return;
            }

            this.clearErrors('dns-custom', 'edge-address', 'listen-port', 'socks-bind-address', 'socks-port', 'http-proxy-port', 'mtu', 'custom-tunnel-doh-url', 'custom-resolver-ip');
            const ok = this.validate({ dnsMode, dnsCustom, edgeAddress, listenPort: socksPort, socksBindAddress, httpProxyPort, mtu, customTunnelDohUrl, customResolverIp, upstreamProxyEnabled, upstreamProxyType, upstreamProxyHost, upstreamProxyPort });
            if (!ok) return;

            try {
                const body = {
                    dns_mode: dnsMode,
                    dns_custom: dnsCustom,
                    edge_address: edgeAddress,
                    socks_bind_address: socksBindAddress,
                    socks_port: Number(socksPort),
                    http_proxy_enabled: httpProxyEnabled,
                    http_proxy_port: Number(httpProxyPort),
                    mtu: Number(mtu),
                    upstream_proxy_enabled: upstreamProxyEnabled,
                    upstream_proxy_type: upstreamProxyType,
                    upstream_proxy_host: upstreamProxyHost,
                    upstream_proxy_port: Number(upstreamProxyPort),
                    upstream_proxy_username: upstreamProxyUsername,
                    upstream_proxy_password: upstreamProxyPassword,
                    tunnel_dns_provider: tunnelDnsProvider,
                    custom_tunnel_doh_url: customTunnelDohUrl,
                    resolver_dns_provider: resolverDnsProvider,
                    custom_resolver_ip: customResolverIp,
                    tls_split_mode: tlsSplitMode,
                    ip_mode: ipMode,
                    transport_version: transportVersion,
                    multiplex_streams: multiplexStreams,
                    utls_fingerprint: utlsFingerprint,
                    tls_fragment_mode: tlsFragmentMode,
                    tls_fragment_fallback_delay_ms: tlsFragmentDelay,
                    latency_probe_url: latencyProbeUrl,
                    bootstrap_dns_provider: bootstrapDnsProvider,
                    custom_bootstrap_doh_url: customBootstrapDohUrl,
                    relayer_provider: relayerProvider,
                    custom_relayer_url: customRelayerUrl,
                    bypass_local_network: bypassLocalNetwork,
                    kill_switch: killSwitch,
                    automatic_recovery: automaticRecovery,
                    always_on: alwaysOn,
                    update_checks: updateChecks,
                    local_proxy_auth_enabled: localProxyAuthEnabled,
                    local_proxy_username: localProxyUsername,
                    local_proxy_password: localProxyPassword,
                    // Preserve the persisted connection mode: this form has
                    // no mode field, so omitting it would silently reset the
                    // app to non-proxy-only mode on every save.
                    proxy_only_mode: !!(this._netCfg && this._netCfg.proxy_only_mode)
                };
                await this.api('/api/network', {
                    method: 'POST',
                    body: JSON.stringify(body)
                });
                this.log('Network settings saved. Restart to apply.');
            } catch (e) {
                this.log(`Failed to save: ${e.message}`);
            }
        }

        // Preserved original semantics: resets the three persisted fields to
        // their defaults (auto, empty, empty) and saves.
        async testRelayerLatency() {
            const resultEl = document.getElementById('relayer-test-result');
            const provider = this.val('relayer-provider') || 'automatic';
            const customUrl = this.val('custom-relayer-url') || '';
            if (provider === 'direct') {
                if (resultEl) resultEl.textContent = 'Direct mode: no relayer to probe.';
                return;
            }
            if (resultEl) resultEl.textContent = 'Probing relayer…';
            try {
                const result = await this.api('/api/network/relayer/test', {
                    method: 'POST',
                    body: JSON.stringify({ provider, custom_url: customUrl })
                });
                const summary = (result.results || [])
                    .map(r => r.ok ? `${new URL(r.relayer).host}: ${r.rtt_ms} ms` : `${new URL(r.relayer).host}: failed`)
                    .join(', ');
                if (resultEl) resultEl.textContent = summary || 'No relayer endpoint configured.';
            } catch (e) {
                if (resultEl) resultEl.textContent = `Relayer test failed: ${e.message}`;
            }
        }

        async checkForUpdates() {
            try {
                const result = await this.api('/api/updates/check');
                if (result.update_available) {
                    this.log(`Update available: ${result.latest_tag} (current v${result.current_version}) — ${result.release_url}`);
                } else {
                    this.log(`Up to date (v${result.current_version}); latest upstream release is ${result.latest_tag}.`);
                }
            } catch (e) {
                this.log(`Update check failed: ${e.message}`);
            }
        }

        resetNetworkConfig() {
            this.set('dns-mode', 'auto');
            this.set('dns-custom', '');
            this.set('edge-address', '');
            this.set('socks-bind-address', '127.0.0.1');
            this.set('socks-port', 1080);
            const http = document.getElementById('http-proxy-enabled'); if (http) http.checked = false;
            this.set('http-proxy-port', 8080);
            this.set('mtu', 1400);
            const upstream = document.getElementById('upstream-proxy-enabled'); if (upstream) upstream.checked = false;
            this.set('upstream-proxy-type', 'socks5');
            this.set('upstream-proxy-host', '');
            this.set('upstream-proxy-port', 1080);
            this.set('upstream-proxy-username', '');
            this.set('upstream-proxy-password', '');
            this.set('tunnel-dns-provider', 'default');
            this.set('custom-tunnel-doh-url', '');
            this.set('resolver-dns-provider', 'automatic');
            this.set('custom-resolver-ip', '');
            this.set('tls-split-mode', 'off');
            this.set('ip-mode', 'dual_stack');
            this.set('transport-version', 'h2');
            this.set('multiplex-streams', '8');
            this.set('utls-fingerprint', 'disabled');
            this.set('tls-fragment-mode', 'disabled');
            this.set('tls-fragment-delay', 300);
            this.set('latency-probe-url', 'https://www.gstatic.com/generate_204');
            this.set('bootstrap-dns-provider', 'automatic');
            this.set('custom-bootstrap-doh-url', '');
            this.set('relayer-provider', 'automatic');
            this.set('custom-relayer-url', '');
            const bypassLocal = document.getElementById('bypass-local-network'); if (bypassLocal) bypassLocal.checked = true;
            const killSwitch = document.getElementById('kill-switch'); if (killSwitch) killSwitch.checked = false;
            const autoRecovery = document.getElementById('automatic-recovery'); if (autoRecovery) autoRecovery.checked = true;
            const alwaysOn = document.getElementById('always-on'); if (alwaysOn) alwaysOn.checked = false;
            const updateChecks = document.getElementById('update-checks'); if (updateChecks) updateChecks.checked = true;
            const localAuth = document.getElementById('local-proxy-auth-enabled'); if (localAuth) localAuth.checked = false;
            this.set('local-proxy-username', '');
            this.set('local-proxy-password', '');
            this.toggleCustomDns();
            this.toggleCustomTunnelDoh();
            this.toggleCustomResolverIp();
            this.toggleBootstrapDoh();
            this.toggleCustomRelayer();
            this.toggleLocalProxyAuth();
            this.saveNetworkConfig();
        }

        validate({ dnsMode, dnsCustom, edgeAddress, listenPort, socksBindAddress, httpProxyPort, mtu, customTunnelDohUrl, customResolverIp, upstreamProxyEnabled, upstreamProxyType, upstreamProxyHost, upstreamProxyPort }) {
            let ok = true;

            if (dnsMode === 'custom') {
                const parts = dnsCustom.split(',').map(p => p.trim()).filter(Boolean);
                if (!parts.length) {
                    this.showError('dns-custom', 'Enter at least one DNS address when using Custom mode.');
                    ok = false;
                } else {
                    for (const part of parts) {
                        if (!part.trim()) {
                            this.showError('dns-custom', 'DNS entries cannot be empty.');
                            ok = false;
                            break;
                        }
                    }
                }
            }

            if (edgeAddress) {
                if (!edgeAddress.includes(':')) {
                    this.showError('edge-address', 'Edge address must be in host:port format.');
                    ok = false;
                } else {
                    const host = edgeAddress.slice(0, edgeAddress.lastIndexOf(':'));
                    const portStr = edgeAddress.slice(edgeAddress.lastIndexOf(':') + 1);
                    if (!host) {
                        this.showError('edge-address', 'Edge address must include a host.');
                        ok = false;
                    } else if (!this._validPort(portStr)) {
                        this.showError('edge-address', 'Edge address port must be an integer between 1 and 65535.');
                        ok = false;
                    }
                }
            }

            if (!this._validPort(listenPort)) {
                this.showError('listen-port', 'Listen port must be an integer between 1 and 65535.');
                ok = false;
            }

            if (socksBindAddress && !this._validIp(socksBindAddress)) {
                this.showError('socks-bind-address', 'SOCKS bind address must be a valid IP address.');
                ok = false;
            }

            if (!this._validPort(httpProxyPort)) {
                this.showError('http-proxy-port', 'HTTP proxy port must be an integer between 1 and 65535.');
                ok = false;
            }

            const mtuValue = Number(mtu);
            if (!Number.isInteger(mtuValue) || mtuValue < 576 || mtuValue > 9000) {
                this.showError('mtu', 'MTU must be an integer between 576 and 9000.');
                ok = false;
            }

            const tunnelMode = document.getElementById('tunnel-dns-provider')?.value || 'default';
            if (tunnelMode === 'custom') {
                if (!customTunnelDohUrl || !String(customTunnelDohUrl).startsWith('https://')) {
                    this.showError('custom-tunnel-doh-url', 'Custom tunnel DoH URL must start with https://.');
                    ok = false;
                }
            }

            const resolverMode = document.getElementById('resolver-dns-provider')?.value || 'automatic';
            if (resolverMode === 'custom') {
                if (!customResolverIp || !this._validIp(customResolverIp)) {
                    this.showError('custom-resolver-ip', 'Custom resolver must be a valid IP address.');
                    ok = false;
                }
            }

            if (upstreamProxyEnabled || upstreamProxyHost) {
                if (upstreamProxyType !== 'socks5' && upstreamProxyType !== 'http') {
                    this.showError('upstream-proxy-type', 'Upstream proxy type must be SOCKS5 or HTTP.');
                    ok = false;
                }
                if (!upstreamProxyHost) {
                    this.showError('upstream-proxy-host', 'Upstream proxy host is required when enabled.');
                    ok = false;
                }
                if (!this._validPort(upstreamProxyPort)) {
                    this.showError('upstream-proxy-port', 'Upstream proxy port must be an integer between 1 and 65535.');
                    ok = false;
                }
            }

            return ok;
        }

        _validPort(v) {
            if (v === null || v === undefined || v === '') return false;
            const n = Number(v);
            return Number.isInteger(n) && n >= 1 && n <= 65535;
        }

        _validIp(v) {
            return /^[0-9a-fA-F:.]+$/.test(String(v || '').trim());
        }

        showError(inputId, message) {
            const input = document.getElementById(inputId);
            const group = input ? input.closest('.setting-group') : null;
            const err = document.getElementById(`${inputId}-error`);
            if (group) group.classList.add('has-error');
            if (err) err.textContent = message;
            if (input && input.setAttribute) input.setAttribute('aria-invalid', 'true');
        }

        clearErrors(...ids) {
            ids.forEach(id => {
                const input = document.getElementById(id);
                const group = input ? input.closest('.setting-group') : null;
                const err = document.getElementById(`${id}-error`);
                if (group) group.classList.remove('has-error');
                if (err) err.textContent = '';
                if (input && input.removeAttribute) input.removeAttribute('aria-invalid');
            });
        }

        bindFormEvents() {
            this.bindCountrySearch();

            const dnsMode = document.getElementById('dns-mode');
            if (dnsMode) dnsMode.addEventListener('change', () => this.toggleCustomDns());
            const tunnelDns = document.getElementById('tunnel-dns-provider');
            if (tunnelDns) tunnelDns.addEventListener('change', () => this.toggleCustomTunnelDoh());
            const resolverDns = document.getElementById('resolver-dns-provider');
            if (resolverDns) resolverDns.addEventListener('change', () => this.toggleCustomResolverIp());
            const bootstrapDns = document.getElementById('bootstrap-dns-provider');
            if (bootstrapDns) bootstrapDns.addEventListener('change', () => this.toggleBootstrapDoh());
            const relayerProvider = document.getElementById('relayer-provider');
            if (relayerProvider) relayerProvider.addEventListener('change', () => this.toggleCustomRelayer());
            const localProxyAuth = document.getElementById('local-proxy-auth-enabled');
            if (localProxyAuth) localProxyAuth.addEventListener('change', () => this.toggleLocalProxyAuth());
            const resetLatencyUrl = document.getElementById('reset-latency-url');
            if (resetLatencyUrl) resetLatencyUrl.addEventListener('click', () => this.set('latency-probe-url', 'https://www.gstatic.com/generate_204'));
            const relayerTestBtn = document.getElementById('btn-relayer-test');
            if (relayerTestBtn) relayerTestBtn.addEventListener('click', () => this.testRelayerLatency());

            const saveBtn = document.getElementById('save-network');
            if (saveBtn) saveBtn.addEventListener('click', () => this.saveNetworkConfig());

            const resetBtn = document.getElementById('reset-network');
            if (resetBtn) resetBtn.addEventListener('click', () => this.resetNetworkConfig());

            const checkUpdatesBtn = document.getElementById('btn-check-updates');
            if (checkUpdatesBtn) checkUpdatesBtn.addEventListener('click', () => this.checkForUpdates());

            // Onboarding prompt: the message navigates to the Account tab;
            // the action button opens the in-app sign-in form there (no
            // console interaction at any point).
            const onboardingMessage = document.getElementById('onboarding-message');
            if (onboardingMessage) {
                onboardingMessage.addEventListener('click', () => this.switchTab('account'));
            }
            const onboardingSignin = document.getElementById('onboarding-signin');
            if (onboardingSignin) {
                onboardingSignin.addEventListener('click', () => {
                    this.switchTab('account');
                    this.beginSignIn();
                });
            }

            const signinForm = document.getElementById('signin-form');
            if (signinForm) {
                signinForm.addEventListener('submit', (ev) => {
                    ev.preventDefault();
                    this.submitSignIn();
                });
            }
            const passwordInput = document.getElementById('signin-password');
            if (passwordInput) {
                // Credentials live in this input only; never persisted.
                passwordInput.value = '';
                window.addEventListener('beforeunload', () => {
                    try { passwordInput.value = ''; } catch (e) { /* noop */ }
                });
            }
            const passwordToggle = document.getElementById('signin-password-toggle');
            if (passwordToggle) {
                passwordToggle.addEventListener('click', () => {
                    const input = document.getElementById('signin-password');
                    if (!input) return;
                    const showing = input.type === 'text';
                    input.type = showing ? 'password' : 'text';
                    passwordToggle.textContent = showing ? 'Show' : 'Hide';
                    passwordToggle.setAttribute('aria-pressed', showing ? 'false' : 'true');
                    passwordToggle.setAttribute('aria-label', showing ? 'Show password' : 'Hide password');
                });
            }
            const verifySubmit = document.getElementById('verify-submit');
            if (verifySubmit) verifySubmit.addEventListener('click', () => this.submitVerification());
            const verifyCancel = document.getElementById('verify-cancel');
            if (verifyCancel) verifyCancel.addEventListener('click', () => this.cancelVerification());

            // Inline confirmation and the errno-125 unblock step.
            const verifyResend = document.getElementById('verify-resend');
            if (verifyResend) verifyResend.addEventListener('click', () => this.resendVerificationCode());
            const unblockSubmit = document.getElementById('unblock-submit');
            if (unblockSubmit) unblockSubmit.addEventListener('click', () => this.submitUnblockCode());
            const unblockResend = document.getElementById('unblock-resend');
            if (unblockResend) unblockResend.addEventListener('click', () => this.resendUnblockCode());
            const unblockCancel = document.getElementById('unblock-cancel');
            if (unblockCancel) unblockCancel.addEventListener('click', () => this.cancelVerification());

            // Session Token import (fallback sign-in path).
            const saveTokenBtn = document.getElementById('btn-save-token');
            if (saveTokenBtn) saveTokenBtn.addEventListener('click', () => this.saveSessionToken());
            const importTokenBtn = document.getElementById('btn-import-token');
            if (importTokenBtn) {
                importTokenBtn.addEventListener('click', () => {
                    const fileInput = document.getElementById('session-token-file');
                    if (fileInput) fileInput.click();
                });
            }
            const tokenFile = document.getElementById('session-token-file');
            if (tokenFile) tokenFile.addEventListener('change', () => this.importSessionTokenFile());
            const tokenInput = document.getElementById('session-token-input');
            if (tokenInput) {
                tokenInput.value = '';
                window.addEventListener('beforeunload', () => {
                    try { tokenInput.value = ''; } catch (e) { /* noop */ }
                });
            }

            const logoutBtn = document.getElementById('btn-logout');
            if (logoutBtn) logoutBtn.addEventListener('click', () => {
                this.signOut();
            });

            const clearBtn = document.getElementById('btn-clear-tokens');
            if (clearBtn) clearBtn.addEventListener('click', () => {
                this.signOut();
            });

            const logClear = document.getElementById('log-clear');
            if (logClear) logClear.addEventListener('click', () => this.clearLog());
            const logCopy = document.getElementById('log-copy');
            if (logCopy) logCopy.addEventListener('click', () => this.copyLog());

            const connToggle = document.getElementById('connection-toggle');
            if (connToggle) connToggle.addEventListener('click', () => this.onConnectionToggle());

            const modeProxyBtn = document.getElementById('mode-proxy-only');
            if (modeProxyBtn) modeProxyBtn.addEventListener('click', () => this.setConnectionMode('proxy'));
            const modeTunBtn = document.getElementById('mode-tun');
            if (modeTunBtn) modeTunBtn.addEventListener('click', () => this.setConnectionMode('tun'));
        }

        // The proxy controller owns connection establishment and teardown as
        // part of the application lifecycle; the API exposes connect/disconnect
        // and restart control-plane actions. The button reflects the true
        // current state and manages the tunnel via the API instead of merely
        // reporting owned-by-lifecycle semantics.
        onConnectionToggle() {
            if (this._actionBusy) return;
            const chip = document.getElementById('connection-state');
            const state = chip ? chip.getAttribute('data-state') : '';
            // While stuck on Connecting the user must still be able to cancel:
            // /api/disconnect cancels an in-flight restart task instead of
            // being ignored until initialize() finishes or times out.
            const connected = (state === UI_STATE.CONNECTING
                || state === UI_STATE.CONNECTED_VERIFIED
                || state === UI_STATE.CONNECTED_VERIFYING
                || state === UI_STATE.CONNECTED_UNVERIFIED
                || state === UI_STATE.PROXY_ACTIVE);
            if (connected) {
                this._actionBusy = true;
                this.log('Disconnecting via /api/disconnect…');
                this.setButtonState(true, 'Disconnecting…');
                this.deferApiAction(() => {
                    this.api('/api/disconnect', {method: 'POST'})
                        .then(data => {
                            this.log(data.detail || 'Disconnected');
                        })
                        .catch(err => {
                            this.log('Disconnect failed: ' + err.message);
                        })
                        .finally(() => {
                            this._actionBusy = false;
                            this.setButtonState(false, 'Connect');
                            this.updateDashboard();
                        });
                });
            } else {
                this._actionBusy = true;
                if (this._authenticated === false) {
                    // Not signed in: /api/restart would 409 ("Not signed in:
                    // sign in first, then connect") and previously surfaced
                    // nothing but a log line — the button appeared dead and
                    // the sign-in path was undiscoverable from the dashboard.
                    // Redirect to the Account tab with the sign-in form open.
                    this.log('Connect blocked: not signed in. Sign in on the Account tab, then press Connect again.');
                    this._actionBusy = false;
                    this._authNotice = 'Sign in to your account before connecting the VPN.';
                    this.updateOnboarding();
                    this.switchTab('account');
                    this.beginSignIn();
                    return;
                }
                const mode = this.currentMode();
                const modeLabel = mode === 'tun' ? 'TUN' : 'Proxy';
                this.log(`No VPN connection is active. Connecting in ${modeLabel} mode via /api/restart…`);
                this.setButtonState(true, 'Connecting…');
                this.applyState(UI_STATE.CONNECTING, this._lastStatus || null);
                this.restartVPN(mode);
            }
        }

        // WebView2 has no Qt main loop: the UI is already on the browser's
        // event loop. Defer the fetch to the next task so this handler returns
        // after painting the optimistic state; fetch itself performs the
        // blocking dial off the render thread.
        deferApiAction(action) {
            window.setTimeout(action, 0);
        }

        restartVPN(mode) {
            const connectMode = mode || this.currentMode();
            this.log(`Starting VPN in ${connectMode === 'tun' ? 'TUN' : 'Proxy'} mode…`);
            this.setButtonState(true, 'Connecting…');
            this.applyState(UI_STATE.CONNECTING, this._lastStatus || null);
            this.deferApiAction(() => {
                this.api('/api/restart', {
                    method: 'POST',
                    body: JSON.stringify({mode: connectMode})
                })
                    .then(data => {
                        this.log(data.detail || 'VPN started');
                        this.updateDashboard();
                    })
                    .catch(err => {
                        const message = err.message || '';
                        this.log('Restart failed: ' + message);
                        if (/not signed in/i.test(message) || this._authenticated === false) {
                            // Stale/expired credentials discovered at connect
                            // time: route the user to the Account tab instead of
                            // leaving the button in an apparently-dead state.
                            this._authNotice = 'Not signed in: enter your credentials on the Account tab, then press Connect again.';
                            this.updateOnboarding();
                            this.switchTab('account');
                            this.beginSignIn();
                        }
                    })
                    .finally(() => {
                        this._actionBusy = false;
                        this.setButtonState(false, 'Connect');
                    });
            });
        }

        setButtonState(disabled, text) {
            const btn = document.getElementById('connection-toggle');
            if (!btn) return;
            // Use a loading state, not HTML `disabled`: the button must keep
            // the arrow/progress cursor and its animated dial while the
            // elevated helper is starting.
            btn.disabled = false;
            btn.classList.toggle('is-connecting', disabled);
            btn.classList.toggle('is-loading', disabled);
            btn.setAttribute('aria-busy', disabled ? 'true' : 'false');
            btn.setAttribute('aria-disabled', disabled ? 'true' : 'false');
            const btnText = btn.querySelector('.btn__text');
            if (btnText) btnText.textContent = text;
        }

        // ------------------------------------------------------------
        // Connection mode (proxy-only vs TUN) — buttons under the dial
        // ------------------------------------------------------------

        currentMode() {
            if (this._selectedMode === 'tun' || this._selectedMode === 'proxy'
                || this._selectedMode === 'proxy_only') {
                return this._selectedMode;
            }
            const modes = (this._lastStatus && this._lastStatus.modes) || {};
            if (modes.selected === 'tun' || modes.selected === 'proxy'
                || modes.selected === 'proxy_only') {
                return modes.selected;
            }
            const tunnel = this._lastStatus && this._lastStatus.tunnel;
            if (tunnel && tunnel.enabled) return 'tun';
            return 'proxy';
        }

        isLiveConnection() {
            const chip = document.getElementById('connection-state');
            const state = chip ? chip.getAttribute('data-state') : '';
            return state === UI_STATE.CONNECTED_VERIFIED
                || state === UI_STATE.CONNECTED_VERIFYING
                || state === UI_STATE.CONNECTED_UNVERIFIED
                || state === UI_STATE.PROXY_ACTIVE
                || state === UI_STATE.CONNECTING;
        }

        setConnectionMode(mode) {
            if (this._modeBusy) return;
            const live = this.isLiveConnection();
            const priorMode = this.currentMode();
            this._selectedMode = mode;
            if (!this._lastStatus) this._lastStatus = {};
            this._lastStatus.modes = {
                ...(this._lastStatus.modes || {}),
                selected: mode,
            };
            const label = mode === 'tun' ? 'TUN' : 'Proxy';
            const previous = this._uiTransition;
            // Selecting a mode while disconnected is a preference, not a
            // connection: persist it, but never paint "connecting" or let
            // the backend start TUN before the user presses Connect.
            this._uiTransition = live
                ? { type: 'mode', targetMode: mode, startedAt: Date.now(), settled: false }
                : null;
            this._modeBusy = true;
            if (live) {
                this.log(`Switching to ${label} mode…`);
                this.setButtonState(true, 'Switching…');
                this.applyState(UI_STATE.CONNECTING, this._lastStatus || null);
            } else {
                this.log(`Selected ${label} mode; press Connect to apply.`);
                this.updateDashboard();
            }
            this.deferApiAction(() => {
                this.api('/api/mode', {
                    method: 'POST',
                    body: JSON.stringify({ mode, apply: live })
                })
                    .then(data => {
                        const ok = data && data.success !== false;
                        this.log((data && data.detail) || (ok ? 'Connection mode applied' : 'Mode change failed'));
                        if (!ok) {
                            this._selectedMode = priorMode;
                            this._uiTransition = previous || null;
                        } else if (data && data.modes) {
                            this._selectedMode = mode;
                            this._lastStatus = {
                                ...(this._lastStatus || {}),
                                modes: data.modes,
                            };
                        }
                    })
                    .catch(err => {
                        this._selectedMode = priorMode;
                        this._uiTransition = previous || null;
                        this.log('Mode change failed: ' + err.message);
                    })
                    .finally(() => {
                        this._modeBusy = false;
                        this._uiTransition = null;
                        if (live) this.setButtonState(false, 'Connect');
                        this.updateDashboard();
                    });
            });
        }

        // ------------------------------------------------------------
        // Account / authentication state
        //
        // The auth state is polled globally (not only when the Account tab
        // is open) so the onboarding prompt reacts to sign-in/sign-out and
        // helper-persisted tokens without needing an app restart.
        // ------------------------------------------------------------

        startAuthPolling() {
            this.refreshAuthState();
            this._authTimer = window.setInterval(() => {
                if (!document.hidden) this.refreshAuthState();
            }, 4000);
            document.addEventListener('visibilitychange', () => {
                if (!document.hidden) this.refreshAuthState();
            });
        }

        async refreshAuthState() {
            // Only a successful /api/account answer defines the state. A
            // failed check must never flip the prompt into signed-out mode:
            // that would show it during transient loading/error conditions.
            try {
                const acc = await this.api('/api/account');
                this.setAuthState(acc.account_status === 'signed in', acc);
                if (!this._signinBusy && !this._signinVerification) {
                    // Don't override live form feedback while the user is
                    // mid-attempt; a backend-driven stage change still wins.
                    this.renderAccountSection(acc);
                    if (acc.signin_stage === 'verification_required') {
                        // A confirmation is already awaiting (e.g. reload
                        // during sign-in): show the verification step again.
                        this.beginSignIn();
                        this.showVerification(acc.verification_method || 'email-2fa', '');
                    }
                }
            } catch (e) {
                // Keep whatever definitive state we already had.
            }
        }

        async loadAccount() {
            await this.refreshAuthState();
        }

        setAuthState(authenticated, acc) {
            const changed = this._authenticated !== authenticated;
            this._authenticated = authenticated;

            const logoutBtn = document.getElementById('btn-logout');
            if (logoutBtn) {
                if (authenticated) logoutBtn.removeAttribute('hidden');
                else logoutBtn.setAttribute('hidden', '');
            }

            if (changed) {
                this._authNotice = '';
                this.updateOnboarding();
                if (authenticated) {
                    // Just signed in (helper handoff or after launch):
                    // country rows were gated to the signed-out label; drop
                    // any stale results and re-measure now.
                    this._latencyCache = {};
                    this._countryLatency = Object.create(null);
                    this.countriesLatencyCycle();
                    this.refreshCountrySelection();
                } else {
                    // Session expired or signed out: measured results no
                    // longer describe an authenticated session.
                    this._latencyCache = {};
                    this._countryLatency = Object.create(null);
                    this.renderSignedOutLatencyLabels();
                    this.hideVerification();
                    this.signinFormVisible(true);
                    this.refreshQuota();
                }
                this._syncCountriesLatencyTimer();
            }
        }

        // Signed-out rows keep a neutral, non-blocking label until sign-in;
        // no probe and no pass/graced "No pass" wording is shown. In-flight
        // probe cycles are superseded so no result applied after the sign-out
        // transition can masquerade as an authenticated measurement.
        renderSignedOutLatencyLabels() {
            this._latencyGen = (this._latencyGen || 0) + 1;
            document.querySelectorAll('.country-latency').forEach(el => {
                if (!el.isConnected) return;
                el.textContent = SIGNED_OUT_LATENCY_LABEL;
            });
        }

        // Onboarding prompt visibility is strictly the negation of a
        // definitive signed-in state:
        //   authenticated === false  -> visible
        //   authenticated === true   -> hidden (display:none via [hidden])
        //   authenticated === null   -> hidden (auth check still loading)
        updateOnboarding() {
            const banner = document.getElementById('onboarding-banner');
            if (!banner) return;
            const textEl = banner.querySelector('.onboarding-banner__text');
            if (this._authenticated === false) {
                if (textEl) {
                    textEl.textContent = this._authNotice
                        || 'Welcome to PerchVPN. To get started, open the Account tab and sign in with your account credentials.';
                }
                banner.classList.toggle('onboarding-banner--error', !!this._authNotice);
                banner.removeAttribute('hidden');
            } else {
                banner.setAttribute('hidden', '');
            }
        }

        // ------------------------------------------------------------
        // In-app sign-in (no console, no helper window)
        // ------------------------------------------------------------

        beginSignIn() {
            const form = document.getElementById('signin-form');
            const verify = document.getElementById('signin-verify');
            if (!form) return;
            verify?.setAttribute('hidden', '');
            this.hideUnblockPanel();
            this.showSigninError('');
            form.removeAttribute('hidden');
            const email = document.getElementById('signin-email');
            if (email && !email.value) email.focus();
        }

        setSigninProgress(inFlight, text) {
            this._signinBusy = !!inFlight;
            const submit = document.getElementById('signin-submit');
            const progress = document.getElementById('signin-progress');
            const progressText = document.getElementById('signin-progress-text');
            const emailInput = document.getElementById('signin-email');
            const passwordInput = document.getElementById('signin-password');
            if (submit) submit.disabled = inFlight;
            if (progress) {
                progress.hidden = !inFlight;
                if (progressText && text) progressText.textContent = text;
            }
            if (emailInput) emailInput.disabled = inFlight;
            if (passwordInput) passwordInput.disabled = inFlight;
        }

        showSigninError(message) {
            const err = document.getElementById('signin-error');
            if (!err) return;
            err.textContent = message;
            err.hidden = !message;
        }

        async submitSignIn(unblockCode = '') {
            if (this._signinBusy) return; // duplicate-submission guard
            const emailInput = document.getElementById('signin-email');
            const passwordInput = document.getElementById('signin-password');
            if (!emailInput || !passwordInput) return;
            const email = emailInput.value.trim();
            const password = passwordInput.value;
            if (!email) {
                this.showSigninError('Enter your Firefox account email.');
                return;
            }
            if (!password) {
                this.showSigninError('Enter your password.');
                return;
            }
            this.showSigninError('');
            this.showUnblockError('');
            this.setSigninProgress(true, unblockCode ? 'Checking code…' : 'Signing in…');
            const verify = document.getElementById('signin-verify');
            verify?.setAttribute('hidden', '');
            try {
                const payload = { email, password, reset: !unblockCode };
                if (unblockCode) payload.unblock_code = unblockCode;
                const result = await this.api('/api/account/signin', {
                    method: 'POST',
                    body: JSON.stringify(payload),
                });
                if (result.status === 'signed_in') {
                    // Success: credentials are consumed; clear state.
                    passwordInput.value = '';
                    emailInput.value = '';
                    this.showSigninError('');
                    this.hideUnblockPanel();
                    this.setSigninProgress(false, '');
                    this.signinFormVisible(false);
                    this._authNotice = '';
                    this.updateOnboarding();
                    this.renderAccountSection({ account_status: 'signed in', empty_stage: true });
                    this.refreshQuota(true);
                    this.log('Signed in from the app.');
                    return;
                }
                if (result.status === 'verification_required') {
                    passwordInput.value = ''; // password only used for the login call
                    this.hideUnblockPanel();
                    this.showVerification(result.verification_method || 'email-2fa', result.message || '');
                    this.setSigninProgress(false, '');
                    return;
                }
                if (result.status === 'unblock_required') {
                    // FxA (errno 125) emailed an authorization code. The
                    // password stays in the input for the retry, while the
                    // Guardian PKCE window opens automatically if available.
                    this.showUnblockPanel(result.message || '');
                    this.setSigninProgress(false, '');
                    return;
                }
                this.setSigninProgress(false, '');
            } catch (e) {
                // Keep the username for correction; sanitized message only.
                if (unblockCode) {
                    this.showUnblockError(e.message || 'That authorization code was not accepted.');
                } else {
                    this.showSigninError(e.message || 'Sign-in failed; try again.');
                }
                this.setSigninProgress(false, '');
            } finally {
                if (passwordInput && this._signinBusy === false && this._signinVerification === undefined) {
                    // Password is never left behind between attempts, but it
                    // must survive an errno-125 retry that needs it again.
                    const verifyHidden = document.getElementById('signin-verify')?.hasAttribute('hidden');
                    const unblockHidden = document.getElementById('signin-unblock')?.hasAttribute('hidden');
                    if (verifyHidden && unblockHidden) {
                        passwordInput.value = '';
                    }
                }
            }
        }

        signinFormVisible(visible) {
            const form = document.getElementById('signin-form');
            if (form) form.hidden = !visible;
        }

        showVerification(method, message) {
            const verify = document.getElementById('signin-verify');
            const text = document.getElementById('signin-verify-text');
            const codeGroup = document.getElementById('signin-code-group');
            const submit = document.getElementById('verify-submit');
            this._signinVerification = method;
            if (!verify) return;
            this.hideUnblockPanel();
            verify.removeAttribute('hidden');
            const isLink = method === 'email';
            if (codeGroup) codeGroup.hidden = isLink;
            if (submit) submit.textContent = isLink ? 'I opened the link' : 'Confirm';
            if (text) {
                text.textContent = isLink
                    ? 'A confirmation link was emailed to you. Open it, then press the button below.'
                    : (method === 'totp'
                        ? (message || 'Enter the code from your authenticator app.')
                        : (message || 'Enter the confirmation code emailed to you.'));
            }
            const codeInput = document.getElementById('signin-code');
            if (codeInput && !isLink) { codeInput.value = ''; codeInput.focus(); }
        }

        hideVerification() {
            const verify = document.getElementById('signin-verify');
            verify?.setAttribute('hidden', '');
            const codeInput = document.getElementById('signin-code');
            if (codeInput) codeInput.value = '';
            this._signinVerification = undefined;
            const err = document.getElementById('verify-error');
            if (err) { err.hidden = true; err.textContent = ''; }
        }

        showVerifyError(message) {
            const err = document.getElementById('verify-error');
            if (!err) return;
            err.textContent = message;
            err.hidden = !message;
        }

        showVerifyFeedback(message) {
            const el = document.getElementById('verify-feedback');
            if (!el) return;
            el.textContent = message || '';
            el.hidden = !message;
        }

        async resendVerificationCode() {
            const btn = document.getElementById('verify-resend');
            if (btn) btn.disabled = true;
            this.showVerifyError('');
            this.showVerifyFeedback('Sending a new code…');
            try {
                const result = await this.api('/api/account/verify/resend', { method: 'POST' });
                this.showVerifyFeedback(result.message || 'A new code was sent; check your email.');
            } catch (e) {
                this.showVerifyFeedback('');
                this.showVerifyError(e.message || 'The code could not be re-sent.');
            } finally {
                if (btn) btn.disabled = false;
            }
        }

        async submitVerification() {
            if (this._signinBusy) return;
            const method = this._signinVerification || 'email-2fa';
            const codeInput = document.getElementById('signin-code');
            const code = method === 'email' ? '' : (codeInput ? codeInput.value.trim() : '');
            if (method !== 'email' && !code) {
                this.showVerifyError(
                    method === 'totp'
                        ? 'Enter the code from your authenticator app.'
                        : 'Enter the confirmation code emailed to you.'
                );
                return;
            }
            this.setSigninProgress(true, 'Confirming…');
            const submit = document.getElementById('verify-submit');
            if (submit) submit.disabled = true;
            try {
                const result = await this.api('/api/account/verify', {
                    method: 'POST',
                    body: JSON.stringify({ code }),
                });
                if (result.status === 'signed_in') {
                    this.hideVerification();
                    this.signinFormVisible(false);
                    this._authNotice = '';
                    this.updateOnboarding();
                    this.renderAccountSection({ account_status: 'signed in' });
                    this.refreshQuota(true);
                    this.log('Confirmation accepted; signed in.');
                    return;
                }
                this.showVerifyError('Unexpected response; try again.');
            } catch (e) {
                this.showVerifyError(e.message || 'Confirmation failed; try again.');
            } finally {
                if (submit) submit.disabled = false;
                this.setSigninProgress(false, '');
            }
        }

        async cancelVerification() {
            try {
                await this.api('/api/account/verify/cancel', { method: 'POST' });
            } catch (e) { /* slot already gone is fine */ }
            this.hideVerification();
            this.hideUnblockPanel();
            this.signinFormVisible(true);
            this.showSigninError('');
            const passwordInput = document.getElementById('signin-password');
            if (passwordInput) passwordInput.value = '';
            this.log('Sign-in attempt cancelled.');
            this.refreshTimedAccountState();
        }

        // ------------------------------------------------------------
        // FxA anti-bot (errno 125) unblock code
        // ------------------------------------------------------------

        showUnblockPanel(message) {
            const panel = document.getElementById('signin-unblock');
            const text = document.getElementById('signin-unblock-text');
            const code = document.getElementById('signin-unblock-code');
            if (text && message) text.textContent = message;
            if (code) code.value = '';
            this.showUnblockError('');
            if (panel) panel.hidden = false;
            if (code) code.focus();
        }

        hideUnblockPanel() {
            const panel = document.getElementById('signin-unblock');
            if (panel) panel.hidden = true;
            const code = document.getElementById('signin-unblock-code');
            if (code) code.value = '';
        }

        showUnblockError(message) {
            const err = document.getElementById('unblock-error');
            if (!err) return;
            err.textContent = message || '';
            err.hidden = !message;
        }

        async submitUnblockCode() {
            const input = document.getElementById('signin-unblock-code');
            const code = input ? input.value.trim() : '';
            if (!code) {
                this.showUnblockError('Enter the authorization code emailed to you.');
                return;
            }
            const emailInput = document.getElementById('signin-email');
            const passwordInput = document.getElementById('signin-password');
            const email = emailInput ? emailInput.value.trim() : '';
            const password = passwordInput ? passwordInput.value : '';
            if (!email || !password) {
                this.showUnblockError('Enter your email and password again to retry.');
                this.hideUnblockPanel();
                this.signinFormVisible(true);
                return;
            }
            await this.submitSignIn(code);
        }

        async resendUnblockCode() {
            const emailInput = document.getElementById('signin-email');
            const email = emailInput ? emailInput.value.trim() : '';
            if (!email) {
                this.showUnblockError('Enter your Firefox account email first.');
                return;
            }
            try {
                await this.api('/api/account/unblock/send', {
                    method: 'POST',
                    body: JSON.stringify({ email }),
                });
                this.showUnblockError('');
                this.log('Authorization code re-sent to your email.');
            } catch (e) {
                this.showUnblockError(e.message || 'The code could not be re-sent.');
            }
        }

        // ------------------------------------------------------------
        // Session Token import (fallback sign-in path)
        // ------------------------------------------------------------

        setSessionTokenFeedback(message, kind) {
            const el = document.getElementById('session-token-feedback');
            if (!el) return;
            el.textContent = message || '';
            el.hidden = !message;
            el.classList.toggle('is-error', kind === 'error');
            el.classList.toggle('is-success', kind === 'success');
        }

        async saveSessionToken() {
            const input = document.getElementById('session-token-input');
            const token = input ? input.value.trim() : '';
            if (!token) {
                this.setSessionTokenFeedback('Paste a session token first.', 'error');
                return;
            }
            const btn = document.getElementById('btn-save-token');
            if (btn) btn.disabled = true;
            this.setSessionTokenFeedback('Checking the token with Firefox Accounts…', '');
            try {
                const result = await this.api('/api/account/session-token', {
                    method: 'POST',
                    body: JSON.stringify({ session_token: token }),
                });
                if (result.status !== 'signed_in') {
                    this.setSessionTokenFeedback('Unexpected response; try again.', 'error');
                    return;
                }
                if (input) input.value = '';
                this.setSessionTokenFeedback('Signed in with the session token.', 'success');
                this._authNotice = '';
                this.updateOnboarding();
                this.renderAccountSection({ account_status: 'signed in' });
                this.refreshQuota(true);
                this.log('Signed in with an imported session token.');
            } catch (e) {
                this.setSessionTokenFeedback(
                    e.message || 'That session token could not be used.', 'error');
            } finally {
                if (btn) btn.disabled = false;
            }
        }

        async importSessionTokenFile() {
            const fileInput = document.getElementById('session-token-file');
            const input = document.getElementById('session-token-input');
            const file = fileInput && fileInput.files && fileInput.files[0];
            if (!file || !input) return;
            try {
                const text = (await file.text()).trim();
                let token = text;
                try {
                    const parsed = JSON.parse(text);
                    token = parsed.session_token || parsed.sessionToken || parsed.token || text;
                } catch (e) { /* plain-text token file */ }
                input.value = String(token).trim();
                this.setSessionTokenFeedback('Token loaded; press Save to sign in.', '');
            } catch (e) {
                this.setSessionTokenFeedback('That file could not be read.', 'error');
            } finally {
                try { fileInput.value = ''; } catch (e) { /* noop */ }
            }
        }

        // Account card (Network tab): transitions with real backend state.
        renderAccountSection(acc) {
            acc = acc || {};
            const signedIn = acc.account_status === 'signed in';
            const stage = acc.signin_stage || (acc.empty_stage ? 'signing_in' : '');

            const pill = document.getElementById('account-status-pill');
            const identifier = document.getElementById('account-identifier');
            const guardianStatus = document.getElementById('account-guardian-status');
            const form = document.getElementById('signin-form');
            const verify = document.getElementById('signin-verify');

            const setState = (pillClass, pillText, showForm, showVerify, guardianText) => {
                if (pill) {
                    pill.className = `account-status-pill ${pillClass}`;
                    pill.textContent = pillText;
                }
                if (form) form.hidden = !showForm;
                if (verify) verify.hidden = !showVerify;
                if (guardianStatus && guardianText !== undefined) guardianStatus.textContent = guardianText;
            };

            if (signedIn) {
                if (identifier) identifier.textContent = acc.identifier_masked || 'Signed in';
                this.hideUnblockPanel();
                setState('is-signed-in', 'Signed in', false, false, 'Guardian session active');
            } else if (stage === 'verification_required') {
                if (identifier) identifier.textContent = acc.email || 'Confirming sign-in…';
                setState('is-signing-in', 'Confirming', false, true, 'Waiting for your confirmation…');
            } else if (stage === 'unblock_required') {
                if (identifier) identifier.textContent = acc.email || 'Confirming sign-in…';
                setState('is-signing-in', 'Confirming', true, false, 'Waiting for the emailed authorization code');
                const unblock = document.getElementById('signin-unblock');
                if (unblock) unblock.hidden = false;
            } else if (stage === 'signing_in') {
                if (identifier) identifier.textContent = acc.email || 'Signing in…';
                setState('is-signing-in', 'Signing in', false, false, 'Waiting for sign-in to complete…');
            } else {
                if (identifier) identifier.textContent = 'Not signed in';
                setState('is-signed-out', 'Signed out', true, false, '—');
            }
        }

        // ------------------------------------------------------------
        // Monthly allowance gauge — Guardian-reported data only
        // ------------------------------------------------------------

        formatAllowance(bytes, decimals = 1) {
            if (bytes === null || bytes === undefined || !isFinite(bytes)) return null;
            const gb = bytes / 1e9;
            if (gb >= 100) return gb.toFixed(0);
            return gb.toFixed(decimals);
        }

        renderQuota(q) {
            const gaugeBox = document.getElementById('allowance-gauge');
            const pill = document.getElementById('account-status-pill');
            const guardianStatus = document.getElementById('account-guardian-status');
            const arc = document.getElementById('gauge-arc');
            const usedEl = document.getElementById('gauge-used');
            const unitEl = document.getElementById('gauge-used-unit');
            const allowEl = document.getElementById('gauge-allowance');
            const remainingEl = document.getElementById('gauge-remaining');
            const percentsEl = document.getElementById('gauge-percents');
            const resetEl = document.getElementById('gauge-reset');
            const sourceEl = document.getElementById('gauge-source');
            if (!gaugeBox || !arc) return;
            const circumference = 439.823;

            const identities = {
                signing_in: ['is-signing-in', 'Signing in', 'Waiting for sign-in to complete…'],
                signed_out: ['is-signed-out', 'Signed out', 'Not authenticated to Guardian'],
                no_pass: ['is-no-pass', 'No pass', 'No active VPN entitlement or Guardian pass'],
                quota_exhausted: ['is-quota-exhausted', 'Quota exhausted', 'Allowance used up for this period'],
                auth_error: ['is-auth-error', 'Rejected', 'Sign in again'],
                service_error: ['is-service-error', 'Service error', 'Guardian unreachable; retrying later'],
                signed_in: ['is-signed-in', 'Signed in', 'Guardian session active'],
            };
            const [pillClass, pillText, guardianText] = identities[q.account_state] || identities.signed_in;
            if (pill) { pill.className = `account-status-pill ${pillClass}`; pill.textContent = pillText; }
            if (guardianStatus) guardianStatus.textContent = guardianText;

            const identifier = document.getElementById('account-identifier');
            if (identifier && q.identifier_masked) identifier.textContent = q.identifier_masked;

            if (q.account_state === 'signed_out') {
                gaugeBox.hidden = true;
                return;
            }
            gaugeBox.hidden = false;

            const setArc = (fraction, cls) => {
                arc.classList.remove('gauge-arc--ok', 'gauge-arc--warn', 'gauge-arc--crit', 'gauge-arc--unlimited');
                if (cls) arc.classList.add(cls);
                arc.style.strokeDashoffset = (circumference * (1 - Math.max(0, Math.min(1, fraction)))).toFixed(3);
            };

            if (q.gauge_state === 'unlimited') {
                if (usedEl) usedEl.textContent = '\u221E';
                if (unitEl) unitEl.textContent = 'no cap';
                if (allowEl) allowEl.textContent = q.message || 'Unlimited monthly allowance';
                if (remainingEl) { remainingEl.textContent = 'No monthly cap applies'; remainingEl.className = 'allowance-gauge__remaining allowance-gauge__remaining--muted'; }
                if (percentsEl) percentsEl.textContent = '';
                if (resetEl) { resetEl.hidden = true; }
                if (sourceEl) sourceEl.textContent = 'Guardian reports this account is not bandwidth-limited';
                setArc(1, 'gauge-arc--ok');
                return;
            }

            if (q.gauge_state !== 'ok' || q.max_bytes === null || q.used_percent === null) {
                if (usedEl) usedEl.textContent = '\u2014';
                if (unitEl) unitEl.textContent = 'unavailable';
                if (allowEl) allowEl.textContent = 'Usage unavailable';
                if (remainingEl) { remainingEl.textContent = q.message || 'Guardian did not report usage for this account'; remainingEl.className = 'allowance-gauge__remaining allowance-gauge__remaining--muted'; }
                if (percentsEl) percentsEl.textContent = '';
                if (resetEl) resetEl.hidden = true;
                if (sourceEl) sourceEl.textContent = 'Quota figures are only shown when Guardian reports them';
                setArc(0, 'gauge-arc--crit');
                return;
            }

            const usedGB = this.formatAllowance(q.used_bytes);
            const maxGB = this.formatAllowance(q.max_bytes);
            const remainGB = this.formatAllowance(q.remaining_bytes);
            if (usedEl) usedEl.textContent = `${usedGB} GB`;
            if (unitEl) unitEl.textContent = 'used this period';
            if (allowEl) allowEl.textContent = `${maxGB} GB monthly allowance`;
            const remainingPercent = q.remaining_percent === null ? null : Math.round(q.remaining_percent);
            if (remainingEl) {
                remainingEl.className = 'allowance-gauge__remaining';
                if (remainingPercent !== null && remainingPercent <= 5) remainingEl.classList.add('allowance-gauge__remaining--red');
                else if (remainingPercent !== null && remainingPercent <= 25) remainingEl.classList.add('allowance-gauge__remaining--amber');
                remainingEl.textContent = `${remainGB} GB remaining`;
            }
            if (percentsEl) {
                percentsEl.textContent = `${Math.round(q.used_percent)}% used \u00b7 ${remainingPercent === null ? '\u2014' : `${remainingPercent}%` } remaining`;
            }
            if (resetEl) {
                if (q.reset_epoch) {
                    const resetDate = new Date(q.reset_epoch * 1000);
                    const days = Math.ceil((resetDate.getTime() - Date.now()) / 86400000);
                    resetEl.textContent = `Resets ${resetDate.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}${days > 0 ? ` (in ${days}d)` : ''}`;
                    resetEl.hidden = false;
                } else {
                    resetEl.hidden = true; // no authoritative reset date: never invent one
                }
            }
            if (sourceEl) sourceEl.textContent = q.usage_source === 'guardian' ? 'Source: Guardian account status' : '';

            const arcClass = (remainingPercent !== null && remainingPercent <= 5) ? 'gauge-arc--crit'
                : (remainingPercent !== null && remainingPercent <= 25) ? 'gauge-arc--warn'
                : 'gauge-arc--ok';
            setArc(Math.max(0, Math.min(1, q.used_percent / 100)), arcClass);
        }

        async refreshQuota(force = false) {
            if (this._authenticated !== true) {
                const gaugeBox = document.getElementById('allowance-gauge');
                if (gaugeBox) gaugeBox.hidden = true;
                return;
            }
            try {
                const q = await this.api(`/api/account/quota${force ? '?refresh=true' : ''}`);
                this._quotaState = q;
                this.renderQuota(q);
                if (this._quotaTimer) { clearInterval(this._quotaTimer); this._quotaTimer = null; }
                // Gentle re-check while the Network tab stays open (the
                // backend TTL caches do the honest fetching).
                this._quotaTimer = window.setInterval(() => this.refreshQuota(false), 60000);
            } catch (e) {
                if (force) {
                    const gaugeBox = document.getElementById('allowance-gauge');
                    if (gaugeBox) gaugeBox.hidden = true;
                    this.log(`Could not refresh account data: ${e.message}`);
                }
            }
        }


        async signOut() {
            try {
                await this.api('/api/account/logout', { method: 'POST' });
                this.log('Signed out. Cached authentication tokens deleted.');
                this.setSessionTokenFeedback('All cached tokens were cleared.', '');
                if (this._accountPollTimer) {
                    clearInterval(this._accountPollTimer);
                    this._accountPollTimer = null;
                }
                this.loadAccount();
            } catch (e) {
                this.log(`Failed to sign out: ${e.message}`);
            }
        }

        // ------------------------------------------------------------
        // Activity log
        // ------------------------------------------------------------

        connectLogWebSocket() {
            try {
                const proto = location.protocol === 'https:' ? 'wss' : 'ws';
                const ws = new WebSocket(`${proto}://${location.host}/ws/logs`);

                ws.onmessage = (ev) => this.log(ev.data);

                ws.onclose = () => {
                    setTimeout(() => this.connectLogWebSocket(), 5000);
                };
            } catch (e) {
                // WebSocket may not be available in all contexts; polling still works.
            }
        }

        // ------------------------------------------------------------
        // Live logs — structured diagnostics view
        //
        // Events come from /api/events (bounded server buffer). Display
        // pause/clear only affect rendering, never collection.
        // ------------------------------------------------------------

        bindDiagnostics() {
            this._eventLog = [];
            this._eventPaused = false;
            this._lastEventId = 0;
            this._seenComponents = new Set();
            const sevFilter = document.getElementById('log-severity-filter');
            if (sevFilter) sevFilter.addEventListener('change', () => this.renderLogEvents());
            const compFilter = document.getElementById('log-component-filter');
            if (compFilter) compFilter.addEventListener('input', () => this.renderLogEvents());
            const pauseBtn = document.getElementById('log-pause');
            if (pauseBtn) {
                pauseBtn.addEventListener('click', () => {
                    this._eventPaused = !this._eventPaused;
                    pauseBtn.textContent = this._eventPaused ? 'Resume' : 'Pause';
                    pauseBtn.setAttribute('aria-pressed', this._eventPaused ? 'true' : 'false');
                });
            }
            this.pollDiagnosticsEvents();
            window.setInterval(() => this.pollDiagnosticsEvents(), 2000);
        }

        async pollDiagnosticsEvents() {
            if (this._eventPaused) return; // display paused: keep server buffer
            // The event buffer only backs the dashboard activity log/debug
            // strip; polling every 2 s from other tabs (or a hidden window)
            // was pure idle load. Returning to the dashboard catches up from
            // `_lastEventId`, so no events are lost.
            if (document.hidden || this.currentTab !== 'dashboard') return;
            try {
                const data = await this.api(`/api/events?after=${this._lastEventId}&limit=120`);
                const events = (data && data.events) || [];
                if (events.length) {
                    events.forEach((ev) => this.pushEvent(ev));
                    this.renderLogEvents();
                    this.renderDiagStrip();
                }
            } catch (e) { /* transient */ }
            // The Debug subsection tracks the same buffer; refresh it even
            // when no new events arrived so the state line stays honest.
            this.renderDebugEvents();
        }

        pushEvent(ev) {
            if (!ev || ev.id === undefined) return;
            if (ev.id <= (this._lastEventId || 0)) return;
            this._lastEventId = ev.id;
            this._eventLog.push(ev);
            while (this._eventLog.length > 400) this._eventLog.shift();
            if (ev.component) {
                const list = document.getElementById('log-component-list');
                if (list && !this._seenComponents.has(ev.component)) {
                    // Rebuild the datalist only when a genuinely new component
                    // appears; per-event rebuilds are pure DOM churn.
                    this._seenComponents.add(ev.component);
                    list.innerHTML = '';
                    Array.from(this._seenComponents).sort().forEach((name) => {
                        const option = document.createElement('option');
                        option.value = name;
                        list.appendChild(option);
                    });
                }
            }
        }

        formatEventTime(ts) {
            const d = new Date(ts * 1000);
            const pad = (n, w = 2) => String(n).padStart(w, '0');
            return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
        }

        renderDiagStrip() {
            const strip = document.getElementById('diag-strip');
            const stripMsg = document.getElementById('diag-strip-msg');
            const stripSev = document.getElementById('diag-strip-sev');
            if (!strip || !stripMsg || !stripSev) return;
            const last = this._eventLog[this._eventLog.length - 1];
            if (!last) return;
            const detail = [last.operation, last.stage].filter(Boolean).join(' ');
            const msg = detail || last.detail || '';
            setTextIfChanged(stripSev, last.severity);
            const sevClass = `log-sev log-sev--${last.severity}`;
            if (stripSev.className !== sevClass) stripSev.className = sevClass;
            setTextIfChanged(stripMsg, `${last.component ? `${last.component}: ` : ''}${msg}${last.repeats > 1 ? ` \u00d7${last.repeats}` : ''}`);
            strip.hidden = false;
        }

        // Debug / Diagnostics subsection of the Live Logs card (the former
        // standalone Debug view, merged and de-duplicated: only the real
        // webui_debug streaming state plus this buffer's DEBUG events).
        renderDebugEvents() {
            const state = document.getElementById('logs-debug-state');
            if (state) {
                setTextIfChanged(state, this._devWatch === true
                    ? 'webui debug streaming: ON (PERCHVPN_WEBUI_DEBUG=1)'
                    : this._devWatch === false
                        ? 'webui debug streaming: OFF (set PERCHVPN_WEBUI_DEBUG=1 to capture internal state)'
                        : 'Diagnostics: pending status poll…');
            }
            const box = document.getElementById('logs-debug-events');
            if (!box) return;
            const details = document.getElementById('logs-debug');
            if (details && !details.open) return; // collapsed: skip row work
            const events = this._eventLog.filter((ev) => ev.severity === 'DEBUG').slice(-40).reverse();
            const frag = document.createDocumentFragment();
            if (!events.length) {
                const msg = document.createElement('div');
                msg.className = 'log-entry log-entry--system';
                msg.textContent = 'No DEBUG events in the buffer.';
                frag.appendChild(msg);
            } else {
                events.forEach((ev) => frag.appendChild(this.buildLogRow(ev)));
            }
            box.replaceChildren(frag);
        }

        // Upper bound on simultaneously rendered log rows; the buffer keeps
        // collecting to EVENT_LOG_MAX, the DOM only ever holds the newest.
        LOG_RENDER_MAX = 250;

        buildLogRow(ev) {
            const row = document.createElement('div');
            row.className = 'log-entry log-entry--structured';
            const parts = [
                [this.formatEventTime(ev.ts), 'log-ts'],
                [ev.severity, `log-sev log-sev--${ev.severity}`],
                [ev.component || '', 'log-component'],
                ['', 'log-body'],
            ];
            parts.forEach(([text, cls]) => {
                const span = document.createElement('span');
                span.className = cls;
                if (cls === 'log-body') {
                    const opStage = [ev.operation, ev.stage].filter(Boolean).join(' ');
                    const chunks = [];
                    if (opStage) chunks.push(opStage);
                    if (ev.outcome) chunks.push(`-> ${ev.outcome}`);
                    if (ev.detail) chunks.push(ev.detail);
                    if (typeof ev.duration_ms === 'number' && ev.duration_ms >= 0) {
                        chunks.push(`(${ev.duration_ms < 1 ? ev.duration_ms.toFixed(2) : Math.round(ev.duration_ms)} ms)`);
                    }
                    span.textContent = chunks.join(' ');
                } else {
                    span.textContent = text;
                }
                row.appendChild(span);
            });
            if (ev.repeats > 1) {
                const rep = document.createElement('span');
                rep.className = 'log-repeats';
                rep.textContent = `\u00d7${ev.repeats}`;
                row.appendChild(rep);
            }
            row.dataset.eid = String(ev.id);
            return row;
        }

        cachedLogRow(ev) {
            // Event rows are immutable once created, so they are cached by
            // event id and reused across renders: streaming updates create
            // rows only for new events instead of rebuilding the container.
            this._logRowCache = this._logRowCache || new Map();
            let row = this._logRowCache.get(String(ev.id));
            if (!row) {
                row = this.buildLogRow(ev);
                if (this._logRowCache.size >= this.LOG_RENDER_MAX * 2) this._logRowCache.clear();
                this._logRowCache.set(String(ev.id), row);
            }
            return row;
        }

        renderLogEvents() {
            const container = document.getElementById('log-container');
            if (!container) return;
            const sev = (document.getElementById('log-severity-filter') || {}).value || 'all';
            const compEl = document.getElementById('log-component-filter');
            const comp = compEl ? (compEl.value || '').trim().toLowerCase() : '';
            const sevRank = { DEBUG: 0, INFO: 1, WARN: 2, ERROR: 3 };
            const filterKey = `${sev}\n${comp}`;
            const events = this._eventLog.filter((ev) =>
                (sev === 'all' ? true : (sevRank[ev.severity] || 0) >= (sevRank[sev] || 0)) &&
                (!comp || String(ev.component || '').toLowerCase().includes(comp))
            );
            const filteredNewestFirst = events.reverse().slice(0, this.LOG_RENDER_MAX);
            this.renderLogInto(container, filteredNewestFirst, filterKey);
        }

        renderLogInto(container, desired, filterKey) {
            const fullRebuildNeeded = () => {
                // Filter switches and eviction-induced order changes fall back
                // to a (cache-reusing) rebuild; a steady stream prepends only.
                if (this._logRenderFilt !== filterKey) return true;
                const domRows = Array.from(container.children);
                if (domRows.some(el => !el.dataset.eid)) return true;
                const domIds = domRows.map(el => el.dataset.eid);
                const desiredIds = desired.map(ev => String(ev.id));
                if (desiredIds.join('\n') === domIds.join('\n')) return false; // nothing to do
                // Fast path: results order must be a strict prepend of new ids.
                if (!domIds.length) return true;
                if (desiredIds.length <= domIds.length) return true;
                const k = desiredIds.length - domIds.length;
                for (let i = 0; i < domIds.length; i++) {
                    if (desiredIds[k + i] !== domIds[i]) return true;
                }
                for (let j = k - 1; j >= 0; j--) {
                    container.insertBefore(this.cachedLogRow(desired[j]), container.firstChild);
                }
                while (container.children.length > this.LOG_RENDER_MAX) {
                    container.removeChild(container.lastChild);
                }
                return false;
            }
            if (fullRebuildNeeded()) {
                this._logRenderFilt = filterKey;
                const frag = document.createDocumentFragment();
                desired.forEach(ev => frag.appendChild(this.cachedLogRow(ev)));
                container.replaceChildren(
                    frag,
                    ...(desired.length ? [] : [(() => {
                        const msg = document.createElement('div');
                        msg.className = 'log-entry log-entry--system log-entry--newest-first';
                        msg.textContent = 'No matching events.';
                        return msg;
                    })()])
                );
            }
        }

        log(text) {
            const container = document.getElementById('log-container');
            if (!container) return;
            // Legacy plain-text notifications become console events so the
            // structured stream stays one source of truth for the panel.
            // Local events use a separate id space (negative) and never
            // interfere with the server cursor.
            const m = /\b(DEBUG|INFO|WARN|WARNING|ERROR|CRITICAL)\b/i.exec(text || '');
            let sev = 'INFO';
            if (m) {
                const up = m[1].toUpperCase();
                if (up === 'WARNING') sev = 'WARN';
                else if (up === 'CRITICAL') sev = 'ERROR';
                else sev = up;
            }
            this._eventLog = this._eventLog || [];
            this._consoleSeq = (this._consoleSeq || 0) - 1;
            this._eventLog.push({
                id: this._consoleSeq,
                ts: Date.now() / 1000,
                severity: sev,
                component: 'console',
                operation: '', stage: 'ui', outcome: '', detail: String(text),
                duration_ms: null, repeats: 1,
            });
            while (this._eventLog.length > 400) this._eventLog.shift();
            this.renderLogEvents();
        }

        clearLog() {
            // Clear the visible history only; backend collection continues.
            this._eventLog = this._eventLog || [];
            this._eventLog.length = 0;
            this.renderLogEvents();
        }

        copyLog() {
            const sev = (document.getElementById('log-severity-filter') || {}).value || 'all';
            const compEl = document.getElementById('log-component-filter');
            const comp = compEl ? (compEl.value || '').trim().toLowerCase() : '';
            const sevRank = { DEBUG: 0, INFO: 1, WARN: 2, ERROR: 3 };
            const events = (this._eventLog || []).filter((ev) =>
                (sev === 'all' ? true : (sevRank[ev.severity] || 0) >= (sevRank[sev] || 0)) &&
                (!comp || String(ev.component || '').toLowerCase().includes(comp))
            );
            const text = events.map((ev) => {
                const bits = [
                    this.formatEventTime(ev.ts),
                    ev.severity,
                    ev.component || '',
                    [ev.operation, ev.stage].filter(Boolean).join(' '),
                    ev.outcome ? `-> ${ev.outcome}` : '',
                    ev.detail || '',
                    (typeof ev.duration_ms === 'number' && ev.duration_ms >= 0) ? `(${Math.round(ev.duration_ms)} ms)` : '',
                    ev.repeats > 1 ? `\u00d7${ev.repeats}` : '',
                ];
                return bits.filter(Boolean).join(' ');
            }).join('\n');
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text).then(() => this.log('Live log copied.')).catch(() => this.log('Copy failed.'));
            } else {
                this.log('Clipboard API unavailable.');
            }
        }

        // ------------------------------------------------------------
        // Utilities
        // ------------------------------------------------------------

        set(id, value) {
            const el = document.getElementById(id);
            if (el) el.value = value;
        }

        val(id) {
            const el = document.getElementById(id);
            return el ? el.value : '';
        }

        esc(s) {
            if (s == null) return '';
            return String(s).replace(/[&<>"']/g, c => ({
                '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
            }[c]));
        }

        formatBytes(n) {
            if (n === 0) return '0 B';
            const units = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(n) / Math.log(1024));
            return (n / Math.pow(1024, i)).toFixed(1) + ' ' + units[i];
        }

        formatSpeed(bps) {
            return this.formatBytes(Math.round(bps)) + '/s';
        }

        formatUptime(s) {
            const parts = [];
            const d = Math.floor(s / 86400);
            const h = Math.floor((s % 86400) / 3600);
            const m = Math.floor((s % 3600) / 60);
            const sec = Math.floor(s % 60);
            if (d) parts.push(d + 'd');
            if (h) parts.push(h + 'h');
            if (m) parts.push(m + 'm');
            parts.push(sec + 's');
            return parts.join(' ');
        }
    }

    // Boot
    function boot() {
        window.perchVPN = new PerchVPNApp();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }
})();