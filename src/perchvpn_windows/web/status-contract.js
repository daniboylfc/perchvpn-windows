// Canonical /api/status -> UI state contract, shared by the backend-facing
// app.js and the Node behaviour harness.
//
// The backend emits "degraded" and "failed" as canonical top-level statuses.
// Older builds emitted "tun_degraded"/"tun_failed"; those remain accepted as
// aliases and are normalised here, in one place, so no consumer can drift.
(function(root) {
    'use strict';

    const STATUS_ALIASES = Object.freeze({
        tun_degraded: 'degraded',
        tun_failed: 'failed'
    });

    const UI_STATE = Object.freeze({
        DISCONNECTED: 'disconnected',
        CONNECTING: 'connecting',
        CONNECTED_VERIFYING: 'connected_verifying',
        CONNECTED_VERIFIED: 'connected_verified',
        CONNECTED_UNVERIFIED: 'connected_unverified',
        PROXY_ACTIVE: 'proxy_active',
        TUN_DEGRADED: 'tun_degraded',
        TUN_FAILED: 'tun_failed'
    });

    const META = Object.freeze({
        [UI_STATE.TUN_DEGRADED]: {
            stateClass: 'is-connecting',
            statusText: 'Tunnel unverified',
            headerClass: 'status-indicator--connecting',
            headerText: 'Tunnel unverified',
            detail: 'Tunnel is up but system traffic is not verified.',
            detailClass: 'info-value--connecting',
            verification: 'Not verified',
            verificationClass: 'info-value--pending',
            subtext: 'The VPN upstream is running, but Windows system traffic is not proven to exit through it yet.',
            exitIp: 'Pending',
            exitCountry: 'Pending',
            tunnelDetail: true
        },
        [UI_STATE.TUN_FAILED]: {
            stateClass: 'is-disconnected',
            statusText: 'Tunnel failed',
            headerClass: 'status-indicator--disconnected',
            headerText: 'Tunnel failed',
            detail: 'The system tunnel is not available.',
            detailClass: 'info-value--disconnected',
            verification: 'Not verified',
            verificationClass: 'info-value--unavailable',
            subtext: 'System traffic is not tunnelled. Fix the tunnel condition shown in System Status, or use Proxy-Only.',
            exitIp: 'Not available',
            exitCountry: 'Not available',
            tunnelDetail: true
        }
    });

    function normaliseStatus(raw) {
        const value = String(raw == null ? '' : raw).trim().toLowerCase();
        return STATUS_ALIASES[value] || value;
    }

    function resolveUiState(data) {
        const d = data || {};
        const status = normaliseStatus(d.status);
        if (status === 'failed') return UI_STATE.TUN_FAILED;
        if (status === 'degraded') return UI_STATE.TUN_DEGRADED;
        if (status === UI_STATE.PROXY_ACTIVE) return UI_STATE.PROXY_ACTIVE;
        if (status === 'connected') {
            switch (String(d.exit_verification_state || 'not_applicable')) {
                case 'verified': return UI_STATE.CONNECTED_VERIFIED;
                case 'failed': return UI_STATE.CONNECTED_UNVERIFIED;
                case 'pending': return UI_STATE.CONNECTED_VERIFYING;
                default: return UI_STATE.CONNECTED_UNVERIFIED;
            }
        }
        if (status === 'connecting') return UI_STATE.CONNECTING;
        return UI_STATE.DISCONNECTED;
    }

    function buttonState(state) {
        const connected = state === UI_STATE.CONNECTED_VERIFIED
            || state === UI_STATE.CONNECTED_VERIFYING
            || state === UI_STATE.CONNECTED_UNVERIFIED
            || state === UI_STATE.PROXY_ACTIVE;
        const connecting = state === UI_STATE.CONNECTING
            || state === UI_STATE.TUN_DEGRADED;
        return {
            connected: connected,
            connecting: connecting,
            error: state === UI_STATE.CONNECTED_UNVERIFIED,
            disabled: connecting,
            pressed: connected,
            label: connected ? 'Disconnect' : 'Connect',
            ariaLabel: connected ? 'Disconnect from VPN' : 'Connect to VPN'
        };
    }

    function detailText(state, data) {
        const meta = META[state];
        if (!meta) return '';
        const tunnelDetail = data && data.tunnel && data.tunnel.detail;
        return (meta.tunnelDetail && tunnelDetail) ? tunnelDetail : meta.detail;
    }

    const api = {
        STATUS_ALIASES: STATUS_ALIASES,
        UI_STATE: UI_STATE,
        META: META,
        normaliseStatus: normaliseStatus,
        resolveUiState: resolveUiState,
        buttonState: buttonState,
        detailText: detailText
    };

    root.PerchStatusContract = api;
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
