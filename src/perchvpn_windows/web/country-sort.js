// Perch VPN — deterministic country ordering by measured latency.
//
// Exposed as a small pure module so the ordering rules can be verified
// directly (tests/test_country_sort.py) without a browser. Ordering is:
//   1. valid measurements, ascending (lowest ping first);
//   2. everything else (missing, invalid, "Measuring…", "Unavailable"),
//      after every valid measurement;
//   3. ties broken by country name, then original position, so repeated
//      sorts of the same data are stable.
(function (root) {
    'use strict';

    function hasValidLatency(ms) {
        return typeof ms === 'number' && Number.isFinite(ms) && ms > 0;
    }

    function compareCountryLatency(a, b) {
        const aMs = a && hasValidLatency(a.ms) ? a.ms : null;
        const bMs = b && hasValidLatency(b.ms) ? b.ms : null;

        if (aMs !== null && bMs !== null) {
            if (aMs !== bMs) return aMs - bMs;
        } else if (aMs !== null) {
            return -1;
        } else if (bMs !== null) {
            return 1;
        }

        const aName = String((a && a.name) || '').toLowerCase();
        const bName = String((b && b.name) || '').toLowerCase();
        if (aName < bName) return -1;
        if (aName > bName) return 1;

        const aIndex = (a && a.index) || 0;
        const bIndex = (b && b.index) || 0;
        return aIndex - bIndex;
    }

    const api = {
        hasValidLatency: hasValidLatency,
        compare: compareCountryLatency
    };

    root.PerchCountrySort = api;
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
