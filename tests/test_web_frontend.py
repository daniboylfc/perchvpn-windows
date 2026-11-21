"""Frontend JavaScript syntax/load-safety checks."""

import shutil
import subprocess
from pathlib import Path
import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_frontend_javascript_passes_syntax_check():
    """The frontend script must parse cleanly or browser tab/button handlers
    cannot be registered at all (e.g. a stray comma can invalidate the whole
    class and silently disable navigation, search, and the connection toggle)."""
    if shutil.which("node") is None:
        pytest.skip("node is not installed in the test environment")
    result = subprocess.run(
        ["node", "--check", str(PROJECT_ROOT / "src" / "perchvpn_windows" / "web" / "app.js")],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_frontend_wires_tabs_and_connection_toggle():
    """Keep the key selectors and event bindings present so the dashboard
    navigation and hero connection control remain interactive."""
    source = (PROJECT_ROOT / "src" / "perchvpn_windows" / "web" / "app.js").read_text(encoding="utf-8")
    assert ".rail__item" in source
    assert "dataset.tab" in source
    assert ".tab-panel" in source
    assert "connection-toggle" in source
    assert "onConnectionToggle" in source


def test_connection_state_classes_drive_emblem():
    """The gear emblem must follow the existing connection state
    (#connection-state[data-state]), not a separate state machine or
    animation flag."""
    source = (PROJECT_ROOT / "src" / "perchvpn_windows" / "web" / "app.js").read_text(encoding="utf-8")
    styles = (PROJECT_ROOT / "src" / "perchvpn_windows" / "web" / "styles.css").read_text(encoding="utf-8")
    assert "is-connected" in source
    assert "is-connecting" in source
    assert "GearCore" in source
    assert "data-state" in source
    assert "gearcore__glow" in styles
    assert "prefers-reduced-motion" in styles


def test_frontend_exposes_mode_switch_and_realtime_url_test():
    """Connection-mode buttons under the gear dial must stay wired, the
    country lists must rank via the surgical realtime URL test (/api/urltest)
    through each city's edge relay, and the separate URL-ping card must stay
    removed (no standalone section — results live in the country rows)."""
    source = (PROJECT_ROOT / "src" / "perchvpn_windows" / "web" / "app.js").read_text(encoding="utf-8")
    html = (PROJECT_ROOT / "src" / "perchvpn_windows" / "web" / "index.html").read_text(encoding="utf-8")
    styles = (PROJECT_ROOT / "src" / "perchvpn_windows" / "web" / "styles.css").read_text(encoding="utf-8")
    assert "proxy_active" in source
    assert "/api/mode" in source
    assert "/api/urltest" in source
    assert "elapsed_ms" in source
    assert "mode-proxy-only" in html and "mode-tun" in html
    assert "btn--mode" in styles and "is-active" in styles
    # The standalone URL-ping section must remain removed.
    assert "ping-now" not in html
    assert "ping-bars" not in html
    assert "/api/url-ping" not in source


def test_console_probes_never_open_windows():
    """PowerShell/netsh probes and the TUN sidecar must route through the
    shared hidden-spawn helper so clicking TUN-mode cannot flash consoles."""
    helper = (PROJECT_ROOT / "src" / "perchvpn_windows" / "win_process.py").read_text(encoding="utf-8")
    assert "CREATE_NO_WINDOW" in helper
    assert "STARTF_USESHOWWINDOW" in helper
    assert "SW_HIDE" in helper
    for name in ("tun_state_capture.py", "tun_recovery.py", "tun_frontend.py"):
        text = (PROJECT_ROOT / "src" / "perchvpn_windows" / name).read_text(encoding="utf-8")
        assert "win_process" in text, f"{name} must use the shared hidden-spawn helper"


def test_frontend_guards_double_actions_and_classifies_urltest_errors():
    """In-flight connect/restart/disconnect actions must not be re-enabled or
    re-labelled by the 2s status poll (double-click protection), the country
    switch must ignore overlapping clicks, superseded latency cycles must not
    overwrite the latency cache, and URL-test failures must be classified
    (Sign in / Quota / No pass / Timeout / Unavailable) instead of a bare
    "Unavailable" for every failure mode."""
    source = (PROJECT_ROOT / "src" / "perchvpn_windows" / "web" / "app.js").read_text(encoding="utf-8")
    # Double-click protection on the connection toggle and busy-priority in
    # the status poll's button refresh.
    assert "if (this._actionBusy) return;" in source
    # Busy actions use a loading class instead of HTML disabled, so the
    # Windows "no symbol" cursor and dead-looking button cannot appear.
    assert "const loading = this._actionBusy || connecting;" in source
    assert "btn.classList.toggle('is-loading', loading);" in source
    assert "const busy = loading ? 'true' : 'false';" in source
    assert "btn.setAttribute('aria-busy', busy);" in source
    assert "btn.classList.toggle('is-loading', disabled);" in source
    assert "if (!this._actionBusy && btn)" in source
    # Country switch ignores overlapping country reinit requests.
    assert "if (this._switchBusy) return;" in source
    # Superseded latency cycles must never write the latency cache.
    assert "if (gen !== this._latencyGen) return; // superseded: never cache" in source
    # URL test failure classification keeps honest failure modes visible.
    assert "latencyErrorLabel" in source
    assert "/Application not initialized|Not signed in/i" in source
    assert "/quota exceeded/i" in source
    assert "/proxy pass/i" in source
    assert "/timed out/i" in source
    assert "'Sign in'" in source and "'Quota'" in source and "'No pass'" in source and "'Timeout'" in source
