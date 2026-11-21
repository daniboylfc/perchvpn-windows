"""Signed-out onboarding prompt + auth-state driven frontend gating.

Strict visibility rules:
* the prompt is visible ONLY when `authenticated === false`,
* hidden while the account state is loading/unknown (`_authenticated === null`),
* hidden for authenticated users (`display:none` via [hidden]),
* reappears after sign-out or session expiry,
* clicking the prompt navigates to the Account tab (the sign-in form's new
  home after the Account tab reorganization), with a Sign In action alongside,
* while signed out, no latency probes are fired and rows never show "No
  pass" — they keep the neutral "Sign in" label.
"""

from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WEB = PROJECT_ROOT / "src" / "perchvpn_windows" / "web"

WELCOME_TEXT = (
    "Welcome to PerchVPN. To get started, open the Account tab and sign in "
    "with your account credentials."
)


def _read(name: str) -> str:
    return (WEB / name).read_text(encoding="utf-8")


class TestOnboardingPromptMarkup:
    def test_banner_exists_with_exact_welcome_copy(self):
        html = _read("index.html")
        assert 'id="onboarding-banner"' in html
        assert 'id="onboarding-message"' in html
        assert 'id="onboarding-signin"' in html
        assert WELCOME_TEXT in html
        # rendered hidden by default; never flashes before the first auth check
        assert "hidden" in html.split('id="onboarding-banner"')[1].split(">")[0]

    def test_banner_styles_and_hidden_rule(self):
        css = _read("styles.css")
        assert ".onboarding-banner" in css
        assert ".onboarding-banner[hidden]" in css
        assert "display: none" in css

    def test_click_navigates_to_account_tab_and_action_signs_in(self):
        source = _read("app.js")
        assert "switchTab('account')" in source
        # The prompt must NOT route to the Network tab anymore.
        assert "switchTab('network')" not in source
        # In-app sign-in: the action opens the Account tab sign-in form.
        assert "this.beginSignIn()" in source
        # The terminal helper is never launched by GUI sign-in.
        assert "/api/account/login" not in source


class TestOnboardingVisibilityLogic:
    def test_visible_only_when_definitively_signed_out(self):
        source = _read("app.js")
        marker = "updateOnboarding"
        assert marker in source
        # gate: only the false state reveals the banner
        assert "if (this._authenticated === false)" in source
        assert "banner.removeAttribute('hidden')" in source

    def test_hidden_for_authenticated_or_loading_users(self):
        source = _read("app.js")
        # hidden when signed in or while auth state is still unknown
        assert "banner.setAttribute('hidden', '')" in source
        assert "this._authenticated" in source

    def test_transition_hooks_reappear_on_signout(self):
        source = _read("app.js")
        assert "setAuthState" in source
        # polling keeps the state fresh so expiry/sign-out re-shows the prompt
        assert "startAuthPolling" in source
        assert "refreshAuthState" in source
        assert "/api/account" in source

    def test_signin_failure_is_visible_to_the_user(self):
        source = _read("app.js")
        # Inline feedback next to the in-app sign-in form.
        assert "showSigninError" in source
        assert 'id="signin-error"' in _read("index.html")
        assert "onboarding-banner--error" in source


class TestSignedOutLatencyGating:
    def test_no_probes_or_pass_requests_while_signed_out(self):
        source = _read("app.js")
        # countriesLatencyCycle gates probing on a definitive signed-in state
        assert "if (this._authenticated === false)" in source
        assert "if (this._authenticated !== true)" in source
        assert "SIGNED_OUT_LATENCY_LABEL" in source
        assert "this.measureLatency(target, gen, force)" in source
        assert "SIGNED_OUT_LATENCY_LABEL" in source

    def test_neutral_sign_in_label_never_no_pass(self):
        source = _read("app.js")
        signed_out_label = "const SIGNED_OUT_LATENCY_LABEL = 'Sign in';"
        assert signed_out_label in source
        assert "No pass" in source  # still classified for genuine 502s
        # the signed-out branch renders the neutral label, not "No pass"
        assert "applyLatencyText(t.els, gen, SIGNED_OUT_LATENCY_LABEL)" in source

    def test_measure_latency_untouched_for_authenticated_flow(self):
        source = _read("app.js")
        assert "/api/urltest?host=" in source
        # unsuccessful and stale results must still never be cached
        assert "if (gen !== this._latencyGen) return; // superseded: never cache" in source

    def test_server_details_probe_also_gated(self):
        source = _read("app.js")
        assert "this._authenticated !== true" in source


class TestAuthStateAfterSignIn:
    def test_sign_in_refreshes_state_and_latencies_without_restart(self):
        source = _read("app.js")
        # account polling after the launch keeps handoff flowing into the GUI
        assert "_accountPollTimer" in source
        # on the signed-in transition: invalidate stale measurements and remeasure
        assert "this.countriesLatencyCycle();" in source
        assert "this._latencyCache = {};" in source
