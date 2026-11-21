"""Regression tests for the silent failure of the in-app Sign-in flow.

Captured failure (live, commit 0040d6e): the user's sign-in POST failed at
the FxA edge (HTTP 406 anti-bot block, probe-verified) and surfaced as a
generic 502 whose inline error text was never visible because the
``.setting-error`` CSS rule keeps ``display: none`` unless a
``.setting-group.has-error`` ancestor exists — the sign-in JS toggles the
[hidden] attribute instead. UI: "Signing in..." briefly, then silent
revert to "Not signed in".
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest

import src.perchvpn_windows.api as api_module
from perchvpn.exceptions import FastlyChallengeError, FxaApiError

PROJECT_ROOT = None  # derived in helpers below


def _app_mock():
    app = SimpleNamespace()
    app.load_persisted_auth = None
    return app


class TestEdgeBlockClassification:
    @pytest.mark.asyncio
    async def test_fxa_406_block_is_503_with_actionable_message(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        api_module._signin_state.update(stage="idle", email="", verification_method="",
                                        session_token=None, expires_at=0.0, attempts=0)

        def fake_login(email, password, token_path=None):
            raise FxaApiError("HTTP 406", errno=None, status_code=406)

        monkeypatch.setattr(api_module.auth_module, "login_with_password", fake_login)
        with pytest.raises(api_module.HTTPException) as excinfo:
            await api_module.account_signin(
                api_module.SigninRequest(email="user@example.com", password="pw")
            )
        assert excinfo.value.status_code == 503
        detail = " ".join(str(excinfo.value.detail).split())
        assert "HTTP 406" in detail
        assert "switch networks" in detail

    @pytest.mark.asyncio
    async def test_fastly_challenge_error_is_503(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        api_module._signin_state.update(stage="idle", email="", verification_method="",
                                        session_token=None, expires_at=0.0, attempts=0)

        def fake_login(email, password, token_path=None):
            raise FastlyChallengeError("challenge did not complete")

        monkeypatch.setattr(api_module.auth_module, "login_with_password", fake_login)
        with pytest.raises(api_module.HTTPException) as excinfo:
            await api_module.account_signin(
                api_module.SigninRequest(email="user@example.com", password="pw")
            )
        assert excinfo.value.status_code == 503
        assert "anti-bot" in str(excinfo.value.detail)

    @pytest.mark.asyncio
    async def test_unhandled_failure_records_exception_type_in_diagnostics(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        api_module._signin_state.update(stage="idle", email="", verification_method="",
                                        session_token=None, expires_at=0.0, attempts=0)

        def fake_login(email, password, token_path=None):
            try:
                raise ValueError("probe failure message")
            except ValueError as inner:
                raise RuntimeError("wrapped") from inner

        last_event_id = max(
            (event["id"] for event in api_module.diagnostics.snapshot()), default=0
        )
        monkeypatch.setattr(api_module.auth_module, "login_with_password", fake_login)
        with pytest.raises(api_module.HTTPException) as excinfo:
            await api_module.account_signin(
                api_module.SigninRequest(email="user@example.com", password="pw")
            )
        assert excinfo.value.status_code == 502
        assert "unavailable right now" in str(excinfo.value.detail)

        new = api_module.diagnostics.snapshot(after_id=last_event_id)
        names = [e["detail"] for e in new if e["operation"] == "in-app sign-in"]
        assert any("RuntimeError" in (d or "") for d in names), names

    @pytest.mark.asyncio
    async def test_invalid_credentials_still_401(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        api_module._signin_state.update(stage="idle", email="", verification_method="",
                                        session_token=None, expires_at=0.0, attempts=0)

        def fake_login(email, password, token_path=None):
            raise FxaApiError("Incorrect password", errno=103, status_code=400)

        monkeypatch.setattr(api_module.auth_module, "login_with_password", fake_login)
        with pytest.raises(api_module.HTTPException) as excinfo:
            await api_module.account_signin(
                api_module.SigninRequest(email="user@example.com", password="pw")
            )
        assert excinfo.value.status_code == 401
        assert excinfo.value.detail == "Incorrect email or password"


class TestInlineErrorVisibility:
    def test_css_renders_hidden_toggled_setting_errors(self):
        import pathlib

        css = (pathlib.Path(__file__).resolve().parents[1]
               / "src" / "perchvpn_windows" / "web" / "styles.css").read_text(encoding="utf-8")
        assert ".setting-error:not([hidden])" in css
        # The override must set display back to block
        block = css[css.find(".setting-error:not([hidden])"):]
        assert "display: block;" in block[:200]

    def test_js_uses_hidden_attribute_pattern(self):
        import pathlib

        js = (pathlib.Path(__file__).resolve().parents[1]
              / "src" / "perchvpn_windows" / "web" / "app.js").read_text(encoding="utf-8")
        # showSigninError toggles [hidden] — that is what the CSS rule fixes.
        assert "err.hidden = !message" in js

    def test_validation_detail_arrays_are_readable(self):
        import pathlib

        js = (pathlib.Path(__file__).resolve().parents[1]
              / "src" / "perchvpn_windows" / "web" / "app.js").read_text(encoding="utf-8")
        assert "Array.isArray(detail)" in js


class TestGuiClickPath:
    def test_submit_inside_form_with_prevent_default(self):
        import pathlib

        root = pathlib.Path(__file__).resolve().parents[1]
        html = (root / "src" / "perchvpn_windows" / "web" / "index.html").read_text(encoding="utf-8")
        js = (root / "src" / "perchvpn_windows" / "web" / "app.js").read_text(encoding="utf-8")

        # The submit button is a real form submit button inside #signin-form
        form_start = html.find('id="signin-form"')
        submit_pos = html.find('id="signin-submit"')
        assert 0 < form_start < submit_pos
        assert 'type="submit"' in html[submit_pos - 40:submit_pos + 40]
        # The JS handler intercepts submit with preventDefault (no reload)
        assert "addEventListener('submit', (ev) => {\n                    ev.preventDefault();\n                    this.submitSignIn();" in js
