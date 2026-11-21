"""Account view layout invariants (clipping + alignment + password toggle).

The live defect: ``.tab-panel { height: 100% }`` inside the flex column
``.app-content`` — with the signed-out onboarding banner stacked above the
panel, the Account panel grew one banner taller than its own viewport, so
its scroll container ran underneath the fixed footer and the Session Token
card could not be brought fully into view.

These are static assertions (fast, always run). The real Chromium bounding
box measurement lives in ``scripts/layout_check.py`` and can be exercised by
setting ``PERCH_RUN_LAYOUT_CHECK=1``.
"""

from __future__ import annotations

import os
import pathlib
import re
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
WEB = ROOT / "src" / "perchvpn_windows" / "web"


def _rule(css: str, selector: str) -> str:
    match = re.search(re.escape(selector) + r"\s*\{([^}]*)\}", css)
    assert match, f"missing rule {selector}"
    return match.group(1)


class TestScrollContainer:
    def test_app_content_is_a_flex_column(self):
        css = (WEB / "styles.css").read_text(encoding="utf-8")
        block = _rule(css, ".app-content")
        assert "display: flex;" in block
        assert "flex-direction: column;" in block
        assert "min-height: 0;" in block

    def test_active_panel_flexes_instead_of_filling_percent(self):
        css = (WEB / "styles.css").read_text(encoding="utf-8")
        block = _rule(css, ".tab-panel")
        assert "flex: 1 1 auto;" in block
        assert "min-height: 0;" in block
        assert "height: 100%;" not in block

    def test_settings_container_scrolls_and_clears_the_footer(self):
        css = (WEB / "styles.css").read_text(encoding="utf-8")
        block = _rule(css, ".settings-container")
        assert "overflow-y: auto;" in block
        assert "min-height: 0;" in block
        assert "padding: 16px 16px calc(" in block
        assert "--footer-height" in block


class TestAccountAlignment:
    def test_account_cards_share_one_width(self):
        css = (WEB / "styles.css").read_text(encoding="utf-8")
        block = _rule(css, ".settings-section--account")
        assert "display: flex;" in block and "flex-direction: column;" in block
        children = _rule(css, ".settings-section--account > *")
        assert "width: 100%;" in children
        assert "max-width: 100%;" in children

    def test_signin_blocks_are_not_narrower_than_the_cards(self):
        css = (WEB / "styles.css").read_text(encoding="utf-8")
        block = _rule(css, ".signin-form,\n.signin-verify")
        assert "width: 100%;" in block
        assert "max-width: 460px" not in block


class TestPasswordToggle:
    def test_toggle_lives_inside_the_password_wrapper(self):
        html = (WEB / "index.html").read_text(encoding="utf-8")
        wrapper = html[html.find('class="password-field"'):]
        wrapper = wrapper[:wrapper.find("</div>")]
        assert 'id="signin-password"' in wrapper
        assert 'id="signin-password-toggle"' in wrapper
        assert 'class="password-row"' not in html

    def test_toggle_is_absolutely_positioned_inside_the_input(self):
        css = (WEB / "styles.css").read_text(encoding="utf-8")
        field = _rule(css, ".password-field")
        toggle = _rule(css, ".password-toggle")
        assert "position: relative;" in field
        assert "max-width: 420px" in field
        assert "position: absolute;" in toggle
        assert "right: 6px;" in toggle

    def test_input_reserves_room_for_the_toggle(self):
        css = (WEB / "styles.css").read_text(encoding="utf-8")
        block = css[css.find(".password-field .setting-input"):]
        block = block[:block.find("}")]
        assert "padding-right: 68px;" in block
        assert "max-width: 100%;" in block


@pytest.mark.skipif(
    os.environ.get("PERCH_RUN_LAYOUT_CHECK") != "1",
    reason="set PERCH_RUN_LAYOUT_CHECK=1 to drive headless Edge",
)
def test_real_chromium_bounding_boxes():
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "layout_check.py"),
         "--size", "1280x800", "--size", "1440x900"],
        capture_output=True, text=True, timeout=300,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS" in result.stdout
