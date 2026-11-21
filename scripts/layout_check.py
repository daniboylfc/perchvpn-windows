#!/usr/bin/env python3
"""Programmatic Account-view layout check using the real Chromium engine.

Copia the shipped ``web/`` assets into a scratch directory (on the Windows
D: drive, never C:), injects a measurement harness, and drives headless
Microsoft Edge over ``--dump-dom`` at the requested viewport sizes. For each
size it reports:

* the scroll container's box vs. the footer and viewport,
* every Account-section element at the top of the scroll,
* every Account-section element after scrolling to the end,
* whether the last card is fully reachable.

Exit code 0 only when nothing overlaps the footer, the scroll container fits
the window, and the Session Token card can be brought fully into view.

Usage (from the repo root, WSL):
    .venv/bin/python scripts/layout_check.py --size 1280x800 --size 1440x900
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WEB_DIR = PROJECT_ROOT / "src" / "perchvpn_windows" / "web"
DEFAULT_EDGE = Path("/mnt/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe")
DEFAULT_WORKDIR = Path("/mnt/d/PerchSandbox/staging/layoutcheck")

HARNESS = r"""
<pre id="bbox-report" style="position:fixed;left:0;top:0;z-index:99999;background:#000;color:#0f0;font-size:8px;max-width:100%;white-space:pre-wrap"></pre>
<script>
(function(){
  function measure(tag, cont) {
    var footer = document.querySelector('.app-footer');
    var fRect = footer.getBoundingClientRect();
    var cRect = cont.getBoundingClientRect();
    var out = {
      tag: tag,
      viewport: {w: window.innerWidth, h: window.innerHeight},
      footer: {top: Math.round(fRect.top), bottom: Math.round(fRect.bottom)},
      container: {
        top: Math.round(cRect.top), bottom: Math.round(cRect.bottom),
        clientHeight: cont.clientHeight, scrollHeight: cont.scrollHeight,
        scrollTop: Math.round(cont.scrollTop),
        overflowY: getComputedStyle(cont).overflowY,
        fitsViewport: cRect.bottom <= window.innerHeight + 0.5 && cRect.top >= -0.5,
        overlapsFooter: cRect.bottom > fRect.top + 0.5,
        canScrollToEnd: cont.scrollHeight - cont.clientHeight <= cont.scrollTop + 1
      },
      elements: []
    };
    var sel = ['#account-card','#signin-form','#signin-verify','#signin-unblock',
               '#verify-resend','.account-actions','#allowance-gauge',
               '#session-token-box','#btn-save-token','#btn-import-token',
               '#btn-clear-tokens','#session-token-input','#signin-password','#signin-password-toggle'];
    sel.forEach(function(s){
      var el = document.querySelector('#account-panel ' + s);
      if (!el) { out.elements.push({sel: s, missing: true}); return; }
      var r = el.getBoundingClientRect();
      out.elements.push({
        sel: s,
        top: Math.round(r.top), bottom: Math.round(r.bottom),
        left: Math.round(r.left), right: Math.round(r.right),
        w: Math.round(r.width), h: Math.round(r.height),
        insideContainer: r.bottom <= cRect.bottom + 0.5 && r.top >= cRect.top - 0.5,
        insideViewport: r.bottom <= window.innerHeight + 0.5 && r.top >= -0.5,
        withinContainerWidth: r.left >= cRect.left - 0.5 && r.right <= cRect.right + 0.5,
        overlapsFooter: r.bottom > fRect.top + 0.5 && r.top < fRect.bottom - 0.5
      });
    });
    return out;
  }
  function ready(fn){ if(document.readyState!=='loading') fn(); else document.addEventListener('DOMContentLoaded', fn); }
  ready(function(){
    setTimeout(function(){
      // Reproduce the real signed-out first-run state: onboarding banner + Account tab.
      var banner = document.getElementById('onboarding-banner');
      if (banner) banner.removeAttribute('hidden');
      document.querySelectorAll('.tab-panel').forEach(function(p){
        p.classList.remove('tab-panel--active'); p.setAttribute('hidden','');
      });
      var acc = document.getElementById('account-panel');
      acc.classList.add('tab-panel--active'); acc.removeAttribute('hidden');
      ['signin-form','signin-verify','signin-unblock','allowance-gauge']
        .forEach(function(id){ var el = document.getElementById(id); if (el) el.removeAttribute('hidden'); });
      var logout = document.getElementById('btn-logout'); if (logout) logout.removeAttribute('hidden');
      var cont = document.querySelector('#account-panel .settings-container');
      if (!cont) { document.getElementById('bbox-report').textContent = 'BBOX_JSON:{"error":"no container"}'; return; }
      var top = measure('top', cont);
      cont.scrollTop = cont.scrollHeight;
      var bottom = measure('bottom', cont);
      document.getElementById('bbox-report').textContent =
        'BBOX_JSON:' + JSON.stringify({top: top, bottom: bottom});
    }, 1500);
  });
})();
</script>
"""


def build_harness(workdir: Path) -> Path:
    if workdir.exists():
        shutil.rmtree(workdir)
    workdir.mkdir(parents=True)
    for item in WEB_DIR.iterdir():
        if item.is_dir():
            shutil.copytree(item, workdir / item.name)
        else:
            shutil.copy2(item, workdir / item.name)
    page = workdir / "index.html"
    html = page.read_text(encoding="utf-8")
    page.write_text(html.replace("</body>", HARNESS + "</body>"), encoding="utf-8")
    return page


def windows_path(path: Path) -> str:
    text = str(path)
    if text.startswith("/mnt/") and len(text) > 6:
        drive = text[5].upper()
        return f"{drive}:{text[6:]}".replace("/", "\\")
    return text


def run_size(edge: Path, page: Path, profile: Path, width: int, height: int) -> dict:
    cmd = [
        str(edge),
        "--headless=new",
        "--disable-gpu",
        "--no-first-run",
        "--no-default-browser-check",
        f"--user-data-dir={windows_path(profile)}",
        f"--window-size={width},{height}",
        "--virtual-time-budget=4000",
        "--dump-dom",
        f"file:///{windows_path(page)}",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    for line in proc.stdout.splitlines():
        marker = "BBOX_JSON:"
        if marker in line:
            payload = line.split(marker, 1)[1]
            payload = payload.split("</pre>", 1)[0]
            return json.loads(payload)
    raise RuntimeError(f"no measurement for {width}x{height}: {proc.stderr[-400:]}")


def evaluate(report: dict) -> list[str]:
    problems: list[str] = []
    top = report["top"]
    bottom = report["bottom"]
    for phase in (top, bottom):
        cont = phase["container"]
        if not cont["fitsViewport"]:
            problems.append(f"[{phase['tag']}] scroll container does not fit the viewport: {cont}")
        if cont["overlapsFooter"]:
            problems.append(f"[{phase['tag']}] scroll container overlaps the footer: {cont}")
        if cont["overflowY"] not in ("auto", "scroll"):
            problems.append(f"[{phase['tag']}] scroll container is not scrollable: {cont['overflowY']}")
    if not bottom["container"]["canScrollToEnd"]:
        problems.append("the scroll never reaches the end of the Account content")

    # Horizontal alignment: every Account block must share the container width.
    lefts, rights = set(), set()
    for el in top["elements"]:
        if el.get("missing"):
            problems.append(f"missing {el['sel']}")
            continue
        if not el["withinContainerWidth"]:
            problems.append(f"{el['sel']} overflows the container horizontally ({el['left']}..{el['right']})")
        if el["sel"] in ("#account-card", "#allowance-gauge", "#session-token-box"):
            lefts.add(el["left"])
            rights.add(el["right"])
    if len(lefts) > 1 or len(rights) > 1:
        problems.append(f"Account cards are not aligned: lefts={sorted(lefts)} rights={sorted(rights)}")

    # At the end of the scroll the Session Token card and its controls must be
    # fully visible -- this is the acceptance criterion for the clipping bug.
    required = {"#session-token-box", "#session-token-input", "#btn-save-token",
                "#btn-import-token", "#btn-clear-tokens"}
    for el in bottom["elements"]:
        if el.get("sel") not in required:
            continue
        if el.get("missing"):
            problems.append(f"missing {el['sel']}")
            continue
        if not el["insideContainer"]:
            problems.append(f"Session Token element {el['sel']} is not reachable in the scroll container")
        if not el["insideViewport"]:
            problems.append(f"Session Token element {el['sel']} clips below the viewport")
        if el["overlapsFooter"]:
            problems.append(f"Session Token element {el['sel']} overlaps the footer")
    token = next((e for e in top["elements"] if e.get("sel") == "#session-token-box"), None)
    if token is None or token.get("missing"):
        problems.append("Session Token card missing from the Account view")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--size", action="append", default=[],
                        help="WIDTHxHEIGHT (repeatable); default 1280x800 and 1440x900")
    parser.add_argument("--edge", default=str(DEFAULT_EDGE))
    parser.add_argument("--workdir", default=str(DEFAULT_WORKDIR))
    args = parser.parse_args()

    sizes = args.size or ["1280x800", "1440x900"]
    edge = Path(args.edge)
    if not edge.exists():
        print(f"FAIL: Edge not found at {edge}", file=sys.stderr)
        return 2
    workdir = Path(args.workdir)
    page = build_harness(workdir)
    profile = workdir / "edgeprofile"
    failed = False
    for size in sizes:
        width, height = (int(part) for part in size.lower().split("x"))
        report = run_size(edge, page, profile, width, height)
        problems = evaluate(report)
        token = next((e for e in report["bottom"]["elements"]
                      if e.get("sel") == "#session-token-box"), {})
        print(f"== {size}: container {report['top']['container']['clientHeight']}px viewport, "
              f"content {report['top']['container']['scrollHeight']}px, "
              f"token bottom {token.get('bottom')} / viewport {report['bottom']['viewport']['h']}")
        if problems:
            failed = True
            for problem in problems:
                print(f"   FAIL {problem}")
        else:
            print("   PASS no clipping, no footer overlap, Session Token fully reachable")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
