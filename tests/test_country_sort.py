"""Focused tests for deterministic country ordering by measured latency.

The comparator lives in web/country-sort.js so the ordering rules are
verified directly (v8 via node) rather than through a browser.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODULE = PROJECT_ROOT / "src" / "perchvpn_windows" / "web" / "country-sort.js"


def _run(js: str):
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not available")
    script = f"const m = require({json.dumps(str(MODULE))});\n{js}"
    result = subprocess.run([node, "-e", script], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_ascending_with_ties_and_unavailable_last():
    ordered = _run(
        """
const rows = [
  { name: 'Germany', ms: null, index: 0 },
  { name: 'France', ms: 80, index: 1 },
  { name: 'Spain', ms: 20, index: 2 },
  { name: 'Italy', ms: 20, index: 3 },
  { name: 'Norway', ms: 0, index: 4 },
  { name: 'Belgium', ms: 20, index: 5 },
];
process.stdout.write(JSON.stringify(rows.slice().sort(m.compare).map(r => r.name)));
"""
    )
    # 20 ms group ordered by name, then 80 ms, then invalid values by name.
    assert ordered == ["Belgium", "Italy", "Spain", "France", "Germany", "Norway"]


def test_missing_invalid_and_non_positive_are_unavailable():
    ordered = _run(
        """
const rows = [
  { name: 'A-missing', ms: undefined, index: 0 },
  { name: 'B-negative', ms: -5, index: 1 },
  { name: 'C-nan', ms: NaN, index: 2 },
  { name: 'D-valid', ms: 12.5, index: 3 },
  { name: 'E-infinity', ms: Infinity, index: 4 },
];
process.stdout.write(JSON.stringify(rows.slice().sort(m.compare).map(r => r.name)));
"""
    )
    assert ordered == ["D-valid", "A-missing", "B-negative", "C-nan", "E-infinity"]


def test_ordering_is_stable_and_idempotent():
    ordered = _run(
        """
const rows = [
  { name: 'Same', ms: 30, index: 2 },
  { name: 'Same', ms: 30, index: 0 },
  { name: 'Other', ms: 10, index: 1 },
  { name: 'Zed', ms: null, index: 3 },
];
const once = rows.slice().sort(m.compare).map(r => r.index);
const twice = rows.slice().sort(m.compare).sort(m.compare).map(r => r.index);
process.stdout.write(JSON.stringify({ once, twice }));
"""
    )
    assert ordered["once"] == ordered["twice"]
    # valid ascending first, then equal-name ties by original position.
    assert ordered["once"] == [1, 0, 2, 3]


def test_frontend_wires_the_shared_comparator():
    index = (PROJECT_ROOT / "src" / "perchvpn_windows" / "web" / "index.html").read_text(encoding="utf-8")
    app = (PROJECT_ROOT / "src" / "perchvpn_windows" / "web" / "app.js").read_text(encoding="utf-8")
    assert "country-sort.js" in index
    assert "PerchCountrySort" in app
    assert "scheduleCountrySort" in app
