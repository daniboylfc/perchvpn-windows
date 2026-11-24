"""The boot/API chain must not pay for aioquic.

``h3_session`` imports aioquic (~140 ms measured on the dev host, ~186 ms in
the frozen bundle) and only an HTTP/3 dial needs it.  ``pool`` and
``controller`` therefore resolve ``H3ProxySession`` lazily, while keeping the
module attribute patchable for the existing tests.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

from src.perchvpn import controller as controller_module
from src.perchvpn.proxy import pool as pool_module

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_api_import_does_not_pull_in_aioquic():
    code = textwrap.dedent(
        """
        import sys
        import perchvpn_windows.api  # the boot/API chain

        loaded = [m for m in sys.modules if m == "aioquic" or m.startswith("aioquic.")]
        assert not loaded, loaded
        assert "perchvpn.proxy.h3_session" not in sys.modules

        # The public names still resolve, and resolving one imports it once.
        from perchvpn.proxy import pool
        assert pool.H3ProxySession.__name__ == "H3ProxySession"
        assert "perchvpn.proxy.h3_session" in sys.modules
        assert pool.H3ProxySession is pool.H3ProxySession
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_pool_exposes_h3_names_lazily():
    assert pool_module.H3ProxySession.__name__ == "H3ProxySession"
    assert pool_module.H3Stream.__name__ == "H3Stream"
    with pytest.raises(AttributeError):
        pool_module.not_a_real_name


def test_controller_h3_class_honours_a_module_patch():
    sentinel = object()
    with patch.object(controller_module, "H3ProxySession", sentinel):
        assert controller_module._h3_session_class() is sentinel
    # Restored to the real class after the patch exits.
    assert controller_module._h3_session_class().__name__ == "H3ProxySession"
