"""Regression tests for the frozen sign-in helper command builder.

The GUI sign-in button posts /api/account/login, which launches the CLI
auth-only helper. Under PyInstaller the helper must run ``<exe> --auth-only``
(the exe already dispatches any argv through cli.main); passing
``-m perchvpn_windows.cli`` made argparse reject ``-m`` so the terminal
window opened and closed instantly and sign-in appeared dead.
"""

import sys
from unittest.mock import patch

from perchvpn_windows.app import auth_helper_command


def test_auth_helper_command_frozen_uses_exe_argv():
    """A frozen build (sys.frozen) must call the exe with --auth-only only."""
    with patch.object(sys, "frozen", True, create=True):
        cmd = auth_helper_command("C:/apps/PerchVPN.exe", env={})
    assert cmd == ["C:/apps/PerchVPN.exe", "--auth-only"]


def test_auth_helper_command_source_uses_module_invocation(monkeypatch):
    """Running from source (real Python) keeps the -m module invocation."""
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    cmd = auth_helper_command("/usr/bin/python3", env={})
    assert cmd == [
        "/usr/bin/python3",
        "-m",
        "perchvpn_windows.cli",
        "--auth-only",
    ]


def test_auth_helper_command_env_frozen_flag_forces_exe_argv():
    """The PERCHVPN_FROZEN=1 env flag forces the frozen form (POSIX tests)."""
    cmd = auth_helper_command("python", env={"PERCHVPN_FROZEN": "1"})
    assert cmd == ["python", "--auth-only"]
