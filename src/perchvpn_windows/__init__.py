"""Perch VPN (Windows): SOCKS5 proxy client for Mozilla VPN.

The ``perchvpn``/``perchvpn_windows`` package names and ``PerchVPNApp``
identifier are retained for import and API compatibility.

Public names are resolved lazily.  The elevated ``--tun-helper`` entry point
imports this package inside a short-lived, UAC-launched process; eagerly
importing the GUI/controller stack here made every helper launch pay the full
app import cost before it could write its spec/state.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .app import PerchVPNApp
    from .config import WindowsConfig
    from .frontend import Socks5Frontend

__all__ = [
    "PerchVPNApp",
    "WindowsConfig",
    "load_config",
    "save_config",
    "Socks5Frontend",
    "get_config_dir",
    "get_proxy_state_path",
    "get_status_path",
    "get_token_path",
    "ensure_config_dir",
]

__version__ = "2.0.4"

_LAZY_ATTRS = {
    "PerchVPNApp": (".app", "PerchVPNApp"),
    "WindowsConfig": (".config", "WindowsConfig"),
    "load_config": (".config", "load_config"),
    "save_config": (".config", "save_config"),
    "Socks5Frontend": (".frontend", "Socks5Frontend"),
    "get_config_dir": (".platform", "get_config_dir"),
    "get_proxy_state_path": (".platform", "get_proxy_state_path"),
    "get_status_path": (".platform", "get_status_path"),
    "get_token_path": (".platform", "get_token_path"),
    "ensure_config_dir": (".platform", "ensure_config_dir"),
}


def __getattr__(name: str):
    try:
        module_name, attr = _LAZY_ATTRS[name]
    except KeyError:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None
    from importlib import import_module

    value = getattr(import_module(module_name, __name__), attr)
    globals()[name] = value
    return value


def __dir__():
    return sorted(set(globals()) | set(__all__))
