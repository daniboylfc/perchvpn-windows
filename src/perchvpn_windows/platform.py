"""Windows platform abstractions: paths, directories."""

from __future__ import annotations

import os
import shutil
from pathlib import Path


def _appdata_base() -> str:
    base = os.environ.get("APPDATA")
    if not base:
        base = str(Path.home() / "AppData" / "Roaming")
    return base


def get_config_dir() -> Path:
    """Return the Perch VPN configuration directory: %APPDATA%/PerchVPN.

    The on-disk directory name stays "PerchVPN" so existing tokens,
    configuration, proxy state and status files remain readable after the
    rebrand; renaming it would strand existing user data.
    """
    return Path(_appdata_base()) / "PerchVPN"


def get_legacy_config_dir() -> Path:
    """Configuration directory of the pre-rebrand install: %APPDATA%/FoxyVPN.

    Tokens minted by earlier builds (the terminal auth helper session the
    rebrand stranded) live here. Never written to by this app after the
    rebrand; consulted only to migrate that store forward once.
    """
    return Path(_appdata_base()) / "FoxyVPN"


def migrate_legacy_tokens() -> bool:
    """Copy a pre-rebrand token store into the current one, exactly once.

    Runs only when %APPDATA%/PerchVPN/tokens.json is absent and
    %APPDATA%/FoxyVPN/tokens.json exists and the one-time sentinel marker
    has not been written: the file is copied byte-for-byte (same schema,
    no rewriting) so the existing validated refresh flow can renew it
    through /v1/oauth/token. Returns True only when a copy actually
    happened. Never logs, prints or transforms token material.

    The sentinel guarantees a legacy store can never resurrect
    credentials after an explicit sign-out: re-launching this function
    once the marker exists is a no-op even if the current tokens.json was
    deleted in between.
    """
    marker = get_legacy_migration_marker_path()
    if marker.exists():
        return False
    legacy = get_legacy_config_dir() / "tokens.json"
    current = get_token_path()
    if not legacy.exists():
        return False
    try:
        ensure_config_dir()
        if current.exists():
            # The current store is authoritative; the legacy copy is
            # superseded and must not resurface after a later sign-out.
            marker.write_text("consumed", encoding="utf-8")
            return False
        shutil.copyfile(legacy, current)
        marker.write_text("consumed", encoding="utf-8")
    except OSError:
        return False
    return current.exists()


def get_legacy_migration_marker_path() -> Path:
    """Sentinel recording that the legacy token store was consumed."""
    return get_config_dir() / ".legacy_migrated"


def discard_legacy_tokens() -> None:
    """Consume the legacy token store on explicit sign-out.

    Writes the sentinel first so an unrecoverable later failure can never
    let migration re-copy the stranded store across a restart, then
    deletes the FoxyVPN token file. Raises BaseException-compatible
    errors so callers can fail closed; a missing legacy file is not an
    error. Never logs, prints or transforms token material.
    """
    ensure_config_dir()
    marker = get_legacy_migration_marker_path()
    try:
        marker.unlink()
    except FileNotFoundError:
        pass
    marker.write_text("consumed", encoding="utf-8")
    legacy = get_legacy_config_dir() / "tokens.json"
    try:
        legacy.unlink()
    except FileNotFoundError:
        pass


def get_token_path() -> Path:
    """Return the token storage path."""
    return get_config_dir() / "tokens.json"


def get_proxy_state_path() -> Path:
    """Return the persisted proxy selection state path."""
    return get_config_dir() / "proxy-state.json"


def get_status_path() -> Path:
    """Return the status file path."""
    return get_config_dir() / "status.json"


def get_tun_ownership_path() -> Path:
    """Return the TUN sidecar ownership record path."""
    return get_config_dir() / "tun-ownership.json"


def ensure_config_dir() -> None:
    """Create the configuration directory if it doesn't exist."""
    get_config_dir().mkdir(parents=True, exist_ok=True)