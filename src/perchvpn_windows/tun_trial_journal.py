"""Durable, fail-closed TUN trial journal."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from perchvpn_windows.platform import get_config_dir
from perchvpn_windows.tun_state_capture import CaptureError, NetworkSnapshot


class TrialPreparationError(Exception):
    """Raised when trial preparation fails and cannot proceed."""
    pass

_JOURNAL_VERSION = 1
_JOURNAL_FILENAME = "tun-trial-journal.json"


class JournalError(Exception):
    """Raised when the journal cannot be read, written, or validated."""


@dataclass
class TrialJournal:
    """In-memory representation of a trial journal."""

    version: int = _JOURNAL_VERSION
    trial_id: str = ""
    created_at: float = 0.0
    state: str = "prepared"
    adapter_name: str = ""
    executable_identity: Optional[dict] = None
    config_hash: str = ""
    network_snapshot: Optional[dict] = None
    ambient_diffs: Optional[List[dict]] = None
    updated_at: float = 0.0

    def __post_init__(self) -> None:
        if not self.trial_id:
            self.trial_id = str(uuid.uuid4())
        if not self.created_at:
            self.created_at = time.time()
        if not self.updated_at:
            self.updated_at = self.created_at

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "trial_id": self.trial_id,
            "created_at": self.created_at,
            "state": self.state,
            "adapter_name": self.adapter_name,
            "executable_identity": self.executable_identity,
            "config_hash": self.config_hash,
            "network_snapshot": self.network_snapshot,
            "ambient_diffs": self.ambient_diffs,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TrialJournal":
        if not isinstance(data, dict):
            raise JournalError("journal must be a JSON object")
        if data.get("version") != _JOURNAL_VERSION:
            raise JournalError(
                "unsupported journal version: %r" % data.get("version")
            )
        state = data.get("state")
        if state not in ("prepared", "running", "stopped", "unverified", "reverting", "completed", "failed"):
            raise JournalError("invalid journal state: %r" % state)
        trial_id = data.get("trial_id")
        if not isinstance(trial_id, str) or not trial_id:
            raise JournalError("missing or invalid trial_id")
        adapter_name = data.get("adapter_name")
        if not isinstance(adapter_name, str) or not adapter_name:
            raise JournalError("missing or invalid adapter_name")
        executable = data.get("executable_identity")
        if executable is not None and not isinstance(executable, dict):
            raise JournalError("executable_identity must be an object or null")
        if executable is not None:
            for key in ("path", "size", "mtime_ns", "sha256"):
                if key not in executable:
                    raise JournalError(
                        "executable_identity missing key: %s" % key
                    )
        snapshot = data.get("network_snapshot")
        if snapshot is not None and not isinstance(snapshot, dict):
            raise JournalError("network_snapshot must be an object or null")
        # Validate network_snapshot if present
        if snapshot is not None:
            try:
                NetworkSnapshot.from_dict(snapshot)
            except (ValueError, CaptureError) as exc:
                raise JournalError("invalid network_snapshot in journal: %s" % exc) from exc
        # Require snapshot for prepared/running states
        if state in ("prepared", "running") and snapshot is None:
            raise JournalError("network_snapshot is required for state %r" % state)
        return cls(
            version=data["version"],
            trial_id=trial_id,
            created_at=float(data.get("created_at", 0)),
            state=state,
            adapter_name=adapter_name,
            executable_identity=executable,
            config_hash=str(data.get("config_hash", "")),
            network_snapshot=snapshot,
            ambient_diffs=(
                list(data["ambient_diffs"])
                if isinstance(data.get("ambient_diffs"), list)
                else None
            ),
            updated_at=float(data.get("updated_at", 0)),
        )


def _journal_path() -> Path:
    return get_config_dir() / _JOURNAL_FILENAME


def _atomic_write(path: Path, data: dict) -> None:
    """Write *data* to *path* atomically with durable flush."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        prefix=path.name + ".tmp-", dir=str(path.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    except Exception as exc:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass
        raise JournalError("cannot persist trial journal: %s" % exc) from exc
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


def load_journal(path=None):
    """Load and validate the journal.  Returns None if absent.

    Raises JournalError on malformed or invalid content.
    """
    p = path if path is not None else _journal_path()
    try:
        raw = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise JournalError("cannot read trial journal: %s" % exc) from exc
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError) as exc:
        raise JournalError("trial journal is corrupt") from exc
    return TrialJournal.from_dict(data)


def save_journal(journal, path=None):
    """Persist *journal* atomically.  Fails if an unresolved journal exists."""
    p = path if path is not None else _journal_path()
    existing = load_journal(p)
    if existing is not None and existing.state in ("prepared", "running", "unverified"):
        if existing.trial_id != journal.trial_id:
            raise JournalError(
                "an unresolved trial journal already exists (trial_id=%s); "
                "refusing to overwrite" % existing.trial_id
            )
    journal.updated_at = time.time()
    _atomic_write(p, journal.to_dict())


def clear_journal(path=None):
    """Remove the journal only when state is 'stopped' (resolved)."""
    p = path if path is not None else _journal_path()
    existing = load_journal(p)
    if existing is not None and existing.state != "stopped":
        raise JournalError(
            "cannot clear unresolved trial journal (state=%s)" % existing.state
        )
    try:
        p.unlink()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise JournalError("cannot remove trial journal: %s" % exc) from exc


def compute_file_identity(path):
    """Compute a SHA-256 identity dict for a file (read-only)."""
    stat = os.stat(path)
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return {
        "path": os.path.abspath(path),
        "size": int(stat.st_size),
        "mtime_ns": int(stat.st_mtime_ns),
        "sha256": digest.hexdigest(),
    }
