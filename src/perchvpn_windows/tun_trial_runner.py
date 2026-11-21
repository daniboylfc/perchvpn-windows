"""TUN trial preparation and lifecycle orchestration.

This module provides the fail-closed trial runner that captures a network
snapshot before advancing a trial to the 'prepared' state. Any failure during
capture or validation aborts the trial immediately without leaving dangling
journal entries.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from perchvpn_windows.tun_state_capture import (
    CaptureError,
    NetworkSnapshot,
    RollbackError,
    StateDifference,
    _run_ps_write,
    compare_snapshots,
    generate_rollback_commands,
    capture_snapshot,
    partition_diffs,
)
from perchvpn_windows.tun_recovery import (
    CLEAN,
    RECOVERY_UNVERIFIED,
    TunRecoveryGate,
    reconcile_stale_ownership,
)
from perchvpn_windows.tun_trial_journal import (
    JournalError,
    TrialJournal,
    TrialPreparationError,
    clear_journal,
    load_journal,
    save_journal,
)

logger = logging.getLogger("perchvpn_windows.tun_trial_runner")


@dataclass
class TrialConfig:
    """Configuration for a TUN trial preparation."""
    adapter_name: str
    config_hash: str
    executable_path: str
    journal_path: Optional[Path] = None


@dataclass
class TrialResult:
    """Result of a trial preparation attempt."""
    journal: Optional[TrialJournal]
    success: bool
    error: Optional[str] = None


class TrialRunner:
    """Orchestrates TUN trial preparation with fail-closed snapshot capture."""

    def __init__(self, config: TrialConfig):
        self.config = config
        self._journal: Optional[TrialJournal] = None

    def _compute_executable_identity(self) -> dict:
        """Compute executable identity for the trial journal."""
        try:
            return compute_file_identity(self.config.executable_path)
        except OSError as exc:
            raise TrialPreparationError(f"cannot read executable: {exc}") from exc

    def prepare(self) -> TrialResult:
        """Prepare a TUN trial by capturing a network snapshot.

        This method:
        1. Captures a complete network snapshot (read-only)
        2. Validates the snapshot schema
        3. Creates a TrialJournal with the snapshot in 'prepared' state
        4. Persists the journal atomically

        Returns:
            TrialResult with success status and journal (or error details).

        The trial is aborted and no journal is left in 'prepared' state if:
        - capture_snapshot() raises CaptureError
        - snapshot validation fails
        - journal persistence fails
        - executable identity computation fails
        """
        logger.info("Starting TUN trial preparation for adapter: %s", self.config.adapter_name)

        # Step 1: Capture network snapshot
        snapshot: NetworkSnapshot
        try:
            snapshot = capture_snapshot()
            logger.debug("Captured network snapshot: %d routes, %d adapters",
                        len(snapshot.routes), len(snapshot.adapters))
        except CaptureError as exc:
            logger.error("Snapshot capture failed: %s", exc)
            return TrialResult(journal=None, success=False, error=f"snapshot capture failed: {exc}")

        # Step 2: Validate snapshot explicitly (defense in depth)
        try:
            snapshot.validate()
        except CaptureError as exc:
            logger.error("Captured snapshot failed validation: %s", exc)
            return TrialResult(journal=None, success=False, error=f"snapshot validation failed: {exc}")

        # Step 3: Build trial journal with validated snapshot
        executable_identity = None
        try:
            executable_identity = self._compute_executable_identity()
        except TrialPreparationError as exc:
            logger.error("Executable identity computation failed: %s", exc)
            return TrialResult(journal=None, success=False, error=f"executable identity failed: {exc}")

        journal = TrialJournal(
            adapter_name=self.config.adapter_name,
            config_hash=self.config.config_hash,
            executable_identity=executable_identity,
            network_snapshot=snapshot.to_dict(),
            state="prepared",
        )

        # Step 4: Persist journal atomically
        try:
            save_journal(journal, path=self.config.journal_path)
            self._journal = journal
            logger.info("Trial prepared successfully: trial_id=%s", journal.trial_id)
            return TrialResult(journal=journal, success=True)
        except JournalError as exc:
            logger.error("Failed to persist trial journal: %s", exc)
            return TrialResult(journal=None, success=False, error=f"journal persistence failed: {exc}")

    def abort(self) -> None:
        """Abort the current trial if one is in progress.

        Cleans up any prepared journal for this trial.
        """
        if self._journal is not None:
            try:
                clear_journal(path=self.config.journal_path)
                logger.info("Aborted trial: trial_id=%s", self._journal.trial_id)
            except JournalError as exc:
                logger.warning("Failed to clear trial journal on abort: %s", exc)
            finally:
                self._journal = None

    def teardown(
        self,
        journal: TrialJournal,
        force_rollback: bool = False,
    ) -> TrialResult:
        """Teardown a trial by comparing current state to baseline and rolling back.

        Steps:
          1. Capture current network snapshot
          2. Compare against journal baseline
          3. If drift or force_rollback, generate + execute remediation commands
          4. Verify rollback; if clean, mark completed and unlink journal
        """
        logger.info("Starting trial teardown: trial_id=%s", journal.trial_id)

        current_snapshot: NetworkSnapshot
        try:
            current_snapshot = capture_snapshot()
        except CaptureError as exc:
            logger.error("Post-trial capture failed: %s", exc)
            return TrialResult(journal=None, success=False, error=f"post-trial capture failed: {exc}")

        baseline_snapshot = NetworkSnapshot.from_dict(journal.network_snapshot or {})

        diffs: List[StateDifference] = compare_snapshots(baseline_snapshot, current_snapshot)

        owned_diffs, ambient_diffs = partition_diffs(
            diffs,
            adapter_name=journal.adapter_name,
            current_snapshot=current_snapshot,
            baseline_snapshot=baseline_snapshot,
        )
        if ambient_diffs:
            logger.warning(
                "Ambient (non-trial) network drift retained, not remediated: %s",
                "; ".join(
                    "%s: %s" % (d.category, d.description) for d in ambient_diffs
                ),
            )

        if not owned_diffs and not force_rollback:
            logger.info(
                "No trial-owned drift detected; marking trial completed"
                " (%d ambient diff(s) reported)", len(ambient_diffs),
            )
            journal.state = "completed"
            journal.ambient_diffs = _ambient_record(ambient_diffs)
            journal.updated_at = time.time()
            try:
                save_journal(journal, path=self.config.journal_path)
                try:
                    self.config.journal_path.unlink()
                except FileNotFoundError:
                    pass
                self._journal = None
                _reconcile_ownership()
                return TrialResult(journal=journal, success=True)
            except JournalError as exc:
                logger.error("Failed to finalize journal: %s", exc)
                return TrialResult(journal=journal, success=False, error=f"journal finalize failed: {exc}")

        logger.warning(
            "Drift detected (%d trial-owned diffs); entering reverting state",
            len(owned_diffs),
        )
        journal.state = "reverting"
        journal.updated_at = time.time()
        try:
            save_journal(journal, path=self.config.journal_path)
        except JournalError as exc:
            logger.error("Failed to transition to reverting: %s", exc)
            journal.state = "failed"
            return TrialResult(journal=journal, success=False, error=f"reverting transition failed: {exc}")

        try:
            commands = generate_rollback_commands(owned_diffs)
        except RollbackError as exc:
            logger.error("Refusing unsafe rollback mutation: %s", exc)
            journal.state = "failed"
            journal.updated_at = time.time()
            try:
                save_journal(journal, path=self.config.journal_path)
            except JournalError:
                pass
            return TrialResult(
                journal=journal,
                success=False,
                error=f"unsafe rollback mutation: {exc}",
            )
        if commands:
            for cmd in commands:
                try:
                    _run_ps_write(cmd)
                except RollbackError as exc:
                    msg = str(exc)
                    if any(
                        err in msg
                        for err in (
                            "ObjectNotFound",
                            "CmdletizationQuery_NotFound",
                            "CimJobException",
                            "Element not found",
                            "No matching MSFT_NetRoute",
                        )
                    ):
                        logger.info(
                            "Ignoring already-remediated entity during rollback (%r): %s",
                            cmd,
                            exc,
                        )
                        continue
                    logger.error("Rollback command failed: %s", exc)
                    journal.state = "failed"
                    journal.updated_at = time.time()
                    try:
                        save_journal(journal, path=self.config.journal_path)
                    except JournalError:
                        pass
                    return TrialResult(
                        journal=journal,
                        success=False,
                        error=f"rollback failed: {exc}",
                    )

        verification_snapshot: NetworkSnapshot
        try:
            verification_snapshot = capture_snapshot()
        except CaptureError as exc:
            logger.error("Verification capture failed: %s", exc)
            journal.state = "failed"
            journal.updated_at = time.time()
            try:
                save_journal(journal, path=self.config.journal_path)
            except JournalError:
                pass
            return TrialResult(
                journal=journal,
                success=False,
                error=f"verification capture failed: {exc}",
            )

        verify_diffs: List[StateDifference] = compare_snapshots(
            baseline_snapshot, verification_snapshot
        )

        verify_owned, verify_ambient = partition_diffs(
            verify_diffs,
            adapter_name=journal.adapter_name,
            current_snapshot=verification_snapshot,
            baseline_snapshot=baseline_snapshot,
        )

        journal.ambient_diffs = _ambient_record(
            ambient_diffs + verify_ambient
        ) if (ambient_diffs or verify_ambient) else None

        if verify_owned:
            logger.error(
                "Rollback verification failed; residual trial-owned diffs remain"
            )
            journal.state = "failed"
            journal.updated_at = time.time()
            try:
                save_journal(journal, path=self.config.journal_path)
            except JournalError:
                pass
            return TrialResult(
                journal=journal,
                success=False,
                error="rollback verification failed: residual diffs remain",
            )

        logger.info(
            "Rollback verified; marking trial completed"
            " (%d ambient diff(s) retained as conflicts)", len(verify_ambient),
        )
        journal.state = "completed"
        journal.updated_at = time.time()
        try:
            save_journal(journal, path=self.config.journal_path)
            try:
                self.config.journal_path.unlink()
            except FileNotFoundError:
                pass
            self._journal = None
            _reconcile_ownership()
            return TrialResult(journal=journal, success=True)
        except JournalError as exc:
            logger.error("Failed to finalize journal after rollback: %s", exc)
            return TrialResult(journal=journal, success=False, error=f"journal finalize failed: {exc}")


def _ambient_record(diff_list: List[StateDifference]) -> List[dict]:
    """Summarize ambient diffs for durable journal evidence."""
    return [
        {"category": d.category, "description": d.description}
        for d in diff_list
    ]


def _reconcile_ownership() -> str:
    """Reconcile any stale ownership record after verified clean teardown.

    Fail-closed: a record that survives reconciliation keeps blocking future
    gate ``pre_start`` calls; only verified-clean reconciliation unlinks it.
    """
    try:
        return reconcile_stale_ownership()
    except Exception as exc:  # noqa: BLE001
        logger.error("Cold-start ownership reconciliation failed: %s", exc)
        return RECOVERY_UNVERIFIED


def prepare_trial(
    *,
    adapter_name: str,
    config_hash: str,
    executable_path: str,
    journal_path: Optional[Path] = None,
) -> TrialResult:
    """Convenience function to prepare a TUN trial.

    Args:
        adapter_name: Name of the TUN adapter for this trial.
        config_hash: Hash of the trial configuration.
        executable_path: Path to the TUN sidecar executable.
        journal_path: Optional custom path for the trial journal.

    Returns:
        TrialResult with success status and journal or error.
    """
    config = TrialConfig(
        adapter_name=adapter_name,
        config_hash=config_hash,
        executable_path=executable_path,
        journal_path=journal_path,
    )
    runner = TrialRunner(config)
    return runner.prepare()


def abort_trial(
    *,
    journal_path: Optional[Path] = None,
) -> None:
    """Abort any pending trial by clearing its journal.

    Args:
        journal_path: Optional custom path for the trial journal.
    """
    try:
        clear_journal(path=journal_path)
        logger.info("Trial aborted and journal cleared")
    except JournalError as exc:
        logger.warning("Failed to clear trial journal on abort: %s", exc)


def compute_file_identity(path: str) -> dict:
    """Compute a SHA-256 identity dict for a file (read-only)."""
    import hashlib
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


def teardown_trial(
    journal: TrialJournal,
    force_rollback: bool = False,
    journal_path: Optional[Path] = None,
) -> TrialResult:
    """Convenience function to tear down a TUN trial.

    Args:
        journal: The trial journal containing the baseline snapshot.
        force_rollback: If True, always attempt rollback even if no diffs.
        journal_path: Optional custom path for the trial journal.

    Returns:
        TrialResult with success status and error details if any.
    """
    runner = TrialRunner(
        TrialConfig(
            adapter_name=journal.adapter_name,
            config_hash=journal.config_hash,
            executable_path=journal.executable_identity.get("path", "")
            if journal.executable_identity
            else "",
            journal_path=journal_path,
        )
    )
    return runner.teardown(journal, force_rollback=force_rollback)
