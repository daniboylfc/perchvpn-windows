"""Opt-in TUN frontend supervisor."""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import shutil
import signal
import subprocess
import sys
import time
from collections import deque
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Sequence, Union

from perchvpn_windows import singbox_config, tun_helper, tun_status
from perchvpn_windows.platform import get_config_dir
from perchvpn_windows.tun_state_capture import _run_ps_write
from perchvpn_windows.win_process import hidden_process_kwargs
from perchvpn_windows.tun_recovery import (
    CLEAN,
    DEFAULT_ADAPTER_NAME,
    RECOVERY_UNVERIFIED,
    RecoveryRun,
    RecoveryUnverified,
    TunRecoveryGate,
)

logger = logging.getLogger("perchvpn_windows.tun_frontend")

__all__ = ["TunFrontend"]

_DEFAULT_CAPTURE_LINES = 100
_DEFAULT_MAX_LINE_BYTES = 4096
_STARTUP_GRACE_SECONDS = 0.2
_DEFAULT_GRACEFUL_STOP_TIMEOUT_SECONDS = 8.0
# User-facing disconnect budget: graceful CTRL_BREAK gets this long to drain
# the multiplex pool; a still-running sidecar is then terminated and the
# recovery gate restores the route/adapter baseline.
_GRACEFUL_ESCALATION_SECONDS = 1.5
_POST_STOP_WINTUN_CLEANUP_DELAY_SECONDS = 1.0
# Evidence cadence. Full captures are native iphlpapi reads (~80 ms measured
# on the production host, where the batched PowerShell probe cost 6.3-7.6 s
# and dominated both startup latency and idle CPU), so the transition cadence
# stays tight; the PowerShell path is only a fallback.
_FULL_EVIDENCE_INTERVAL_SECONDS = 15.0
_FULL_EVIDENCE_INTERVAL_STEADY_SECONDS = 60.0
# Presence probing is native too (~50 ms): 1 s while the sidecar is coming up
# so the metric pin fires as soon as Wintun publishes the interface, 5 s once
# the state is steady.
_PRESENCE_PROBE_INTERVAL_SECONDS = 5.0
_PRESENCE_PROBE_INTERVAL_STARTING_SECONDS = 1.0
# Safety valve for an authoritative-looking "absent" presence verdict: while
# the sidecar is alive but no evidence has ever been captured, a full capture
# still runs at this cadence so a broken presence fast path can never freeze
# readiness at "starting" forever (2026-11-18: a truncated native adapter
# list hid the PerchVPN adapter and left the GUI on "connecting").
_EVIDENCE_RETRY_SECONDS = 5.0
# Reconcile tick: 1 s while transitioning; 30 s once verified-steady.  Route
# or sidecar degradation wakes the loop immediately (see _reconcile_wake).
_RECONCILE_INTERVAL_STEADY_SECONDS = 30.0
# A freshly pinned adapter that still cannot reach the internet through the
# tunnel after this long is a settled failure (most often a competing tunnel
# owning the default route): degrade honestly and back off instead of
# spinning the 3 s transitional poller forever with the UI stuck at
# "connecting".
_EGRESS_STALL_DEGRADED_SECONDS = 20.0
_EGRESS_STALL_PROBE_TIMEOUT = 5.0
# Direct system-egress probe cadence: 20 s while the tunnel is settling,
# 30 s once traffic_verified holds steady (the probe is a real network
# round-trip; steady state must stay near-zero CPU, not near-zero idle).
_EGRESS_INTERVAL_TRANSITION_SECONDS = 20.0
# While the tunnel is up but not yet verified, re-probe at the reconcile
# cadence. The old 20 s transition interval kept a transient identity
# mismatch visible as "connecting" for a full 20 s (2026-11-20 log:
# 16:32:44 -> 16:33:04) even though the routes had settled in ~1 s.
_EGRESS_INTERVAL_VERIFYING_SECONDS = 1.0
_EGRESS_INTERVAL_STEADY_SECONDS = 30.0
# The async exit-identity trace must run after the Wintun routes settle:
# firing it ~1 s after the metric pin raced the route install and observed
# the physical exit, regressing traffic_verified to tunnel_operational.
_IDENTITY_SETTLE_SECONDS = 1.5
_IDENTITY_RETRY_SECONDS = 1.0
_IDENTITY_MAX_ATTEMPTS = 10
_IDENTITY_RETRY_BACKOFF_SECONDS = 30.0
_CREATE_NEW_PROCESS_GROUP = getattr(
    subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200
)
_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
_CTRL_BREAK_EVENT = getattr(signal, "CTRL_BREAK_EVENT", None)


def _validated_bypass(bypass: Sequence[str]) -> tuple[str, ...]:
    """Validate IP/CIDR entries rendered as sing-box route exclusions."""
    entries = tuple(str(v).strip() for v in (bypass or ()) if str(v).strip())
    for entry in entries:
        try:
            ipaddress.ip_network(entry, strict=False)
        except ValueError as exc:
            raise ValueError("invalid --bypass entry %r: %s" % (entry, exc)) from exc
    return entries


def _default_elevated() -> bool:
    if sys.platform != "win32":
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


class _RecoveryBudget:
    """Bounded automatic-restart allowance (upstream v2.0.3 parity).

    Mirrors the Android client's ``RecoveryBudget``: at most two automatic
    restarts per 15-minute window, after which repeated crashes stay failed
    instead of loop-respawn.
    """

    _WINDOW_SECONDS = 15 * 60.0
    _MAX_ATTEMPTS = 2

    def __init__(self) -> None:
        self._attempts: deque[float] = deque()

    def try_acquire(self, now: float) -> bool:
        while self._attempts and now - self._attempts[0] >= self._WINDOW_SECONDS:
            self._attempts.popleft()
        if len(self._attempts) >= self._MAX_ATTEMPTS:
            return False
        self._attempts.append(now)
        return True


class TunFrontend:
    def __init__(
        self,
        *,
        enabled: bool = False,
        opt_in: bool = False,
        executable_path: str = "",
        proxy_host: str = "127.0.0.1",
        proxy_port: int = 1080,
        mtu: int = 1400,
        extra_args: Optional[list[str]] = None,
        is_elevated: Optional[Callable[[], bool]] = None,
        capture_lines: int = _DEFAULT_CAPTURE_LINES,
        max_line_bytes: int = _DEFAULT_MAX_LINE_BYTES,
        recovery_gate: Optional[TunRecoveryGate] = None,
        graceful_stop: bool = False,
        bypass: Sequence[str] = (),
        bypass_processes: Optional[Sequence[str]] = None,
        adapter_name: str = singbox_config.DEFAULT_ADAPTER,
        config_path: Optional[str] = None,
        ip_mode: Optional[str] = None,
        bypass_local_network: bool = True,
        local_proxy_users: Optional[dict[str, str]] = None,
        kill_switch: bool = False,
        automatic_recovery: bool = False,
        utls_fingerprint: str = "disabled",
        tunnel_dns_provider: str = "default",
        custom_tunnel_doh_url: str = "",
        auto_detect_interface: bool = True,
    ) -> None:
        self.enabled = bool(enabled)
        self.opt_in = bool(opt_in)
        self.executable_path = (executable_path or "").strip()
        self.proxy_host = proxy_host or "127.0.0.1"
        self.proxy_port = int(proxy_port)
        self.mtu = int(mtu)
        self.extra_args = list(extra_args or [])
        self.bypass = _validated_bypass(bypass)
        self._excluded_networks = singbox_config.excluded_networks(self.bypass)
        self.bypass_processes = tuple(
            str(v).strip()
            for v in (
                singbox_config.DEFAULT_BYPASS_PROCESSES
                if bypass_processes is None
                else bypass_processes
            )
            if str(v).strip()
        )
        self.adapter_name = (adapter_name or singbox_config.DEFAULT_ADAPTER).strip()
        self.ip_mode = (ip_mode or "").strip() or None
        self.bypass_local_network = bool(bypass_local_network)
        self.local_proxy_users = (
            {str(u): str(p) for u, p in (local_proxy_users or {}).items() if u and p}
            or None
        )
        self.kill_switch = bool(kill_switch)
        self.utls_fingerprint = (utls_fingerprint or "disabled").strip().lower()
        self.tunnel_dns_provider = (tunnel_dns_provider or "default").strip().lower()
        self.custom_tunnel_doh_url = str(custom_tunnel_doh_url or "").strip()
        self.auto_detect_interface = bool(auto_detect_interface)
        self.automatic_recovery = bool(automatic_recovery)
        self._recovery_budget = _RecoveryBudget()
        self.config_path = (
            Path(config_path)
            if config_path
            else get_config_dir() / "sing-box.json"
        )
        self._is_elevated_fn = is_elevated or _default_elevated
        self._capture_lines = int(capture_lines)
        if self._capture_lines <= 0:
            raise ValueError("capture_lines must be a positive integer")
        self._max_line_bytes = int(max_line_bytes)
        if self._max_line_bytes <= 0:
            raise ValueError("max_line_bytes must be a positive integer")
        self._process = None
        self._monitor_task = None
        self._stopping = False
        self._status = "disabled" if not self.enabled else "stopped"
        self.stdout = deque(maxlen=self._capture_lines)
        self.stderr = deque(maxlen=self._capture_lines)
        self._recovery_gate = (
            recovery_gate if recovery_gate is not None else TunRecoveryGate()
        )
        self._recovery_run = None
        self._recovery_state = CLEAN
        self._recovery_lock: Optional[asyncio.Lock] = None
        self._spawn_confirmed = False
        # True once a spawned run's verdict was consumed in-process: only then
        # is an UNVERIFIED verdict re-derivable from the durable record.
        self._recovery_run_consumed = False
        self._graceful_stop = bool(graceful_stop)
        # Truthful readiness evidence. ``status`` keeps its historical
        # process-lifecycle meaning; ``state`` is the evidence-based TUN
        # readiness classification surfaced to the UI.
        self._state = "disabled" if not self.enabled else "starting"
        self._state_detail = ""
        self._evidence: Optional[tun_status.AdapterEvidence] = None
        self._egress: Optional[Dict[str, Any]] = None
        self._baseline: Optional[Dict[str, Any]] = None
        self._expected_exit_ip = ""
        self._expected_country = ""
        self._spawn_failed = False
        self._configured = False
        self._metric_pinned = False
        self._pinned_at = None
        self._spawned_at: Optional[float] = None
        self._stall_degraded = False
        self._stall_hint = ""
        self._last_egress_error = ""
        self._competing_hint = ""
        self._pin_lock: asyncio.Lock = asyncio.Lock()
        self._identity_task: Optional[asyncio.Task] = None
        self._identity_attempted = False
        self._identity_retry_at = 0.0
        self._egress_identity: Dict[str, Any] = {}
        self._state_listener: Optional[Callable[[str, str], None]] = None
        self._reconcile_task: Optional[asyncio.Task] = None
        self._reconcile_interval = 1.0
        self._reconcile_wake: Optional[asyncio.Event] = None
        # Post-pin egress stall tracking (fast-fail to degraded, see
        # _EGRESS_STALL_DEGRADED_SECONDS).
        self._pinned_at: Optional[float] = None
        self._stall_degraded = False
        self._stall_hint = ""
        self._last_egress_error = ""
        self._competing_hint = ""
        self._egress_interval = _EGRESS_INTERVAL_TRANSITION_SECONDS
        self._last_egress_check = 0.0
        # Evidence cadence control: the full adapter/route/DNS capture is
        # heavy PowerShell work and must not run on every reconcile tick,
        # and the cheap presence check is cached between its own probes.
        self._last_full_evidence = 0.0
        self._last_presence: Optional[bool] = None
        self._last_presence_probe = 0.0
        self._evidence_missing_logged = False

    @property
    def status(self) -> str:
        return self._status

    @property
    def state(self) -> str:
        """Evidence-based readiness state (see perchvpn_windows.tun_status)."""
        return self._state

    @property
    def state_detail(self) -> str:
        return self._state_detail

    @property
    def recovery_state(self) -> str:
        return self._recovery_state

    def set_verification_target(
        self,
        exit_ip: str = "",
        country: str = "",
        baseline: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Record what a successful system-egress probe must look like.

        ``exit_ip``/``country`` come from the verified SOCKS5 exit check;
        ``baseline`` is the pre-TUN direct egress, used to detect traffic that
        still leaves through the physical path.
        """
        self._expected_exit_ip = str(exit_ip or "")
        self._expected_country = str(country or "")
        if baseline is not None:
            self._baseline = baseline

    def set_state_listener(
        self, listener: Optional[Callable[[str, str], None]]
    ) -> None:
        """Register a callback fired on every TUN state transition."""
        self._state_listener = listener

    def payload(self) -> Dict[str, Any]:
        """Machine-readable readiness evidence for /api/status."""
        process_alive = (
            self._process is not None
            and getattr(self._process, "returncode", None) is None
        )
        return {
            "enabled": bool(self.enabled),
            "state": self._state,
            "detail": self._state_detail,
            "adapter": self._adapter_name(),
            "process_alive": process_alive,
            "process_status": self._status,
            "configured": self._configured,
            "elevated": self.is_elevated(),
            "recovery_state": self._recovery_state,
            "adapter_evidence": self._evidence.to_dict() if self._evidence else None,
            "system_egress": self._egress,
            "expected_exit_ip": self._expected_exit_ip,
            "expected_country": self._expected_country,
        }

    async def _enforce_split_route_metrics(
        self,
        alias: Optional[Union[str, int]] = None,
        metric: int = 1,
    ) -> None:
        """sing-box installs carved routes with metric 0 natively; no CIM modification needed."""
        return

    async def _enforce_adapter_metric(
        self,
        alias: Optional[Union[str, int]] = None,
        metric: int = 1,
    ) -> Optional[int]:
        """Pin the Wintun adapter metric after it has been detected.

        sing-box owns the adapter and its routes on Windows, but it does not
        expose a metric knob for the interface itself.  With a high metric,
        Windows can keep preferring the physical default route even though
        the /1 split routes are present.  ``Set-NetIPInterface`` sets the
        interface metric to a low value once the adapter appears and the
        read-back proves the value landed.
        """
        if isinstance(alias, int):
            metric = alias
            alias = None
        target_alias = str(alias or self._adapter_name()).strip()
        if sys.platform != "win32":
            logger.debug("TUN adapter metric pin is Windows-only; skipping")
            return None
        try:
            from perchvpn_windows import iphelper

            ifindex = None
            for row in iphelper.adapters_native():
                if str(row.get("Name") or "") == target_alias:
                    ifindex = int(row.get("InterfaceIndex") or 0)
                    break
            if ifindex and iphelper.set_interface_metric_native(ifindex, 2, metric):
                after = iphelper.interface_entry_native(ifindex, 2)
                if after is not None and after.get("InterfaceMetric") == metric:
                    logger.info(
                        "TUN adapter metric %d pinned natively on %s (ifIndex %d)",
                        metric,
                        target_alias,
                        ifindex,
                    )
                    return metric
        except Exception as exc:  # noqa: BLE001 - native pin is best-effort
            logger.debug("native TUN adapter metric pin failed: %s", exc)
        quoted = tun_status._ps_quote(target_alias)
        script = (
            "$ErrorActionPreference='Stop';"
            "Set-NetIPInterface -InterfaceAlias %s -AddressFamily IPv4 "
            "-InterfaceMetric %d -ErrorAction Stop | Out-Null;"
            "$after = Get-NetIPInterface -InterfaceAlias %s -AddressFamily IPv4 "
            "-ErrorAction Stop | Select-Object -First 1;"
            "if (-not $after) { throw 'adapter vanished after metric change' };"
            "if ([int]$after.InterfaceMetric -ne %d) { "
            "throw ('adapter metric not applied: {0}' -f $after.InterfaceMetric) };"
            "Write-Output ('metric=%d' -f $after.InterfaceMetric)"
        ) % (quoted, metric, quoted, metric, metric)
        try:
            raw = await asyncio.to_thread(_run_ps_write, script)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - metric is best-effort evidence
            logger.warning("TUN adapter metric pin failed: %s", exc)
            return None
        text = str(raw or "").strip()
        try:
            actual = int(text.split("=", 1)[1])
        except (IndexError, ValueError):
            actual = None
        if actual != metric:
            logger.error(
                "TUN adapter metric read-back failed: expected %d, got %r",
                metric,
                raw,
            )
            return None
        logger.info("TUN adapter metric pinned to %d on %s", metric, target_alias)
        return actual

    async def reconcile(self) -> str:
        """Collect OS evidence and update the honest readiness state.

        The adapter metric is pinned whenever a TUN adapter is detected, and
        the rest of the capture is read-only: adapter/address/route evidence
        plus a direct (unproxied) egress measurement. Routes are still owned
        by sing-box's ``auto_route``.
        """
        if not self.enabled:
            self._state = tun_status.STATE_DISABLED
            self._state_detail = "TUN is not enabled; only SOCKS5 clients are tunnelled."
            return self._state
        configured = self._configured
        if not configured:
            try:
                self._resolve_executable()
                configured = True
            except (ValueError, RuntimeError):
                configured = False
        self._configured = configured

        process_alive = (
            self._process is not None
            and getattr(self._process, "returncode", None) is None
        )
        evidence = None
        now = time.monotonic()
        if self.enabled and configured and self.is_elevated() and process_alive:
            # Start from the cached evidence; it is only replaced by a new
            # full capture (or dropped when the sidecar is not usable).
            evidence = self._evidence
            full_due = evidence is not None and (
                (now - self._last_full_evidence) >= self._full_evidence_interval()
            )
            presence = self._last_presence
            if evidence is None and presence is None:
                # Pre-adapter (sing-box is still creating the Wintun
                # interface): every 3 s tick must not pay a full PowerShell
                # capture. The cheap presence check decides whether a full
                # capture can find anything at all; the first capture runs
                # on the same tick the adapter is first seen, so spawn ->
                # metric pin gains all the skipped full captures.
                presence = await tun_status.probe_adapter_presence(
                    self._adapter_name()
                )
                self._last_presence_probe = now
                if presence is not None:
                    self._last_presence = presence
            elif not full_due and (
                (now - self._last_presence_probe) >= self._presence_probe_interval()
            ):
                self._last_presence_probe = now
                presence = await tun_status.probe_adapter_presence(
                    self._adapter_name()
                )
                if presence is not None:
                    self._last_presence = presence
            # Full evidence runs when due, when the (cheap) presence check
            # says the adapter appeared, or when the presence check was
            # inconclusive (non-Windows, invalid name, probe failure).  While
            # presence is False the cached evidence stays valid until the
            # next full capture, so normal runtime never captures on every
            # tick.
            spawn_elapsed = (
                now - self._spawned_at if self._spawned_at is not None else 0.0
            )
            retry_anchor = max(
                self._last_full_evidence, self._spawned_at or 0.0
            )
            force_due = (
                evidence is None
                and spawn_elapsed >= _EVIDENCE_RETRY_SECONDS
                and (now - retry_anchor) >= _EVIDENCE_RETRY_SECONDS
            )
            if full_due or presence is not False or force_due:
                evidence = await tun_status.probe_adapter(self._adapter_name())
                self._last_full_evidence = time.monotonic()
                if (
                    force_due
                    and evidence.present is False
                    and not self._evidence_missing_logged
                ):
                    self._evidence_missing_logged = True
                    logger.warning(
                        "TUN adapter evidence still absent %.1fs after sidecar "
                        "spawn; readiness cannot progress (%s)",
                        spawn_elapsed,
                        evidence.error or "adapter not reported by the OS",
                    )
        self._evidence = evidence
        if evidence is not None and evidence.present and not self._metric_pinned:
            alias = self._adapter_name()
            async with self._pin_lock:
                if not self._metric_pinned:
                    try:
                        await self._enforce_adapter_metric(alias)
                        await self._enforce_split_route_metrics(alias)
                    finally:
                        self._metric_pinned = True
                        self._pinned_at = time.monotonic()
                        if self._spawned_at is not None:
                            logger.info(
                                "TUN metric pin completed %.2fs after sidecar spawn",
                                self._pinned_at - self._spawned_at,
                            )

        if (
            evidence is not None
            and evidence.up
            and evidence.has_ipv4
            and process_alive
        ):
            # The egress probe and stall fast-fail also run while
            # default-route coverage is unconfirmed (adapter_ready):
            # observed egress is stronger evidence than the coverage
            # heuristic, and a genuinely black-holed tunnel must reach the
            # 20 s degraded fast-fail even if the route table never looks
            # right to the classifier.
            now = time.monotonic()
            egress_ok = bool(self._egress and self._egress.get("ok"))
            if (
                not egress_ok
                or (now - self._last_egress_check) >= self._egress_interval
            ):
                # Settle at 250 ms cadence and stop on the first successful
                # IP-literal TCP probe; a failed attempt must not wait for the
                # full 20 s background interval before the UI can go connected.
                fresh = await tun_status.wait_for_system_egress(
                    timeout=1.0
                )
                # The fast TCP verdict carries no address. Keep the last
                # settled identity so a TCP-only probe cannot erase the
                # leak/exit verdict (or the exit IP shown in the GUI).
                cached_v4 = self._egress_identity.get("ipv4") or {}
                fresh_v4 = fresh.get("ipv4") or {}
                if (
                    fresh.get("ok")
                    and not fresh_v4.get("ip")
                    and cached_v4.get("ip")
                ):
                    fresh = dict(fresh)
                    fresh["ipv4"] = dict(
                        fresh_v4,
                        ip=cached_v4.get("ip"),
                        country=cached_v4.get("country", ""),
                        source=cached_v4.get("source") or "identity",
                    )
                self._egress = fresh
                self._last_egress_check = now
            await self._track_egress_stall(time.monotonic())

            if self._egress and self._egress.get("ok"):
                now_ident = time.monotonic()
                identity_ip = str(
                    (self._egress_identity.get("ipv4") or {}).get("ip") or ""
                )
                needs_identity = (
                    not identity_ip
                    or self._state != tun_status.STATE_TRAFFIC_VERIFIED
                )
                can_probe = (
                    not self._identity_attempted
                    or now_ident >= self._identity_retry_at
                )
                if (
                    needs_identity
                    and can_probe
                    and (
                        self._identity_task is None
                        or self._identity_task.done()
                    )
                ):
                    self._identity_attempted = True
                    self._identity_task = asyncio.create_task(
                        self._probe_identity_background()
                    )

        return self._update_classification(configured=configured, process_alive=process_alive)

    def _refresh_stall_tracking(self, now: float) -> None:
        """Record the latest egress error and clear stall state on recovery."""
        if self._egress and self._egress.get("ok"):
            if self._stall_degraded:
                logger.info(
                    "TUN egress recovered after stall; leaving degraded state"
                )
            self._stall_degraded = False
            self._stall_hint = ""
            self._last_egress_error = ""
            return
        error = str((self._egress or {}).get("error") or "")
        if error:
            self._last_egress_error = error

    async def _track_egress_stall(self, now: float) -> None:
        """Fast-fail a post-pin tunnel that never carried any traffic.

        After the adapter metric is pinned, more than
        ``_EGRESS_STALL_DEGRADED_SECONDS`` of continuously failed egress
        probes means the tunnel is black-holed (most often a competing
        tunnel owns the default route).  Degrade honestly with the probe
        error plus a competing-default-route hint, and treat the settled
        state as steady so the cadence backs off instead of polling every
        3 s forever.
        """
        self._refresh_stall_tracking(now)
        if self._stall_degraded:
            return
        if self._pinned_at is None:
            return
        if self._egress and self._egress.get("ok"):
            return
        if (now - self._pinned_at) <= _EGRESS_STALL_DEGRADED_SECONDS:
            return
        self._stall_degraded = True
        if self._competing_hint:
            foreign: Optional[str] = self._competing_hint
        else:
            foreign = await tun_status.detect_foreign_default_tunnel(
                self._adapter_name(), timeout=_EGRESS_STALL_PROBE_TIMEOUT
            )
        self._stall_hint = (
            "; another adapter (%s) holds the IPv4 default route; disconnect "
            "it or restart PerchVPN" % foreign
            if foreign
            else ""
        )
        logger.warning(
            "no traffic through TUN for %.0fs after metric pin "
            "(probe: %s)%s",
            now - self._pinned_at,
            self._last_egress_error or "unknown error",
            self._stall_hint,
        )

    async def _probe_identity_background(self) -> None:
        """Best-effort exit identity, settled and retried off the hot path.

        Identity is cosmetic for readiness (the TCP fast path already
        proves connectivity), but it is also the leak check. Firing it
        immediately after the metric pin raced the route install and saw
        the physical exit, flipping a verified tunnel back to
        ``tunnel_operational`` for the whole 20 s transition interval.
        Settle first, then retry at the verifying cadence so a transient
        mismatch self-heals in ~1 s instead of stalling the GUI.
        """
        try:
            for attempt in range(_IDENTITY_MAX_ATTEMPTS):
                await asyncio.sleep(
                    _IDENTITY_SETTLE_SECONDS
                    if attempt == 0
                    else _IDENTITY_RETRY_SECONDS
                )
                if not (
                    self._process is not None
                    and getattr(self._process, "returncode", None) is None
                ):
                    return
                identity = await tun_status.probe_system_egress_identity(
                    timeout=2.0
                )
                if not (
                    identity.get("ok")
                    and (
                        (identity.get("ipv4") or {}).get("ok")
                        or (identity.get("ipv6") or {}).get("ok")
                    )
                ):
                    continue
                self._egress_identity = identity
                # Publish both observed families: the expected exit may be
                # IPv6 while only the IPv4 probe used to be kept, which made
                # the comparison permanently inconclusive.
                previous = self._egress or {}
                merged = dict(previous)
                for family in ("ipv4", "ipv6"):
                    observed = identity.get(family) or {}
                    if observed.get("ok"):
                        merged[family] = observed
                    elif family not in merged:
                        merged[family] = observed
                self._egress = merged
                self._update_classification()
                if self._state == tun_status.STATE_TRAFFIC_VERIFIED:
                    self._identity_retry_at = float("inf")
                    return
            self._identity_retry_at = (
                time.monotonic() + _IDENTITY_RETRY_BACKOFF_SECONDS
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.debug("background TUN identity probe failed: %s", exc)
            self._identity_retry_at = (
                time.monotonic() + _IDENTITY_RETRY_BACKOFF_SECONDS
            )

    def _update_classification(
        self,
        configured: Optional[bool] = None,
        process_alive: Optional[bool] = None,
    ) -> str:
        if configured is None:
            configured = self._configured
        if process_alive is None:
            process_alive = (
                self._process is not None
                and getattr(self._process, "returncode", None) is None
            )
        if self._evidence is not None:
            # Keep the evidence's exclusion context in sync with the config
            # actually built: route_exclude_address carves /32 holes into the
            # decomposed default-route table and the coverage classifier must
            # not count those sentinels as missing routes.
            self._evidence.excluded_networks = self._excluded_networks
        result = tun_status.classify(
            enabled=self.enabled,
            opted_in=self.opt_in,
            configured=configured,
            elevated=self.is_elevated(),
            process_alive=process_alive,
            spawn_failed=self._spawn_failed,
            recovery_required=self._recovery_state == RECOVERY_UNVERIFIED,
            evidence=self._evidence,
            egress=self._egress,
            expected_exit_ip=self._expected_exit_ip,
            expected_country=self._expected_country,
            baseline=self._baseline,
        )
        was_stable = self._steady_state_now()
        previous_state = self._state
        self._state = result["state"]
        self._state_detail = result["detail"]
        # Steady verified state relaxes the direct egress probe cadence: the
        # probes are real network round-trips and must not keep the API
        # process busy once traffic_verified holds.
        if self._state == tun_status.STATE_TRAFFIC_VERIFIED:
            self._egress_interval = _EGRESS_INTERVAL_STEADY_SECONDS
        elif self._state in (
            tun_status.STATE_TUNNEL_OPERATIONAL,
            tun_status.STATE_ROUTES_CONFIGURED,
            tun_status.STATE_ADAPTER_READY,
        ):
            # The tunnel is up but not verified: probe at the reconcile
            # cadence, never the 20 s transition interval.
            self._egress_interval = _EGRESS_INTERVAL_VERIFYING_SECONDS
        else:
            self._egress_interval = _EGRESS_INTERVAL_TRANSITION_SECONDS
        # A settled post-pin egress stall outranks transitional "connecting"
        # states: the UI must leave "connecting" with an honest reason.
        if self._stall_degraded and self._state in (
            tun_status.STATE_STARTING,
            tun_status.STATE_ADAPTER_READY,
            tun_status.STATE_ROUTES_CONFIGURED,
            tun_status.STATE_TUNNEL_OPERATIONAL,
        ):
            self._state = tun_status.STATE_DEGRADED
            self._state_detail = "no traffic through TUN (probe: %s)%s" % (
                self._last_egress_error or "unknown error",
                self._stall_hint,
            )
        # A competing VPN tunnel detected at preflight is surfaced
        # immediately in every transitional state; it clears once egress
        # verification proves the two tunnels coexist fine.
        if (
            self._competing_hint
            and not (self._egress and self._egress.get("ok"))
            and self._state in (
                tun_status.STATE_STARTING,
                tun_status.STATE_ADAPTER_READY,
                tun_status.STATE_ROUTES_CONFIGURED,
                tun_status.STATE_TUNNEL_OPERATIONAL,
            )
        ):
            self._state_detail = (
                "Another VPN tunnel (%s) is active; disconnect it before "
                "starting PerchVPN TUN" % self._competing_hint
            )
        elif self._competing_hint and self._egress and self._egress.get("ok"):
            self._competing_hint = ""
        if self._state != previous_state:
            logger.info(
                "TUN state transition: %s -> %s (%s)",
                previous_state,
                self._state,
                self._state_detail,
            )
            listener = self._state_listener
            if listener is not None:
                try:
                    listener(self._state, self._state_detail)
                except Exception:  # noqa: BLE001 - a listener must not break readiness
                    logger.debug("TUN state listener failed", exc_info=True)
        if was_stable and not self._steady_state_now():
            # A verified-steady tunnel regressed (adapter vanished, egress
            # changed, sidecar died): re-reconcile immediately instead of
            # waiting out the backed-off steady cadence.
            self._wake_reconcile()
        return self._state

    def _steady_state_now(self) -> bool:
        # A settled post-pin stall counts as steady for cadence purposes: the
        # failure is static and the 30 s poll is the right response, while
        # the wake signal still fires on any further real regression.
        return (
            tun_status.is_stable_reconcile_state(self._state)
            or self._stall_degraded
        )

    def _reconcile_interval_for_state(self) -> float:
        """Fast cadence while transitioning; backed-off once verified-steady."""
        if self._steady_state_now():
            return _RECONCILE_INTERVAL_STEADY_SECONDS
        return self._reconcile_interval

    def _full_evidence_interval(self) -> float:
        if self._steady_state_now():
            return _FULL_EVIDENCE_INTERVAL_STEADY_SECONDS
        return _FULL_EVIDENCE_INTERVAL_SECONDS

    def _presence_probe_interval(self) -> float:
        if self._steady_state_now():
            return _PRESENCE_PROBE_INTERVAL_SECONDS
        return _PRESENCE_PROBE_INTERVAL_STARTING_SECONDS

    def _wake_reconcile(self) -> None:
        """Cut the reconcile sleep short after a state regression or exit."""
        if self._reconcile_wake is not None:
            self._reconcile_wake.set()

    def _start_reconcile_loop(self) -> None:
        if sys.platform != "win32":
            return
        if self._reconcile_task is not None and not self._reconcile_task.done():
            return
        if self._reconcile_wake is None:
            self._reconcile_wake = asyncio.Event()
        self._reconcile_task = asyncio.ensure_future(self._reconcile_loop())

    async def _reconcile_loop(self) -> None:
        try:
            while True:
                try:
                    await self.reconcile()
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001 - never kill the loop
                    logger.warning("TUN readiness probe failed: %s", exc)
                interval = self._reconcile_interval_for_state()
                wake = self._reconcile_wake
                if wake is None:
                    await asyncio.sleep(interval)
                    continue
                # A regression or sidecar exit set between ticks cuts the sleep
                # short; the wake is consumed after firing so a stale set does
                # not spin the loop.
                try:
                    await asyncio.wait_for(wake.wait(), timeout=interval)
                except asyncio.TimeoutError:
                    pass
                wake.clear()
        except asyncio.CancelledError:
            raise
        finally:
            self._reconcile_task = None

    async def _stop_reconcile_loop(self) -> None:
        task = self._reconcile_task
        self._reconcile_task = None
        if task is None or task.done():
            return
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass

    def _get_recovery_lock(self) -> asyncio.Lock:
        lock = self._recovery_lock
        if lock is None:
            lock = asyncio.Lock()
            self._recovery_lock = lock
        return lock

    def _adapter_name(self) -> str:
        # Keep accepting the old --tun flag for recovery-gate compatibility,
        # but the sing-box config uses interface_name from the constructor.
        args = list(self.extra_args)
        for index, arg in enumerate(args):
            if arg == "--tun" and index + 1 < len(args):
                value = str(args[index + 1]).strip()
                if value:
                    return value
            if arg.startswith("--tun="):
                value = arg.split("=", 1)[1].strip()
                if value:
                    return value
        return self.adapter_name or DEFAULT_ADAPTER_NAME

    def is_elevated(self) -> bool:
        try:
            return bool(self._is_elevated_fn())
        except Exception:
            return False

    def _last_stderr_line(self) -> str:
        """Most recent non-empty sidecar stderr line for failure details."""
        for line in reversed(self.stderr):
            text = str(line or "").strip()
            if text:
                return text[:500]
        return ""

    def _resolve_executable(self) -> str:
        if not self.executable_path:
            raise ValueError("tun_executable_path is not configured")
        p = Path(self.executable_path)
        if p.is_file():
            resolved_path = p
        else:
            resolved = shutil.which(self.executable_path)
            if not resolved:
                raise ValueError("sing-box executable not found: %r" % self.executable_path)
            resolved_path = Path(resolved)
        if sys.platform == "win32":
            dll = resolved_path.parent / "wintun.dll"
            if not dll.is_file():
                raise ValueError("wintun.dll not found alongside sing-box.exe: %s" % dll)
        return str(resolved_path)

    _LEGACY_TUN2PROXY_FLAGS = (
        "--setup",
        "--tun",
        "--proxy",
        "--dns",
        "--mtu",
        "--bypass",
        "--ipv6-enabled",
    )

    def _singbox_extra_args(self) -> list[str]:
        """Drop tun2proxy-only flags so an old config cannot poison argv."""
        kept: list[str] = []
        skip_next = False
        for arg in self.extra_args:
            text = str(arg)
            if skip_next:
                skip_next = False
                continue
            if text in self._LEGACY_TUN2PROXY_FLAGS:
                skip_next = True
                continue
            if any(text.startswith(flag + "=") for flag in self._LEGACY_TUN2PROXY_FLAGS):
                continue
            kept.append(text)
        return kept

    def build_command(self) -> list[str]:
        if not self.enabled:
            raise RuntimeError("TUN frontend is disabled")
        if not self.opt_in:
            raise RuntimeError("TUN frontend requires explicit opt-in")
        if not self.is_elevated():
            raise RuntimeError("TUN frontend requires an elevated process")
        exe = self._resolve_executable()
        # Persist the sidecar's own log next to the generated config: WFP,
        # route and forwarding errors from sing-box are otherwise invisible
        # once the process exits (stdout/stderr only live in bounded deques).
        sidecar_log_path = str(get_config_dir() / "sing-box.log")
        config = singbox_config.build_config(
            proxy_host=self.proxy_host,
            proxy_port=self.proxy_port,
            adapter=self._adapter_name(),
            mtu=self.mtu,
            bypass=self.bypass,
            bypass_processes=self.bypass_processes,
            log_output=sidecar_log_path,
            mixed_port=singbox_config.available_mixed_port(),
            ip_mode=self.ip_mode,
            bypass_local_network=self.bypass_local_network,
            local_proxy_users=self.local_proxy_users,
            kill_switch=self.kill_switch,
            utls_fingerprint=self.utls_fingerprint,
            tunnel_dns_provider=self.tunnel_dns_provider,
            custom_tunnel_doh_url=self.custom_tunnel_doh_url,
            auto_detect_interface=self.auto_detect_interface,
        )
        config_path = singbox_config.write_config(self.config_path, config)
        logger.info("wrote sing-box config before launch: %s", config_path)
        cmd = [exe]
        cmd.extend(self._singbox_extra_args())
        cmd.extend(["run", "-c", str(config_path)])
        return cmd

    async def start(self) -> None:
        if self._process is not None and getattr(self._process, "returncode", None) is None:
            logger.debug("TUN sidecar already running; not starting a duplicate")
            if self.enabled:
                self._status = "running"
            return
        if not self.enabled:
            self._status = "disabled"
            self._state = tun_status.STATE_DISABLED
            self._state_detail = "TUN is not enabled; only SOCKS5 clients are tunnelled."
            logger.info("TUN frontend disabled by default; not starting sidecar")
            return
        if not self.opt_in:
            self._status = "not_opted_in"
            self._state = tun_status.STATE_NOT_OPTED_IN
            self._state_detail = "TUN requires explicit opt-in (tun_opt_in)."
            logger.warning("TUN frontend requires explicit opt-in; not starting")
            return
        if not self.is_elevated():
            self._status = "not_elevated"
            self._state = tun_status.STATE_NOT_ELEVATED
            self._state_detail = (
                "Administrator privileges are required to create the Wintun "
                "adapter and routes."
            )
            logger.warning("TUN frontend requires an elevated process; not starting")
            return
        try:
            resolved_exe = self._resolve_executable()
        except (ValueError, RuntimeError) as exc:
            self._status = "not_configured"
            self._state = tun_status.STATE_NOT_CONFIGURED
            self._state_detail = "sing-box.exe / wintun.dll not found: %s" % exc
            logger.error("TUN frontend not configured: %s", exc)
            return
        # Detect a competing VPN tunnel concurrently with the recovery gate:
        # two TUNs claiming 0.0.0.0/0 can collide in WFP, so the conflict is
        # surfaced immediately (log + state detail) rather than discovered
        # after a stall.  Coexistence is still allowed — the 12:19 run
        # routed fine alongside a foreign singbox_tun — but the user gets
        # the actionable message up front, and the post-pin stall fast-fail
        # degrades with the same hint if the collision does black-hole.
        competing_task = asyncio.ensure_future(
            tun_status.detect_competing_tunnel(self._adapter_name(), timeout=4.0)
        )
        # Stale-Wintun cleanup runs CONCURRENTLY with the recovery gate: it
        # only removes non-present Wintun PnP nodes (decided against the
        # live Get-NetAdapter list, never a live foreign adapter), so it is
        # independent of the gate's read-only capture and its PS spawn used
        # to serialize 1-2 s behind the gate on every start. (Non-Windows
        # hosts no-op inside the helper.)
        cleanup_task = asyncio.ensure_future(self._cleanup_stale_wintun())
        # Fail closed before spawning anything if recovery cannot be proven
        # clean.  The gate's read-only PowerShell work (baseline snapshot,
        # drift audit, unverified-latch verification) runs in a worker thread
        # and BEFORE the config write: it used to run synchronously on the
        # event loop between the config write and the spawn, freezing
        # /api/status for ~15 s (six serialized PowerShell spawns) so the
        # UI abandoned the start request while Wintun initialized.
        self._spawn_confirmed = False
        gate_started = time.monotonic()
        last_recovery_exc = None
        for attempt in range(3):
            try:
                self._recovery_run = await asyncio.to_thread(
                    self._recovery_gate.pre_start,
                    resolved_exe,
                    self._adapter_name(),
                    operator_trial=True,
                )
                last_recovery_exc = None
                break
            except RecoveryUnverified as exc:
                last_recovery_exc = exc
                message = str(exc).lower()
                if attempt == 0 and "unverified" in message:
                    # A previous stop that could not prove teardown leaves an
                    # unverified latch.  If its recorded PID is dead and the
                    # adapter is gone, reconcile (restore baseline) and retry
                    # instead of blocking forever.
                    try:
                        outcome = await asyncio.to_thread(
                            self._recovery_gate.reconcile_stale_ownership
                        )
                    except Exception:  # noqa: BLE001
                        outcome = RECOVERY_UNVERIFIED
                    if outcome == CLEAN:
                        continue
                if attempt < 2 and "adapter" in message:
                    await asyncio.sleep(0.5)
                    continue
                break
            except Exception as exc:  # noqa: BLE001
                last_recovery_exc = exc
                break
        # Consume the concurrent preflight detection before any fail-closed
        # return so the task is never orphaned mid-start.
        try:
            competing = await competing_task
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - preflight detection is best-effort
            competing = None
        if competing:
            self._competing_hint = str(competing)
            logger.warning(
                "Another VPN tunnel (%s) is active; disconnect it before "
                "starting PerchVPN TUN",
                competing,
            )
        # Consume the concurrent stale-Wintun cleanup before any fail-closed
        # return so the task is never orphaned mid-start.
        cleanup_exc: Optional[Exception] = None
        if cleanup_task is not None:
            try:
                await cleanup_task
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                cleanup_exc = exc
        logger.info(
            "TUN pre-start gate finished in %.2fs (competing=%s, cleanup=%s)",
            time.monotonic() - gate_started,
            "yes" if competing else "no",
            "failed" if cleanup_exc is not None else "ok",
        )
        if last_recovery_exc is not None:
            self._recovery_run = None
            self._recovery_state = RECOVERY_UNVERIFIED
            self._status = RECOVERY_UNVERIFIED
            self._state = tun_status.STATE_RECOVERY_REQUIRED
            self._state_detail = "Previous TUN ownership is unverified: %s" % last_recovery_exc
            logger.error("TUN recovery gate failed closed: %s", last_recovery_exc)
            return
        if cleanup_exc is not None:
            # A killed sing-box can leave a non-present Wintun PnP node
            # behind; a failed cleanup must fail closed exactly as when it
            # ran serialized after the gate.
            logger.error("stale Wintun cleanup failed: %s", cleanup_exc)
            self._spawn_failed = True
            self._status = "failed"
            self._state = tun_status.STATE_FAILED
            self._state_detail = "stale Wintun cleanup failed: %s" % cleanup_exc
            self._recovery_gate.clear_run(self._recovery_run)
            self._recovery_run = None
            return

        self._metric_pinned = False
        self._pinned_at = None
        self._spawned_at = None
        self._stall_degraded = False
        self._stall_hint = ""
        self._last_egress_error = ""
        self._identity_attempted = False
        self._identity_retry_at = 0.0
        self._egress_identity = {}
        self._last_full_evidence = 0.0
        self._last_presence = None
        self._last_presence_probe = 0.0
        self._evidence_missing_logged = False

        logger.info("Starting TUN sidecar (proxy=%s:%s)", self.proxy_host, self.proxy_port)
        try:
            cmd = self.build_command()
            self._configured = True
        except (ValueError, RuntimeError) as exc:
            self._status = "not_configured"
            self._state = tun_status.STATE_NOT_CONFIGURED
            self._state_detail = "sing-box.exe / wintun.dll not found: %s" % exc
            logger.error("TUN frontend not configured: %s", exc)
            self._recovery_gate.clear_run(self._recovery_run)
            self._recovery_run = None
            return
        self._stopping = False
        self.stdout.clear()
        self.stderr.clear()
        spawn_kwargs = {}
        if sys.platform == "win32":
            # Keep the sidecar's console hidden; its output is piped and not
            # routed via the Windows Console API, so a hidden window cannot
            # break the graceful stop path.
            spawn_kwargs.update(
                hidden_process_kwargs(new_process_group=bool(self._graceful_stop))
            )
        elif self._graceful_stop:
            spawn_kwargs["start_new_session"] = True
        try:
            self._process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                **spawn_kwargs,
            )
        except (OSError, FileNotFoundError) as exc:
            self._status = "failed"
            self._spawn_failed = True
            self._state = tun_status.STATE_FAILED
            self._state_detail = "sing-box failed to start: %s" % exc
            logger.error("TUN sidecar failed to start: %s", exc)
            self._process = None
            self._recovery_gate.clear_run(self._recovery_run)
            self._recovery_run = None
            return

        self._spawn_confirmed = True
        # Spawn -> metric-pin wall-clock anchor for the startup-latency log.
        self._spawned_at = time.monotonic()

        # Record PID + creation time so a later run can distinguish our child
        # from a reused PID.  If identity cannot be proven, stop the child we
        # just started (via its handle, never by PID alone) and fail closed.
        try:
            create_time = self._recovery_gate.creation_time(self._process.pid)
            self._recovery_gate.mark_running(
                self._recovery_run, self._process.pid, create_time
            )
        except RecoveryUnverified as exc:
            logger.error(
                "TUN recovery gate could not record child identity: %s", exc
            )
            await self._terminate_process(self._process)
            self._process = None
            self._status = RECOVERY_UNVERIFIED
            self._recovery_state = RECOVERY_UNVERIFIED
            await self._verify_recovery()
            return
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "TUN recovery gate error while recording child identity: %s", exc
            )
            await self._terminate_process(self._process)
            self._process = None
            self._status = RECOVERY_UNVERIFIED
            self._recovery_state = RECOVERY_UNVERIFIED
            await self._verify_recovery()
            return

        self._recovery_state = CLEAN
        self._status = "running"
        self._state = tun_status.STATE_STARTING
        self._state_detail = "sing-box started; awaiting adapter/route evidence."
        self._monitor_task = asyncio.ensure_future(self._monitor())
        self._start_reconcile_loop()
        try:
            await asyncio.sleep(_STARTUP_GRACE_SECONDS)
        except asyncio.CancelledError:
            raise
        if self._process is not None and self._process.returncode is not None:
            stderr = self._last_stderr_line()
            self._status = "failed"
            self._state = tun_status.STATE_FAILED
            self._state_detail = "sing-box exited during startup (code=%s)%s" % (
                self._process.returncode,
                (": " + stderr) if stderr else "",
            )
            logger.error(
                "TUN sidecar exited during startup (code=%s): %s",
                self._process.returncode,
                stderr or "(no stderr)",
            )
            await self._verify_recovery()

    _PROC_TERM_WAIT_SECONDS = 5.0
    _PROC_POLL_ATTEMPTS = 10
    _PROC_POLL_STEP_SECONDS = 0.1

    async def _terminate_process(self, proc) -> bool:
        if proc is None or getattr(proc, "returncode", None) is not None:
            return True
        try:
            proc.terminate()
        except ProcessLookupError:
            return True
        except OSError as exc:
            logger.error("TUN sidecar terminate() failed: %r", exc)
            return False
        try:
            await asyncio.wait_for(
                proc.wait(), timeout=self._PROC_TERM_WAIT_SECONDS
            )
            return True
        except asyncio.TimeoutError:
            logger.error(
                "TUN sidecar exit notification did not fire %.1fs after "
                "terminate(); escalating to kill()",
                self._PROC_TERM_WAIT_SECONDS,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.error("TUN sidecar wait failed after terminate(): %r", exc)
        try:
            proc.kill()
        except ProcessLookupError:
            return True
        except OSError as exc:
            logger.error("TUN sidecar kill() failed: %r", exc)
            return False
        try:
            await asyncio.wait_for(
                proc.wait(), timeout=self._PROC_TERM_WAIT_SECONDS
            )
            return True
        except asyncio.TimeoutError:
            pass
        except asyncio.CancelledError:
            raise
        except Exception:
            pass
        # The asyncio exit-notify chain may never deliver the returncode even
        # though the process is dead (observed live on Windows with
        # tun2proxy-bin.exe: adapter vanished and teardown verified clean,
        # yet the Process object still reported returncode=None).  Verify
        # death against the OS itself via the raw Popen poll before
        # declaring failure.
        for _ in range(self._PROC_POLL_ATTEMPTS):
            if getattr(proc, "returncode", None) is not None:
                return True
            if self._proc_raw_exit_code(proc) is not None:
                return True
            await asyncio.sleep(self._PROC_POLL_STEP_SECONDS)
        logger.error(
            "TUN sidecar did not exit after terminate()+kill() within the "
            "bounded window"
        )
        return False

    @staticmethod
    def _proc_raw_exit_code(proc):
        """OS-level exit status independent of the asyncio exit-notify chain.

        Uses the underlying Popen so ``stop()`` reflects real process death
        even when the proactor exit-notification never fires.
        """
        raw = getattr(getattr(proc, "_transport", None), "_proc", None)
        if raw is None:
            return None
        try:
            return raw.poll()
        except Exception:  # noqa: BLE001
            return None

    def _mark_stop_failed(self, reason: str) -> None:
        self._status = "stop_failed"
        self._recovery_state = RECOVERY_UNVERIFIED
        logger.error(
            "TUN shutdown incomplete: %s; no forced kill performed and "
            "ownership record left intact",
            reason,
        )
        # Never let a wedged stop leave a stale connected state published:
        # the app-level status may already say "disconnected", so claiming
        # traffic_verified here contradicts every later disconnect/restart.
        self._state = tun_status.STATE_FAILED
        self._state_detail = f"TUN shutdown incomplete: {reason}"

    def _send_graceful_shutdown(self, proc) -> None:
        """Send the runtime's supported console-control shutdown event.

        Windows delivery requires the sidecar to share a console and belong to
        a new process group.  A no-console GUI launch can raise OSError; that
        is reported by ``stop_graceful`` as ``stop_failed`` and must not fall
        back to terminate()/kill() or adapter deletion.
        """
        if proc is None or getattr(proc, "returncode", None) is not None:
            return
        if sys.platform == "win32":
            if _CTRL_BREAK_EVENT is None:
                raise RuntimeError("CTRL_BREAK_EVENT is unavailable")
            proc.send_signal(_CTRL_BREAK_EVENT)
            return
        import os

        os.killpg(os.getpgid(proc.pid), signal.SIGINT)

    async def _cancel_identity_probe(self) -> None:
        task = self._identity_task
        self._identity_task = None
        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass

    async def stop_graceful(
        self, timeout: float = _DEFAULT_GRACEFUL_STOP_TIMEOUT_SECONDS
    ) -> bool:
        """Ask the sidecar to exit without terminate()/kill().

        A bounded timeout is mandatory.  If the child does not exit, the
        ownership record is deliberately left intact and recovery is reported
        as unverified so an operator can inspect it.

        On Windows this requires a console shared with the sidecar.  A GUI
        process without a console can fail to deliver CTRL_BREAK_EVENT; the
        resulting ``stop_failed`` state is fail-closed and does not authorize
        forced termination or adapter deletion.
        """
        timeout = float(timeout)
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if not self._graceful_stop:
            raise RuntimeError("graceful shutdown requires graceful_stop=True")
        await self._stop_reconcile_loop()
        await self._cancel_identity_probe()
        self._metric_pinned = False
        self._pinned_at = None
        self._stall_degraded = False
        self._stall_hint = ""
        self._last_egress_error = ""
        self._competing_hint = ""

        if self._process is None and self._monitor_task is None:
            await self._verify_recovery()
            if self._recovery_state != RECOVERY_UNVERIFIED and self.enabled:
                self._status = "stopped"
            return self._recovery_state != RECOVERY_UNVERIFIED

        self._stopping = True
        proc = self._process
        if proc is not None and getattr(proc, "returncode", None) is None:
            try:
                self._send_graceful_shutdown(proc)
            except ProcessLookupError:
                pass
            except Exception as exc:  # noqa: BLE001
                self._mark_stop_failed(f"graceful shutdown signal failed: {exc}")
                return False

        if proc is not None:
            try:
                await asyncio.wait_for(
                    proc.wait(), timeout=min(timeout, _GRACEFUL_ESCALATION_SECONDS)
                )
            except asyncio.TimeoutError:
                # The sidecar owns the TUN adapter and its routes; draining a
                # full multiplex session pool measured ~5-6s live, which
                # dominates the whole disconnect.  TerminateProcess on the
                # owned child is instant and the recovery gate then restores
                # the baseline (verified in the sandbox: 0 ghosts, 0 route
                # delta, ~4s converge).  Escalate only while the child is
                # provably ours (mark_running identity); a termination
                # failure still falls back to the fail-closed stop_timeout.
                logger.info(
                    "TUN sidecar still running %.1fs after graceful shutdown; "
                    "escalating to terminate()",
                    _GRACEFUL_ESCALATION_SECONDS,
                )
                if not await self._terminate_process(proc):
                    self._status = "stop_timeout"
                    self._recovery_state = RECOVERY_UNVERIFIED
                    logger.error(
                        "TUN sidecar could not be terminated after %.1fs "
                        "graceful window; ownership record left intact",
                        _GRACEFUL_ESCALATION_SECONDS,
                    )
                    return False
            except asyncio.CancelledError:
                self._mark_stop_failed("graceful shutdown was cancelled")
                raise
            except Exception as exc:  # noqa: BLE001
                self._mark_stop_failed(f"sidecar wait failed after shutdown signal: {exc}")
                return False

        if self._monitor_task is not None:
            monitor_task = self._monitor_task
            monitor_task.cancel()
            try:
                await asyncio.wait({monitor_task})
            except asyncio.CancelledError:
                self._mark_stop_failed(
                    "graceful shutdown was cancelled while stopping the monitor"
                )
                raise
            except Exception:
                pass
            self._monitor_task = None
        self._process = None
        try:
            await self._verify_recovery()
        except asyncio.CancelledError:
            self._mark_stop_failed(
                "graceful shutdown was cancelled during recovery verification"
            )
            raise
        if self._recovery_state != RECOVERY_UNVERIFIED and self.enabled:
            self._status = "stopped"
        return self._recovery_state != RECOVERY_UNVERIFIED

    async def _cleanup_stale_wintun(self) -> None:
        if os.name != "nt":
            return
        await asyncio.to_thread(
            tun_helper.cleanup_stale_wintun_adapters,
            self._adapter_name(),
        )

    async def _verify_recovery(self) -> None:
        async with self._get_recovery_lock():
            run = self._recovery_run
            if run is None:
                # A previous verification already consumed the run.  Returning
                # with the stale UNVERIFIED verdict latched this frontend (and
                # therefore every later disconnect/restart) forever, so
                # re-derive the verdict from the durable ownership record.
                # Only when a run really was consumed: a start that never
                # spawned has nothing to reconcile and must stay failed closed.
                if (
                    self._recovery_run_consumed
                    and self._recovery_state == RECOVERY_UNVERIFIED
                ):
                    await self._reverify_without_run()
                return
            if not self._spawn_confirmed:
                self._recovery_run = None
                self._recovery_state = RECOVERY_UNVERIFIED
                self._status = RECOVERY_UNVERIFIED
                logger.error(
                    "TUN spawn completion could not be confirmed; the ownership "
                    "record stays ambiguous and operator action is required "
                    "(no adapter was deleted and no process was killed)"
                )
                return
            try:
                result = await self._recovery_gate.verify_after_exit(run)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                logger.error("TUN recovery verification error: %s", exc)
                result = RECOVERY_UNVERIFIED
            self._recovery_run = None
            self._spawn_confirmed = False
            self._recovery_run_consumed = True
            if result == RECOVERY_UNVERIFIED:
                self._recovery_state = RECOVERY_UNVERIFIED
                self._status = RECOVERY_UNVERIFIED
                logger.error(
                    "TUN adapter recovery is unverified; operator action required "
                    "(no adapter was deleted and no process was killed)"
                )
            else:
                # Baseline restoration (+ verification) happens inside
                # TunRecoveryGate.verify_after_exit, which only reports CLEAN
                # and clears the durable record after restoration succeeds.
                # The adapter is gone; remove the now-orphaned PnP node so the
                # next start cannot collide with it.  Windows can publish the
                # node slightly after Get-NetAdapter stops listing the adapter,
                # so give PnP a moment before the first scan.
                if os.name == "nt":
                    await asyncio.sleep(_POST_STOP_WINTUN_CLEANUP_DELAY_SECONDS)
                try:
                    await self._cleanup_stale_wintun()
                except Exception as exc:  # noqa: BLE001
                    logger.error("post-stop Wintun cleanup failed: %s", exc)
                    self._recovery_state = RECOVERY_UNVERIFIED
                    self._status = RECOVERY_UNVERIFIED
                else:
                    self._recovery_state = CLEAN

    async def _reverify_without_run(self) -> None:
        """Re-derive an UNVERIFIED verdict from the durable ownership record.

        ``TunRecoveryGate.reconcile_stale_ownership`` is the cold-start path
        for exactly this situation (no in-process run left).  It validates the
        recorded process/adapter, restores the persisted baseline when the
        owned adapter is gone, and clears the record only when that succeeds.
        """
        try:
            result = await asyncio.to_thread(
                self._recovery_gate.reconcile_stale_ownership
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - keep the verdict, retry later
            logger.warning("TUN recovery re-check failed: %s", exc)
            return
        if str(result) == CLEAN:
            self._recovery_state = CLEAN
            self._status = "stopped"
            logger.info("TUN recovery re-check converged: ownership record clean")
        else:
            self._recovery_state = RECOVERY_UNVERIFIED
            self._status = RECOVERY_UNVERIFIED
            logger.warning(
                "TUN recovery re-check still unverified (%s); ownership retained",
                result,
            )

    async def stop(self) -> bool:
        if self._graceful_stop:
            return await self.stop_graceful()
        await self._stop_reconcile_loop()
        await self._cancel_identity_probe()
        self._metric_pinned = False
        self._pinned_at = None
        self._stall_degraded = False
        self._stall_hint = ""
        self._last_egress_error = ""
        if self._process is None and self._monitor_task is None:
            await self._verify_recovery()
            if self._recovery_state != RECOVERY_UNVERIFIED and self.enabled:
                self._status = "stopped"
            return self._recovery_state != RECOVERY_UNVERIFIED
        self._stopping = True
        proc = self._process
        _t = time.monotonic()
        try:
            terminated = await self._terminate_process(proc)
        except asyncio.CancelledError:
            self._mark_stop_failed("shutdown was cancelled during process termination")
            raise
        except Exception as exc:  # noqa: BLE001
            self._mark_stop_failed(f"process termination failed: {exc}")
            raise
        logger.info(
            "TUN sidecar terminate completed in %.2fs (terminated=%s)",
            time.monotonic() - _t,
            terminated,
        )
        if not terminated:
            self._mark_stop_failed("process termination failed")
            return False
        if self._monitor_task is not None:
            monitor_task = self._monitor_task
            monitor_task.cancel()
            try:
                await asyncio.wait({monitor_task})
            except asyncio.CancelledError:
                self._mark_stop_failed(
                    "shutdown was cancelled while stopping the monitor"
                )
                raise
            except Exception:
                pass
            self._monitor_task = None
        self._process = None
        _t = time.monotonic()
        try:
            await self._verify_recovery()
        except asyncio.CancelledError:
            self._mark_stop_failed(
                "shutdown was cancelled during recovery verification"
            )
            raise
        logger.info(
            "TUN recovery verification completed in %.2fs (state=%s)",
            time.monotonic() - _t,
            self._recovery_state,
        )
        if self._recovery_state != RECOVERY_UNVERIFIED and self.enabled:
            self._status = "stopped"
        return self._recovery_state != RECOVERY_UNVERIFIED

    async def _monitor(self) -> None:
        proc = self._process
        if proc is None:
            return

        async def _drain(stream, sink) -> None:
            if stream is None:
                return
            try:
                async for raw in stream:
                    try:
                        marker = "...[truncated]"
                        if len(raw) > self._max_line_bytes:
                            budget = self._max_line_bytes - len(marker.encode("utf-8"))
                            if budget < 0:
                                budget = 0
                            data = raw[:budget]
                            text = data.decode("utf-8", errors="replace").rstrip("\n")
                            # Guarantee the final encoded size respects the bound.
                            while text and len((text + marker).encode("utf-8")) > self._max_line_bytes:
                                text = text[:-1]
                            if self._max_line_bytes >= len(marker.encode("utf-8")):
                                text = text + marker
                        else:
                            text = raw.decode("utf-8", errors="replace").rstrip("\n")
                        sink.append(text)
                    except Exception:
                        sink.append(repr(raw))
            except Exception:
                pass

        try:
            await asyncio.gather(
                _drain(proc.stdout, self.stdout),
                _drain(proc.stderr, self.stderr),
            )
        except Exception:
            pass
        try:
            await proc.wait()
        except Exception:
            pass
        if self._stopping:
            if self._status in ("stop_timeout", "stop_failed"):
                logger.error(
                    "TUN sidecar exited after graceful shutdown did not complete "
                    "(code=%s); reconciling ownership record without killing or deleting",
                    proc.returncode,
                )
                # Preserve stop_timeout/stop_failed as evidence; this only
                # reconciles the ownership record.
                await self._verify_recovery()
            return
        if self._status == "running":
            stderr = self._last_stderr_line()
            self._status = "failed"
            self._state = tun_status.STATE_FAILED
            self._state_detail = "sing-box exited unexpectedly (code=%s)%s" % (
                proc.returncode,
                (": " + stderr) if stderr else "",
            )
            logger.error(
                "TUN sidecar exited unexpectedly (code=%s): %s",
                proc.returncode,
                stderr or "(no stderr)",
            )
            # Do not let the backed-off steady cadence delay failure handling.
            self._wake_reconcile()
            await self._verify_recovery()
            if self.automatic_recovery and self._recovery_budget.try_acquire(
                time.monotonic()
            ):
                logger.warning(
                    "TUN sidecar exited unexpectedly (code=%s); automatic "
                    "recovery restart within budget",
                    proc.returncode,
                )
                try:
                    await self.start()
                except Exception as exc:  # noqa: BLE001
                    logger.error("automatic TUN recovery restart failed: %s", exc)
