"""Top-level orchestrator: owns the current Guardian proxy pass, the upstream
session pool, background renewal/quota-monitor loops, and the optional JSON
status file."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import random
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Awaitable, Callable, Dict, Iterable, List, Optional

from . import auth as auth_module
from . import guardian
from .exceptions import ProxyError, QuotaExceededError, TokenInvalidError
from .proxy.h3_session import H3ProxySession
from .proxy.http1_session import H1ProxySession
from .proxy.pool import ProxySession, SessionPool
from .proxy.session import H2ProxySession
from .proxy.transport_options import TransportOptions
from .proxy.upstream_proxy import UpstreamProxyConfig
from .proxystate import ProxyCandidate

if TYPE_CHECKING:
    from perchvpn_windows.metrics import TrafficMetrics

logger = logging.getLogger("perchvpn.controller")

PROXY_PASS_RENEW_LEAD_SECONDS = 120
PROXY_PASS_RETRY_DELAY_SECONDS = 30
PROXY_PASS_RENEW_TIMEOUT_SECONDS = 120
QUOTA_CHECK_INTERVAL_SECONDS = 15 * 60

# Bounded upstream candidate failover. Mirrors the Android client's initial
# dial budget (MAX_ALTERNATE_EDGES + 1 = 4 attempts) and its full-jitter
# backoff (base 2s, cap 8s). Attempts are bounded whether or not alternates
# exist; a single-candidate configuration still gets a few retries.
INITIAL_DIAL_MAX_ATTEMPTS = 4
INITIAL_DIAL_BACKOFF_BASE_SECONDS = 2.0
INITIAL_DIAL_BACKOFF_CAP_SECONDS = 8.0


def _initial_dial_backoff(attempt: int) -> float:
    """Full-jitter backoff for initial dial attempt ``attempt`` (1-based)."""
    upper = min(INITIAL_DIAL_BACKOFF_BASE_SECONDS * (1 << (max(attempt, 1) - 1)), INITIAL_DIAL_BACKOFF_CAP_SECONDS)
    return max(upper * random.random(), INITIAL_DIAL_BACKOFF_BASE_SECONDS / 4)


def _is_quic_timeout(exc: Exception) -> bool:
    """True when a pool start failure is the HTTP/3 QUIC handshake timing
    out (vs DNS/connect/HTTP-layer errors), the signature of a UDP path
    that is blocked or an edge that does not serve QUIC."""
    message = str(exc)
    return "QUIC handshake failed" in message and "TimeoutError" in message


@dataclass
class ControllerConfig:
    guardian_endpoint: str
    candidate: ProxyCandidate
    upstream_conns: int
    handshake_timeout: float
    max_conns: int = 256
    status_file: Optional[str] = None
    # Mirrors the original Go client's -h3 flag: use HTTP/3 (QUIC/UDP)
    # instead of HTTP/2 (TCP) for the upstream tunnel transport.
    use_http3: bool = False
    # Upstream proxy for H2 transport-level chaining (data-plane).
    # When enabled, H3 upstream proxy chaining is not supported and will
    # fail explicitly before connecting.
    upstream_proxy: Optional[UpstreamProxyConfig] = None
    # Optional custom edge address (host or host:port) used for the TCP/TLS
    # connection while preserving the original hostname for SNI/TLS.
    edge_host: Optional[str] = None
    edge_port: Optional[int] = None
    # Verified hostname -> address pins for this activation.  Unlike
    # ``edge_host``, which applies to every candidate, this is keyed by the
    # candidate hostname, so alternates keep dialing their own verified
    # address and a resolved pin is never reused for the wrong SNI.
    edge_hosts: Dict[str, str] = field(default_factory=dict)
    # Additional same-country edges to fail over to, best-effort, in order.
    # Never persisted as the user's saved primary selection.
    alternates: List[ProxyCandidate] = field(default_factory=list)
    # Physical-NIC source address to pin upstream dials to (None = OS default).
    source_bind_ip: Optional[str] = None
    # Verified address for the upstream proxy hostname. When set, the TCP
    # connection dials this literal address while SOCKS5/HTTP-CONNECT and
    # TLS keep the configured proxy hostname for authentication and SNI.
    upstream_proxy_host: Optional[str] = None
    # Physical interface index for the upstream-proxy dial (Windows
    # IP_UNICAST_IF); None = OS default routing.
    physical_interface: Optional[int] = None
    # Fail closed instead of letting the OS resolver pick an address for a
    # hostname-shaped upstream proxy (a fresh answer could leave the physical
    # underlay). Ignored for literal-IP proxy configurations.
    require_pinned_upstream: bool = False
    # Upstream v2.0.3 parity: transport selection and ClientHello options.
    transport_version: str = "h2"  # h1 | h2 | h3
    utls_fingerprint: str = "disabled"
    tls_fragment_mode: str = "disabled"
    tls_fragment_fallback_delay_ms: int = 300
    multiplex_streams: int = 8
    # When True, the controller never switches transports on its own: an
    # HTTP/1.1 close storm or an HTTP/3 QUIC timeout surfaces as an error
    # instead of a clean HTTP/2 fallback.
    transport_pinned: bool = False


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


class ProxyController:
    """Owns the Guardian proxy pass lifecycle and the upstream session pool."""

    def __init__(self, config: ControllerConfig, auth: auth_module.RuntimeAuth):
        self.config = config
        self.auth = auth
        self.proxy_pass: Optional[guardian.ProxyPassInfo] = None
        self.pool: Optional[SessionPool] = None
        self.accepting = False
        self._reason = "starting"
        self._tasks: List[asyncio.Task] = []
        self._stopped = asyncio.Event()
        self._started_at: Optional[float] = None
        self._metrics: Optional["TrafficMetrics"] = None
        # Ordered failover list: the selected candidate first, then same-country
        # alternates. Index advances on connection failure so repeated attempts
        # do not hammer one dead edge; alternates are never persisted.
        self._candidates: List[ProxyCandidate] = [config.candidate, *config.alternates]
        self._candidate_index = 0
        self._auth_lock = asyncio.Lock()
        # Effective transport: starts at the configured selection and can be
        # switched to HTTP/2 by a clean fallback (close storm / QUIC timeout)
        # unless the caller pinned the transport explicitly.
        self._effective_transport = config.transport_version
        self._effective_use_http3 = config.use_http3
        self._transport_fallback_in_progress = False
        # App hook: repoint the SOCKS5 frontend at a replacement pool.
        self.on_pool_replaced: Optional[Callable[[SessionPool], Awaitable[None]]] = None

    @property
    def current_candidate(self) -> ProxyCandidate:
        """The candidate the factory is currently dialing. Safe to read from
        the app for status/exit verification."""
        return self._candidates[self._candidate_index % len(self._candidates)]

    @property
    def status(self) -> str:
        """Human-readable controller status."""
        return self._reason

    @property
    def transport(self) -> str:
        """Upstream transport selected for this controller."""
        return {
            "h1": "http1",
            "h2": "http2",
            "h3": "http3",
        }.get(self._effective_transport, "http3" if self._effective_use_http3 else "http2")

    @property
    def uptime(self) -> float:
        """Seconds since controller startup."""
        return time.monotonic() - self._started_at if self._started_at else 0.0

    @property
    def metrics(self) -> Optional["TrafficMetrics"]:
        """Traffic metrics for the active controller, if initialized."""
        return self._metrics

    def apply_edge_pins(self, pins: Dict[str, str], blocked: Iterable[str] = ()) -> None:
        """Install verified per-hostname pins and drop unpinnable failover edges.

        A hostname that could not be resolved on the physical path must not
        stay dialable: the OS resolver could later resolve it into the tunnel.
        """
        self.config.edge_hosts.update(pins or {})
        blocked = {host for host in (blocked or ()) if host}
        if blocked:
            self.config.alternates = [
                entry
                for entry in self.config.alternates
                if entry.host not in blocked
            ]
            self._candidates = [
                entry for entry in self._candidates if entry.host not in blocked
            ]
            if not self._candidates:
                self._candidates = [self.config.candidate]
            if self.config.candidate not in self._candidates:
                self._candidates.insert(0, self.config.candidate)
            self._candidate_index %= len(self._candidates)

    def _rotate_candidate(self) -> None:
        # No await between read and write, so this is atomic on the event loop.
        self._candidate_index = (self._candidate_index + 1) % len(self._candidates)

    async def _connect_candidate(self, candidate: ProxyCandidate) -> ProxySession:
        # Reject H3 + upstream_proxy combination explicitly before connecting.
        if self.config.use_http3 and self.config.upstream_proxy is not None:
            raise ProxyError(
                "upstream proxy chaining is not supported over HTTP/3; disable --http3 or --upstream-proxy"
            )
        # Only a pinned address for THIS candidate's hostname may be dialed:
        # a post-activation DNS answer can never race the verified pin into
        # the tunnel, and a pin resolved for the primary is never reused for
        # an alternate (wrong SNI/address pair).
        self._check_upstream_proxy_pin()
        pinned = self.config.edge_hosts.get(candidate.host)
        edge_host = pinned or self.config.edge_host
        # A per-host pin belongs to ``candidate.port``; ``edge_port`` only
        # describes a custom edge host shared by every candidate.
        edge_port = None if pinned else self.config.edge_port
        options = TransportOptions.from_values(
            utls_fingerprint=self.config.utls_fingerprint,
            tls_fragment_mode=self.config.tls_fragment_mode,
            tls_fragment_fallback_delay_ms=self.config.tls_fragment_fallback_delay_ms,
            multiplex_streams=self.config.multiplex_streams,
        )
        # Fall back to the configured transport when attributes are unset
        # (tests construct controllers without __init__).
        effective_transport = getattr(self, "_effective_transport", None) or self.config.transport_version
        effective_http3 = getattr(self, "_effective_use_http3", None)
        if effective_http3 is None:
            effective_http3 = self.config.use_http3
        if effective_transport == "h1":
            session: ProxySession = H1ProxySession(
                candidate.host,
                candidate.port,
                self.proxy_pass.raw_token,
                upstream_proxy=self.config.upstream_proxy,
                edge_host=edge_host,
                edge_port=edge_port,
                source_bind_ip=self.config.source_bind_ip,
                upstream_proxy_host=self.config.upstream_proxy_host,
                physical_interface=self.config.physical_interface,
                options=options,
            )
        elif effective_http3:
            session: ProxySession = H3ProxySession(
                candidate.host,
                candidate.port,
                self.proxy_pass.raw_token,
                source_bind_ip=self.config.source_bind_ip,
                edge_host=edge_host,
            )
        else:
            session = H2ProxySession(
                candidate.host,
                candidate.port,
                self.proxy_pass.raw_token,
                upstream_proxy=self.config.upstream_proxy,
                edge_host=edge_host,
                edge_port=edge_port,
                source_bind_ip=self.config.source_bind_ip,
                upstream_proxy_host=self.config.upstream_proxy_host,
                physical_interface=self.config.physical_interface,
                options=options,
            )
        try:
            await session.connect(timeout=self.config.handshake_timeout)
        except BaseException:
            # Never leak a half-open session (read/keepalive tasks, socket).
            try:
                await session.close()
            except Exception:  # noqa: BLE001
                pass
            raise
        return session

    def _check_upstream_proxy_pin(self) -> None:
        """Never let the OS resolver choose the upstream-proxy address while
        the tunnel owns the default route: the proxy must be reached at a
        verified physical-underlay address (or a literal configured IP)."""
        proxy = self.config.upstream_proxy
        if proxy is None or not self.config.require_pinned_upstream:
            return
        if _is_ip_literal(proxy.host):
            return
        pin = self.config.upstream_proxy_host
        if not pin or not _is_ip_literal(pin):
            raise ProxyError(
                "upstream proxy hostname "
                f"{proxy.host!r} has no verified physical-underlay address pin; "
                "refusing to resolve it while the tunnel owns the default route"
            )

    async def _session_factory(self) -> ProxySession:
        """Build one upstream session on the current candidate. On failure an
        attempt that is still on the current candidate advances the index, so
        the next attempt (initial retry or a later client-driven reconnect)
        uses a different edge while a concurrent pool dial round rotates at most
        once. No sleeping here: this runs under the session pool's lock and must
        not block all clients."""
        candidate = self.current_candidate
        try:
            return await self._connect_candidate(candidate)
        except Exception as exc:
            logger.warning("upstream %s connection failed: %s", candidate.authority, exc)
            # Only an attempt that is still on the current candidate advances it.
            if self.current_candidate is candidate:
                self._rotate_candidate()
            raise

    async def start(
        self, initial_pass: Optional[guardian.ProxyPassInfo] = None
    ) -> SessionPool:
        """Start the pool and lifecycle tasks.

        ``initial_pass`` lets a country switch reuse the still-valid Guardian
        proxy pass instead of paying another Guardian round-trip. An expired
        or about-to-expire pass is ignored (never silently used), so the
        normal acquisition path still protects correctness.
        """
        if initial_pass is not None and self._pass_is_usable(initial_pass):
            self.proxy_pass = initial_pass
        else:
            await self._acquire_initial_pass()

        import time
        from perchvpn_windows.metrics import TrafficMetrics
        self._started_at = time.monotonic()
        self._metrics = TrafficMetrics()

        logger.info("upstream transport=%s", self.transport)

        self.pool = self._new_pool()
        for attempt in range(1, INITIAL_DIAL_MAX_ATTEMPTS + 1):
            try:
                await self.pool.start()
                break
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "upstream connection attempt %d/%d failed: %s",
                    attempt,
                    INITIAL_DIAL_MAX_ATTEMPTS,
                    exc,
                )
                # HTTP/3 whose QUIC handshakes all time out (UDP path
                # blocked or edge not serving QUIC) falls back cleanly to
                # HTTP/2 instead of failing the connect.
                if (
                    attempt < INITIAL_DIAL_MAX_ATTEMPTS
                    and not self.config.transport_pinned
                    and self._effective_transport == "h3"
                    and _is_quic_timeout(exc)
                ):
                    logger.warning(
                        "HTTP/3 QUIC handshake to %s timed out (UDP path may be "
                        "blocked); falling back to HTTP/2",
                        self.current_candidate.authority,
                    )
                    if await self._rebuild_pool_with_transport(
                        "h2", reason="HTTP/3 QUIC handshake timeout"
                    ):
                        continue
                if attempt >= INITIAL_DIAL_MAX_ATTEMPTS:
                    raise
                await asyncio.sleep(_initial_dial_backoff(attempt))
        self.accepting = True
        self._reason = "ok"
        await self._write_status_file()

        self._tasks.append(asyncio.create_task(self._renewal_loop()))
        self._tasks.append(asyncio.create_task(self._quota_monitor_loop()))
        return self.pool

    def _new_pool(self) -> SessionPool:
        """Build a pool for the effective transport."""
        return SessionPool(
            self.config.upstream_conns,
            self._session_factory,
            self._metrics,
            max_streams_per_session=(
                1
                if self._effective_transport == "h1"
                else self.config.multiplex_streams
            ),
            total_stream_target=self.config.max_conns,
            on_close_storm=self._handle_close_storm,
        )

    async def _rebuild_pool_with_transport(self, transport: str, reason: str) -> bool:
        """Swap the serving pool to a different transport, cleanly.

        Starts the replacement pool before tearing the old one down, so
        in-flight client streams keep draining on their existing sessions
        while new connections immediately use the new transport. Returns
        False (keeping the current pool) when the replacement cannot start.
        """
        if self._transport_fallback_in_progress:
            return False
        old_pool = self.pool
        previous_transport = self._effective_transport
        previous_http3 = self._effective_use_http3
        self._transport_fallback_in_progress = True
        try:
            self._effective_transport = transport
            self._effective_use_http3 = transport == "h3"
            replacement = self._new_pool()
            await replacement.start()
            self.pool = replacement
            logger.info(
                "session pool rebuilt on %s (%s); draining the old %s pool",
                transport,
                reason,
                previous_transport,
            )
            repoint = self.on_pool_replaced
            if repoint is not None:
                try:
                    await repoint(replacement)
                except Exception:  # noqa: BLE001 - never strand the new pool
                    logger.exception("pool-replaced callback failed")
            if old_pool is not None:
                await old_pool.close()
            return True
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "%s fallback pool failed to start (%s); keeping the %s pool",
                transport,
                exc,
                previous_transport,
            )
            self._effective_transport = previous_transport
            self._effective_use_http3 = previous_http3
            return False
        finally:
            self._transport_fallback_in_progress = False

    async def _handle_close_storm(self) -> None:
        """Pool close-storm signal (observed session closes, not ordinary
        load). HTTP/1.1's session-per-tunnel relay turns any rapid session
        churn into dial storms and unusable client paths; fall back to
        HTTP/2 multiplexing unless the transport was explicitly pinned."""
        if self._effective_transport != "h1" or self.config.transport_pinned:
            return
        await self._rebuild_pool_with_transport(
            "h2", reason="HTTP/1.1 upstream session churn (close storm)"
        )

    async def _ensure_fresh_access_token(self) -> None:
        """Proactively renew an expired/expiring access token before it is used
        for proxy-pass acquisition. A second expiry check under the lock
        prevents concurrent duplicate refreshes. Never prompts; on failure the
        session-token pool is tried, and if that is unavailable the caller is
        told not to proceed (never silently uses a known-expired token)."""
        if not self.auth.access_token_expired():
            return
        async with self._auth_lock:
            if not self.auth.access_token_expired():
                return
            if self.auth.token.refresh_token:
                try:
                    self.auth = auth_module.refresh_runtime_auth(self.auth)
                    logger.info("renewed the account's expired access token")
                    return
                except Exception as exc:  # noqa: BLE001
                    logger.warning("access-token renewal failed; trying the session-token pool: %s", exc)
            rotated = auth_module.rotate_session_token(self.auth)
            if rotated is not None:
                self.auth = rotated
                logger.info("rotated to a fresh session token after a renewal failure")
                return
            raise auth_module.AccessTokenExpiredError(
                "the account's access token has expired and could not be renewed; sign in again"
            )

    async def _acquire_usable_pass(self) -> guardian.ProxyPassInfo:
        """Acquire a Guardian proxy pass, renewing the access token first when
        it has expired or is about to expire."""
        await self._ensure_fresh_access_token()
        return guardian.fetch_proxy_pass(
            self.config.guardian_endpoint, self.auth.access_token
        )

    @staticmethod
    def _pass_is_usable(
        info: guardian.ProxyPassInfo, margin_seconds: float = 15.0
    ) -> bool:
        """True only for a pass that is already valid and not near expiry."""
        try:
            now = datetime.now(timezone.utc)
            return (
                info.not_before() <= now
                and (info.expires_at() - now).total_seconds() > margin_seconds
            )
        except Exception:  # noqa: BLE001 - malformed pass means "not usable"
            return False

    async def _acquire_initial_pass(self) -> None:
        """Acquire the initial Guardian proxy pass."""
        self.proxy_pass = await self._acquire_usable_pass()

    async def _renewal_loop(self) -> None:
        """Background loop: renew proxy pass before expiry."""
        try:
            while not self._stopped.is_set():
                try:
                    await asyncio.sleep(PROXY_PASS_RENEW_LEAD_SECONDS)
                    if self._stopped.is_set():
                        return
                    self.proxy_pass = await self._acquire_usable_pass()
                    if self.pool:
                        self.pool.update_token(self.proxy_pass.raw_token)
                except asyncio.CancelledError:
                    return
                except Exception as exc:  # noqa: BLE001
                    logger.warning("proxy pass renewal failed: %s", exc)
        except asyncio.CancelledError:
            pass

    async def _quota_monitor_loop(self) -> None:
        """Background loop: monitor Guardian entitlement quota."""
        try:
            while not self._stopped.is_set():
                try:
                    await asyncio.sleep(QUOTA_CHECK_INTERVAL_SECONDS)
                    if self._stopped.is_set():
                        return
                    guardian.fetch_user_info(self.config.guardian_endpoint, self.auth.access_token)
                except asyncio.CancelledError:
                    return
                except Exception as exc:  # noqa: BLE001
                    logger.warning("quota check failed: %s", exc)
        except asyncio.CancelledError:
            pass

    async def stop(self) -> None:
        """Stop the controller and all upstream sessions."""
        self._stopped.set()
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        if self.pool:
            await self.pool.close()
            self.pool = None

    async def _write_status_file(self) -> None:
        """Write the optional JSON status file describing proxy-pass health."""
        if not self.config.status_file:
            return
        try:
            status = {
                "status": self._reason,
                "uptime": time.monotonic() - self._started_at if self._started_at else 0,
                "candidate": self.current_candidate.authority,
                "transport": "http3" if self.config.use_http3 else "http2",
            }
            path = Path(self.config.status_file)

            def _write() -> None:
                path.parent.mkdir(parents=True, exist_ok=True)
                fd, tmp_path = tempfile.mkstemp(
                    prefix=path.name + ".tmp-", dir=str(path.parent)
                )
                try:
                    with os.fdopen(fd, "w", encoding="utf-8") as fh:
                        json.dump(status, fh, indent=2)
                    os.replace(tmp_path, path)
                finally:
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)

            await asyncio.to_thread(_write)
        except Exception as exc:  # noqa: BLE001
            logger.warning("could not write status file: %s", exc)
