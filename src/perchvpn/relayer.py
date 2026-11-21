"""Control-plane relayer routing (upstream v2.0.3 ``RelayerInterceptor``).

Mirrors the Android client's relay semantics:

* selected endpoint categories (``guardian``, ``fxa``, ``config``,
  ``server_list``) are relayed through a worker URL;
* ``automatic`` tries direct first and only relays on a failover status
  (HTTP 451 by default) or a connection error, then walks every candidate
  relayer in order;
* ``direct`` never relays; an explicit provider pins a single relayer;
* the relayed request carries the original URL base64url-encoded (no
  padding) as the ``url`` query parameter.
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:  # httpx is a hard dependency of the control plane; keep import-local.
    import httpx
except ImportError:  # pragma: no cover
    httpx = None  # type: ignore[assignment]

__all__ = [
    "AUTOMATIC",
    "CATEGORIES",
    "DEFAULT_FAILOVER_CODES",
    "DEFAULT_RELAYERS",
    "DIRECT",
    "RelayerState",
    "build_relayer_url",
    "candidate_relayers",
    "configure",
    "current_state",
    "match_category",
    "measure_relayer_rtt",
    "request_with_relayer",
    "should_relay",
]

AUTOMATIC = "automatic"
DIRECT = "direct"

DEFAULT_RELAYERS: Dict[str, str] = {
    "cloudflare": "https://relayer.foxyvpn.workers.dev",
    "vercel": "https://relayer.foxyvpn.vercel.app",
}

CATEGORIES = ("guardian", "fxa", "config", "server_list")
DEFAULT_FAILOVER_CODES = frozenset({451})
DEFAULT_RELAY_TIMEOUT = 10.0

_state_lock = None


@dataclass(frozen=True)
class RelayerState:
    """Immutable relayer routing configuration."""

    provider: str = DIRECT
    custom_url: str = ""
    routed_endpoints: Tuple[str, ...] = ("guardian",)
    failover_codes: frozenset = DEFAULT_FAILOVER_CODES

    def with_candidates(self) -> "RelayerState":
        return self


_default_state = RelayerState()
_state: RelayerState = _default_state


def configure(
    provider: str = DIRECT,
    custom_url: str = "",
    routed_endpoints: Iterable[str] = (),
    failover_codes: Optional[Iterable[int]] = None,
) -> RelayerState:
    """Install the module-level relayer state used by the HTTP client hook."""
    global _state
    normalized = tuple(
        str(ep).strip().lower()
        for ep in (routed_endpoints or ())
        if str(ep or "").strip()
    )
    codes = DEFAULT_FAILOVER_CODES if failover_codes is None else frozenset(int(c) for c in failover_codes)
    _state = RelayerState(
        provider=str(provider or DIRECT).strip().lower(),
        custom_url=str(custom_url or "").strip(),
        routed_endpoints=normalized or ("guardian",),
        failover_codes=codes,
    )
    return _state


def current_state() -> RelayerState:
    return _state


def build_relayer_url(relayer_base: str, target_url: str) -> str:
    """Encode the target as ``?url=<base64url>`` on the relayer base."""
    raw = str(relayer_base or "").strip()
    if raw and not raw.lower().startswith(("http://", "https://")):
        raw = "https://" + raw
    encoded = base64.urlsafe_b64encode(str(target_url).encode("utf-8")).decode("ascii")
    if raw.endswith("?url=") or raw.endswith("&url="):
        return raw + encoded
    if "?" in raw:
        return f"{raw}&url={encoded}"
    return f"{raw.rstrip('/')}/?url={encoded}"


def match_category(url: str, category: str) -> bool:
    url = str(url or "")
    category = str(category or "").strip().lower()
    if category == "guardian":
        return ("/api/v1/fpn/" in url) or (
            "vpn.mozilla.org" in url and "/api/v1/" in url
        )
    if category == "fxa":
        return "accounts.firefox.com" in url or "/oauth/" in url
    if category == "config":
        return "FoxyConfig" in url or "foxy_config" in url
    if category == "server_list":
        return "vpn-serverlist" in url or "serverlist" in url
    return False


def candidate_relayers(provider: str, custom_url: str = "") -> List[str]:
    """Ordered relayer base URLs for a provider (mirrors upstream)."""
    provider = str(provider or "").strip().lower()
    custom = str(custom_url or "").strip()
    if provider == DIRECT:
        return []
    if provider == AUTOMATIC:
        seen: List[str] = []
        for url in DEFAULT_RELAYERS.values():
            if url not in seen:
                seen.append(url)
        return seen
    if provider == "custom":
        return [custom] if custom.startswith("https://") else []
    base = DEFAULT_RELAYERS.get(provider)
    if base:
        return [base]
    if custom.startswith("https://"):
        return [custom]
    return []


def should_relay(url: str, state: Optional[RelayerState] = None) -> bool:
    state = state or current_state()
    if state.provider == DIRECT:
        return False
    return any(match_category(url, category) for category in state.routed_endpoints)


def _direct_request(client, method: str, url: str, **kwargs):
    """Issue one attempt bypassing any relaying override on the client."""
    raw = getattr(client, "_request_direct", None)
    if raw is None:
        raw = client.request
    return raw(method, url, **kwargs)


def request_with_relayer(
    client: Any,
    method: str,
    url: str,
    *,
    state: Optional[RelayerState] = None,
    failover_exception_types: Tuple[type, ...] = (httpx.HTTPError,) if httpx else (Exception,),
    **kwargs: Any,
) -> Any:
    """Direct-first request with relayer failover.

    ``client`` is any httpx-compatible client. The direct response is
    returned unchanged unless its status is a failover code or the request
    raises; then every candidate relayer is tried in order and the first
    non-failover response wins. If every attempt fails, the direct outcome
    (exception or response) is re-raised/returned unchanged.
    """
    state = state or current_state()
    direct_response = None
    direct_error: Optional[BaseException] = None
    try:
        direct_response = _direct_request(client, method, url, **kwargs)
        if direct_response.status_code not in state.failover_codes:
            return direct_response
    except failover_exception_types as exc:
        direct_error = exc

    candidates = candidate_relayers(state.provider, state.custom_url)
    for base in candidates:
        relayed_url = build_relayer_url(base, url)
        try:
            response = _direct_request(client, method, relayed_url, **kwargs)
            if response.status_code not in state.failover_codes:
                return response
        except failover_exception_types:
            continue

    if direct_error is not None:
        raise direct_error
    return direct_response


def measure_relayer_rtt(
    provider: str,
    custom_url: str = "",
    *,
    timeout: float = 5.0,
    client: Any = None,
) -> List[Dict[str, Any]]:
    """Measure the HTTPS round-trip to every candidate relayer endpoint."""
    if client is None:
        if httpx is None:  # pragma: no cover
            raise RuntimeError("httpx is required for relayer latency probes")
        client = httpx.Client(trust_env=False, timeout=timeout)
        own_client = True
    else:
        own_client = False
    results: List[Dict[str, Any]] = []
    try:
        for base in candidate_relayers(provider, custom_url):
            started = time.monotonic()
            try:
                response = client.request("GET", base, timeout=timeout)
                rtt_ms = (time.monotonic() - started) * 1000.0
                results.append(
                    {
                        "relayer": base,
                        "ok": response.status_code < 500,
                        "status": response.status_code,
                        "rtt_ms": round(rtt_ms, 2),
                        "error": "",
                    }
                )
            except Exception as exc:  # noqa: BLE001
                results.append(
                    {
                        "relayer": base,
                        "ok": False,
                        "status": None,
                        "rtt_ms": None,
                        "error": str(exc),
                    }
                )
    finally:
        if own_client:
            client.close()
    return results
