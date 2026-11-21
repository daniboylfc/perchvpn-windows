"""Shared outbound-transport parity options (upstream v2.0.3).

Three knobs mirror the Android client's tunnel settings:

* ``utls_fingerprint`` — browser TLS ClientHello emulation.  Python's stdlib
  TLS stack cannot replay another browser byte-for-byte, but the knobs it
  does expose (cipher preference order, ECDH curve preference) are applied
  here deterministically; sing-box's DNS DoH server gets a real ``tls.utls``
  block.  The honest limitation is documented on the returned knob list.
* ``tls_fragment_mode`` — ``record`` splits the TLS handshake records the
  ClientHello is carried in, ``packet`` segments the raw first-flight bytes
  with pacing, ``combined`` does both.  Fragmentation only runs for the
  fragment budget (``tls_fragment_fallback_delay_ms``, default 300), after
  which bytes pass through unfragmented.  It is applied where this codebase
  owns the record stream: the HTTP/1.1 CONNECT transport (memory-BIO
  handshake).  The HTTP/2/3 asyncio transports write records through the
  event loop's SSL transport, where record interception is not available.
* ``multiplex_streams`` — per-session concurrent-stream soft cap.
"""

from __future__ import annotations

import ssl
import time
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

__all__ = [
    "COMBINED",
    "DISABLED",
    "FRAGMENT_MODES",
    "PACKET",
    "PACKET_SEGMENT_SIZE",
    "RECORD",
    "SINGBOX_UTLS_FINGERPRINTS",
    "TransportOptions",
    "configure_client_hello",
    "fragment_bytes",
    "packet_segments",
    "split_tls_records",
]

DISABLED = "disabled"
RECORD = "record"
PACKET = "packet"
COMBINED = "combined"
FRAGMENT_MODES = (DISABLED, RECORD, PACKET, COMBINED)

# First-flight TCP segment size for packet fragmentation (bytes).
PACKET_SEGMENT_SIZE = 64
# Pause between paced segments; the fragment budget caps the total window.
_SEGMENT_PAUSE_SECONDS = 0.005

# ClientHello emulation knobs keyed by fingerprint.  These are the settings
# the Python TLS stack can actually influence; they change what an observer
# sees in cipher/curve preference but are NOT full browser emulation.
_FINGERPRINT_KNOBS = {
    "chrome": {"curve": "X25519", "ciphers": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"},
    "edge": {"curve": "X25519", "ciphers": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"},
    "firefox": {"curve": "X25519", "ciphers": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"},
    "safari": {"curve": "prime256v1", "ciphers": "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"},
    "ios": {"curve": "X25519", "ciphers": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305"},
}
RANDOMIZED_CIPHER_ROTATIONS = 3

# Fingerprints understood by sing-box's ``tls.utls`` blocks.
SINGBOX_UTLS_FINGERPRINTS = {
    "chrome": "chrome",
    "edge": "edge",
    "firefox": "firefox",
    "safari": "safari",
    "ios": "ios",
    "random": "random",
    "randomized": "randomized",
}


@dataclass(frozen=True)
class TransportOptions:
    """Immutable transport parity options handed to every session dial."""

    utls_fingerprint: str = "disabled"
    tls_fragment_mode: str = DISABLED
    tls_fragment_fallback_delay_ms: int = 300
    multiplex_streams: int = 8

    @classmethod
    def from_values(
        cls,
        utls_fingerprint: str = "disabled",
        tls_fragment_mode: str = DISABLED,
        tls_fragment_fallback_delay_ms: int = 300,
        multiplex_streams: int = 8,
    ) -> "TransportOptions":
        return cls(
            utls_fingerprint=str(utls_fingerprint or "disabled").strip().lower(),
            tls_fragment_mode=str(tls_fragment_mode or DISABLED).strip().lower(),
            tls_fragment_fallback_delay_ms=int(tls_fragment_fallback_delay_ms or 0),
            multiplex_streams=int(multiplex_streams or 8),
        )

    @property
    def fragmenting(self) -> bool:
        return self.tls_fragment_mode in (RECORD, PACKET, COMBINED)

    @property
    def fragment_fallback_seconds(self) -> float:
        return max(0, self.tls_fragment_fallback_delay_ms) / 1000.0


def configure_client_hello(
    context: ssl.SSLContext, fingerprint: str
) -> List[str]:
    """Apply the stdlib-controllable ClientHello knobs for ``fingerprint``.

    Returns the list of applied knob descriptions (empty for ``disabled``).
    Raises nothing for unknown fingerprints — they simply apply no knobs,
    mirroring upstream's "disabled" fallback behaviour.
    """
    fp = str(fingerprint or "").strip().lower()
    if fp in ("", "disabled"):
        return []
    applied: List[str] = []
    knobs = _FINGERPRINT_KNOBS.get(fp)
    if knobs:
        try:
            context.set_ciphers(knobs["ciphers"])
            applied.append(f"ciphers={fp}")
        except ssl.SSLError:
            applied.append("ciphers=unavailable")
        try:
            context.set_ecdh_curve(knobs["curve"])
            applied.append(f"curve={knobs['curve']}")
        except (ssl.SSLError, ValueError, NotImplementedError):
            applied.append("curve=unavailable")
    elif fp in ("random", "randomized"):
        try:
            context.set_ciphers("ALL:@SECLEVEL=1")
            applied.append("ciphers=randomized")
        except ssl.SSLError:
            applied.append("ciphers=unavailable")
        applied.append("curve=unavailable")
    return applied


def split_tls_records(data: bytes, max_len: int = 256) -> List[bytes]:
    """Split TLS record payloads into ``max_len``-sized sub-records.

    Handshake records (content type 22) are re-emitted as several records
    with rebuilt 5-byte headers; every other record type passes through
    untouched.  Malformed leading bytes are passed through unchanged.
    """
    out: List[bytes] = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 5 or data[offset] != 22:
            out.append(data[offset:])
            break
        version = data[offset + 1: offset + 3]
        length = int.from_bytes(data[offset + 3: offset + 5], "big")
        payload_start = offset + 5
        payload_end = min(payload_start + length, len(data))
        payload = data[payload_start:payload_end]
        for start in range(0, len(payload), max_len):
            chunk = payload[start: start + max_len]
            out.append(bytes([22]) + version + len(chunk).to_bytes(2, "big") + chunk)
        if payload_end < payload_start + length:
            out.append(data[payload_end:])
            break
        offset = payload_end
    return out


def packet_segments(data: bytes, segment_size: int = PACKET_SEGMENT_SIZE) -> List[bytes]:
    """Split raw first-flight bytes into small TCP segments."""
    if segment_size <= 0:
        return [data]
    return [data[start: start + segment_size] for start in range(0, len(data), segment_size)]


def fragment_bytes(
    data: bytes,
    options: TransportOptions,
    *,
    clock: Optional[Sequence[float]] = None,
) -> List[Tuple[bytes, float]]:
    """Return ``(chunk, pause_before_seconds)`` pairs for a first flight.

    The fragment budget starts at the first send; once
    ``tls_fragment_fallback_delay_ms`` has elapsed the remaining bytes are
    emitted as one unfragmented chunk (the fallback).
    """
    mode = options.tls_fragment_mode
    if not options.fragmenting or not data:
        return [(data, 0.0)]
    budget = options.fragment_fallback_seconds

    if mode == COMBINED:
        chunks: List[bytes] = []
        for record in split_tls_records(data):
            chunks.extend(packet_segments(record))
    elif mode == PACKET:
        chunks = packet_segments(data)
    else:  # RECORD
        chunks = split_tls_records(data)

    now = (clock or time.monotonic)
    started = now()
    out: List[Tuple[bytes, float]] = []
    for index, chunk in enumerate(chunks):
        if index == 0:
            out.append((chunk, 0.0))
            continue
        if now() - started >= budget:
            remainder = b"".join(chunks[index:])
            out.append((remainder, _SEGMENT_PAUSE_SECONDS))
            break
        pause = _SEGMENT_PAUSE_SECONDS
        if mode == RECORD:
            pause = 0.0
        out.append((chunk, pause))
    return out
