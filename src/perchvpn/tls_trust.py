"""Strict upstream TLS trust roots.

Upstream dials must always verify, and must succeed on hosts whose
platform trust store is missing newer roots (e.g. a 2025-era GlobalSign
root used by MASQUE edges).  ``ssl.create_default_context()`` loads the
platform store (Windows cert store on win32); adding certifi's bundle
alongside keeps verification strict while covering roots the platform
store may lack.  For HTTP/3 (aioquic) the bundle is handed over
explicitly so trust never depends on aioquic's internal fallback.

certifi is a hard runtime dependency of httpx, so this is bundled in
frozen builds; absence degrades to platform roots only and NEVER
disables verification.
"""

from __future__ import annotations

import logging
import ssl
from typing import Optional

logger = logging.getLogger("perchvpn.tls_trust")


def certifi_cafile() -> Optional[str]:
    """Path to the bundled certifi CA store, or None when unavailable."""
    try:
        import certifi

        return certifi.where()
    except Exception:  # noqa: BLE001 - absence degrades to platform roots
        logger.info("certifi is not available; upstream TLS uses platform roots only")
        return None


def load_certifi_roots(context: ssl.SSLContext) -> bool:
    """Load certifi's CA bundle into a context that already has platform roots.

    Returns True when the bundle was added.  A failure is logged and the
    context keeps its platform roots; verification mode is never touched.
    """
    cafile = certifi_cafile()
    if cafile is None:
        return False
    try:
        context.load_verify_locations(cafile=cafile)
        return True
    except (ssl.SSLError, OSError, ValueError) as exc:
        logger.info("certifi CA bundle could not be loaded (%s); using platform roots", exc)
        return False
