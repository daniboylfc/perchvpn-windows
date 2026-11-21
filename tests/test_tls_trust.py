"""F3: strict upstream TLS verification with certifi roots wired in.

Covers: certifi bundle availability, platform-root contexts that gain
certifi roots without ever relaxing verify_mode, and the per-transport
wiring (HTTP/1.1 context factory, HTTP/2 connect, HTTP/3 QuicConfiguration).
"""

from __future__ import annotations

import ssl
import types
from pathlib import Path
from unittest.mock import patch

import pytest

from src.perchvpn.exceptions import ProxyError
from src.perchvpn.proxy import http1_session
from src.perchvpn.proxy import h3_session
from src.perchvpn.proxy import session as h2_session_module
from src.perchvpn.tls_trust import certifi_cafile, load_certifi_roots


def test_certifi_cafile_points_at_existing_bundle():
    cafile = certifi_cafile()
    assert cafile is not None
    assert Path(cafile).is_file()


def test_load_certifi_roots_adds_roots_and_keeps_strict_mode():
    context = ssl.create_default_context()
    assert context.verify_mode == ssl.CERT_REQUIRED

    assert load_certifi_roots(context) is True

    assert context.verify_mode == ssl.CERT_REQUIRED
    # The loaded trust set must match a context built directly from the
    # certifi bundle.  Count-based growth asserts are environment-sensitive:
    # some platform stores already carry the exact certifi set, and OpenSSL
    # dedupes identical roots on load.
    certifi_context = ssl.create_default_context(
        cafile=certifi_cafile()
    )
    loaded_subjects = {c["subject"] for c in context.get_ca_certs()}
    certifi_subjects = {c["subject"] for c in certifi_context.get_ca_certs()}
    assert certifi_subjects <= loaded_subjects


def test_h1_tls_context_is_strict_and_loads_certifi():
    seen = []

    def spy(context):
        seen.append(context)
        return True

    with patch.object(http1_session, "load_certifi_roots", spy):
        context = http1_session._tls_context(None)

    assert seen == [context]
    assert context.verify_mode == ssl.CERT_REQUIRED


class _FakeQuicConnectCM:
    def __init__(self, recorder, *args, **kwargs):
        recorder.append(self)
        self.configuration = kwargs.get("configuration")

    async def __aenter__(self):
        return types.SimpleNamespace(http=object())

    async def __aexit__(self, *exc):
        return False


@pytest.mark.asyncio
async def test_h3_configuration_pins_strict_verification():
    recorder = []
    session = h3_session.H3ProxySession(
        "203.0.113.7", 443, "tok", edge_host="203.0.113.7"
    )
    with patch.object(h3_session, "quic_connect", lambda *a, **kw: _FakeQuicConnectCM(recorder, *a, **kw)):
        await session.connect(timeout=1.0)

    try:
        assert recorder, "QUIC connect was not invoked"
        configuration = recorder[0].configuration
        assert configuration.verify_mode == ssl.CERT_REQUIRED
        assert configuration.cafile == certifi_cafile()
    finally:
        if session._keepalive_task:
            session._keepalive_task.cancel()


@pytest.mark.asyncio
async def test_h2_connect_loads_certifi_roots():
    seen = []

    def spy(context):
        seen.append(context)
        return True

    session = h2_session_module.H2ProxySession("127.0.0.1", 1, "tok")
    with patch.object(h2_session_module, "load_certifi_roots", spy):
        with pytest.raises((ProxyError, OSError)):
            await session.connect(timeout=0.5)

    assert seen, "h2 connect did not load certifi roots"
    assert seen[0].verify_mode == ssl.CERT_REQUIRED
