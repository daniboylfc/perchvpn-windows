"""Diagnostics buffer: structure, redaction, aggregation and bounds."""

from __future__ import annotations

import logging
import threading
import time

import pytest

from src.perchvpn_windows import diagnostics


@pytest.fixture()
def buf():
    return diagnostics.DiagnosticsBuffer(max_events=50)


class TestRedaction:
    def test_bearer_tokens(self):
        assert "<redacted>" in diagnostics.redact("Authorization: Bearer abc.def.ghi")
        assert "abc.def.ghi" not in diagnostics.redact("Authorization: Bearer abc.def.ghi")

    def test_jwt_like_strings(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1aWQifQ.sig12345"
        out = diagnostics.redact(f"got token {jwt} ok")
        # The JWT itself may be swallowed by the broader token rule; either
        # way no credential residue may survive.
        assert jwt not in out
        assert "<redacted" in out
        bare = diagnostics.redact(jwt)
        assert bare == "<redacted-jwt>"

    def test_password_and_token_fields(self):
        out = diagnostics.redact('password=hunter2 and token=abcdefghij')
        assert "hunter2" not in out
        assert "abcdefghij" not in out
        assert "<redacted>" in out

    def test_plain_text_untouched(self):
        assert diagnostics.redact("server-list cache hit") == "server-list cache hit"

    def test_exception_rendering(self):
        try:
            raise RuntimeError("pass Bearer sekrettoken123 failed")
        except RuntimeError as exc:
            text = diagnostics.redact_exception(exc)
        assert "sekrettoken123" not in text
        assert "RuntimeError" in text

    def test_long_lines_clamped(self):
        out = diagnostics.redact("x" * 5000)
        assert len(out) <= 600


class TestBuffer:
    def test_event_structure(self, buf):
        rid = buf.emit("WARNING", "guardian", "proxy-pass", "fetch_failed",
                       outcome="http_401", detail="rejected", duration_ms=44.2)
        events = buf.snapshot()
        assert len(events) == 1
        ev = events[0]
        assert ev["id"] == rid
        assert ev["severity"] == "WARN"
        assert ev["component"] == "guardian"
        assert ev["operation"] == "proxy-pass"
        assert ev["stage"] == "fetch_failed"
        assert ev["outcome"] == "http_401"
        assert ev["detail"] == "rejected"
        assert ev["duration_ms"] == 44.2
        assert isinstance(ev["ts"], float)
        assert ev["repeats"] == 1

    def test_duplicate_aggregation_within_window(self, buf):
        buf.emit("INFO", "countries", "server-list", "cache_hit", outcome="hit")
        buf.emit("INFO", "countries", "server-list", "cache_hit", outcome="hit")
        buf.emit("INFO", "countries", "server-list", "cache_hit", outcome="hit")
        assert buf.size() == 1
        assert buf.snapshot()[0]["repeats"] == 3

    def test_different_details_do_not_aggregate(self, buf):
        buf.emit("INFO", "urltest", "probe", "complete", outcome="ok", detail="relay=a:1")
        buf.emit("INFO", "urltest", "probe", "complete", outcome="ok", detail="relay=b:2")
        assert buf.size() == 2

    def test_after_id_filter(self, buf):
        first = buf.emit("INFO", "a", "op1", "stage")
        second = buf.emit("INFO", "b", "op2", "stage")
        recent = buf.snapshot(after_id=first)
        assert [e["id"] for e in recent] == [second]

    def test_bounded_history(self, buf):
        for i in range(120):
            buf.emit("INFO", "comp", f"op{i}", "stage", detail=f"d{i}")
        assert buf.size() == 50
        events = buf.snapshot()
        assert events[-1]["detail"] == "d119"  # newest kept, oldest evicted

    def test_thread_safety_smoke(self, buf):
        def worker(n):
            for i in range(50):
                buf.emit("INFO", f"c{n}", f"op{i}", "stage", detail=f"d{i}")

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert buf.size() == 50


class TestLoggingHandler:
    def test_records_become_events_with_severity(self):
        handler = diagnostics.LoggingDiagnosticsHandler(buffer=diagnostics.DiagnosticsBuffer())
        logger = logging.getLogger("perch.test.events")
        old_level = logger.level
        logger.setLevel(logging.INFO)
        rule = logging.Filter()
        handler.emit = handler.emit  # noqa: B015 - attribute exists
        record = logging.LogRecord(
            name="perch.test.events", level=logging.WARNING, pathname=__file__,
            lineno=1, msg="pass fetch rejected: %s", args=("HTTP 401",), exc_info=None,
        )
        handler.emit(record)
        events = handler._buffer.snapshot()
        assert len(events) == 1
        ev = events[0]
        assert ev["severity"] == "WARN"
        assert ev["component"] == "events"
        logger.setLevel(old_level)

    def test_uvicorn_access_skipped(self):
        buf = diagnostics.DiagnosticsBuffer()
        handler = diagnostics.LoggingDiagnosticsHandler(buffer=buf)
        record = logging.LogRecord(
            name="uvicorn.access", level=logging.INFO, pathname=__file__,
            lineno=1, msg="POST /api/status 200", args=(), exc_info=None,
        )
        handler.emit(record)
        assert buf.size() == 0

    def test_credential_redaction_through_logging(self):
        buf = diagnostics.DiagnosticsBuffer()
        handler = diagnostics.LoggingDiagnosticsHandler(buffer=buf)
        record = logging.LogRecord(
            name="perch.auth", level=logging.ERROR, pathname=__file__,
            lineno=1, msg="signin failed for Bearer eyJx.yyy.zzzzzzzzzz",
            args=(), exc_info=None,
        )
        handler.emit(record)
        blob = str(buf.snapshot()[0])
        assert "eyJx" not in blob

    def test_emit_redacts_values(self, buf):
        buf.emit("INFO", "guardian", "proxy-pass", "acquired",
                 detail="token=verylongsecretvalue999")
        ev = buf.snapshot()[0]
        assert "verylongsecretvalue999" not in str(ev)
