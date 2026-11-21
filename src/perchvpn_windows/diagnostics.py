"""Bounded in-memory diagnostics buffer with credential redaction.

Not a telemetry pipeline and no external dependency: a fixed-size ring of
structured events (severity / component / operation / stage / outcome /
duration / detail) fed from (a) explicit lifecycle emissions in the API
layer and (b) a stdlib ``logging`` handler so every log line the app
already produces appears as a structured event too.

Security: every stored field passes through the same redactor - Bearer
tokens, passwords, tokens, authorization/Hawk headers and long
secret-looking strings are replaced before anything is retained. Raised
exceptions are formatted and redacted the same way.
"""

from __future__ import annotations

import logging
import itertools
import re
import threading
import time
from collections import deque
from typing import Any, Deque, Dict, List, Optional

_MAX_EVENTS = 600
_REPEAT_WINDOW_SECONDS = 1.0
_MAX_DETAIL_CHARS = 600

# Redaction is deliberately blunt: it is cheaper to over- than under-redact.
_REDACTIONS = [
    (re.compile(r"(Bearer\s+)[^\s'\";,]+"), r"\1<redacted>"),
    (re.compile(r"(?i)\b(password|passwd|secret|token|authorization|hawk)[^A-Za-z0-9]{1,4}[^\s'\";,]{4,}"), r"\1<redacted>"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}"), "<redacted-jwt>"),
    (re.compile(r"(?i)\b(access_token|refresh_token|session_token)[^A-Za-z0-9]{1,4}[A-Za-z0-9_\-]{8,}"), r"\1<redacted>"),
]


def redact(text: str) -> str:
    if not text:
        return text
    value = str(text)
    for pattern, replacement in _REDACTIONS:
        value = pattern.sub(replacement, value)
    if len(value) > _MAX_DETAIL_CHARS:
        value = value[: _MAX_DETAIL_CHARS - 1] + "\u2026"
    return value


class DiagnosticsBuffer:
    def __init__(self, max_events: int = _MAX_EVENTS):
        self._lock = threading.Lock()
        self._events: Deque[Dict[str, Any]] = deque(maxlen=max_events)
        self._ids = itertools.count(1)
        self._last: Optional[Dict[str, Any]] = None

    def emit(
        self,
        severity: str,
        component: str,
        operation: str,
        stage: str,
        *,
        outcome: str = "",
        detail: str = "",
        duration_ms: Optional[float] = None,
        corr_id: str = "",
        extra: Optional[Dict[str, Any]] = None,
    ) -> int:
        """Record one event; identical neighbours inside the repeat window
        are aggregated into a single row with a repetition count."""
        severity = {
            "WARNING": "WARN",
        }.get(severity.upper(), severity.upper())
        repeat_key = (severity, component, operation, stage, outcome, detail)
        now = time.time()
        with self._lock:
            last = self._last
            if (
                last is not None
                and last["ts"] >= now - _REPEAT_WINDOW_SECONDS
                and (
                    last["severity"],
                    last["component"],
                    last["operation"],
                    last["stage"],
                    last["outcome"],
                    last["detail"],
                )
                == repeat_key
            ):
                last["ts"] = now
                last["repeats"] = int(last.get("repeats", 1)) + 1
                return int(last["id"])
            event: Dict[str, Any] = {
                "id": next(self._ids),
                "ts": now,
                "severity": severity,
                "component": redact(component),
                "operation": redact(operation),
                "stage": redact(stage),
                "outcome": redact(outcome),
                "detail": redact(detail),
                "duration_ms": duration_ms,
                "corr_id": redact(corr_id) if corr_id else "",
                "repeats": 1,
            }
            if extra:
                for key, value in extra.items():
                    event[f"extra_{key}"] = redact(value) if isinstance(value, str) else value
            self._events.append(event)
            self._last = event
            return int(event["id"])

    def snapshot(self, after_id: int = 0, limit: int = 200) -> List[Dict[str, Any]]:
        with self._lock:
            events = [e for e in self._events if int(e["id"]) > after_id]
        if limit and len(events) > limit:
            events = events[-limit:]
        return [dict(e) for e in events]

    def size(self) -> int:
        with self._lock:
            return len(self._events)


_BUFFER = DiagnosticsBuffer()


class LoggingDiagnosticsHandler(logging.Handler):
    """Feeds stdlib log records into the diagnostics buffer as events.

    Skips uvicorn.access HTTP logs (the GUI polls the API each second, so
    per-request logs would be pure noise) and keeps routine polls visible
    only at DEBUG level.
    """

    def __init__(self, buffer: Optional[DiagnosticsBuffer] = None, level: int = logging.INFO):
        super().__init__(level=level)
        self._buffer = buffer or _BUFFER

    def emit(self, record: logging.LogRecord) -> None:  # noqa: A003
        try:
            name = record.name
            if name.startswith("uvicorn.access"):
                return
            try:
                message = record.getMessage()
            except Exception:  # noqa: BLE001
                message = str(record.msg)
            severity = "DEBUG" if record.levelno <= logging.DEBUG else "INFO"
            if record.levelno == logging.WARNING:
                severity = "WARN"
            elif record.levelno >= logging.ERROR:
                severity = "ERROR"
            operation = getattr(record, "operation", "") or ""
            stage = getattr(record, "stage", "") or ""
            outcome = ""
            duration_ms = getattr(record, "duration_ms", None)
            if not operation:
                # No explicit operation: use the message as the observable
                # detail, keep the operation generic per component.
                operation = "log"
                outcome = message
            corr_id = str(getattr(record, "corr_id", "") or "")
            self._buffer.emit(
                severity,
                component=name.split(".")[-1] or name,
                operation=operation,
                stage=stage,
                outcome=outcome,
                detail="" if message == outcome else message,
                duration_ms=duration_ms if isinstance(duration_ms, (int, float)) else None,
                corr_id=corr_id,
            )
        except Exception:  # noqa: BLE001 - never break the logging pipeline
            self.handleError(record)


def emit(
    severity: str,
    component: str,
    operation: str,
    stage: str,
    *,
    outcome: str = "",
    detail: str = "",
    duration_ms: Optional[float] = None,
    corr_id: str = "",
) -> int:
    return _BUFFER.emit(
        severity, component, operation, stage,
        outcome=outcome, detail=detail, duration_ms=duration_ms, corr_id=corr_id,
    )


def snapshot(after_id: int = 0, limit: int = 200) -> List[Dict[str, Any]]:
    return _BUFFER.snapshot(after_id=after_id, limit=limit)


def install_logger_handler(level: int = logging.INFO) -> None:
    handler = LoggingDiagnosticsHandler(level=level)
    root = logging.getLogger()
    for existing in root.handlers:
        if isinstance(existing, LoggingDiagnosticsHandler):
            return
    root.addHandler(handler)


def redact_exception(exc: BaseException) -> str:
    """One-line, redacted view of an exception for diagnostics."""
    type_text = type(exc).__name__
    message = str(exc)
    return redact(f"{type_text}: {message}" if message else type_text)
