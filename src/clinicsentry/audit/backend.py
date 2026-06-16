"""Pluggable audit backends.

Three concrete implementations ship: in-memory (tests), append-only file (dev),
and SQLite (lightweight production). PostgreSQL/S3 backends from README §8 are
intentionally left as future work behind the same `AuditBackend` interface.
"""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
import threading
from abc import ABC, abstractmethod
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

from clinicsentry.types import AuditEvent, AuditEventType, ClinicalRiskTier

__all__ = [
    "AuditBackend",
    "InMemoryAuditBackend",
    "FileAuditBackend",
    "SqliteAuditBackend",
]


class AuditBackend(ABC):
    """Abstract append-only audit store."""

    @abstractmethod
    def append(self, event: AuditEvent) -> None:
        """Persist ``event``."""

    @abstractmethod
    def read_session(self, session_id: str) -> Iterator[AuditEvent]:
        """Yield events for ``session_id`` in sequence order."""

    def list_sessions(self) -> list[str]:
        """Return distinct session ids present in the store (override for efficiency)."""
        seen: set[str] = set()
        for sid in self._iter_session_ids():
            seen.add(sid)
        return sorted(seen)

    def _iter_session_ids(self) -> Iterator[str]:
        """Iterate session ids. Subclasses should override for efficiency."""
        return iter(())


class InMemoryAuditBackend(AuditBackend):
    """Thread-safe list-backed backend, capped to ``max_events`` entries."""

    def __init__(self, *, max_events: int | None = None) -> None:
        """Initialize with an optional cap on retained events."""
        self._events: list[AuditEvent] = []
        self._lock = threading.Lock()
        self._max_events = max_events

    def append(self, event: AuditEvent) -> None:
        """Append under a lock; truncate if the cap is exceeded."""
        with self._lock:
            self._events.append(event)
            if self._max_events is not None and len(self._events) > self._max_events:
                # Drop oldest (FIFO).
                excess = len(self._events) - self._max_events
                del self._events[:excess]

    def read_session(self, session_id: str) -> Iterator[AuditEvent]:
        """Yield events for the given session, ordered by sequence number."""
        return iter(
            sorted(
                (e for e in self._events if e.session_id == session_id),
                key=lambda e: e.sequence_number,
            )
        )

    def all_events(self) -> list[AuditEvent]:
        """Return every event stored (test helper)."""
        return list(self._events)

    def _iter_session_ids(self) -> Iterator[str]:
        """Yield each event's session id."""
        return (e.session_id for e in self._events)


class FileAuditBackend(AuditBackend):
    """JSON-Lines append-only file backend."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)
        self._lock = threading.Lock()

    def append(self, event: AuditEvent) -> None:
        """Append a JSON line and fsync to disk (serialized across threads)."""
        line = json.dumps(event.to_dict(), default=str) + "\n"
        with self._lock, self.path.open("a", encoding="utf-8") as fh:
            fh.write(line)
            fh.flush()
            with contextlib.suppress(OSError):  # some FS disallow fsync
                os.fsync(fh.fileno())

    def read_session(self, session_id: str) -> Iterator[AuditEvent]:
        """Stream events filtered by session id, ordered by sequence number."""
        events: list[AuditEvent] = []
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                payload = json.loads(line)
                if payload.get("session_id") != session_id:
                    continue
                events.append(_event_from_dict(payload))
        events.sort(key=lambda e: e.sequence_number)
        return iter(events)

    def _iter_session_ids(self) -> Iterator[str]:
        """Yield each line's session id."""
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                sid = payload.get("session_id")
                if sid:
                    yield sid


class SqliteAuditBackend(AuditBackend):
    """SQLite append-only backend with sequence-ordered retrieval."""

    _DDL = """
    CREATE TABLE IF NOT EXISTS audit_events (
        event_id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        sequence_number INTEGER NOT NULL,
        timestamp TEXT NOT NULL,
        payload TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_audit_session
        ON audit_events(session_id, sequence_number);
    """

    def __init__(self, path: str | Path) -> None:
        """Open the SQLite database in WAL mode for concurrent reads."""
        self.path = str(path)
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(self._DDL)
        self._conn.commit()
        self._lock = threading.Lock()

    def append(self, event: AuditEvent) -> None:
        """Insert a row under a lock; any UPDATE or DELETE is intentionally not exposed."""
        payload = json.dumps(event.to_dict(), default=str)
        with self._lock:
            self._conn.execute(
                "INSERT INTO audit_events (event_id, session_id, sequence_number, "
                "timestamp, payload) VALUES (?, ?, ?, ?, ?)",
                (
                    event.event_id,
                    event.session_id,
                    event.sequence_number,
                    event.timestamp.isoformat(),
                    payload,
                ),
            )
            self._conn.commit()

    def read_session(self, session_id: str) -> Iterator[AuditEvent]:
        """Return events ordered by sequence number."""
        cur = self._conn.execute(
            "SELECT payload FROM audit_events WHERE session_id = ? ORDER BY sequence_number",
            (session_id,),
        )
        for row in cur.fetchall():
            yield _event_from_dict(json.loads(row[0]))

    def close(self) -> None:
        """Close the underlying connection."""
        self._conn.close()

    def _iter_session_ids(self) -> Iterator[str]:
        """Query distinct session ids."""
        cur = self._conn.execute("SELECT DISTINCT session_id FROM audit_events")
        for row in cur.fetchall():
            yield row[0]


def _event_from_dict(payload: dict[str, Any]) -> AuditEvent:
    """Rehydrate an :class:`AuditEvent` from a serialized dict."""
    risk = payload.get("risk_tier")
    return AuditEvent(
        event_id=payload["event_id"],
        session_id=payload["session_id"],
        sequence_number=int(payload["sequence_number"]),
        timestamp=datetime.fromisoformat(payload["timestamp"]),
        event_type=AuditEventType(payload["event_type"]),
        agent_id=payload.get("agent_id", "unknown"),
        agent_framework=payload.get("agent_framework", "unknown"),
        input_hash=payload.get("input_hash", ""),
        output_hash=payload.get("output_hash", ""),
        redacted_input=payload.get("redacted_input", {}) or {},
        redacted_output=payload.get("redacted_output", {}) or {},
        phi_tags_detected=list(payload.get("phi_tags_detected", []) or []),
        risk_tier=ClinicalRiskTier(risk) if risk else None,
        confidence_score=payload.get("confidence_score"),
        escalation_decision=payload.get("escalation_decision"),
        prev_event_hash=payload.get("prev_event_hash", ""),
        signature=payload.get("signature", ""),
    )
