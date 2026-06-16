"""Escalation delivery channels (review queue, webhook).

Channels are pluggable: each implements :meth:`dispatch` to route an
:class:`EscalationDecision`. Concrete implementations include:

- :class:`InMemoryReviewQueue` — list-backed FIFO for tests / smoke runs.
- :class:`SQLiteReviewQueue` — file-backed with SLA tracking columns.
- :class:`WebhookChannel` — HTTP POST with exponential backoff retry.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from clinicsentry.types import EscalationDecision

__all__ = [
    "EscalationChannel",
    "InMemoryReviewQueue",
    "SQLiteReviewQueue",
    "WebhookChannel",
    "QueuedReview",
]


class EscalationChannel(Protocol):
    """Structural type for an escalation delivery channel."""

    def dispatch(  # pragma: no cover - protocol
        self,
        decision: EscalationDecision,
        *,
        session_id: str,
        action_name: str,
        context: dict[str, Any] | None = None,
    ) -> None:
        """Route ``decision`` to the configured destination."""
        ...


@dataclass
class QueuedReview:
    """A review queue entry with SLA tracking metadata."""

    session_id: str
    action_name: str
    decision: EscalationDecision
    enqueued_at: datetime
    sla_deadline: datetime
    review_id: str
    status: str = "pending"


@dataclass
class InMemoryReviewQueue:
    """Thread-safe FIFO review queue suitable for tests."""

    sla_hours: int = 4
    _queue: list[QueuedReview] = field(default_factory=list, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    def dispatch(
        self,
        decision: EscalationDecision,
        *,
        session_id: str,
        action_name: str,
        context: dict[str, Any] | None = None,
    ) -> None:
        """Append a :class:`QueuedReview` to the queue."""
        now = datetime.now(UTC)
        from uuid import uuid4

        entry = QueuedReview(
            session_id=session_id,
            action_name=action_name,
            decision=decision,
            enqueued_at=now,
            sla_deadline=now + timedelta(hours=self.sla_hours),
            review_id=str(uuid4()),
        )
        with self._lock:
            self._queue.append(entry)

    def pending(self) -> list[QueuedReview]:
        """Snapshot the pending entries."""
        with self._lock:
            return [e for e in self._queue if e.status == "pending"]

    def overdue(self) -> list[QueuedReview]:
        """Pending entries past their SLA deadline."""
        now = datetime.now(UTC)
        return [e for e in self.pending() if e.sla_deadline < now]

    def resolve(self, review_id: str, status: str = "resolved") -> bool:
        """Mark ``review_id`` resolved; return True if found."""
        with self._lock:
            for entry in self._queue:
                if entry.review_id == review_id:
                    entry.status = status
                    return True
        return False


class SQLiteReviewQueue:
    """File-backed review queue with SLA tracking columns."""

    _DDL = """
    CREATE TABLE IF NOT EXISTS reviews (
        review_id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        action_name TEXT NOT NULL,
        decision_json TEXT NOT NULL,
        enqueued_at TEXT NOT NULL,
        sla_deadline TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending'
    );
    CREATE INDEX IF NOT EXISTS idx_reviews_status ON reviews(status);
    """

    def __init__(self, path: str | Path, sla_hours: int = 4) -> None:
        """Open / create the SQLite database."""
        self.path = str(path)
        self.sla_hours = sla_hours
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.executescript(self._DDL)
        self._lock = threading.Lock()

    def dispatch(
        self,
        decision: EscalationDecision,
        *,
        session_id: str,
        action_name: str,
        context: dict[str, Any] | None = None,
    ) -> None:
        """Insert a new pending review row."""
        from uuid import uuid4

        now = datetime.now(UTC)
        review_id = str(uuid4())
        sla = now + timedelta(hours=self.sla_hours)
        with self._lock:
            self._conn.execute(
                "INSERT INTO reviews (review_id, session_id, action_name, "
                "decision_json, enqueued_at, sla_deadline) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    review_id,
                    session_id,
                    action_name,
                    json.dumps(decision.to_dict()),
                    now.isoformat(),
                    sla.isoformat(),
                ),
            )
            self._conn.commit()

    def pending(self) -> Iterator[dict[str, Any]]:
        """Yield every pending row as a dict."""
        cur = self._conn.execute("SELECT * FROM reviews WHERE status = 'pending'")
        cols = [c[0] for c in cur.description]
        for row in cur.fetchall():
            yield dict(zip(cols, row, strict=False))


@dataclass
class WebhookChannel:
    """HTTP POST channel with exponential backoff retry.

    The dispatched payload is a JSON object with three keys:

    - ``session_id`` (str)
    - ``action_name`` (str)
    - ``decision`` (the decision as returned by :meth:`EscalationDecision.to_dict`)
    """

    url: str
    timeout_seconds: float = 5.0
    max_retries: int = 3
    backoff_base: float = 0.5

    def dispatch(
        self,
        decision: EscalationDecision,
        *,
        session_id: str,
        action_name: str,
        context: dict[str, Any] | None = None,
    ) -> None:
        """POST the decision to ``self.url`` with retries on transient errors."""
        body = json.dumps(
            {
                "session_id": session_id,
                "action_name": action_name,
                "decision": decision.to_dict(),
                "context": context or {},
            }
        ).encode()
        req = urllib.request.Request(
            self.url,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        last_exc: Exception | None = None
        for attempt in range(self.max_retries):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:  # noqa: S310  # nosec B310 - operator-configured https webhook endpoint
                    if 200 <= resp.status < 300:
                        return
                    raise urllib.error.HTTPError(
                        self.url, resp.status, "non-2xx", resp.headers, None
                    )
            except (urllib.error.URLError, TimeoutError) as exc:
                last_exc = exc
                time.sleep(self.backoff_base * (2**attempt))
        if last_exc is not None:
            raise last_exc
