"""Escalation channels: review queues and webhook delivery."""

from __future__ import annotations

import json
import urllib.error
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from clinicsentry.escalation import channels
from clinicsentry.escalation.channels import (
    InMemoryReviewQueue,
    SQLiteReviewQueue,
    WebhookChannel,
)
from clinicsentry.types import ClinicalRiskTier, EscalationDecision


def _decision() -> EscalationDecision:
    return EscalationDecision(
        action="escalate",
        tier=ClinicalRiskTier.INTERVENTIONAL,
        confidence=0.4,
        escalation_reason="low confidence",
    )


def test_in_memory_queue_overdue_and_resolve() -> None:
    q = InMemoryReviewQueue(sla_hours=4)
    q.dispatch(_decision(), session_id="s1", action_name="order_med")
    q.dispatch(_decision(), session_id="s2", action_name="order_lab")
    assert len(q.pending()) == 2
    assert q.overdue() == []

    first = q.pending()[0]
    first.sla_deadline = datetime.now(UTC) - timedelta(minutes=1)
    assert [e.review_id for e in q.overdue()] == [first.review_id]

    assert q.resolve(first.review_id, status="approved") is True
    assert first.status == "approved"
    assert len(q.pending()) == 1
    assert q.resolve("missing") is False


def test_sqlite_queue_persists_pending_rows(tmp_path: Path) -> None:
    db = tmp_path / "reviews.db"
    q = SQLiteReviewQueue(db, sla_hours=2)
    q.dispatch(_decision(), session_id="s1", action_name="order_med", context={"k": "v"})
    rows = list(q.pending())
    assert len(rows) == 1
    row = rows[0]
    assert row["session_id"] == "s1"
    assert row["action_name"] == "order_med"
    assert row["status"] == "pending"
    assert json.loads(row["decision_json"])["action"] == "escalate"
    enqueued = datetime.fromisoformat(row["enqueued_at"])
    deadline = datetime.fromisoformat(row["sla_deadline"])
    assert deadline - enqueued == timedelta(hours=2)

    reopened = SQLiteReviewQueue(db)
    assert len(list(reopened.pending())) == 1


class _Resp:
    def __init__(self, status: int) -> None:
        self.status = status
        self.headers: dict[str, str] = {}

    def __enter__(self) -> _Resp:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


def _patch(monkeypatch: pytest.MonkeyPatch, outcomes: list[Any]) -> list[Any]:
    calls: list[Any] = []

    def fake_urlopen(req: Any, timeout: float) -> _Resp:
        calls.append((req, timeout))
        outcome = outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return _Resp(outcome)

    monkeypatch.setattr(channels.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(channels.time, "sleep", lambda _s: None)
    return calls


def test_webhook_posts_json_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _patch(monkeypatch, [204])
    ch = WebhookChannel(url="https://hooks.example.test/review", timeout_seconds=2.0)
    ch.dispatch(_decision(), session_id="s1", action_name="order_med", context={"a": 1})
    assert len(calls) == 1
    req, timeout = calls[0]
    assert timeout == 2.0
    assert req.get_method() == "POST"
    assert req.get_header("Content-type") == "application/json"
    body = json.loads(req.data)
    assert body["session_id"] == "s1"
    assert body["action_name"] == "order_med"
    assert body["decision"]["action"] == "escalate"
    assert body["context"] == {"a": 1}


def test_webhook_retries_transient_errors_then_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _patch(monkeypatch, [urllib.error.URLError("down"), TimeoutError(), 200])
    WebhookChannel(url="https://hooks.example.test/r").dispatch(
        _decision(), session_id="s", action_name="a"
    )
    assert len(calls) == 3


def test_webhook_raises_after_exhausting_retries(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _patch(monkeypatch, [500, 503])
    ch = WebhookChannel(url="https://hooks.example.test/r", max_retries=2)
    with pytest.raises(urllib.error.HTTPError):
        ch.dispatch(_decision(), session_id="s", action_name="a")
    assert len(calls) == 2


def test_webhook_with_zero_retries_is_a_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _patch(monkeypatch, [])
    WebhookChannel(url="https://hooks.example.test/r", max_retries=0).dispatch(
        _decision(), session_id="s", action_name="a"
    )
    assert calls == []
