"""Storage behaviour of the in-memory, file and SQLite audit backends."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from clinicsentry.audit.backend import (
    AuditBackend,
    FileAuditBackend,
    InMemoryAuditBackend,
    SqliteAuditBackend,
)
from clinicsentry.types import AuditEvent, AuditEventType, ClinicalRiskTier


def _event(session_id: str, seq: int, **kw: object) -> AuditEvent:
    return AuditEvent(
        event_type=AuditEventType.TOOL_CALL,
        session_id=session_id,
        sequence_number=seq,
        agent_id="agent",
        agent_framework="test",
        **kw,  # type: ignore[arg-type]
    )


def test_base_list_sessions_defaults_to_empty() -> None:
    class Minimal(AuditBackend):
        def append(self, event: AuditEvent) -> None:
            return None

        def read_session(self, session_id: str) -> Iterator[AuditEvent]:
            return iter(())

    assert Minimal().list_sessions() == []


def test_in_memory_cap_drops_oldest() -> None:
    be = InMemoryAuditBackend(max_events=2)
    for i in range(3):
        be.append(_event("s", i))
    assert [e.sequence_number for e in be.all_events()] == [1, 2]


@pytest.fixture(params=["file", "sqlite"])
def durable(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[AuditBackend]:
    if request.param == "file":
        yield FileAuditBackend(tmp_path / "nested" / "audit.jsonl")
    else:
        be = SqliteAuditBackend(tmp_path / "audit.db")
        yield be
        be.close()


def test_round_trip_preserves_fields_and_orders_by_sequence(durable: AuditBackend) -> None:
    durable.append(_event("s1", 2))
    durable.append(
        _event(
            "s1",
            1,
            risk_tier=ClinicalRiskTier.INTERVENTIONAL,
            confidence_score=0.75,
            escalation_decision={"action": "escalate"},
            phi_tags_detected=["SSN"],
            redacted_input={"q": "[SSN]"},
            prev_event_hash="abc",
            signature="sig",
        )
    )
    durable.append(_event("s2", 1))

    events = list(durable.read_session("s1"))
    assert [e.sequence_number for e in events] == [1, 2]
    first = events[0]
    assert first.risk_tier is ClinicalRiskTier.INTERVENTIONAL
    assert first.confidence_score == 0.75
    assert first.escalation_decision == {"action": "escalate"}
    assert first.phi_tags_detected == ["SSN"]
    assert first.redacted_input == {"q": "[SSN]"}
    assert first.prev_event_hash == "abc"
    assert first.signature == "sig"
    assert events[1].risk_tier is None
    assert durable.list_sessions() == ["s1", "s2"]
    assert list(durable.read_session("missing")) == []


def test_file_backend_skips_blank_and_corrupt_lines(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    be = FileAuditBackend(path)
    be.append(_event("s1", 1))
    with path.open("a", encoding="utf-8") as fh:
        fh.write("\n{not json\n")
        fh.write('{"other": 1}\n')
    be.append(_event("s2", 1))
    assert be.list_sessions() == ["s1", "s2"]
    with path.open("w", encoding="utf-8") as fh:
        fh.write("\n")
    assert list(be.read_session("s1")) == []
