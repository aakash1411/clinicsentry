"""Audit chain integrity and report generation tests."""

from __future__ import annotations

from clinicsentry.audit.backend import InMemoryAuditBackend
from clinicsentry.audit.chain import AuditChain
from clinicsentry.audit.report import build_report
from clinicsentry.types import AuditEvent, AuditEventType


def _make_chain() -> AuditChain:
    return AuditChain(
        session_id="s1",
        secret_key=b"a" * 32,
        backend=InMemoryAuditBackend(),
    )


def test_chain_verification_passes_for_clean_session() -> None:
    chain = _make_chain()
    for i in range(5):
        chain.emit(
            AuditEvent(
                event_type=AuditEventType.AGENT_LLM_CALL,
                session_id="s1",
                sequence_number=0,
                redacted_input={"i": i},
            )
        )
    ok, errors = chain.verify()
    assert ok, errors


def test_chain_tampering_detected() -> None:
    chain = _make_chain()
    for i in range(3):
        chain.emit(
            AuditEvent(
                event_type=AuditEventType.AGENT_LLM_CALL,
                session_id="s1",
                sequence_number=0,
                redacted_input={"i": i},
            )
        )
    backend: InMemoryAuditBackend = chain.backend  # type: ignore[assignment]
    backend._events[1].redacted_input = {"i": 99}  # tamper
    ok, errors = chain.verify()
    assert not ok
    assert errors


def test_report_aggregates_events() -> None:
    chain = _make_chain()
    chain.emit(
        AuditEvent(
            event_type=AuditEventType.SESSION_START,
            session_id="s1",
            sequence_number=0,
        )
    )
    chain.emit(
        AuditEvent(
            event_type=AuditEventType.TOOL_CALL,
            session_id="s1",
            sequence_number=0,
            agent_id="t1",
            redacted_input={"tool_name": "t1"},
            confidence_score=0.9,
        )
    )
    chain.emit(
        AuditEvent(
            event_type=AuditEventType.SESSION_END,
            session_id="s1",
            sequence_number=0,
        )
    )
    backend: InMemoryAuditBackend = chain.backend  # type: ignore[assignment]
    report = build_report(
        session_id="s1",
        events=backend.read_session("s1"),
        framework="generic",
    )
    assert report.session_summary["total_events"] == 3
    assert len(report.clinical_decision_summary["actions_taken"]) == 1
    # The DSL engine emits one entry per rule; HIPAA-164.312-b is the audit-controls rule.
    audit_ctrl = report.compliance_attestation["HIPAA-164.312-b"]
    assert audit_ctrl["satisfied"] is True
    assert audit_ctrl["severity"] == "blocker"


def test_chain_emit_is_thread_safe() -> None:
    """Concurrent emitters must yield a gapless, verifiable chain."""
    import threading

    chain = _make_chain()

    def emitter() -> None:
        for i in range(50):
            chain.emit(
                AuditEvent(
                    event_type=AuditEventType.AGENT_LLM_CALL,
                    session_id="s1",
                    sequence_number=0,
                    redacted_input={"i": i},
                )
            )

    threads = [threading.Thread(target=emitter) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    ok, errors = chain.verify()
    assert ok, errors
    seqs = [e.sequence_number for e in chain.backend.read_session("s1")]
    assert seqs == list(range(1, 401))


def test_chain_tail_truncation_detected() -> None:
    """Deleting the last events keeps hash links valid — verify must still fail."""
    chain = _make_chain()
    for i in range(5):
        chain.emit(
            AuditEvent(
                event_type=AuditEventType.AGENT_LLM_CALL,
                session_id="s1",
                sequence_number=0,
                redacted_input={"i": i},
            )
        )
    backend: InMemoryAuditBackend = chain.backend  # type: ignore[assignment]
    del backend._events[-2:]  # truncate tail
    ok, errors = chain.verify()
    assert not ok
    assert any("truncated" in e for e in errors)


def test_chain_sequence_gap_detected() -> None:
    chain = _make_chain()
    for i in range(4):
        chain.emit(
            AuditEvent(
                event_type=AuditEventType.AGENT_LLM_CALL,
                session_id="s1",
                sequence_number=0,
                redacted_input={"i": i},
            )
        )
    backend: InMemoryAuditBackend = chain.backend  # type: ignore[assignment]
    del backend._events[1]  # remove a middle event
    ok, errors = chain.verify()
    assert not ok


def test_rehydrated_chain_skips_tail_check() -> None:
    """A fresh chain over an existing backend (CLI verify) must not report truncation."""
    chain = _make_chain()
    for i in range(3):
        chain.emit(
            AuditEvent(
                event_type=AuditEventType.AGENT_LLM_CALL,
                session_id="s1",
                sequence_number=0,
                redacted_input={"i": i},
            )
        )
    fresh = AuditChain(session_id="s1", secret_key=b"a" * 32, backend=chain.backend)
    # The fresh instance emits SESSION events in real use; here it emitted none.
    ok, errors = fresh.verify()
    assert ok, errors
