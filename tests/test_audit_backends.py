"""Tests for new audit backends: OTEL exporter, S3 archival, Chained."""

from __future__ import annotations

import json
from typing import Any

import pytest

from clinicsentry.audit import (
    ChainedAuditBackend,
    InMemoryAuditBackend,
    OTELAuditBackend,
    S3AuditBackend,
)
from clinicsentry.audit.chain import AuditChain
from clinicsentry.types import AuditEvent, AuditEventType


def _make_event(session_id: str = "s1", seq: int = 0) -> AuditEvent:
    return AuditEvent(
        event_type=AuditEventType.AGENT_LLM_CALL,
        session_id=session_id,
        sequence_number=seq,
        agent_id="agent-x",
        agent_framework="test",
    )


# --- InMemory hardening --------------------------------------------------


def test_inmemory_backend_caps_events_to_max() -> None:
    backend = InMemoryAuditBackend(max_events=3)
    for i in range(10):
        backend.append(_make_event(seq=i))
    assert len(backend.all_events()) == 3
    # Oldest dropped, newest retained.
    sequence_numbers = [e.sequence_number for e in backend.all_events()]
    assert sequence_numbers == [7, 8, 9]


# --- OTEL wrapper --------------------------------------------------------


def test_otel_backend_delegates_appends() -> None:
    inner = InMemoryAuditBackend()
    backend = OTELAuditBackend(inner, tracer=None)
    backend.append(_make_event())
    assert len(inner.all_events()) == 1


def test_otel_backend_invokes_tracer_when_present() -> None:
    inner = InMemoryAuditBackend()

    calls: list[str] = []

    class _Span:
        def __enter__(self) -> _Span:
            return self

        def __exit__(self, *exc: Any) -> None:
            return None

        def set_attribute(self, *_args: Any, **_kw: Any) -> None:
            pass

    class _Tracer:
        def start_as_current_span(self, name: str) -> _Span:
            calls.append(name)
            return _Span()

    backend = OTELAuditBackend(inner, tracer=_Tracer())
    backend.append(_make_event())
    assert calls == ["clinicsentry.audit.agent_llm_call"]


# --- S3 (with stub client) -----------------------------------------------


class _FakeS3:
    def __init__(self) -> None:
        self.objects: dict[tuple[str, str], bytes] = {}
        self.put_calls: list[dict[str, Any]] = []

    def put_object(self, **kwargs: Any) -> None:
        self.objects[(kwargs["Bucket"], kwargs["Key"])] = kwargs["Body"]
        self.put_calls.append(kwargs)

    def get_object(self, Bucket: str, Key: str) -> dict[str, Any]:
        body = self.objects[(Bucket, Key)]

        class _Body:
            def read(self_inner) -> bytes:
                return body

        return {"Body": _Body()}

    def get_paginator(self, _name: str) -> Any:
        objects = [{"Key": k} for (_b, k) in self.objects]

        class _Paginator:
            def paginate(self_inner, **_: Any) -> list[dict[str, list[dict[str, str]]]]:
                return [{"Contents": objects}]

        return _Paginator()


def test_s3_backend_flush_writes_jsonl_object() -> None:
    fake = _FakeS3()
    backend = S3AuditBackend(bucket="archive", prefix="cg/", client=fake, flush_every=10)
    for i in range(3):
        backend.append(_make_event(seq=i))
    backend.flush("s1")
    body = fake.objects[("archive", "cg/s1.jsonl")]
    lines = [json.loads(line) for line in body.decode().splitlines()]
    assert [e["sequence_number"] for e in lines] == [0, 1, 2]


def test_s3_backend_lists_sessions_by_listing_keys() -> None:
    fake = _FakeS3()
    backend = S3AuditBackend(bucket="archive", prefix="cg/", client=fake, flush_every=10)
    for sid in ("alpha", "beta"):
        backend.append(_make_event(session_id=sid))
        backend.flush(sid)
    assert sorted(backend.list_sessions()) == ["alpha", "beta"]


# --- Chained fan-out ------------------------------------------------------


def test_chained_backend_appends_to_each_member() -> None:
    a = InMemoryAuditBackend()
    b = InMemoryAuditBackend()
    chain = ChainedAuditBackend([a, b])
    chain.append(_make_event())
    assert len(a.all_events()) == 1
    assert len(b.all_events()) == 1


def test_chained_backend_read_returns_first_nonempty() -> None:
    hot = InMemoryAuditBackend()
    cold = InMemoryAuditBackend()
    hot.append(_make_event())  # only in hot
    chain = ChainedAuditBackend([hot, cold])
    assert sum(1 for _ in chain.read_session("s1")) == 1


# --- Chain compatibility --------------------------------------------------


def test_audit_chain_works_with_chained_backend_end_to_end() -> None:
    chain_backend = ChainedAuditBackend([InMemoryAuditBackend(), InMemoryAuditBackend()])
    chain = AuditChain(session_id="s1", secret_key=b"x" * 32, backend=chain_backend)
    chain.emit(_make_event())
    ok, errors = chain.verify()
    assert ok, errors


def test_chained_backend_requires_at_least_one_backend() -> None:
    with pytest.raises(ValueError, match="at least one"):
        ChainedAuditBackend([])
