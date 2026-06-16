"""Mutation-killing tests for :mod:`clinicsentry.audit.chain`.

These tests target specific surviving mutants from mutmut runs: sequence
counter behaviour, hash-determinism, classmethod surface, and the verify()
error path.
"""

from __future__ import annotations

import pytest

from clinicsentry.audit.backend import InMemoryAuditBackend
from clinicsentry.audit.chain import AuditChain, _canonical_json
from clinicsentry.types import AuditEvent, AuditEventType


def _new_chain() -> AuditChain:
    return AuditChain(
        session_id="s1",
        secret_key=b"k" * 32,
        backend=InMemoryAuditBackend(),
    )


def _emit(chain: AuditChain) -> AuditEvent:
    return chain.emit(
        AuditEvent(
            event_type=AuditEventType.AGENT_LLM_CALL,
            session_id="s1",
            sequence_number=0,
        )
    )


# ---------------------------------------------------------------------------
# Sequence counter
# ---------------------------------------------------------------------------


def test_first_emit_starts_at_sequence_one() -> None:
    """``_sequence = 0`` plus ``+= 1`` means first event has sequence_number == 1."""
    chain = _new_chain()
    first = _emit(chain)
    assert first.sequence_number == 1


def test_sequence_strictly_increments_by_one() -> None:
    """Kills ``_sequence += 1`` → ``= 1`` and → ``+= 2`` mutants."""
    chain = _new_chain()
    seqs = [_emit(chain).sequence_number for _ in range(5)]
    assert seqs == [1, 2, 3, 4, 5]


# ---------------------------------------------------------------------------
# Classmethod surface
# ---------------------------------------------------------------------------


def test_in_memory_is_callable_as_classmethod() -> None:
    """Kills the ``@classmethod`` removal mutant."""
    chain = AuditChain.in_memory(session_id="s2", secret_key=b"k" * 32)
    assert isinstance(chain, AuditChain)
    assert chain.session_id == "s2"
    # The convenience constructor should give a usable, verifying chain.
    chain.emit(
        AuditEvent(
            event_type=AuditEventType.SESSION_START,
            session_id="s2",
            sequence_number=0,
        )
    )
    ok, errors = chain.verify()
    assert ok, errors


# ---------------------------------------------------------------------------
# Canonical JSON
# ---------------------------------------------------------------------------


def test_canonical_json_is_key_order_independent() -> None:
    """Kills ``sort_keys=True`` → ``False`` mutant.

    Two dicts with identical contents in different insertion orders must
    serialize to byte-identical canonical form.
    """
    a = {"b": 1, "a": 2, "c": 3}
    b = {"a": 2, "c": 3, "b": 1}
    assert _canonical_json(a) == _canonical_json(b)


def test_canonical_json_uses_minimal_separators() -> None:
    """Kills separator-corruption mutants (``,`` → ``XX,XX``, ``:`` → ``XX:XX``)."""
    payload = {"a": 1, "b": 2}
    out = _canonical_json(payload)
    assert b"XX" not in out
    assert out == b'{"a":1,"b":2}'


# ---------------------------------------------------------------------------
# Verify error path
# ---------------------------------------------------------------------------


def test_verify_returns_false_on_prev_hash_tamper() -> None:
    """Kills the ``return False, errors`` → ``return True, errors`` mutant."""
    chain = _new_chain()
    _emit(chain)
    _emit(chain)
    backend = chain.backend  # type: ignore[attr-defined]
    backend._events[1].prev_event_hash = "tampered"  # type: ignore[attr-defined]
    ok, errors = chain.verify()
    assert ok is False
    assert errors


def test_verify_error_message_exact_form_on_prev_hash_tamper() -> None:
    """Kills XX-corruption of the prev-hash mismatch error literal.

    The full error must start with ``event <id> (#<n>) has prev_event_hash``
    with no XX-bracket corruption anywhere.
    """
    chain = _new_chain()
    _emit(chain)
    second = _emit(chain)
    backend = chain.backend  # type: ignore[attr-defined]
    backend._events[1].prev_event_hash = "tampered"  # type: ignore[attr-defined]
    ok, errors = chain.verify()
    assert not ok
    assert len(errors) == 1
    err = errors[0]
    assert "XX" not in err
    expected_prefix = f"event {second.event_id} (#{second.sequence_number}) has "
    assert err.startswith(expected_prefix), err
    assert err.endswith("prev_event_hash mismatch at index 1"), err


def test_verify_signature_error_exact_form() -> None:
    """Kills XX-corruption of the signature-invalid error literal."""
    chain = _new_chain()
    first = _emit(chain)
    backend = chain.backend  # type: ignore[attr-defined]
    backend._events[0].signature = "0" * 64  # type: ignore[attr-defined]
    ok, errors = chain.verify()
    assert not ok
    assert len(errors) == 1
    err = errors[0]
    assert "XX" not in err
    assert err == f"event {first.event_id} signature invalid"


# ---------------------------------------------------------------------------
# Secret-key type validation
# ---------------------------------------------------------------------------


def test_secret_key_must_be_bytes_exact_message() -> None:
    """Kills XX-corruption of the TypeError message literal."""
    with pytest.raises(TypeError) as excinfo:
        AuditChain(session_id="s", secret_key="not-bytes", backend=InMemoryAuditBackend())  # type: ignore[arg-type]
    assert str(excinfo.value) == "secret_key must be bytes"
