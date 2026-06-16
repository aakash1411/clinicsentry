"""Tamper-evident audit chain.

Each emitted event is hash-linked to its predecessor (``prev_event_hash``) and
HMAC-signed (``signature``). Any modification of a historical event invalidates
all subsequent hashes.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
from dataclasses import dataclass
from typing import Any

from clinicsentry.audit.backend import AuditBackend, InMemoryAuditBackend
from clinicsentry.types import AuditEvent

__all__ = [
    "AuditChain",
    "event_input_for_hash",
    "hash_event",
]


def _canonical_json(payload: dict[str, Any]) -> bytes:
    """Stable serialization for hashing: sorted keys, no whitespace."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()


def event_input_for_hash(event: AuditEvent) -> dict[str, Any]:
    """Subset of an event's serialized form that contributes to its content hash."""
    payload = event.to_dict()
    payload.pop("signature", None)
    return payload


def hash_event(event: AuditEvent) -> str:
    """Return the SHA-256 content hash of ``event``."""
    return hashlib.sha256(_canonical_json(event_input_for_hash(event))).hexdigest()


@dataclass
class AuditChain:
    """Coordinates sequence numbers, hash linking, and HMAC signing."""

    session_id: str
    secret_key: bytes
    backend: AuditBackend

    def __post_init__(self) -> None:
        if not isinstance(self.secret_key, (bytes, bytearray)):
            raise TypeError("secret_key must be bytes")
        self._sequence = 0
        self._prev_hash = ""
        # Sequence/prev-hash updates must be atomic with the backend append —
        # a race here breaks the gapless-monotonic guarantee (ADR-0003).
        self._lock = threading.Lock()

    @classmethod
    def in_memory(cls, session_id: str, secret_key: bytes) -> AuditChain:
        """Convenience constructor with an in-memory backend."""
        return cls(session_id=session_id, secret_key=secret_key, backend=InMemoryAuditBackend())

    def emit(self, event: AuditEvent) -> AuditEvent:
        """Stamp ``event`` with sequence/prev/sig and persist it via the backend.

        Returns the (mutated) event for caller convenience. Writes happen
        synchronously and *before* any further processing — this guarantees the
        audit-first invariant (README §5). Emission is thread-safe.
        """
        with self._lock:
            self._sequence += 1
            event.session_id = self.session_id
            event.sequence_number = self._sequence
            event.prev_event_hash = self._prev_hash
            # signature is computed without itself, then stamped onto the event.
            sig = hmac.new(
                self.secret_key, _canonical_json(event_input_for_hash(event)), hashlib.sha256
            ).hexdigest()
            event.signature = sig
            self._prev_hash = hash_event(event)
            self.backend.append(event)
        return event

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify(self) -> tuple[bool, list[str]]:
        """Verify the chain stored in the backend for this session.

        Checks, in order: sequence contiguity (1..n, no gaps), prev-hash
        linkage, and HMAC signatures. When this instance has emitted events,
        the stored tail is additionally compared against the in-memory head —
        deleting the *last* events of a chain leaves the hash links intact, so
        truncation is only detectable against an external reference point.

        Returns ``(ok, errors)``. ``errors`` describes the first detected break.
        """
        errors: list[str] = []
        prev = ""
        count = 0
        for i, event in enumerate(self.backend.read_session(self.session_id)):
            count += 1
            if event.sequence_number != i + 1:
                errors.append(
                    f"event {event.event_id} has sequence_number "
                    f"{event.sequence_number}, expected {i + 1} (gap or reorder)"
                )
                return False, errors
            if event.prev_event_hash != prev:
                errors.append(
                    f"event {event.event_id} (#{event.sequence_number}) has "
                    f"prev_event_hash mismatch at index {i}"
                )
                return False, errors
            expected_sig = hmac.new(
                self.secret_key,
                _canonical_json(event_input_for_hash(event)),
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(expected_sig, event.signature):
                errors.append(f"event {event.event_id} signature invalid")
                return False, errors
            prev = hash_event(event)
        if self._sequence > 0:
            if count != self._sequence:
                errors.append(
                    f"chain truncated: backend holds {count} events, {self._sequence} were emitted"
                )
                return False, errors
            if prev != self._prev_hash:
                errors.append("chain head mismatch: stored tail differs from emitted tail")
                return False, errors
        return True, errors
