"""Replay-protection nonce stores for clinician authorizations.

The default :class:`InMemoryNonceStore` protects a single process. Multi-replica
deployments should supply a shared implementation (Redis ``SET NX EX``, a
Postgres unique index, ...) satisfying the :class:`NonceStore` protocol.
"""

from __future__ import annotations

import threading
import time
from typing import Protocol, runtime_checkable

__all__ = [
    "InMemoryNonceStore",
    "NonceStore",
]


@runtime_checkable
class NonceStore(Protocol):
    """Atomic check-and-set store for single-use authorization nonces."""

    def add(self, key: str, expires_at: float) -> bool:
        """Record ``key`` until ``expires_at`` (unix seconds).

        Returns True if the key was newly recorded, False if it was already
        present and unexpired (i.e. a replay).
        """
        ...


class InMemoryNonceStore:
    """Thread-safe, process-local nonce store with expiry-based pruning."""

    def __init__(self) -> None:
        self._entries: dict[str, float] = {}
        self._lock = threading.Lock()

    def add(self, key: str, expires_at: float) -> bool:
        """Atomically record ``key``; False if it is already present."""
        now = time.time()
        with self._lock:
            expired = [k for k, exp in self._entries.items() if exp < now]
            for k in expired:
                del self._entries[k]
            if key in self._entries:
                return False
            self._entries[key] = expires_at
            return True

    def __len__(self) -> int:
        """Number of unexpired-or-unpruned nonces currently held."""
        return len(self._entries)
