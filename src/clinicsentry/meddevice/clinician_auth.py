"""Clinician authorization for Class B/C autonomous actions.

The authorization flow accepts an Ed25519-signed authorization token from a
trusted clinician keypair. The token's payload includes the action name, the
session id, and a short-lived nonce; this guarantees per-call freshness and
prevents replay across sessions.

A FastAPI mobile-companion flow (out of scope for this module) generates the
signed tokens; this file only validates them.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass, field
from typing import Any

from clinicsentry.meddevice.nonces import InMemoryNonceStore, NonceStore

__all__ = [
    "ClinicianAuthError",
    "AuthorizationToken",
    "ClinicianAuthValidator",
]


class ClinicianAuthError(Exception):
    """Raised when an authorization token fails validation."""


@dataclass
class AuthorizationToken:
    """Decoded clinician authorization token."""

    clinician_id: str
    session_id: str
    action_name: str
    issued_at: int
    nonce: str
    args_hash: str = ""

    @classmethod
    def decode(cls, blob: str) -> AuthorizationToken:
        """Decode a base64 JSON payload."""
        try:
            payload = json.loads(base64.b64decode(blob))
        except (ValueError, OSError) as exc:
            raise ClinicianAuthError("malformed token") from exc
        try:
            return cls(
                clinician_id=str(payload["clinician_id"]),
                session_id=str(payload["session_id"]),
                action_name=str(payload["action_name"]),
                issued_at=int(payload["issued_at"]),
                nonce=str(payload["nonce"]),
                args_hash=str(payload.get("args_hash", "")),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ClinicianAuthError("missing required token fields") from exc

    def encode(self) -> bytes:
        """Encode for signing (raw JSON bytes).

        ``args_hash`` is only included when set, so tokens issued before
        argument binding existed keep verifying.
        """
        payload: dict[str, Any] = {
            "clinician_id": self.clinician_id,
            "session_id": self.session_id,
            "action_name": self.action_name,
            "issued_at": self.issued_at,
            "nonce": self.nonce,
        }
        if self.args_hash:
            payload["args_hash"] = self.args_hash
        return json.dumps(payload, sort_keys=True).encode()


@dataclass
class ClinicianAuthValidator:
    """Validate Ed25519-signed clinician authorization tokens.

    ``public_keys`` maps clinician ids to PEM/DER-encoded Ed25519 public keys.
    The validator enforces a ``max_age_seconds`` window, rejects tokens dated
    more than ``clock_skew_seconds`` in the future, and rejects replayed
    nonces via ``nonce_store`` (process-local by default; supply a shared
    store for multi-replica deployments).
    """

    public_keys: dict[str, bytes]
    max_age_seconds: int = 120
    clock_skew_seconds: int = 30
    nonce_store: NonceStore = field(default_factory=InMemoryNonceStore)

    def validate(
        self,
        token_blob: str,
        signature: bytes,
        *,
        expected_session_id: str | None = None,
        expected_action: str | None = None,
        expected_args_hash: str | None = None,
    ) -> AuthorizationToken:
        """Validate the token; return the decoded payload or raise.

        When ``expected_*`` values are given the token must be bound to them;
        a token for another session, action or argument set is rejected.
        """
        try:  # pragma: no cover - optional dep
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.serialization import load_pem_public_key
        except ImportError as exc:  # pragma: no cover
            raise ClinicianAuthError(
                "cryptography is required for clinician authorization; "
                "pip install 'clinicsentry[signing]'"
            ) from exc

        token = AuthorizationToken.decode(token_blob)
        pub_pem = self.public_keys.get(token.clinician_id)
        if pub_pem is None:
            raise ClinicianAuthError(f"unknown clinician: {token.clinician_id}")

        now = int(time.time())
        if now - token.issued_at > self.max_age_seconds:
            raise ClinicianAuthError("token expired")
        if token.issued_at - now > self.clock_skew_seconds:
            raise ClinicianAuthError("token issued in the future")
        if expected_session_id is not None and token.session_id != expected_session_id:
            raise ClinicianAuthError("token bound to a different session")
        if expected_action is not None and token.action_name != expected_action:
            raise ClinicianAuthError("token bound to a different action")
        if expected_args_hash is not None and token.args_hash != expected_args_hash:
            raise ClinicianAuthError("token not bound to these arguments")

        try:
            public_key: Any = load_pem_public_key(pub_pem)
            public_key.verify(signature, token.encode())
        except (InvalidSignature, ValueError) as exc:
            raise ClinicianAuthError("invalid signature") from exc

        expires_at = token.issued_at + self.max_age_seconds + self.clock_skew_seconds
        if not self.nonce_store.add(f"{token.session_id}:{token.nonce}", expires_at):
            raise ClinicianAuthError("token replay detected")
        return token
