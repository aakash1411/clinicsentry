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
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ClinicianAuthError("missing required token fields") from exc

    def encode(self) -> bytes:
        """Encode for signing (raw JSON bytes)."""
        return json.dumps(
            {
                "clinician_id": self.clinician_id,
                "session_id": self.session_id,
                "action_name": self.action_name,
                "issued_at": self.issued_at,
                "nonce": self.nonce,
            },
            sort_keys=True,
        ).encode()


@dataclass
class ClinicianAuthValidator:
    """Validate Ed25519-signed clinician authorization tokens.

    ``public_keys`` maps clinician ids to PEM/DER-encoded Ed25519 public keys.
    The validator enforces a ``max_age_seconds`` window and rejects replayed
    nonces.
    """

    public_keys: dict[str, bytes]
    max_age_seconds: int = 120
    _seen_nonces: set[tuple[str, str]] = field(default_factory=set, init=False)

    def validate(self, token_blob: str, signature: bytes) -> AuthorizationToken:
        """Validate the token; return the decoded payload or raise."""
        try:  # pragma: no cover - optional dep
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.serialization import load_pem_public_key
        except ImportError as exc:  # pragma: no cover
            raise ClinicianAuthError(
                "cryptography is required for clinician authorization"
            ) from exc

        token = AuthorizationToken.decode(token_blob)
        pub_pem = self.public_keys.get(token.clinician_id)
        if pub_pem is None:
            raise ClinicianAuthError(f"unknown clinician: {token.clinician_id}")

        now = int(time.time())
        if now - token.issued_at > self.max_age_seconds:
            raise ClinicianAuthError("token expired")
        nonce_key = (token.session_id, token.nonce)
        if nonce_key in self._seen_nonces:
            raise ClinicianAuthError("token replay detected")

        try:
            public_key: Any = load_pem_public_key(pub_pem)
            public_key.verify(signature, token.encode())
        except (InvalidSignature, ValueError) as exc:
            raise ClinicianAuthError("invalid signature") from exc

        self._seen_nonces.add(nonce_key)
        return token
