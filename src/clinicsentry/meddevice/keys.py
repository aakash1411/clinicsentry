"""Key providers for ClinicSentry cryptographic operations (ADR-0005).

Three implementations ship in v1:

- :class:`SoftwareKeyProvider` (default, research-only)
- :class:`EnvKeyProvider` (env var base64; for containerized deployments)
- :class:`PKCS11KeyProvider` (HSM-backed; optional ``clinicsentry[hsm]`` extra)

All providers expose ``sign(data) -> bytes`` and ``verify(data, sig) -> bool``
plus ``current_key_id() -> str`` so the audit chain can record which key
signed each event.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from dataclasses import dataclass, field
from typing import Any, Protocol

__all__ = [
    "KeyProvider",
    "SoftwareKeyProvider",
    "EnvKeyProvider",
    "PKCS11KeyProvider",
]


class KeyProvider(Protocol):
    """Structural type for an HMAC signing key source."""

    def sign(self, data: bytes) -> bytes:  # pragma: no cover - protocol
        """Return an HMAC signature over ``data``."""
        ...

    def verify(self, data: bytes, signature: bytes) -> bool:  # pragma: no cover - protocol
        """Constant-time verify of ``signature`` against ``data``."""
        ...

    def current_key_id(self) -> str:  # pragma: no cover - protocol
        """Stable identifier of the key currently in use (for rotation audit)."""
        ...


@dataclass
class SoftwareKeyProvider:
    """In-process software key. RESEARCH USE ONLY — see RESPONSIBLE_USE.md."""

    key: bytes = field(default_factory=lambda: os.urandom(32))
    key_id: str = "software-default"

    def sign(self, data: bytes) -> bytes:
        """Compute HMAC-SHA256 over ``data``."""
        return hmac.new(self.key, data, hashlib.sha256).digest()

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Constant-time HMAC verify."""
        return hmac.compare_digest(self.sign(data), signature)

    def current_key_id(self) -> str:
        """Return the static key id."""
        return self.key_id


@dataclass
class EnvKeyProvider:
    """Key loaded from an environment variable (base64-encoded)."""

    env_var: str = "CLINICSENTRY_HMAC_KEY"
    key_id: str = "env"
    _key: bytes = field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Decode the key at construction time so misconfig fails fast."""
        raw = os.environ.get(self.env_var)
        if not raw:
            raise RuntimeError(f"Env var {self.env_var} not set; cannot construct EnvKeyProvider.")
        self._key = base64.b64decode(raw)
        if len(self._key) < 32:
            raise RuntimeError(f"{self.env_var} must decode to >= 32 bytes")

    def sign(self, data: bytes) -> bytes:
        """HMAC-SHA256 over ``data``."""
        return hmac.new(self._key, data, hashlib.sha256).digest()

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Constant-time HMAC verify."""
        return hmac.compare_digest(self.sign(data), signature)

    def current_key_id(self) -> str:
        """Return the configured key id."""
        return self.key_id


@dataclass
class PKCS11KeyProvider:
    """HSM-backed signer via PKCS#11. Requires ``clinicsentry[hsm]``.

    The provider lazily opens a session on first sign/verify call so process
    fork-safety is preserved. ``key_label`` selects the HSM-stored secret key.
    """

    library_path: str
    token_label: str
    pin: str
    key_label: str
    key_id: str = "hsm"
    _session: Any = field(default=None, init=False, repr=False)

    def _ensure_session(self) -> Any:
        """Open the PKCS#11 session if not already open."""
        if self._session is not None:
            return self._session
        try:  # pragma: no cover - optional dep
            import pkcs11
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "PKCS11KeyProvider requires python-pkcs11. "
                "Install: `pip install 'clinicsentry[hsm]'`."
            ) from exc

        lib = pkcs11.lib(self.library_path)
        token = lib.get_token(token_label=self.token_label)
        self._session = token.open(user_pin=self.pin)
        return self._session

    def _key_handle(self) -> Any:
        """Resolve the secret key handle inside the session."""
        import pkcs11

        session = self._ensure_session()
        return session.get_key(label=self.key_label, key_type=pkcs11.KeyType.GENERIC_SECRET)

    def sign(self, data: bytes) -> bytes:
        """HMAC-SHA256 via the HSM."""
        try:  # pragma: no cover - HSM-only path
            import pkcs11

            mechanism = pkcs11.Mechanism.SHA256_HMAC
            return bytes(self._key_handle().sign(data, mechanism=mechanism))
        except ImportError:  # pragma: no cover
            raise

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Constant-time verify via the HSM."""
        return hmac.compare_digest(self.sign(data), signature)

    def current_key_id(self) -> str:
        """Return the configured HSM key id."""
        return f"hsm:{self.key_label}"
