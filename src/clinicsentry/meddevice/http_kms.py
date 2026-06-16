"""HTTP KMS-backed key provider for self-hosted vault deployments.

Implements the :class:`clinicsentry.meddevice.keys.KeyProvider` protocol
against any HTTP-based KMS that exposes ``sign`` and ``verify`` endpoints,
with first-class support for **HashiCorp Vault Transit** secrets engine.

Vault Transit setup::

    vault secrets enable transit
    vault write -f transit/keys/clinicsentry type=hmac

Usage::

    from clinicsentry.meddevice.http_kms import HTTPKMSKeyProvider

    provider = HTTPKMSKeyProvider(
        base_url="http://localhost:8200",
        key_name="clinicsentry",
        auth_token="hvs.xxxx",  # or use VAULT_TOKEN env var
    )
    sig = provider.sign(b"audit-event-bytes")
    assert provider.verify(b"audit-event-bytes", sig)

The provider uses ``urllib.request`` (stdlib) to avoid adding ``requests`` as
a hard dependency. For production, consider setting ``timeout`` appropriately.
"""

from __future__ import annotations

import base64
import hmac as hmac_mod
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "HTTPKMSKeyProvider",
]


@dataclass
class HTTPKMSKeyProvider:
    """HTTP-based HMAC signer compatible with HashiCorp Vault Transit.

    Args:
        base_url: Vault server URL, e.g. ``http://localhost:8200``.
        key_name: Name of the transit key (must be ``type=hmac``).
        auth_token: Vault token. Falls back to ``VAULT_TOKEN`` env var.
        mount_path: Transit secrets engine mount path.
        hash_algorithm: Hash algorithm for HMAC (``sha2-256``, ``sha2-384``,
            ``sha2-512``).
        timeout: HTTP request timeout in seconds.
        _client: Optional pre-built callable for testing. Signature:
            ``(method, url, body) -> response_dict``.
    """

    base_url: str = "http://localhost:8200"
    key_name: str = "clinicsentry"
    auth_token: str = ""
    mount_path: str = "transit"
    hash_algorithm: str = "sha2-256"
    timeout: float = 5.0
    _client: Any = field(default=None, init=True, repr=False)

    def __post_init__(self) -> None:
        """Resolve auth token from env if not provided."""
        if not self.auth_token:
            self.auth_token = os.environ.get("VAULT_TOKEN", "")

    def _request(
        self, method: str, path: str, body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Make an HTTP request to the Vault API."""
        if self._client is not None:
            url = f"{self.base_url}/v1/{self.mount_path}/{path}"
            return self._client(method, url, body)  # type: ignore[no-any-return]

        url = f"{self.base_url}/v1/{self.mount_path}/{path}"
        data = json.dumps(body).encode() if body else None
        req = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "X-Vault-Token": self.auth_token,
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310  # nosec B310 - operator-configured KMS/Vault endpoint
                return json.loads(resp.read())  # type: ignore[no-any-return]
        except urllib.error.HTTPError as exc:
            body_text = exc.read().decode() if exc.fp else ""
            raise RuntimeError(f"Vault HTTP {exc.code} on {method} {url}: {body_text}") from exc

    def sign(self, data: bytes) -> bytes:
        """Compute HMAC via Vault Transit ``hmac/<key_name>``."""
        b64_input = base64.b64encode(data).decode()
        resp = self._request(
            "POST",
            f"hmac/{self.key_name}",
            body={
                "input": b64_input,
                "algorithm": self.hash_algorithm,
            },
        )
        # Vault returns: {"data": {"hmac": "vault:v1:<base64>"}}
        hmac_str = resp["data"]["hmac"]
        # Strip the "vault:v1:" prefix
        b64_sig = hmac_str.split(":")[-1]
        return base64.b64decode(b64_sig)

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Verify HMAC via Vault Transit ``verify/<key_name>``.

        Falls back to local constant-time compare if the verify endpoint
        is unavailable.
        """
        b64_input = base64.b64encode(data).decode()
        b64_sig = base64.b64encode(signature).decode()
        # Vault expects the full "vault:v1:<base64>" format
        vault_hmac = f"vault:v1:{b64_sig}"
        try:
            resp = self._request(
                "POST",
                f"verify/{self.key_name}",
                body={
                    "input": b64_input,
                    "hmac": vault_hmac,
                    "algorithm": self.hash_algorithm,
                },
            )
            return bool(resp["data"]["valid"])
        except Exception:
            # Fallback: re-sign and compare
            expected = self.sign(data)
            return hmac_mod.compare_digest(expected, signature)

    def current_key_id(self) -> str:
        """Return the namespaced Vault Transit key identifier."""
        return f"vault-transit:{self.base_url}/{self.mount_path}/{self.key_name}"
