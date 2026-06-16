"""Cloud KMS-backed key providers.

Three providers implement the :class:`clinicsentry.meddevice.keys.KeyProvider`
protocol against managed cloud KMS services:

- :class:`AWSKMSKeyProvider` — AWS KMS via boto3 ``generate_mac`` / ``verify_mac``.
- :class:`GCPKMSKeyProvider` — Google Cloud KMS ``MacSign`` / ``MacVerify``.
- :class:`AzureKeyVaultKeyProvider` — Azure Key Vault HMAC operations.

All providers are tested against **sandboxed** emulators (LocalStack for AWS,
respx-mocked HTTP for GCP and Azure) so the test suite never touches real
cloud infrastructure. See ``tests/test_cloud_kms_*.py``.

Each provider's SDK is loaded lazily inside ``__post_init__`` / methods so the
package stays importable on a minimal venv. Install:

```bash
pip install 'clinicsentry[cloud-kms]'
```
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "AWSKMSKeyProvider",
    "GCPKMSKeyProvider",
    "AzureKeyVaultKeyProvider",
]


@dataclass
class AWSKMSKeyProvider:
    """AWS KMS-backed HMAC signer.

    Uses ``generate_mac`` / ``verify_mac`` which require a KMS key with
    ``KeyUsage=GENERATE_VERIFY_MAC`` and ``KeySpec=HMAC_256``. The
    ``endpoint_url`` parameter lets tests point boto3 at LocalStack.

    Args:
        key_id: AWS KMS Key ID, ARN, or alias.
        region_name: AWS region for the boto3 client.
        endpoint_url: optional override for sandboxed testing (LocalStack).
        mac_algorithm: KMS MAC algorithm; defaults to ``HMAC_SHA_256``.
    """

    key_id: str
    region_name: str = "us-east-1"
    endpoint_url: str | None = None
    mac_algorithm: str = "HMAC_SHA_256"
    _client: Any = field(default=None, init=False, repr=False)

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            import boto3
        except ImportError as exc:  # pragma: no cover - optional dep
            raise ImportError(
                "AWSKMSKeyProvider requires boto3. "
                "Install: `pip install 'clinicsentry[cloud-kms]'`."
            ) from exc
        self._client = boto3.client(
            "kms",
            region_name=self.region_name,
            endpoint_url=self.endpoint_url,
        )
        return self._client

    def sign(self, data: bytes) -> bytes:
        """Compute an HMAC over ``data`` via KMS ``generate_mac``."""
        resp = self._get_client().generate_mac(
            KeyId=self.key_id,
            Message=data,
            MacAlgorithm=self.mac_algorithm,
        )
        return bytes(resp["Mac"])

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Verify ``signature`` over ``data`` via KMS ``verify_mac``.

        Falls back to constant-time comparison against a fresh ``generate_mac``
        result if the KMS endpoint doesn't implement ``verify_mac`` (some
        LocalStack tiers).
        """
        client = self._get_client()
        try:
            resp = client.verify_mac(
                KeyId=self.key_id,
                Message=data,
                MacAlgorithm=self.mac_algorithm,
                Mac=signature,
            )
            return bool(resp.get("MacValid"))
        except Exception:
            expected = self.sign(data)
            return hmac.compare_digest(expected, signature)

    def current_key_id(self) -> str:
        """Return the namespaced KMS key identifier."""
        return f"aws-kms:{self.region_name}:{self.key_id}"


@dataclass
class GCPKMSKeyProvider:
    """Google Cloud KMS-backed HMAC signer.

    Uses the MAC operations on a CryptoKey with purpose ``MAC`` and
    ``HMAC_SHA256`` algorithm.

    Args:
        resource_name: Fully qualified key resource, e.g.
            ``projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1``.
        client: optional pre-built ``KeyManagementServiceClient`` (for tests
            with a mocked / emulator-connected client).
    """

    resource_name: str
    client: Any = None

    def _get_client(self) -> Any:
        if self.client is not None:
            return self.client
        try:
            from google.cloud import kms
        except ImportError as exc:  # pragma: no cover - optional dep
            raise ImportError(
                "GCPKMSKeyProvider requires google-cloud-kms. "
                "Install: `pip install 'clinicsentry[cloud-kms]'`."
            ) from exc
        self.client = kms.KeyManagementServiceClient()
        return self.client

    def sign(self, data: bytes) -> bytes:
        """Compute HMAC via Google KMS ``mac_sign``."""
        client = self._get_client()
        response = client.mac_sign(request={"name": self.resource_name, "data": data})
        return bytes(response.mac)

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Verify HMAC via Google KMS ``mac_verify``."""
        client = self._get_client()
        try:
            response = client.mac_verify(
                request={"name": self.resource_name, "data": data, "mac": signature}
            )
            return bool(response.success)
        except Exception:
            expected = self.sign(data)
            return hmac.compare_digest(expected, signature)

    def current_key_id(self) -> str:
        """Return the namespaced GCP KMS key identifier."""
        return f"gcp-kms:{self.resource_name}"


@dataclass
class AzureKeyVaultKeyProvider:
    """Azure Key Vault-backed HMAC signer.

    Uses ``CryptographyClient.sign`` with HMAC algorithms against an
    octet-sequence (oct-HSM) key. Either a pre-built ``CryptographyClient`` or
    ``(vault_url, key_name, credential)`` may be supplied.

    Args:
        vault_url: Azure Key Vault URL, e.g. ``https://myvault.vault.azure.net``.
        key_name: Name of the HMAC-capable key inside the vault.
        credential: Optional explicit credential; defaults to
            ``DefaultAzureCredential`` when SDKs are installed.
        client: Optional pre-built ``CryptographyClient`` (for tests).
        algorithm: Azure signature algorithm; default ``"HS256"``.
    """

    vault_url: str = ""
    key_name: str = ""
    credential: Any = None
    client: Any = None
    algorithm: str = "HS256"

    def _get_client(self) -> Any:
        if self.client is not None:
            return self.client
        try:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.keys.crypto import CryptographyClient
        except ImportError as exc:  # pragma: no cover - optional dep
            raise ImportError(
                "AzureKeyVaultKeyProvider requires azure-keyvault-keys + azure-identity. "
                "Install: `pip install 'clinicsentry[cloud-kms]'`."
            ) from exc
        cred = self.credential or DefaultAzureCredential()
        key_id = f"{self.vault_url.rstrip('/')}/keys/{self.key_name}"
        self.client = CryptographyClient(key_id, cred)
        return self.client

    def sign(self, data: bytes) -> bytes:
        """Compute HMAC via Azure Key Vault ``sign``."""
        result = self._get_client().sign(self.algorithm, data)
        return bytes(result.signature)

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Verify HMAC via Azure Key Vault ``verify``."""
        client = self._get_client()
        try:
            result = client.verify(self.algorithm, data, signature)
            return bool(result.is_valid)
        except Exception:
            expected = self.sign(data)
            return hmac.compare_digest(expected, signature)

    def current_key_id(self) -> str:
        """Return the namespaced Azure Key Vault key identifier."""
        return f"azure-kv:{self.vault_url}/{self.key_name}"
