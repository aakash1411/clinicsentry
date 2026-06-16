"""Unit tests for GCP + Azure KMS providers using fake clients.

These tests do not need any cloud emulator: the providers accept an injected
``client`` object and we use a hand-rolled fake that satisfies the duck-typed
SDK surface. This keeps the suite green on a minimal venv and proves the
provider wiring is correct independently of the live SDKs.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

import pytest

from clinicsentry.meddevice.cloud_kms import (
    AzureKeyVaultKeyProvider,
    GCPKMSKeyProvider,
)

# ---------------------------------------------------------------------------
# Fake GCP KMS client
# ---------------------------------------------------------------------------


@dataclass
class _GCPMacResponse:
    mac: bytes


@dataclass
class _GCPVerifyResponse:
    success: bool


class _FakeGCPClient:
    """Duck-typed stand-in for ``google.cloud.kms.KeyManagementServiceClient``."""

    def __init__(self, secret: bytes = b"fake-gcp-secret") -> None:
        self.secret = secret
        self.sign_calls: list[dict] = []
        self.verify_calls: list[dict] = []
        self.raise_on_verify = False

    def mac_sign(self, request: dict) -> _GCPMacResponse:
        self.sign_calls.append(request)
        mac = hmac.new(self.secret, request["data"], hashlib.sha256).digest()
        return _GCPMacResponse(mac=mac)

    def mac_verify(self, request: dict) -> _GCPVerifyResponse:
        if self.raise_on_verify:
            raise RuntimeError("emulator does not implement mac_verify")
        self.verify_calls.append(request)
        expected = hmac.new(self.secret, request["data"], hashlib.sha256).digest()
        return _GCPVerifyResponse(success=hmac.compare_digest(expected, request["mac"]))


@pytest.fixture
def gcp_provider() -> GCPKMSKeyProvider:
    return GCPKMSKeyProvider(
        resource_name="projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
        client=_FakeGCPClient(),
    )


def test_gcp_sign_returns_bytes_and_calls_mac_sign(
    gcp_provider: GCPKMSKeyProvider,
) -> None:
    sig = gcp_provider.sign(b"x")
    assert isinstance(sig, bytes)
    assert len(sig) == 32  # SHA-256
    fake = gcp_provider.client
    assert len(fake.sign_calls) == 1
    assert fake.sign_calls[0]["data"] == b"x"
    assert fake.sign_calls[0]["name"].endswith("cryptoKeyVersions/1")


def test_gcp_verify_roundtrip(gcp_provider: GCPKMSKeyProvider) -> None:
    sig = gcp_provider.sign(b"payload")
    assert gcp_provider.verify(b"payload", sig) is True
    assert gcp_provider.verify(b"payload", b"\x00" * 32) is False


def test_gcp_verify_falls_back_when_emulator_lacks_mac_verify() -> None:
    """If mac_verify raises, the provider must fall back to constant-time compare."""
    fake = _FakeGCPClient()
    fake.raise_on_verify = True
    provider = GCPKMSKeyProvider(
        resource_name="projects/p/locations/l/keyRings/r/cryptoKeys/k", client=fake
    )
    sig = provider.sign(b"payload")
    assert provider.verify(b"payload", sig) is True
    assert provider.verify(b"payload", b"bad" + b"\x00" * 29) is False


def test_gcp_current_key_id_includes_resource() -> None:
    provider = GCPKMSKeyProvider(
        resource_name="projects/p/locations/l/keyRings/r/cryptoKeys/k", client=_FakeGCPClient()
    )
    assert provider.current_key_id() == "gcp-kms:projects/p/locations/l/keyRings/r/cryptoKeys/k"


# ---------------------------------------------------------------------------
# Fake Azure Key Vault CryptographyClient
# ---------------------------------------------------------------------------


@dataclass
class _AzSignResult:
    signature: bytes


@dataclass
class _AzVerifyResult:
    is_valid: bool


class _FakeAzureCryptoClient:
    """Stand-in for ``azure.keyvault.keys.crypto.CryptographyClient``."""

    def __init__(self, secret: bytes = b"fake-azure-secret") -> None:
        self.secret = secret
        self.sign_calls: list[tuple[str, bytes]] = []
        self.verify_calls: list[tuple[str, bytes, bytes]] = []
        self.raise_on_verify = False

    def sign(self, algorithm: str, data: bytes) -> _AzSignResult:
        self.sign_calls.append((algorithm, data))
        return _AzSignResult(signature=hmac.new(self.secret, data, hashlib.sha256).digest())

    def verify(self, algorithm: str, data: bytes, signature: bytes) -> _AzVerifyResult:
        if self.raise_on_verify:
            raise RuntimeError("emulator does not implement verify")
        self.verify_calls.append((algorithm, data, signature))
        expected = hmac.new(self.secret, data, hashlib.sha256).digest()
        return _AzVerifyResult(is_valid=hmac.compare_digest(expected, signature))


@pytest.fixture
def azure_provider() -> AzureKeyVaultKeyProvider:
    return AzureKeyVaultKeyProvider(
        vault_url="https://myvault.vault.azure.net",
        key_name="audit-hmac",
        client=_FakeAzureCryptoClient(),
    )


def test_azure_sign_uses_default_algorithm(
    azure_provider: AzureKeyVaultKeyProvider,
) -> None:
    sig = azure_provider.sign(b"x")
    assert isinstance(sig, bytes)
    assert len(sig) == 32
    fake = azure_provider.client
    assert fake.sign_calls == [("HS256", b"x")]


def test_azure_verify_roundtrip(azure_provider: AzureKeyVaultKeyProvider) -> None:
    sig = azure_provider.sign(b"audit-payload")
    assert azure_provider.verify(b"audit-payload", sig) is True
    assert azure_provider.verify(b"audit-payload", b"\x00" * 32) is False


def test_azure_verify_falls_back_when_sdk_raises() -> None:
    fake = _FakeAzureCryptoClient()
    fake.raise_on_verify = True
    provider = AzureKeyVaultKeyProvider(
        vault_url="https://v.vault.azure.net", key_name="k", client=fake
    )
    sig = provider.sign(b"payload")
    assert provider.verify(b"payload", sig) is True
    assert provider.verify(b"payload", b"bad" + b"\x00" * 29) is False


def test_azure_current_key_id_includes_vault_and_name() -> None:
    provider = AzureKeyVaultKeyProvider(
        vault_url="https://v.vault.azure.net", key_name="k", client=_FakeAzureCryptoClient()
    )
    assert provider.current_key_id() == "azure-kv:https://v.vault.azure.net/k"


# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------


def test_providers_conform_to_keyprovider_protocol(
    gcp_provider: GCPKMSKeyProvider, azure_provider: AzureKeyVaultKeyProvider
) -> None:
    """Both providers must look like KeyProvider duck-types: sign/verify/current_key_id."""
    for provider in (gcp_provider, azure_provider):
        assert callable(provider.sign)
        assert callable(provider.verify)
        assert callable(provider.current_key_id)
        sig = provider.sign(b"d")
        assert isinstance(sig, bytes)
        assert provider.verify(b"d", sig) is True
        assert isinstance(provider.current_key_id(), str)
