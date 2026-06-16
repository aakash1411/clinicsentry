"""Unit tests for HTTPKMSKeyProvider using a fake Vault client.

No real Vault server is needed — the provider accepts an injected ``_client``
callable that simulates the Vault Transit HTTP API.
"""

from __future__ import annotations

import base64
import hashlib
import hmac

import pytest

from clinicsentry.meddevice.http_kms import HTTPKMSKeyProvider

# ---------------------------------------------------------------------------
# Fake Vault Transit client
# ---------------------------------------------------------------------------


class _FakeVaultClient:
    """Duck-typed stand-in for Vault Transit HTTP API."""

    def __init__(self, secret: bytes = b"fake-vault-secret") -> None:
        self.secret = secret
        self.calls: list[tuple[str, str, dict | None]] = []
        self.raise_on_verify = False

    def __call__(self, method: str, url: str, body: dict | None = None) -> dict:
        """Simulate a Vault API request."""
        self.calls.append((method, url, body))

        if "/hmac/" in url and method == "POST":
            assert body is not None
            input_bytes = base64.b64decode(body["input"])
            mac = hmac.new(self.secret, input_bytes, hashlib.sha256).digest()
            b64_mac = base64.b64encode(mac).decode()
            return {"data": {"hmac": f"vault:v1:{b64_mac}"}}

        if "/verify/" in url and method == "POST":
            if self.raise_on_verify:
                raise RuntimeError("verify endpoint unavailable")
            assert body is not None
            input_bytes = base64.b64decode(body["input"])
            expected = hmac.new(self.secret, input_bytes, hashlib.sha256).digest()
            # Parse the vault:v1:<base64> format
            sig_b64 = body["hmac"].split(":")[-1]
            actual = base64.b64decode(sig_b64)
            return {"data": {"valid": hmac.compare_digest(expected, actual)}}

        raise RuntimeError(f"Unexpected request: {method} {url}")


@pytest.fixture
def vault_provider() -> HTTPKMSKeyProvider:
    """Create a provider backed by the fake client."""
    return HTTPKMSKeyProvider(
        base_url="http://fake-vault:8200",
        key_name="test-key",
        auth_token="fake-token",
        _client=_FakeVaultClient(),
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_sign_returns_bytes(vault_provider: HTTPKMSKeyProvider) -> None:
    """Sign should return raw HMAC bytes."""
    sig = vault_provider.sign(b"hello")
    assert isinstance(sig, bytes)
    assert len(sig) == 32  # SHA-256


def test_sign_verify_roundtrip(vault_provider: HTTPKMSKeyProvider) -> None:
    """Sign then verify should succeed."""
    data = b"audit-event-payload"
    sig = vault_provider.sign(data)
    assert vault_provider.verify(data, sig) is True


def test_verify_rejects_bad_signature(vault_provider: HTTPKMSKeyProvider) -> None:
    """Verify should reject a tampered signature."""
    sig = vault_provider.sign(b"original")
    assert vault_provider.verify(b"tampered", sig) is False


def test_verify_falls_back_on_endpoint_error() -> None:
    """If the verify endpoint errors, fall back to sign + constant-time compare."""
    fake = _FakeVaultClient()
    fake.raise_on_verify = True
    provider = HTTPKMSKeyProvider(
        base_url="http://fake-vault:8200",
        key_name="test-key",
        auth_token="fake-token",
        _client=fake,
    )
    sig = provider.sign(b"payload")
    assert provider.verify(b"payload", sig) is True
    assert provider.verify(b"tampered", sig) is False


def test_current_key_id(vault_provider: HTTPKMSKeyProvider) -> None:
    """Key ID should include the Vault URL and key name."""
    kid = vault_provider.current_key_id()
    assert "vault-transit:" in kid
    assert "test-key" in kid
    assert "fake-vault" in kid


def test_sign_calls_correct_endpoint(vault_provider: HTTPKMSKeyProvider) -> None:
    """Sign should POST to /v1/transit/hmac/<key_name>."""
    vault_provider.sign(b"data")
    fake = vault_provider._client
    assert len(fake.calls) == 1
    method, url, body = fake.calls[0]
    assert method == "POST"
    assert "/v1/transit/hmac/test-key" in url
    assert body is not None
    assert "input" in body
    assert body["algorithm"] == "sha2-256"


def test_auth_token_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Auth token should fall back to VAULT_TOKEN env var."""
    monkeypatch.setenv("VAULT_TOKEN", "env-token-123")
    provider = HTTPKMSKeyProvider(key_name="k", _client=_FakeVaultClient())
    assert provider.auth_token == "env-token-123"


def test_auth_token_explicit_overrides_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Explicit auth_token should take precedence over env var."""
    monkeypatch.setenv("VAULT_TOKEN", "env-token")
    provider = HTTPKMSKeyProvider(
        key_name="k", auth_token="explicit-token", _client=_FakeVaultClient()
    )
    assert provider.auth_token == "explicit-token"
