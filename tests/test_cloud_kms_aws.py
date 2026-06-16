"""Integration test for :class:`AWSKMSKeyProvider` against LocalStack.

LocalStack's KMS service supports ``CreateKey`` with HMAC key specs, so we can
exercise the real boto3 ``generate_mac`` / ``verify_mac`` calls without
touching live AWS. The whole module is skipped on a minimal venv.
"""

from __future__ import annotations

import os
import socket
import time

import pytest

try:
    import boto3
    from testcontainers.core.container import DockerContainer

    _MISSING: str | None = None
except ImportError as exc:
    _MISSING = str(exc)

from tests._docker_guard import docker_daemon_reachable

pytestmark = [
    pytest.mark.integration,
    pytest.mark.slow,
    pytest.mark.skipif(_MISSING is not None, reason=f"deps missing: {_MISSING}"),
    pytest.mark.skipif(not docker_daemon_reachable(), reason="docker daemon not reachable"),
]


@pytest.fixture(scope="module")
def localstack_kms() -> str:
    """Spin up LocalStack with KMS enabled; yield the endpoint URL."""
    container = (
        DockerContainer("localstack/localstack:3.6")
        .with_exposed_ports(4566)
        .with_env("SERVICES", "kms")
        .with_env("DEBUG", "0")
    )
    container.start()
    try:
        host = container.get_container_host_ip()
        port = int(container.get_exposed_port(4566))
        endpoint = f"http://{host}:{port}"

        # Wait until LocalStack's KMS service is accepting connections.
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                with socket.create_connection((host, port), timeout=1):
                    break
            except OSError:
                time.sleep(0.5)
        else:  # pragma: no cover
            raise RuntimeError("LocalStack KMS port never opened")
        # Sleep a beat for service init beyond TCP readiness.
        time.sleep(2)
        yield endpoint
    finally:
        container.stop()


@pytest.fixture
def kms_key(localstack_kms: str) -> str:
    """Create a fresh HMAC-256 KMS key in LocalStack; return its KeyId."""
    os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
    os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
    client = boto3.client("kms", region_name="us-east-1", endpoint_url=localstack_kms)
    resp = client.create_key(KeyUsage="GENERATE_VERIFY_MAC", KeySpec="HMAC_256")
    return resp["KeyMetadata"]["KeyId"]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


from clinicsentry.meddevice.cloud_kms import AWSKMSKeyProvider  # noqa: E402


def test_aws_kms_sign_returns_bytes(localstack_kms: str, kms_key: str) -> None:
    provider = AWSKMSKeyProvider(key_id=kms_key, endpoint_url=localstack_kms)
    sig = provider.sign(b"hello")
    assert isinstance(sig, bytes)
    assert len(sig) >= 32  # HMAC-SHA256 is 32 bytes


def test_aws_kms_verify_accepts_valid_signature(localstack_kms: str, kms_key: str) -> None:
    provider = AWSKMSKeyProvider(key_id=kms_key, endpoint_url=localstack_kms)
    data = b"clinical-event-payload"
    sig = provider.sign(data)
    assert provider.verify(data, sig) is True


def test_aws_kms_verify_rejects_corrupted_signature(localstack_kms: str, kms_key: str) -> None:
    provider = AWSKMSKeyProvider(key_id=kms_key, endpoint_url=localstack_kms)
    data = b"clinical-event-payload"
    sig = provider.sign(data)
    bad = b"\x00" * len(sig)
    assert provider.verify(data, bad) is False


def test_aws_kms_current_key_id_includes_namespace(localstack_kms: str, kms_key: str) -> None:
    provider = AWSKMSKeyProvider(key_id=kms_key, endpoint_url=localstack_kms)
    kid = provider.current_key_id()
    assert kid.startswith("aws-kms:")
    assert kms_key in kid
