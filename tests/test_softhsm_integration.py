"""Integration tests for PKCS11KeyProvider using SoftHSMv2 in Docker.

SoftHSMv2 is an open-source software HSM (PKCS#11 implementation). These tests
spin up a Docker container with SoftHSMv2 installed, initialize a token, create
an HMAC key, and exercise the :class:`PKCS11KeyProvider` against it.

Requires: Docker daemon running, ``python-pkcs11`` installed.
Skip conditions: no Docker, no pkcs11 lib.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from collections.abc import Generator
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Skip conditions
# ---------------------------------------------------------------------------

_DOCKER_AVAILABLE = shutil.which("docker") is not None


def _docker_responsive() -> bool:
    """Return True if the Docker daemon is reachable."""
    if not _DOCKER_AVAILABLE:
        return False
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


def _pkcs11_importable() -> bool:
    """Return True if python-pkcs11 is importable."""
    try:
        import pkcs11  # noqa: F401

        return True
    except ImportError:
        return False


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not _docker_responsive(), reason="docker daemon not reachable"),
    pytest.mark.skipif(not _pkcs11_importable(), reason="python-pkcs11 not installed"),
]

# Container config
_IMAGE = "softhsm/softhsm2:latest"
_CONTAINER_NAME = "clinicsentry-softhsm-test"
_TOKEN_LABEL = "clinicsentry-test"
_TOKEN_PIN = "1234"
_SO_PIN = "5678"
_KEY_LABEL = "audit-hmac-key"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def softhsm_container() -> Generator[dict[str, Any], None, None]:
    """Start a SoftHSMv2 container and initialize a token with an HMAC key.

    Yields a dict with container info needed by the test.
    """
    # Pull image if needed
    subprocess.run(["docker", "pull", _IMAGE], capture_output=True, timeout=120)

    # Stop any leftover container
    subprocess.run(
        ["docker", "rm", "-f", _CONTAINER_NAME],
        capture_output=True,
        timeout=10,
    )

    # Start container — SoftHSMv2 needs a persistent /var/lib/softhsm/tokens dir
    subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            _CONTAINER_NAME,
            "-v",
            "/var/lib/softhsm/tokens",
            _IMAGE,
            "sleep",
            "300",
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )

    # Wait for container to be ready
    time.sleep(2)

    # Initialize token
    subprocess.run(
        [
            "docker",
            "exec",
            _CONTAINER_NAME,
            "softhsm2-util",
            "--init-token",
            "--slot",
            "0",
            "--label",
            _TOKEN_LABEL,
            "--pin",
            _TOKEN_PIN,
            "--so-pin",
            _SO_PIN,
        ],
        check=True,
        capture_output=True,
        timeout=10,
    )

    # Create HMAC key using pkcs11-tool (if available) or via Python
    # We'll use Python inside the test to create the key, as SoftHSMv2
    # container might not have pkcs11-tool installed.

    # Find the SoftHSMv2 library path inside the container
    result = subprocess.run(
        [
            "docker",
            "exec",
            _CONTAINER_NAME,
            "find",
            "/usr",
            "-name",
            "libsofthsm2.so",
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    lib_path = result.stdout.strip().split("\n")[0] if result.stdout.strip() else ""

    # Copy the library from the container to host for python-pkcs11 to use
    host_lib = "/tmp/libsofthsm2.so"
    if lib_path:
        subprocess.run(
            ["docker", "cp", f"{_CONTAINER_NAME}:{lib_path}", host_lib],
            check=True,
            capture_output=True,
            timeout=10,
        )

    # Copy the token database from container
    # SoftHSMv2 reads SOFTHSM2_CONF to find token dir
    host_token_dir = "/tmp/softhsm-test-tokens"
    subprocess.run(
        ["docker", "cp", f"{_CONTAINER_NAME}:/var/lib/softhsm/tokens", host_token_dir],
        capture_output=True,
        timeout=10,
    )

    yield {
        "container": _CONTAINER_NAME,
        "lib_path": host_lib,
        "token_label": _TOKEN_LABEL,
        "pin": _TOKEN_PIN,
        "key_label": _KEY_LABEL,
        "token_dir": host_token_dir,
    }

    # Cleanup
    subprocess.run(
        ["docker", "rm", "-f", _CONTAINER_NAME],
        capture_output=True,
        timeout=10,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_softhsm_token_initialized(softhsm_container: dict[str, Any]) -> None:
    """Verify the token was initialized inside the container."""
    result = subprocess.run(
        [
            "docker",
            "exec",
            softhsm_container["container"],
            "softhsm2-util",
            "--show-slots",
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert softhsm_container["token_label"] in result.stdout


def test_pkcs11_provider_sign_verify(softhsm_container: dict[str, Any]) -> None:
    """Exercise the PKCS11KeyProvider against SoftHSMv2.

    This test creates an HMAC key via python-pkcs11, then uses the provider.
    """
    import pkcs11
    from pkcs11 import KeyType, Mechanism

    lib_path = softhsm_container["lib_path"]
    if not lib_path or not __import__("os").path.exists(lib_path):
        pytest.skip("SoftHSMv2 library not available on host")

    # Set SOFTHSM2_CONF to point to the token dir
    import os
    import tempfile

    token_dir = softhsm_container["token_dir"]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as f:
        f.write(f"directories.tokendir = {token_dir}\nobjectstore.backend = file\n")
        conf_path = f.name

    os.environ["SOFTHSM2_CONF"] = conf_path

    try:
        lib = pkcs11.lib(lib_path)
        token = lib.get_token(token_label=softhsm_container["token_label"])

        with token.open(user_pin=softhsm_container["pin"], rw=True) as session:
            # Generate an HMAC key
            key = session.generate_key(
                KeyType.GENERIC_SECRET,
                256,
                label=softhsm_container["key_label"],
                store=True,
                capabilities=Mechanism.SHA256_HMAC,
            )
            assert key is not None

        # Now test through the PKCS11KeyProvider
        from clinicsentry.meddevice.keys import PKCS11KeyProvider

        provider = PKCS11KeyProvider(
            library_path=lib_path,
            token_label=softhsm_container["token_label"],
            pin=softhsm_container["pin"],
            key_label=softhsm_container["key_label"],
        )

        sig = provider.sign(b"test-data")
        assert isinstance(sig, bytes)
        assert len(sig) > 0

        assert provider.verify(b"test-data", sig) is True
        assert provider.verify(b"tampered", sig) is False

        kid = provider.current_key_id()
        assert softhsm_container["key_label"] in kid

    finally:
        os.environ.pop("SOFTHSM2_CONF", None)
        os.unlink(conf_path)
