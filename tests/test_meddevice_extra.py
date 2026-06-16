"""Tests for CIA generator, IEC 62304 Ed2 mapping, and key providers."""

from __future__ import annotations

import base64
import os

import pytest

from clinicsentry.meddevice import (
    DeploymentSnapshot,
    EnvKeyProvider,
    SoftwareKeyProvider,
    SoftwareSafetyClass,
    build_cia,
    translate_to_edition2,
)

# --- CIA generator --------------------------------------------------------


def test_cia_flags_safety_class_upgrade() -> None:
    base = DeploymentSnapshot(version="1.0", safety_class=SoftwareSafetyClass.A)
    target = DeploymentSnapshot(version="2.0", safety_class=SoftwareSafetyClass.B)
    cia = build_cia(base, target)
    assert "safety_class_upgrade" in cia.regulator_flags
    assert "safety_class" in cia.diffs


def test_cia_flags_dose_range_expansion_per_role() -> None:
    base = DeploymentSnapshot(version="1.0", dose_ranges={"basal": (0.0, 5.0)})
    target = DeploymentSnapshot(version="1.1", dose_ranges={"basal": (0.0, 6.0)})
    cia = build_cia(base, target)
    assert "dose_range_expansion:basal" in cia.regulator_flags


def test_cia_flags_rate_limit_relaxation() -> None:
    base = DeploymentSnapshot(version="1.0", rate_limit_per_hour=6)
    target = DeploymentSnapshot(version="1.1", rate_limit_per_hour=12)
    cia = build_cia(base, target)
    assert "rate_limit_relaxation" in cia.regulator_flags


def test_cia_no_flags_for_identical_snapshots() -> None:
    snap = DeploymentSnapshot(version="1.0")
    cia = build_cia(snap, snap)
    assert cia.regulator_flags == []
    assert cia.diffs == {}


def test_cia_to_dict_is_serializable() -> None:
    base = DeploymentSnapshot(version="1.0")
    target = DeploymentSnapshot(version="2.0")
    cia = build_cia(base, target)
    payload = cia.to_dict()
    assert payload["base_version"] == "1.0"
    assert payload["target_version"] == "2.0"


# --- IEC 62304 Ed2 mapping ------------------------------------------------


def test_iec_edition2_class_b_maps_to_rigor_level_ii() -> None:
    rl = translate_to_edition2(SoftwareSafetyClass.B)
    assert rl.code == "II"
    assert "Architecture Document" in rl.required_documents


def test_iec_edition2_class_c_requires_anomaly_resolution() -> None:
    rl = translate_to_edition2(SoftwareSafetyClass.C)
    assert "Anomaly Resolution Procedure" in rl.required_documents


# --- Key providers --------------------------------------------------------


def test_software_key_provider_signs_and_verifies() -> None:
    kp = SoftwareKeyProvider(key=b"x" * 32, key_id="test")
    sig = kp.sign(b"hello")
    assert kp.verify(b"hello", sig) is True
    assert kp.verify(b"world", sig) is False
    assert kp.current_key_id() == "test"


def test_env_key_provider_reads_base64_env(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = base64.b64encode(b"y" * 32).decode()
    monkeypatch.setenv("CLINICSENTRY_HMAC_KEY", raw)
    kp = EnvKeyProvider()
    sig = kp.sign(b"payload")
    assert kp.verify(b"payload", sig) is True


def test_env_key_provider_rejects_short_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CLINICSENTRY_HMAC_KEY", base64.b64encode(b"short").decode())
    with pytest.raises(RuntimeError, match=">= 32 bytes"):
        EnvKeyProvider()


def test_env_key_provider_rejects_missing_env() -> None:
    os.environ.pop("CLINICSENTRY_HMAC_KEY", None)
    with pytest.raises(RuntimeError, match="not set"):
        EnvKeyProvider()
