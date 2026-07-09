"""Policy YAML loader.

Schema (v0.1) — example::

    phi_firewall:
      mode: REDACT
      use_presidio: false
      decode_encoded: true
      max_depth: 64
      overrides:
        DATE: GENERALIZE
        ZIP: GENERALIZE
    escalation:
      thresholds:
        informational: 0.6
        advisory: 0.8
      on_unregistered_action: escalate
    audit:
      backend: file
      path: ./audit.log
      retention_years: 7
    meddevice_mode:
      enabled: true
      software_safety_class: B
      device_type: closed_loop_drug_delivery
      intended_use: dosage advisory
      manufacturer: Acme
      strict_dose_ranges: true
      dose_ranges:
        - parameter: basal_rate_u_per_hr
          min: 0.0
          max: 5.0
          unit: U/hr
      rate_limit_per_hour: 6

Loading is strict: unknown keys and out-of-range values raise
:class:`~clinicsentry.errors.PolicyError` naming the offending field —
a typo'd block (e.g. ``meddevice_mod``) silently disabling enforcement would
fail open.
"""

from __future__ import annotations

import math
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from clinicsentry.errors import PolicyError
from clinicsentry.meddevice.mode import (
    DoseRange,
    MedDeviceConfig,
    SoftwareSafetyClass,
)
from clinicsentry.phi.redaction import RedactionMode
from clinicsentry.types import ClinicalRiskTier

__all__ = [
    "AuditPolicy",
    "PolicyConfig",
    "load_policy",
    "policy_schema",
]

_TOP_LEVEL_KEYS = {"version", "phi_firewall", "escalation", "audit", "meddevice_mode"}
_PHI_KEYS = {
    "mode",
    "use_presidio",
    "overrides",
    "decode_encoded",
    "max_depth",
    "allowlist",
    "detectors",
    "custom_detectors",
    "locales",
    "skip_fields",
    "always_redact_fields",
    "detector_backend",
}
_ESCALATION_KEYS = {"thresholds", "on_unregistered_action"}
_AUDIT_KEYS = {"backend", "path", "retention_years"}
_MEDDEVICE_KEYS = {
    "enabled",
    "software_safety_class",
    "device_type",
    "intended_use",
    "manufacturer",
    "udi",
    "dose_ranges",
    "rate_limit_per_hour",
    "strict_dose_ranges",
}
_DOSE_RANGE_KEYS = {"parameter", "min", "max", "min_value", "max_value", "unit"}


@dataclass
class AuditPolicy:
    """Audit-trail subset of policy."""

    backend: str = "memory"
    path: str = ""
    retention_years: int = 7


@dataclass
class PolicyConfig:
    """Top-level parsed policy."""

    phi_mode: RedactionMode = RedactionMode.REDACT
    phi_overrides: dict[str, RedactionMode] = field(default_factory=dict)
    use_presidio: bool = False
    decode_encoded: bool = True
    max_scan_depth: int = 64
    phi_allowlist: dict[str, list[str]] = field(default_factory=dict)
    phi_detectors: list[str] | None = None
    phi_locales: list[str] = field(default_factory=list)
    phi_custom_detectors: list[dict[str, Any]] = field(default_factory=list)
    phi_skip_fields: list[str] = field(default_factory=list)
    phi_always_redact_fields: list[str] = field(default_factory=list)
    phi_detector_backend: str | None = None
    escalation_thresholds: dict[ClinicalRiskTier, float] = field(default_factory=dict)
    on_unregistered_action: str = "escalate"
    audit: AuditPolicy = field(default_factory=AuditPolicy)
    meddevice: MedDeviceConfig = field(default_factory=MedDeviceConfig)
    raw: dict[str, Any] = field(default_factory=dict)
    version: str = "0.1.0"


_ENV_PREFIX = "CLINICSENTRY_"
# Longest-first so CLINICSENTRY_PHI_FIREWALL_MODE resolves to section
# "phi_firewall", key "mode" despite the embedded underscore.
_ENV_SECTIONS = sorted(_TOP_LEVEL_KEYS - {"version"}, key=len, reverse=True)


def _apply_env_overrides(data: dict[str, Any], environ: Mapping[str, str]) -> dict[str, Any]:
    """Overlay ``CLINICSENTRY_<SECTION>_<KEY>`` env vars onto ``data`` (ADR-0012).

    Nested keys use a double underscore, e.g.
    ``CLINICSENTRY_ESCALATION_THRESHOLDS__ADVISORY=0.9``. Values are parsed as
    YAML scalars so booleans and numbers round-trip. Variables that do not match
    a known policy section (e.g. ``CLINICSENTRY_HMAC_KEY``) are ignored —
    secrets are never policy fields.
    """
    out = {k: dict(v) if isinstance(v, dict) else v for k, v in data.items()}
    for name, raw in environ.items():
        if not name.startswith(_ENV_PREFIX):
            continue
        rest = name[len(_ENV_PREFIX) :].lower()
        section = next((s for s in _ENV_SECTIONS if rest == s or rest.startswith(s + "_")), None)
        if section is None:
            continue
        key_path = rest[len(section) + 1 :]
        if not key_path:
            continue
        try:
            value = yaml.safe_load(raw)
        except yaml.YAMLError:
            value = raw
        target = out.setdefault(section, {})
        if not isinstance(target, dict):
            raise PolicyError(f"cannot apply env override {name}: {section} is not a mapping")
        parts = key_path.split("__")
        for part in parts[:-1]:
            target = target.setdefault(part, {})
            if not isinstance(target, dict):
                raise PolicyError(f"cannot apply env override {name}: {part} is not a mapping")
        target[parts[-1]] = value
    return out


def _require_keys(block: dict[str, Any], allowed: set[str], where: str) -> None:
    """Raise PolicyError on unrecognized keys (typos fail open otherwise)."""
    unknown = set(block) - allowed
    if unknown:
        raise PolicyError(
            f"unknown {where} key(s): {sorted(unknown)}; allowed: {sorted(allowed)}",
            context={"where": where, "unknown": sorted(unknown)},
        )


def _require_mapping(value: Any, where: str) -> dict[str, Any]:
    """Coerce a possibly-None YAML block into a dict or raise PolicyError."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise PolicyError(f"{where} must be a mapping, got {type(value).__name__}")
    return value


@dataclass
class _PhiPolicy:
    """Parsed phi_firewall block (internal carrier)."""

    mode: RedactionMode
    overrides: dict[str, RedactionMode]
    use_presidio: bool
    decode_encoded: bool
    max_depth: int
    allowlist: dict[str, list[str]]
    detectors: list[str] | None
    locales: list[str]
    custom_detectors: list[dict[str, Any]]
    skip_fields: list[str]
    always_redact_fields: list[str]
    detector_backend: str | None


def _str_list(value: Any, where: str) -> list[str]:
    """Validate a policy value as a list of strings."""
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise PolicyError(f"{where} must be a list of strings, got {value!r}")
    return list(value)


def _parse_phi(block: dict[str, Any]) -> _PhiPolicy:
    """Parse and validate the phi_firewall block."""
    _require_keys(block, _PHI_KEYS, "phi_firewall")
    mode_raw = block.get("mode", "REDACT")
    try:
        mode = RedactionMode(mode_raw)
    except ValueError:
        raise PolicyError(
            f"invalid phi_firewall.mode {mode_raw!r}; expected one of "
            f"{[m.value for m in RedactionMode]}"
        ) from None
    overrides: dict[str, RedactionMode] = {}
    for k, v in _require_mapping(block.get("overrides"), "phi_firewall.overrides").items():
        try:
            overrides[str(k)] = RedactionMode(v)
        except ValueError:
            raise PolicyError(
                f"invalid phi_firewall.overrides[{k!r}] = {v!r}; expected one of "
                f"{[m.value for m in RedactionMode]}"
            ) from None
    max_depth = block.get("max_depth", 64)
    if not isinstance(max_depth, int) or isinstance(max_depth, bool) or max_depth < 1:
        raise PolicyError(f"phi_firewall.max_depth must be a positive integer, got {max_depth!r}")

    allowlist: dict[str, list[str]] = {}
    for k, v in _require_mapping(block.get("allowlist"), "phi_firewall.allowlist").items():
        allowlist[str(k).upper()] = _str_list(v, f"phi_firewall.allowlist[{k!r}]")

    locales = _str_list(block.get("locales"), "phi_firewall.locales")
    from clinicsentry.phi.locales import supported_locales

    unknown_locales = [loc for loc in locales if loc not in supported_locales()]
    if unknown_locales:
        raise PolicyError(
            f"unsupported phi_firewall.locales {unknown_locales}; supported: {supported_locales()}"
        )

    custom_raw = block.get("custom_detectors") or []
    if not isinstance(custom_raw, list):
        raise PolicyError("phi_firewall.custom_detectors must be a list")
    custom_detectors = [
        _require_mapping(entry, f"phi_firewall.custom_detectors[{i}]")
        for i, entry in enumerate(custom_raw)
    ]
    from clinicsentry.phi.custom import build_custom_detectors

    try:
        built = build_custom_detectors(custom_detectors)
    except ValueError as exc:
        raise PolicyError(f"phi_firewall.custom_detectors: {exc}") from exc

    detectors_raw = block.get("detectors")
    detectors: list[str] | None = None
    if detectors_raw is not None:
        detectors = _str_list(detectors_raw, "phi_firewall.detectors")
        from clinicsentry.phi.detectors import known_labels

        custom_labels = {d.label for d in built}
        unknown = [d for d in detectors if d not in known_labels() | custom_labels]
        if unknown:
            raise PolicyError(
                f"unknown phi_firewall.detectors {unknown}; "
                f"known: {sorted(known_labels() | custom_labels)}"
            )
        # Custom labels are additive; the detectors list selects built-ins.
        detectors = [d for d in detectors if d not in custom_labels]

    backend_raw = block.get("detector_backend")
    detector_backend: str | None = None
    if backend_raw is not None:
        detector_backend = str(backend_raw)
        from clinicsentry.phi.cloud import _BACKENDS

        if detector_backend not in _BACKENDS:
            raise PolicyError(
                f"unknown phi_firewall.detector_backend {detector_backend!r}; "
                f"supported: {sorted(_BACKENDS)}"
            )

    return _PhiPolicy(
        mode=mode,
        overrides=overrides,
        use_presidio=bool(block.get("use_presidio", False)),
        decode_encoded=bool(block.get("decode_encoded", True)),
        max_depth=max_depth,
        allowlist=allowlist,
        detectors=detectors,
        locales=locales,
        custom_detectors=custom_detectors,
        skip_fields=_str_list(block.get("skip_fields"), "phi_firewall.skip_fields"),
        always_redact_fields=_str_list(
            block.get("always_redact_fields"), "phi_firewall.always_redact_fields"
        ),
        detector_backend=detector_backend,
    )


def _parse_escalation(block: dict[str, Any]) -> tuple[dict[ClinicalRiskTier, float], str]:
    """Parse and validate the escalation block."""
    _require_keys(block, _ESCALATION_KEYS, "escalation")
    thresholds: dict[ClinicalRiskTier, float] = {}
    for k, v in _require_mapping(block.get("thresholds"), "escalation.thresholds").items():
        try:
            tier = ClinicalRiskTier(k)
        except ValueError:
            raise PolicyError(
                f"invalid escalation.thresholds tier {k!r}; expected one of "
                f"{[t.value for t in ClinicalRiskTier]}"
            ) from None
        try:
            threshold = float(v)
        except (TypeError, ValueError):
            raise PolicyError(f"escalation.thresholds[{k!r}] must be a number, got {v!r}") from None
        if not math.isfinite(threshold) or not 0.0 <= threshold <= 1.01:
            raise PolicyError(
                f"escalation.thresholds[{k!r}] must be in [0, 1.01] "
                f"(1.01 = always escalate), got {threshold}"
            )
        thresholds[tier] = threshold
    on_unregistered = str(block.get("on_unregistered_action", "escalate"))
    if on_unregistered not in {"escalate", "tier_default"}:
        raise PolicyError(
            "escalation.on_unregistered_action must be 'escalate' or 'tier_default', "
            f"got {on_unregistered!r}"
        )
    return thresholds, on_unregistered


def _parse_audit(block: dict[str, Any]) -> AuditPolicy:
    """Parse and validate the audit block."""
    _require_keys(block, _AUDIT_KEYS, "audit")
    retention = block.get("retention_years", 7)
    if not isinstance(retention, int) or isinstance(retention, bool) or retention < 0:
        raise PolicyError(
            f"audit.retention_years must be a non-negative integer, got {retention!r}"
        )
    return AuditPolicy(
        backend=str(block.get("backend", "memory")),
        path=str(block.get("path", "")),
        retention_years=retention,
    )


def _parse_dose_range(dr: Any, index: int) -> DoseRange:
    """Parse and validate a single dose-range entry."""
    dr = _require_mapping(dr, f"meddevice_mode.dose_ranges[{index}]")
    _require_keys(dr, _DOSE_RANGE_KEYS, f"meddevice_mode.dose_ranges[{index}]")
    parameter = str(dr.get("parameter", "")).strip()
    if not parameter:
        raise PolicyError(f"meddevice_mode.dose_ranges[{index}].parameter is required")
    try:
        min_value = float(dr.get("min", dr.get("min_value", 0.0)))
        max_value = float(dr.get("max", dr.get("max_value", 0.0)))
    except (TypeError, ValueError):
        raise PolicyError(f"meddevice_mode.dose_ranges[{index}] min/max must be numbers") from None
    if not (math.isfinite(min_value) and math.isfinite(max_value)):
        raise PolicyError(f"meddevice_mode.dose_ranges[{index}] min/max must be finite")
    if min_value > max_value:
        raise PolicyError(
            f"meddevice_mode.dose_ranges[{index}]: min ({min_value}) > max ({max_value})"
        )
    return DoseRange(
        parameter=parameter,
        min_value=min_value,
        max_value=max_value,
        unit=str(dr.get("unit", "")),
    )


def _parse_meddevice(block: dict[str, Any]) -> MedDeviceConfig:
    """Parse and validate the meddevice_mode block."""
    _require_keys(block, _MEDDEVICE_KEYS, "meddevice_mode")
    cls_raw = block.get("software_safety_class", "A")
    try:
        safety_class = SoftwareSafetyClass(cls_raw)
    except ValueError:
        raise PolicyError(
            f"invalid meddevice_mode.software_safety_class {cls_raw!r}; expected one of "
            f"{[c.value for c in SoftwareSafetyClass]}"
        ) from None
    rate_limit = block.get("rate_limit_per_hour")
    if rate_limit is not None and (
        not isinstance(rate_limit, int) or isinstance(rate_limit, bool) or rate_limit < 1
    ):
        raise PolicyError(
            f"meddevice_mode.rate_limit_per_hour must be a positive integer or null, "
            f"got {rate_limit!r}"
        )
    ranges_raw = block.get("dose_ranges") or []
    if not isinstance(ranges_raw, list):
        raise PolicyError("meddevice_mode.dose_ranges must be a list")
    return MedDeviceConfig(
        enabled=bool(block.get("enabled", False)),
        software_safety_class=safety_class,
        device_type=str(block.get("device_type", "")),
        intended_use=str(block.get("intended_use", "")),
        manufacturer=str(block.get("manufacturer", "")),
        udi=str(block.get("udi", "")),
        dose_ranges=[_parse_dose_range(dr, i) for i, dr in enumerate(ranges_raw)],
        rate_limit_per_hour=rate_limit,
        strict_dose_ranges=bool(block.get("strict_dose_ranges", True)),
    )


def load_policy(source: str | Path | dict[str, Any], *, apply_env: bool = True) -> PolicyConfig:
    """Load policy from a YAML path, YAML string, or pre-parsed dict.

    Precedence (ADR-0012): built-in defaults → ``source`` →
    ``CLINICSENTRY_*`` environment variables. Pass ``apply_env=False`` to
    skip the environment layer.

    Raises:
        PolicyError: on malformed YAML, unknown keys, or out-of-range values.
    """
    if isinstance(source, dict):
        data: Any = source
    elif isinstance(source, Path) or (
        isinstance(source, str) and Path(source).exists() and Path(source).is_file()
    ):
        try:
            with open(source, encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
        except yaml.YAMLError as exc:
            raise PolicyError(f"invalid policy YAML in {source}: {exc}") from exc
    else:
        try:
            data = yaml.safe_load(source) or {}
        except yaml.YAMLError as exc:
            raise PolicyError(f"invalid policy YAML string: {exc}") from exc

    if not isinstance(data, dict):
        raise PolicyError(f"policy must be a mapping, got {type(data).__name__}")
    if apply_env:
        data = _apply_env_overrides(data, os.environ)
    _require_keys(data, _TOP_LEVEL_KEYS, "top-level")

    phi = _parse_phi(_require_mapping(data.get("phi_firewall"), "phi_firewall"))
    thresholds, on_unregistered = _parse_escalation(
        _require_mapping(data.get("escalation"), "escalation")
    )
    audit = _parse_audit(_require_mapping(data.get("audit"), "audit"))
    meddevice = _parse_meddevice(_require_mapping(data.get("meddevice_mode"), "meddevice_mode"))
    return PolicyConfig(
        phi_mode=phi.mode,
        phi_overrides=phi.overrides,
        use_presidio=phi.use_presidio,
        decode_encoded=phi.decode_encoded,
        max_scan_depth=phi.max_depth,
        phi_allowlist=phi.allowlist,
        phi_detectors=phi.detectors,
        phi_locales=phi.locales,
        phi_custom_detectors=phi.custom_detectors,
        phi_skip_fields=phi.skip_fields,
        phi_always_redact_fields=phi.always_redact_fields,
        phi_detector_backend=phi.detector_backend,
        escalation_thresholds=thresholds,
        on_unregistered_action=on_unregistered,
        audit=audit,
        meddevice=meddevice,
        raw=data,
        version=str(data.get("version", "0.1.0")),
    )


def policy_schema() -> dict[str, Any]:
    """Return the authoritative JSON Schema for policy files.

    Printed by ``clinicsentry policy-schema``; docs examples are validated
    against the same key sets in CI so schema and docs cannot drift.
    """
    from clinicsentry.phi.cloud import _BACKENDS
    from clinicsentry.phi.locales import supported_locales

    modes = [m.value for m in RedactionMode]
    tiers = [t.value for t in ClinicalRiskTier]
    str_array = {"type": "array", "items": {"type": "string"}}
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "ClinicSentry policy",
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "version": {"type": "string"},
            "phi_firewall": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "mode": {"enum": modes},
                    "use_presidio": {"type": "boolean"},
                    "decode_encoded": {"type": "boolean"},
                    "max_depth": {"type": "integer", "minimum": 1},
                    "overrides": {
                        "type": "object",
                        "additionalProperties": {"enum": modes},
                    },
                    "allowlist": {
                        "type": "object",
                        "additionalProperties": str_array,
                    },
                    "detectors": str_array,
                    "locales": {
                        "type": "array",
                        "items": {"enum": supported_locales()},
                    },
                    "custom_detectors": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["label", "pattern"],
                            "properties": {
                                "label": {"type": "string"},
                                "pattern": {"type": "string"},
                                "flags": str_array,
                                "confidence": {
                                    "type": "number",
                                    "exclusiveMinimum": 0,
                                    "maximum": 1,
                                },
                                "mode": {"enum": modes},
                            },
                        },
                    },
                    "skip_fields": str_array,
                    "always_redact_fields": str_array,
                    "detector_backend": {
                        "enum": [*sorted(_BACKENDS), None],
                    },
                },
            },
            "escalation": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "thresholds": {
                        "type": "object",
                        "propertyNames": {"enum": tiers},
                        "additionalProperties": {
                            "type": "number",
                            "minimum": 0,
                            "maximum": 1.01,
                        },
                    },
                    "on_unregistered_action": {"enum": ["escalate", "tier_default"]},
                },
            },
            "audit": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "backend": {"type": "string"},
                    "path": {"type": "string"},
                    "retention_years": {"type": "integer", "minimum": 0},
                },
            },
            "meddevice_mode": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "enabled": {"type": "boolean"},
                    "software_safety_class": {"enum": ["A", "B", "C"]},
                    "device_type": {"type": "string"},
                    "intended_use": {"type": "string"},
                    "manufacturer": {"type": "string"},
                    "udi": {"type": "string"},
                    "strict_dose_ranges": {"type": "boolean"},
                    "dose_ranges": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["parameter"],
                            "properties": {
                                "parameter": {"type": "string"},
                                "min": {"type": "number"},
                                "max": {"type": "number"},
                                "min_value": {"type": "number"},
                                "max_value": {"type": "number"},
                                "unit": {"type": "string"},
                            },
                        },
                    },
                    "rate_limit_per_hour": {"type": ["integer", "null"], "minimum": 1},
                },
            },
        },
    }
