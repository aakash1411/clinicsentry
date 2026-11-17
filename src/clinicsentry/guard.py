"""Top-level :class:`ClinicSentry` facade tying all four modules together."""

from __future__ import annotations

import os
import threading
import time
import warnings
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any
from uuid import uuid4

from clinicsentry.adapters.base import AgentFrameworkAdapter, GenericAdapter
from clinicsentry.audit.backend import (
    AuditBackend,
    FileAuditBackend,
    InMemoryAuditBackend,
    SqliteAuditBackend,
)
from clinicsentry.audit.chain import AuditChain
from clinicsentry.audit.report import build_report
from clinicsentry.errors import AuthorizationRequired, DoseOutOfRange, EscalationRaised
from clinicsentry.escalation.confidence import ConfidenceInputs, ConfidenceScorer
from clinicsentry.escalation.router import EscalationRouter, RegisteredAction
from clinicsentry.meddevice.clinician_auth import ClinicianAuthError, ClinicianAuthValidator
from clinicsentry.meddevice.mode import MedDeviceMode, arguments_hash
from clinicsentry.phi.firewall import MetricHook, PHIFinding, PHIFirewall
from clinicsentry.phi.propagation import PropagationGraph
from clinicsentry.policy import PolicyConfig, load_policy
from clinicsentry.types import (
    AuditEvent,
    AuditEventType,
    ClinicalRiskTier,
    EscalationDecision,
    PHITag,
    RegulatoryReport,
)

__all__ = [
    "ClinicSentry",
]

_REVIEW_DECISIONS = frozenset({"approved", "rejected", "modified"})


class ClinicSentry:
    """Single entry point for the four ClinicSentry modules."""

    def __init__(
        self,
        policy: str | Path | dict[str, Any] | PolicyConfig | None = None,
        framework: str = "generic",
        session_id: str | None = None,
        secret_key: bytes | None = None,
        adapter: AgentFrameworkAdapter | None = None,
        audit_backend: AuditBackend | None = None,
        detectors: Sequence[Any] = (),
        on_metric: MetricHook | None = None,
    ) -> None:
        """Construct a guard instance.

        Args:
            policy: a :class:`PolicyConfig`, a YAML path/string, or a dict.
            framework: framework label written into audit events.
            session_id: optional explicit session id (one is generated otherwise).
            secret_key: HMAC key for audit signing; auto-generated when omitted.
            adapter: explicit adapter; defaults to :class:`GenericAdapter`.
            audit_backend: override storage; otherwise resolved from policy.
            detectors: custom detector objects (from ``register_detector``).
            on_metric: callback ``(name, value, tags)`` for firewall metrics.
        """
        cfg = policy if isinstance(policy, PolicyConfig) else load_policy(policy or {})
        self.policy = cfg
        self.framework = framework
        self.session_id = session_id or str(uuid4())
        key_was_generated = secret_key is None
        self.secret_key = secret_key or os.urandom(32)

        from clinicsentry.phi.custom import build_custom_detectors

        custom = [*build_custom_detectors(cfg.phi_custom_detectors), *detectors]
        self.propagation = PropagationGraph()
        self.firewall = PHIFirewall(
            mode=cfg.phi_mode,
            overrides=cfg.phi_overrides,
            use_presidio=cfg.use_presidio,
            session_salt=self.session_id,
            propagation=self.propagation,
            decode_encoded=cfg.decode_encoded,
            max_depth=cfg.max_scan_depth,
            allowlist={k: list(v) for k, v in cfg.phi_allowlist.items()},
            detectors=cfg.phi_detectors,
            locales=cfg.phi_locales,
            custom_detectors=custom,
            skip_fields=cfg.phi_skip_fields,
            always_redact_fields=cfg.phi_always_redact_fields,
            detector_backend=cfg.phi_detector_backend,
            on_metric=on_metric,
            on_scan=self._record_phi_scan,
        )
        self.scorer = ConfidenceScorer()
        self.router = EscalationRouter(
            thresholds=cfg.escalation_thresholds,
            scorer=self.scorer,
            on_unregistered_action=cfg.on_unregistered_action,
        )
        self.meddevice = MedDeviceMode(config=cfg.meddevice)

        backend = audit_backend or _resolve_backend(cfg)
        self.audit_backend = backend
        if key_was_generated and not isinstance(backend, InMemoryAuditBackend):
            warnings.warn(
                "ClinicSentry generated an ephemeral HMAC key for a persistent audit "
                "backend — the chain in this store cannot be verified after this "
                "process exits. Pass secret_key= explicitly (e.g. from "
                "CLINICSENTRY_HMAC_KEY or a KeyProvider, see ADR-0005) and store it "
                "in a secret manager.",
                UserWarning,
                stacklevel=2,
            )
        self.chain = AuditChain(
            session_id=self.session_id, secret_key=self.secret_key, backend=backend
        )

        self.adapter = adapter or GenericAdapter(self)
        # action name -> list of (args_hash or None, monotonic expiry)
        self._grants: dict[str, list[tuple[str | None, float]]] = {}
        self._grants_lock = threading.Lock()
        self._ended = False
        self.last_report: RegulatoryReport | None = None

        # Emit SESSION_START first so the chain's genesis is recorded.
        self.emit_event(
            AuditEvent(
                event_type=AuditEventType.SESSION_START,
                session_id=self.session_id,
                sequence_number=0,
                agent_framework=self.framework,
                redacted_input={"policy_version": cfg.version},
            )
        )

    # ------------------------------------------------------------------
    # Action registration (delegates to router + meddevice)
    # ------------------------------------------------------------------

    def register_action(
        self,
        tier: ClinicalRiskTier,
        description: str = "",
        iec62304_requirement: str | None = None,
        required_fields: set[str] | None = None,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Register an action and apply MedDevice class constraints."""
        decorator = self.router.register_action(
            tier=tier,
            description=description,
            iec62304_requirement=iec62304_requirement,
            required_fields=required_fields,
        )

        def wrap(func: Callable[..., Any]) -> Callable[..., Any]:
            """Wrap ``func`` with router registration + meddevice validation."""
            wrapped = decorator(func)
            action = self.router.get_action(func.__name__)
            if action is not None:
                self.meddevice.validate_registration(action)
            return wrapped

        return wrap

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def emit_event(self, event: AuditEvent) -> AuditEvent:
        """Pass-through to the audit chain (write-before-process invariant)."""
        return self.chain.emit(event)

    def evaluate_action(
        self,
        action_name: str,
        *,
        output_text: str = "",
        reasoning_text: str = "",
        provided_fields: set[str] | None = None,
    ) -> EscalationDecision:
        """Compute and audit the escalation decision for an action invocation."""
        action = self.router.get_action(action_name)
        required = action.required_fields if action else set()
        inputs = ConfidenceInputs(
            output_text=output_text,
            reasoning_text=reasoning_text,
            provided_fields=set(provided_fields or ()),
            required_fields=required,
        )
        decision = self.router.decide(action_name, confidence_inputs=inputs)
        self.emit_event(
            AuditEvent(
                event_type=AuditEventType.ESCALATION_TRIGGERED
                if decision.action != "proceed"
                else AuditEventType.AGENT_LLM_RESPONSE,
                session_id=self.session_id,
                sequence_number=0,
                agent_framework=self.framework,
                agent_id=action_name,
                risk_tier=decision.tier,
                confidence_score=decision.confidence,
                escalation_decision=decision.to_dict(),
            )
        )
        return decision

    # ------------------------------------------------------------------
    # PHI evidence
    # ------------------------------------------------------------------

    def _record_phi_scan(
        self, findings: list[PHIFinding], tags: list[PHITag], origin_agent: str
    ) -> None:
        """Emit PHI_DETECTED / PHI_REDACTED for a scan (types and counts only)."""
        agent = origin_agent if origin_agent and origin_agent != "unknown" else "phi_firewall"
        tag_ids = [t.tag_id for t in tags]
        detected = Counter(f.phi_type for f in findings) or Counter(t.phi_type for t in tags)
        self.emit_event(
            AuditEvent(
                event_type=AuditEventType.PHI_DETECTED,
                session_id=self.session_id,
                sequence_number=0,
                agent_framework=self.framework,
                agent_id=agent,
                redacted_input={"phi_types": dict(detected), "count": sum(detected.values())},
                phi_tags_detected=tag_ids,
            )
        )
        redacted = [f for f in findings if f.replacement is not None]
        if not redacted:
            return
        self.emit_event(
            AuditEvent(
                event_type=AuditEventType.PHI_REDACTED,
                session_id=self.session_id,
                sequence_number=0,
                agent_framework=self.framework,
                agent_id=agent,
                redacted_input={
                    "phi_types": dict(Counter(f.phi_type for f in redacted)),
                    "count": len(redacted),
                    "actions": sorted({f.action for f in redacted}),
                },
                phi_tags_detected=tag_ids,
            )
        )

    # ------------------------------------------------------------------
    # Runtime tool-call enforcement
    # ------------------------------------------------------------------

    def check_tool_call(
        self, tool_name: str, arguments: Mapping[str, Any]
    ) -> RegisteredAction | None:
        """Enforce runtime safety controls before a tool executes.

        Applies, in order: the emergency stop, declared dose ranges (when
        MedDevice mode is enabled), and the interventional gate. A registered
        ``INTERVENTIONAL`` action is always escalated and only proceeds when a
        matching clinician approval (see :meth:`approve_interventional`) is
        pending; the approval is consumed. Returns the registered action, or
        ``None`` for unregistered tools.

        Raises:
            EmergencyStop: the kill-switch is engaged.
            DoseOutOfRange: a dose parameter or the device rate limit is violated.
            EscalationRaised: interventional action without clinician approval.
        """
        self.meddevice.assert_running()
        action = self.router.get_action(tool_name)
        tier = action.tier if action else None
        if self.meddevice.config.enabled:
            self._check_doses(tool_name, tier, arguments)
        if tier != ClinicalRiskTier.INTERVENTIONAL:
            return action

        decision = self.router.decide(tool_name)
        approved = self._consume_grant(tool_name, arguments_hash(dict(arguments)))
        self.emit_event(
            AuditEvent(
                event_type=AuditEventType.ESCALATION_TRIGGERED,
                session_id=self.session_id,
                sequence_number=0,
                agent_framework=self.framework,
                agent_id=tool_name,
                risk_tier=tier,
                confidence_score=decision.confidence,
                escalation_decision={**decision.to_dict(), "clinician_authorized": approved},
            )
        )
        if not approved:
            raise EscalationRaised(decision, context={"action": tool_name})
        if self.meddevice.config.enabled and not self.meddevice.record_device_change():
            self._policy_violation(tool_name, tier, "rate_limit_exceeded")
            raise DoseOutOfRange("device change rate limit exceeded", context={"action": tool_name})
        return action

    def _check_doses(
        self, tool_name: str, tier: ClinicalRiskTier | None, arguments: Mapping[str, Any]
    ) -> None:
        """Validate top-level numeric arguments against declared dose ranges."""
        cfg = self.meddevice.config
        if not cfg.dose_ranges:
            return
        declared = {dr.parameter for dr in cfg.dose_ranges}
        for param, value in arguments.items():
            numeric = isinstance(value, int | float) and not isinstance(value, bool)
            if param in declared:
                ok = numeric and self.meddevice.validate_dose(param, float(value))
                reason = "dose_out_of_range"
            elif numeric and cfg.strict_dose_ranges and tier == ClinicalRiskTier.INTERVENTIONAL:
                ok = False
                reason = "undeclared_dose_parameter"
            else:
                continue
            if not ok:
                self._policy_violation(tool_name, tier, reason, parameter=param)
                raise DoseOutOfRange(
                    f"parameter '{param}' failed dose validation ({reason})",
                    context={"action": tool_name, "parameter": param},
                )

    def _policy_violation(
        self,
        action_name: str,
        tier: ClinicalRiskTier | None,
        reason: str,
        **details: str,
    ) -> None:
        """Audit a blocked action (PHI-free: names and reason codes only)."""
        self.emit_event(
            AuditEvent(
                event_type=AuditEventType.POLICY_VIOLATION,
                session_id=self.session_id,
                sequence_number=0,
                agent_framework=self.framework,
                agent_id=action_name,
                risk_tier=tier,
                redacted_input={"reason": reason, **details},
            )
        )

    # ------------------------------------------------------------------
    # Clinician approval + human review
    # ------------------------------------------------------------------

    def approve_interventional(
        self,
        action_name: str,
        *,
        clinician_id: str,
        signature: str,
        nonce: str,
        issued_at: int,
        arguments: Mapping[str, Any] | None = None,
    ) -> None:
        """Record a verified HMAC clinician approval for one interventional call.

        The signature must be produced by
        :func:`clinicsentry.meddevice.sign_interventional_authorization` over
        this session id, ``action_name``, a single-use ``nonce``, a fresh
        ``issued_at`` and, when ``arguments`` is given, their
        :func:`~clinicsentry.meddevice.arguments_hash`. Keys come from
        ``MedDeviceConfig.authorized_clinician_keys``.

        Raises:
            ValueError: ``action_name`` is not a registered interventional action.
            AuthorizationRequired: the signature is invalid, stale or replayed.
        """
        self._require_interventional(action_name)
        args_hash = arguments_hash(dict(arguments)) if arguments is not None else ""
        ok = self.meddevice.verify_clinician_signature(
            action_name,
            clinician_id,
            signature,
            session_id=self.session_id,
            nonce=nonce,
            issued_at=issued_at,
            args_hash=args_hash,
        )
        if not ok:
            self._policy_violation(
                action_name, ClinicalRiskTier.INTERVENTIONAL, "clinician_authorization_invalid"
            )
            raise AuthorizationRequired(
                "clinician authorization invalid, expired or replayed",
                context={"action": action_name},
            )
        self._add_grant(action_name, args_hash or None, clinician_id, mechanism="hmac")

    def approve_interventional_token(
        self,
        token_blob: str,
        signature: bytes,
        validator: ClinicianAuthValidator,
        *,
        arguments: Mapping[str, Any] | None = None,
    ) -> None:
        """Record a verified Ed25519 clinician token approval for one call.

        The token must be bound to this session; when ``arguments`` is given
        it must also carry their :func:`~clinicsentry.meddevice.arguments_hash`.

        Raises:
            ValueError: the token's action is not a registered interventional action.
            AuthorizationRequired: the token fails validation.
        """
        args_hash = arguments_hash(dict(arguments)) if arguments is not None else None
        try:
            token = validator.validate(
                token_blob,
                signature,
                expected_session_id=self.session_id,
                expected_args_hash=args_hash,
            )
        except ClinicianAuthError as exc:
            self._policy_violation(
                "clinician_token", ClinicalRiskTier.INTERVENTIONAL, "clinician_token_invalid"
            )
            raise AuthorizationRequired(str(exc)) from exc
        self._require_interventional(token.action_name)
        self._add_grant(
            token.action_name, token.args_hash or None, token.clinician_id, mechanism="ed25519"
        )

    def record_human_review(
        self,
        action_name: str,
        *,
        reviewer_id: str,
        decision: str,
        rationale: str = "",
    ) -> AuditEvent:
        """Close an escalation loop by auditing a reviewer's decision.

        ``decision`` is one of ``approved`` / ``rejected`` / ``modified``.
        ``rationale`` is passed through the PHI firewall before it is stored.
        """
        if decision not in _REVIEW_DECISIONS:
            raise ValueError(f"decision must be one of {sorted(_REVIEW_DECISIONS)}")
        action = self.router.get_action(action_name)
        redacted_rationale = (
            self.firewall.scan(rationale, origin_agent=reviewer_id).redacted if rationale else ""
        )
        return self.emit_event(
            AuditEvent(
                event_type=AuditEventType.HUMAN_REVIEW_RESPONSE,
                session_id=self.session_id,
                sequence_number=0,
                agent_framework=self.framework,
                agent_id=action_name,
                risk_tier=action.tier if action else None,
                redacted_input={
                    "reviewer_id": reviewer_id,
                    "decision": decision,
                    "rationale": redacted_rationale,
                },
            )
        )

    def _require_interventional(self, action_name: str) -> None:
        action = self.router.get_action(action_name)
        if action is None or action.tier != ClinicalRiskTier.INTERVENTIONAL:
            raise ValueError(f"'{action_name}' is not a registered interventional action")

    def _add_grant(
        self, action_name: str, args_hash: str | None, clinician_id: str, *, mechanism: str
    ) -> None:
        expires = time.monotonic() + self.meddevice.AUTHORIZATION_MAX_AGE_SECONDS
        with self._grants_lock:
            self._grants.setdefault(action_name, []).append((args_hash, expires))
        self.emit_event(
            AuditEvent(
                event_type=AuditEventType.HUMAN_REVIEW_RESPONSE,
                session_id=self.session_id,
                sequence_number=0,
                agent_framework=self.framework,
                agent_id=action_name,
                risk_tier=ClinicalRiskTier.INTERVENTIONAL,
                redacted_input={
                    "reviewer_id": clinician_id,
                    "decision": "approved",
                    "mechanism": mechanism,
                    "arguments_bound": args_hash is not None,
                },
            )
        )

    def _consume_grant(self, action_name: str, args_hash: str) -> bool:
        now = time.monotonic()
        with self._grants_lock:
            grants = [g for g in self._grants.get(action_name, []) if g[1] >= now]
            for i, (bound_hash, _exp) in enumerate(grants):
                if bound_hash is None or bound_hash == args_hash:
                    del grants[i]
                    self._grants[action_name] = grants
                    return True
            self._grants[action_name] = grants
        return False

    # ------------------------------------------------------------------
    # Session close
    # ------------------------------------------------------------------

    def end_session(self, intended_use: str = "") -> RegulatoryReport:
        """Emit SESSION_END and produce the regulatory report.

        Idempotent: calling again after the session has ended rebuilds the
        report without emitting a second SESSION_END event.
        """
        if not self._ended:
            self.emit_event(
                AuditEvent(
                    event_type=AuditEventType.SESSION_END,
                    session_id=self.session_id,
                    sequence_number=0,
                    agent_framework=self.framework,
                )
            )
            self._ended = True
        events = list(self.audit_backend.read_session(self.session_id))
        iec_section = self.meddevice.report_section() if self.meddevice.config.enabled else None
        self.last_report = build_report(
            session_id=self.session_id,
            events=events,
            framework=self.framework,
            intended_use=intended_use,
            policy_version=self.policy.version,
            phi_tags=self.propagation.tags,
            propagation_edges=self.propagation.edges,
            iec62304=iec_section,
        )
        return self.last_report

    def verify_audit_chain(self) -> tuple[bool, list[str]]:
        """Return (ok, errors) for this session's hash chain."""
        return self.chain.verify()

    def close(self) -> None:
        """Release backend resources (no-op for backends without ``close``)."""
        close = getattr(self.audit_backend, "close", None)
        if callable(close):
            close()

    # ------------------------------------------------------------------
    # Context-manager protocol — guarantees SESSION_END even on exceptions
    # ------------------------------------------------------------------

    def __enter__(self) -> ClinicSentry:
        """Enter the guard context."""
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: Any
    ) -> None:
        """Audit any in-flight exception, end the session, release the backend."""
        if exc_type is not None and not self._ended:
            # Record the failure class only — messages may contain PHI.
            self.emit_event(
                AuditEvent(
                    event_type=AuditEventType.MODULE_ERROR,
                    session_id=self.session_id,
                    sequence_number=0,
                    agent_framework=self.framework,
                    redacted_input={"exception_type": exc_type.__name__},
                )
            )
        if not self._ended:
            self.end_session()
        self.close()


def _resolve_backend(cfg: PolicyConfig) -> AuditBackend:
    """Construct the audit backend specified in policy."""
    backend = cfg.audit.backend.lower()
    if backend == "file":
        path = cfg.audit.path or "./clinicsentry_audit.log"
        return FileAuditBackend(path)
    if backend == "sqlite":
        path = cfg.audit.path or "./clinicsentry_audit.sqlite"
        return SqliteAuditBackend(path)
    if backend in {"postgres", "postgresql"}:
        from clinicsentry.audit.postgres import PostgresAuditBackend

        return PostgresAuditBackend(cfg.audit.path)
    if backend == "s3":
        from clinicsentry.audit.s3 import S3AuditBackend

        bucket, _, prefix = cfg.audit.path.partition("/")
        return S3AuditBackend(bucket=bucket, prefix=prefix or "clinicsentry/")
    return InMemoryAuditBackend()
