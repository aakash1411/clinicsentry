"""Top-level :class:`ClinicSentry` facade tying all four modules together."""

from __future__ import annotations

import os
import warnings
from collections.abc import Callable
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
from clinicsentry.escalation.confidence import ConfidenceInputs, ConfidenceScorer
from clinicsentry.escalation.router import EscalationRouter
from clinicsentry.meddevice.mode import MedDeviceMode
from clinicsentry.phi.firewall import PHIFirewall
from clinicsentry.phi.propagation import PropagationGraph
from clinicsentry.policy import PolicyConfig, load_policy
from clinicsentry.types import (
    AuditEvent,
    AuditEventType,
    ClinicalRiskTier,
    EscalationDecision,
    RegulatoryReport,
)

__all__ = [
    "ClinicSentry",
]


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
    ) -> None:
        """Construct a guard instance.

        Args:
            policy: a :class:`PolicyConfig`, a YAML path/string, or a dict.
            framework: framework label written into audit events.
            session_id: optional explicit session id (one is generated otherwise).
            secret_key: HMAC key for audit signing; auto-generated when omitted.
            adapter: explicit adapter; defaults to :class:`GenericAdapter`.
            audit_backend: override storage; otherwise resolved from policy.
        """
        cfg = policy if isinstance(policy, PolicyConfig) else load_policy(policy or {})
        self.policy = cfg
        self.framework = framework
        self.session_id = session_id or str(uuid4())
        key_was_generated = secret_key is None
        self.secret_key = secret_key or os.urandom(32)

        self.propagation = PropagationGraph()
        self.firewall = PHIFirewall(
            mode=cfg.phi_mode,
            overrides=cfg.phi_overrides,
            use_presidio=cfg.use_presidio,
            session_salt=self.session_id,
            propagation=self.propagation,
            decode_encoded=cfg.decode_encoded,
            max_depth=cfg.max_scan_depth,
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
