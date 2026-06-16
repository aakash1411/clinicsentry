"""Risk-tiered escalation routing (Module 2, README §7)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Any

from clinicsentry.escalation.confidence import (
    ConfidenceInputs,
    ConfidenceResult,
    ConfidenceScorer,
)
from clinicsentry.types import ClinicalRiskTier, EscalationDecision

__all__ = [
    "RegisteredAction",
    "EscalationRouter",
]


@dataclass
class RegisteredAction:
    """Action metadata captured by the @register_action decorator."""

    name: str
    tier: ClinicalRiskTier
    description: str = ""
    iec62304_requirement: str | None = None
    required_fields: set[str] = field(default_factory=set)


# Default escalation thresholds per tier — README §7.
DEFAULT_THRESHOLDS: dict[ClinicalRiskTier, float] = {
    ClinicalRiskTier.INFORMATIONAL: 0.60,
    ClinicalRiskTier.ADVISORY: 0.80,
    ClinicalRiskTier.INTERVENTIONAL: 1.01,  # >1.0 ⇒ always escalate
}

# Default channel matrix per (tier, confidence_band).
DEFAULT_CHANNELS: dict[tuple[ClinicalRiskTier, str], dict[str, Any]] = {
    (ClinicalRiskTier.INFORMATIONAL, "low"): {
        "channel": "human_review_queue",
        "priority": "low",
        "sla_hours": 24,
        "reviewer_role": "clinical_reviewer",
    },
    (ClinicalRiskTier.ADVISORY, "low"): {
        "channel": "clinician_alert",
        "priority": "medium",
        "sla_hours": 4,
        "reviewer_role": "attending_physician",
    },
    (ClinicalRiskTier.ADVISORY, "medium"): {
        "channel": "proceed_with_annotation",
        "annotation_template": "AI-generated recommendation, confidence: {confidence:.2f}",
        "reviewer_role": "attending_physician",
    },
    (ClinicalRiskTier.INTERVENTIONAL, "any"): {
        "channel": "block_with_error",
        "message": "Interventional action requires explicit human authorization",
        "reviewer_role": "attending_physician",
    },
}


class EscalationRouter:
    """Holds the action registry and emits :class:`EscalationDecision` objects."""

    def __init__(
        self,
        thresholds: dict[ClinicalRiskTier, float] | None = None,
        channels: dict[tuple[ClinicalRiskTier, str], dict[str, Any]] | None = None,
        scorer: ConfidenceScorer | None = None,
        on_unregistered_action: str = "escalate",
    ) -> None:
        """Initialize router.

        Args:
            thresholds: per-tier confidence thresholds (merged over defaults).
            channels: per (tier, band) channel config (merged over defaults).
            scorer: confidence scorer instance.
            on_unregistered_action: ``"escalate"`` (fail closed, default) routes
                any action that was never registered to human review regardless
                of confidence; ``"tier_default"`` scores it as ADVISORY.
        """
        if on_unregistered_action not in {"escalate", "tier_default"}:
            raise ValueError(
                "on_unregistered_action must be 'escalate' or 'tier_default', "
                f"got {on_unregistered_action!r}"
            )
        self.thresholds = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
        self.channels = {**DEFAULT_CHANNELS, **(channels or {})}
        self.scorer = scorer or ConfidenceScorer()
        self.on_unregistered_action = on_unregistered_action
        self._actions: dict[str, RegisteredAction] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register_action(
        self,
        tier: ClinicalRiskTier,
        description: str = "",
        iec62304_requirement: str | None = None,
        required_fields: set[str] | None = None,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator: tag a callable with its clinical risk metadata."""

        def decorate(func: Callable[..., Any]) -> Callable[..., Any]:
            action = RegisteredAction(
                name=func.__name__,
                tier=tier,
                description=description,
                iec62304_requirement=iec62304_requirement,
                required_fields=set(required_fields or ()),
            )
            self._actions[func.__name__] = action
            func.__clinical_action__ = action  # type: ignore[attr-defined]
            return func

        return decorate

    def get_action(self, name: str) -> RegisteredAction | None:
        """Look up a registered action by name."""
        return self._actions.get(name)

    # ------------------------------------------------------------------
    # Decision
    # ------------------------------------------------------------------

    def decide(
        self,
        action_name: str,
        confidence_inputs: ConfidenceInputs | None = None,
        precomputed: ConfidenceResult | None = None,
    ) -> EscalationDecision:
        """Produce an :class:`EscalationDecision` for an action invocation."""
        action = self._actions.get(action_name)
        tier = action.tier if action else ClinicalRiskTier.ADVISORY
        if precomputed is not None:
            conf = precomputed
        elif confidence_inputs is not None:
            if action and action.required_fields and not confidence_inputs.required_fields:
                # Never mutate the caller's inputs object.
                confidence_inputs = replace(
                    confidence_inputs, required_fields=set(action.required_fields)
                )
            conf = self.scorer.score(confidence_inputs)
        else:
            conf = ConfidenceResult(score=self.scorer.default_when_unscored, breakdown={})

        if action is None and self.on_unregistered_action == "escalate":
            channel_cfg = self.channels.get((tier, "low"), {})
            return EscalationDecision(
                action="escalate",
                tier=tier,
                confidence=conf.score,
                confidence_breakdown=conf.breakdown,
                escalation_reason=(
                    f"Action '{action_name}' is not registered; "
                    "unregistered actions escalate by default"
                ),
                escalation_channel=channel_cfg.get("channel", "human_review_queue"),
                suggested_reviewer_role=channel_cfg.get("reviewer_role", ""),
            )

        threshold = self.thresholds[tier]
        below = conf.score < threshold

        if tier == ClinicalRiskTier.INTERVENTIONAL:
            channel_cfg = self.channels.get((tier, "any"), {})
            return EscalationDecision(
                action="block",
                tier=tier,
                confidence=conf.score,
                confidence_breakdown=conf.breakdown,
                escalation_reason=channel_cfg.get(
                    "message", "Interventional action requires human authorization"
                ),
                escalation_channel=channel_cfg.get("channel", "block_with_error"),
                suggested_reviewer_role=channel_cfg.get("reviewer_role", ""),
            )

        if below:
            band = "low"
            channel_cfg = self.channels.get((tier, band), {})
            return EscalationDecision(
                action="escalate",
                tier=tier,
                confidence=conf.score,
                confidence_breakdown=conf.breakdown,
                escalation_reason=(
                    f"Confidence {conf.score:.2f} below {tier.value} threshold {threshold:.2f}"
                ),
                escalation_channel=channel_cfg.get("channel", "human_review_queue"),
                suggested_reviewer_role=channel_cfg.get("reviewer_role", ""),
            )

        # Advisory-medium = proceed with annotation; informational-high = clean proceed.
        if tier == ClinicalRiskTier.ADVISORY:
            channel_cfg = self.channels.get((tier, "medium"), {})
            return EscalationDecision(
                action="proceed",
                tier=tier,
                confidence=conf.score,
                confidence_breakdown=conf.breakdown,
                escalation_reason=channel_cfg.get("annotation_template", "").format(
                    confidence=conf.score
                ),
                escalation_channel=channel_cfg.get("channel", "proceed_with_annotation"),
                suggested_reviewer_role=channel_cfg.get("reviewer_role", ""),
            )

        return EscalationDecision(
            action="proceed",
            tier=tier,
            confidence=conf.score,
            confidence_breakdown=conf.breakdown,
            escalation_channel="proceed",
        )
