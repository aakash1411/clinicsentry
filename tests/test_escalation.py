"""Tests for the clinical escalation router and confidence scorer."""

from __future__ import annotations

from clinicsentry.escalation.confidence import (
    ConfidenceInputs,
    ConfidenceScorer,
    InMemoryVocabulary,
)
from clinicsentry.escalation.router import EscalationRouter
from clinicsentry.types import ClinicalRiskTier


def test_self_reported_confidence_extraction() -> None:
    scorer = ConfidenceScorer()
    res = scorer.score(ConfidenceInputs(reasoning_text="I am 90% confident."))
    assert res.breakdown["self_reported"] == 0.90


def test_hallucination_signal_uses_drug_vocab() -> None:
    drugs = InMemoryVocabulary.from_iterable(["Metformin", "Lisinopril"])
    scorer = ConfidenceScorer()
    good = scorer.score(ConfidenceInputs(output_text="Continue Metformin", drug_vocab=drugs))
    bad = scorer.score(ConfidenceInputs(output_text="Start Foomycin", drug_vocab=drugs))
    assert good.breakdown["hallucination"] == 1.0
    assert bad.breakdown["hallucination"] == 0.0


def test_interventional_always_blocks() -> None:
    router = EscalationRouter()

    @router.register_action(
        tier=ClinicalRiskTier.INTERVENTIONAL,
        description="Modify pump rate",
    )
    def modify_pump_rate() -> None: ...

    decision = router.decide(
        "modify_pump_rate",
        confidence_inputs=ConfidenceInputs(reasoning_text="100% confident"),
    )
    assert decision.action == "block"
    assert decision.escalation_channel == "block_with_error"


def test_advisory_below_threshold_escalates() -> None:
    router = EscalationRouter()

    @router.register_action(tier=ClinicalRiskTier.ADVISORY, description="Recommend dose")
    def recommend_dose() -> None: ...

    decision = router.decide(
        "recommend_dose",
        confidence_inputs=ConfidenceInputs(reasoning_text="Confidence: 50%"),
    )
    assert decision.action == "escalate"
    assert decision.confidence < 0.8


def test_advisory_above_threshold_proceeds_with_annotation() -> None:
    router = EscalationRouter()

    @router.register_action(tier=ClinicalRiskTier.ADVISORY, description="Recommend dose")
    def recommend_dose() -> None: ...

    decision = router.decide(
        "recommend_dose",
        confidence_inputs=ConfidenceInputs(reasoning_text="Confidence: 95%"),
    )
    assert decision.action == "proceed"
    assert decision.escalation_channel == "proceed_with_annotation"


def test_unregistered_action_escalates_by_default() -> None:
    """Fail closed: an action that was never registered must not proceed."""
    router = EscalationRouter()
    decision = router.decide(
        "never_registered",
        confidence_inputs=ConfidenceInputs(reasoning_text="Confidence: 99%"),
    )
    assert decision.action == "escalate"
    assert "not registered" in decision.escalation_reason


def test_unregistered_action_tier_default_opt_out() -> None:
    router = EscalationRouter(on_unregistered_action="tier_default")
    decision = router.decide(
        "never_registered",
        confidence_inputs=ConfidenceInputs(reasoning_text="Confidence: 99%"),
    )
    assert decision.action == "proceed"


def test_decide_does_not_mutate_caller_inputs() -> None:
    router = EscalationRouter()

    @router.register_action(tier=ClinicalRiskTier.ADVISORY, required_fields={"note"})
    def act() -> None: ...

    inputs = ConfidenceInputs(reasoning_text="Confidence: 95%")
    router.decide("act", confidence_inputs=inputs)
    assert inputs.required_fields == set()


def test_scorer_rejects_negative_weights() -> None:
    import pytest

    with pytest.raises(ValueError, match="non-negative"):
        ConfidenceScorer(weights={"self_reported": -0.5, "grounding": 1.0})
    with pytest.raises(ValueError, match="zero"):
        ConfidenceScorer(weights={"self_reported": 0.0})
    with pytest.raises(ValueError, match="default_when_unscored"):
        ConfidenceScorer(default_when_unscored=1.5)


def test_router_rejects_invalid_unregistered_policy() -> None:
    import pytest

    with pytest.raises(ValueError, match="on_unregistered_action"):
        EscalationRouter(on_unregistered_action="ignore")
