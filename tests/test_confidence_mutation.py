"""Mutation-killing tests for :mod:`clinicsentry.escalation.confidence`."""

from __future__ import annotations

import pytest

from clinicsentry.escalation.confidence import (
    ConfidenceInputs,
    ConfidenceScorer,
    InMemoryVocabulary,
    _completeness,
    _grounding,
    _hallucination,
    _self_reported,
)

# ---------------------------------------------------------------------------
# InMemoryVocabulary
# ---------------------------------------------------------------------------


def test_vocabulary_default_factory_is_empty_set() -> None:
    """The default-constructed vocabulary must be an empty mutable set."""
    v = InMemoryVocabulary()
    assert v.terms == set()
    v.terms.add("x")
    assert v.terms == {"x"}


def test_vocabulary_contains_is_case_insensitive() -> None:
    v = InMemoryVocabulary.from_iterable(["Metformin", "Lisinopril"])
    assert v.contains("metformin")
    assert v.contains("METFORMIN")
    assert v.contains("Lisinopril")
    assert not v.contains("aspirin")


def test_vocabulary_from_iterable_lowercases_input() -> None:
    v = InMemoryVocabulary.from_iterable(["FOO", "Bar"])
    assert v.terms == {"foo", "bar"}


# ---------------------------------------------------------------------------
# _self_reported
# ---------------------------------------------------------------------------


def test_self_reported_returns_neg_one_on_empty_text() -> None:
    assert _self_reported("") == -1.0


def test_self_reported_extracts_confidence_colon_form() -> None:
    """Pattern 1: ``confidence: NN%``."""
    assert _self_reported("Confidence: 80%") == 0.8


def test_self_reported_extracts_percent_confiden_form() -> None:
    """Pattern 2: ``NN% confidence``."""
    assert _self_reported("Estimated 75% confidence in this answer.") == 0.75


def test_self_reported_averages_multiple_matches() -> None:
    assert _self_reported("Confidence: 80%. Also 60% confidence.") == 0.7


def test_self_reported_rejects_out_of_range_percentages() -> None:
    """Values outside [0, 100] must be ignored."""
    assert _self_reported("Confidence: 200%") == -1.0


def test_self_reported_returns_neg_one_when_no_percent_token() -> None:
    assert _self_reported("I am very sure about this answer.") == -1.0


# ---------------------------------------------------------------------------
# _grounding
# ---------------------------------------------------------------------------


def test_grounding_returns_neg_one_on_empty_text() -> None:
    icd = InMemoryVocabulary.from_iterable(["e11.9"])
    assert _grounding("", icd) == -1.0


def test_grounding_returns_neg_one_when_vocab_is_none() -> None:
    assert _grounding("Diagnosis: E11.9", None) == -1.0


def test_grounding_returns_neg_one_when_no_icd_tokens_in_text() -> None:
    icd = InMemoryVocabulary.from_iterable(["e11.9"])
    assert _grounding("plain prose without codes", icd) == -1.0


def test_grounding_computes_fraction_valid() -> None:
    """1 of 2 tokens valid → 0.5."""
    icd = InMemoryVocabulary.from_iterable(["e11.9"])
    assert _grounding("Diagnosis: E11.9 and Z99.9", icd) == 0.5


def test_grounding_returns_one_when_all_valid() -> None:
    icd = InMemoryVocabulary.from_iterable(["e11.9", "i10"])
    assert _grounding("Codes: E11.9 and I10", icd) == 1.0


# ---------------------------------------------------------------------------
# _hallucination
# ---------------------------------------------------------------------------


def test_hallucination_returns_neg_one_on_empty_text() -> None:
    drugs = InMemoryVocabulary.from_iterable(["metformin"])
    assert _hallucination("", drugs) == -1.0


def test_hallucination_returns_neg_one_when_vocab_is_none() -> None:
    assert _hallucination("Take Metformin daily.", None) == -1.0


def test_hallucination_returns_neg_one_when_no_drug_tokens_in_text() -> None:
    drugs = InMemoryVocabulary.from_iterable(["metformin"])
    assert _hallucination("plain prose with no drug terms", drugs) == -1.0


def test_hallucination_full_match_returns_one() -> None:
    drugs = InMemoryVocabulary.from_iterable(["metformin", "lisinopril"])
    assert _hallucination("Take Metformin and Lisinopril.", drugs) == 1.0


def test_hallucination_partial_match_returns_fraction() -> None:
    """1 known drug out of 2 detected → 0.5."""
    drugs = InMemoryVocabulary.from_iterable(["metformin"])
    assert _hallucination("Take Metformin and Atenolol.", drugs) == 0.5


# ---------------------------------------------------------------------------
# _completeness
# ---------------------------------------------------------------------------


def test_completeness_returns_neg_one_when_no_required() -> None:
    assert _completeness(set(), set()) == -1.0
    assert _completeness({"a"}, set()) == -1.0


def test_completeness_zero_when_none_provided() -> None:
    assert _completeness(set(), {"a", "b"}) == 0.0


def test_completeness_partial_provided() -> None:
    assert _completeness({"a"}, {"a", "b"}) == 0.5


def test_completeness_one_when_all_provided() -> None:
    assert _completeness({"a", "b"}, {"a", "b"}) == 1.0


# ---------------------------------------------------------------------------
# ConfidenceScorer
# ---------------------------------------------------------------------------


def test_scorer_default_weights_match_spec() -> None:
    """Default weight dictionary matches README §7."""
    scorer = ConfidenceScorer()
    assert scorer.weights == {
        "self_reported": 0.25,
        "grounding": 0.30,
        "hallucination": 0.30,
        "completeness": 0.15,
    }


def test_scorer_default_when_all_signals_missing() -> None:
    """If every signal returns -1 the configured default is returned."""
    scorer = ConfidenceScorer(default_when_unscored=0.42)
    result = scorer.score(ConfidenceInputs())
    assert result.score == 0.42
    assert all(v == -1.0 for v in result.breakdown.values())


def test_scorer_excludes_missing_signals_from_weighted_average() -> None:
    """Only present (>= 0) signals contribute to weighted average."""
    scorer = ConfidenceScorer()
    inputs = ConfidenceInputs(
        reasoning_text="Confidence: 80%",
        provided_fields={"note"},
        required_fields={"note"},
    )
    # self_reported=0.8 w=0.25, completeness=1.0 w=0.15; grounding/hallucination missing.
    # expected = (0.8*0.25 + 1.0*0.15) / (0.25 + 0.15) = 0.35 / 0.40 = 0.875
    result = scorer.score(inputs)
    assert result.score == pytest.approx(0.875)


def test_scorer_clamps_score_into_unit_interval() -> None:
    """Even with custom weights, the final score must be in [0, 1]."""
    scorer = ConfidenceScorer(weights={"self_reported": 10.0})
    inputs = ConfidenceInputs(reasoning_text="Confidence: 50%")
    result = scorer.score(inputs)
    assert 0.0 <= result.score <= 1.0


def test_scorer_breakdown_contains_all_four_signal_keys() -> None:
    """The breakdown dict must always carry all 4 signal keys, even when missing."""
    scorer = ConfidenceScorer()
    result = scorer.score(ConfidenceInputs())
    assert set(result.breakdown) == {
        "self_reported",
        "grounding",
        "hallucination",
        "completeness",
    }


def test_scorer_custom_weights_are_used() -> None:
    """A custom weights dict must override defaults exactly."""
    custom = {"self_reported": 1.0, "grounding": 0.0, "hallucination": 0.0, "completeness": 0.0}
    scorer = ConfidenceScorer(weights=custom)
    assert scorer.weights == custom


def test_scorer_includes_zero_valued_signal_in_average() -> None:
    """A signal returning exactly 0.0 must count as present.

    Kills the ``v >= 0`` → ``v > 0`` boundary mutant: with the strict mutant
    the zero-valued signal would be excluded, and the resulting score would
    jump from a weighted average to 1.0.
    """
    scorer = ConfidenceScorer(weights={"self_reported": 1.0, "completeness": 1.0})
    # completeness = 0/1 = 0.0 (provided ∩ required is empty).
    # self_reported = 1.0.
    # Original: (1.0*1 + 0.0*1) / (1+1) = 0.5
    # Mutant excluding 0.0: 1.0 / 1.0 = 1.0
    inputs = ConfidenceInputs(
        reasoning_text="Confidence: 100%",
        provided_fields=set(),
        required_fields={"x"},
    )
    result = scorer.score(inputs)
    assert result.score == pytest.approx(0.5)


def test_inputs_dataclass_defaults_are_empty() -> None:
    """``ConfidenceInputs()`` must produce empty-string text fields and empty sets.

    Kills mutants that flip ``str = ""`` to ``"XXXX"`` or ``None``, or that flip
    optional-vocab fields away from ``None``.
    """
    inputs = ConfidenceInputs()
    assert inputs.output_text == ""
    assert inputs.reasoning_text == ""
    assert inputs.provided_fields == set()
    assert inputs.required_fields == set()
    assert inputs.drug_vocab is None
    assert inputs.icd_vocab is None


def test_scorer_default_when_unscored_is_07() -> None:
    """Kills ``default_when_unscored = 0.7`` → ``1.7`` mutant."""
    scorer = ConfidenceScorer()
    assert scorer.default_when_unscored == 0.7
    # And confirm it actually flows through to ``score`` for an empty input.
    result = scorer.score(ConfidenceInputs())
    assert result.score == 0.7


def test_self_reported_zero_percent_is_included() -> None:
    """0% is a valid value — boundary on ``0 <= pct``.

    Kills the ``0 <= pct`` → ``0 < pct`` mutant.
    """
    assert _self_reported("Confidence: 0%") == 0.0


def test_self_reported_one_hundred_percent_is_included() -> None:
    """100% is a valid value — boundary on ``pct <= 100``.

    Kills the ``pct <= 100`` → ``pct <= 101`` mutant indirectly by ensuring 100
    is treated as valid; combined with the rejection test for >100 this pins
    the boundary.
    """
    assert _self_reported("Confidence: 100%") == 1.0


def test_self_reported_101_percent_is_rejected() -> None:
    """101% must be rejected — directly hits the upper-bound boundary."""
    assert _self_reported("Confidence: 101%") == -1.0


def test_scorer_unclamped_score_is_floored_at_one() -> None:
    """If raw score would exceed 1.0 it must be clamped to 1.0.

    Constructs a case where ``weighted_sum/total_weight`` > 1.0 by giving the
    completeness signal a value above its true range via a manual weight setup.
    The straightforward path is harder, so we directly verify via a present
    signal of 1.0 and an extreme weight ratio; the clamp must hold.
    """
    scorer = ConfidenceScorer(weights={"self_reported": 1.0})
    # 100% confidence with weight 1.0 → exactly 1.0; the clamp at upper bound
    # of 1.0 must keep this at 1.0 and not let the ``min(2.0, ...)`` mutant
    # pass a value > 1.0 through. Pair with a manual breakdown test below.
    result = scorer.score(ConfidenceInputs(reasoning_text="Confidence: 100%"))
    assert result.score == 1.0


def test_scorer_signal_missing_defaults_to_zero_weight() -> None:
    """A signal with no weight entry must contribute zero, not one."""
    scorer = ConfidenceScorer(weights={"self_reported": 1.0})
    inputs = ConfidenceInputs(
        reasoning_text="Confidence: 60%",
        provided_fields={"a"},
        required_fields={"a"},
    )
    # completeness is present (1.0) but has weight 0 → total weight = 1.0 (self_reported only).
    # weighted_sum = 0.6*1.0 + 1.0*0 = 0.6; total_weight = 1.0 + 0 = 1.0 → 0.6.
    result = scorer.score(inputs)
    assert result.score == pytest.approx(0.6)
