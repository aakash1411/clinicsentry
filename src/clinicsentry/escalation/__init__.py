"""Clinical Escalation Router (Module 2)."""

from clinicsentry.escalation.channels import (
    EscalationChannel,
    InMemoryReviewQueue,
    SQLiteReviewQueue,
    WebhookChannel,
)
from clinicsentry.escalation.confidence import ConfidenceScorer
from clinicsentry.escalation.extra_signals import (
    GuidelineAdherenceSignal,
    GuidelineRule,
    HistoricalConsistencySignal,
    OverridePredictionSignal,
    UncertaintySignal,
    calibrate_thresholds,
)
from clinicsentry.escalation.router import EscalationRouter, RegisteredAction
from clinicsentry.escalation.temperature_scaling import TemperatureScaler

__all__ = [
    "EscalationRouter",
    "RegisteredAction",
    "ConfidenceScorer",
    "EscalationChannel",
    "InMemoryReviewQueue",
    "SQLiteReviewQueue",
    "WebhookChannel",
    "HistoricalConsistencySignal",
    "UncertaintySignal",
    "GuidelineAdherenceSignal",
    "GuidelineRule",
    "OverridePredictionSignal",
    "calibrate_thresholds",
    "TemperatureScaler",
]
