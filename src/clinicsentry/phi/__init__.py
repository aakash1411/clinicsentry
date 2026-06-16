"""PHI Firewall (Module 1)."""

from clinicsentry.phi.adversarial import (
    AdversarialDetector,
    AdversarialNormalizer,
    EncodedPHIDetector,
    NormalizedText,
    normalize_with_map,
)
from clinicsentry.phi.firewall import PHIFirewall, PHIScanResult
from clinicsentry.phi.minimum_necessary import minimum_necessary
from clinicsentry.phi.pipeline import (
    ContextFilter,
    Detector,
    DetectorPipeline,
    clinical_false_positive_predicate,
)
from clinicsentry.phi.propagation import PropagationGraph

__all__ = [
    "AdversarialDetector",
    "AdversarialNormalizer",
    "ContextFilter",
    "Detector",
    "DetectorPipeline",
    "EncodedPHIDetector",
    "NormalizedText",
    "PHIFirewall",
    "PHIScanResult",
    "PropagationGraph",
    "clinical_false_positive_predicate",
    "minimum_necessary",
    "normalize_with_map",
]
