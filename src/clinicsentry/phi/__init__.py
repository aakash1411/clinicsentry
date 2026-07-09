"""PHI Firewall (Module 1)."""

from clinicsentry.phi.adversarial import (
    AdversarialDetector,
    AdversarialNormalizer,
    EncodedPHIDetector,
    NormalizedText,
    normalize_with_map,
)
from clinicsentry.phi.custom import (
    CustomDetector,
    CustomRegexDetector,
    register_detector,
)
from clinicsentry.phi.firewall import (
    PHIFinding,
    PHIFirewall,
    PHIScanResult,
    TokenizeResult,
)
from clinicsentry.phi.locales import locale_specs, supported_locales
from clinicsentry.phi.minimum_necessary import minimum_necessary
from clinicsentry.phi.pipeline import (
    ContextFilter,
    Detector,
    DetectorPipeline,
    clinical_false_positive_predicate,
)
from clinicsentry.phi.propagation import PropagationGraph
from clinicsentry.phi.streaming import StreamRedactor

__all__ = [
    "AdversarialDetector",
    "AdversarialNormalizer",
    "ContextFilter",
    "CustomDetector",
    "CustomRegexDetector",
    "Detector",
    "DetectorPipeline",
    "EncodedPHIDetector",
    "NormalizedText",
    "PHIFinding",
    "PHIFirewall",
    "PHIScanResult",
    "PropagationGraph",
    "StreamRedactor",
    "TokenizeResult",
    "clinical_false_positive_predicate",
    "locale_specs",
    "minimum_necessary",
    "normalize_with_map",
    "register_detector",
    "supported_locales",
]
