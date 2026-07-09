"""Cloud PHI-detection adapters.

These wrap managed NER services behind the same ``Detector`` protocol the
firewall uses, so teams can combine the fast regex pass with cloud recall for
names/addresses. Enable via policy::

    phi_firewall:
      detector_backend: aws_comprehend_medical

A backend failure returns no hits rather than failing the scan (matching the
Presidio layer): the deterministic detectors remain active, and the error is
reported through the metrics hook as ``clinicsentry.detector.error``.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from clinicsentry.phi.detectors import Hit

__all__ = ["AWSComprehendMedicalDetector", "build_cloud_detector"]

# DetectPHI accepts at most 20k UTF-8 bytes per call.
_CM_MAX_CHARS = 20_000


class AWSComprehendMedicalDetector:
    """AWS Comprehend Medical ``DetectPHI`` as a firewall detector.

    Requires ``boto3`` (``pip install clinicsentry[s3]`` or ``boto3`` directly)
    and AWS credentials in the environment. Pass ``client`` explicitly for
    testing or custom session configuration.
    """

    def __init__(
        self,
        client: Any = None,
        region_name: str | None = None,
        on_error: Callable[[Exception], None] | None = None,
    ) -> None:
        if client is None:
            try:
                import boto3
            except ImportError as exc:
                raise ImportError(
                    "AWSComprehendMedicalDetector requires boto3; "
                    "pip install boto3 (or clinicsentry[s3])"
                ) from exc
            client = boto3.client("comprehendmedical", region_name=region_name)
        self._client = client
        self._on_error = on_error

    def detect(self, text: str) -> list[Hit]:
        """Return hits from DetectPHI, chunking to the service size limit."""
        if not text:
            return []
        hits: list[Hit] = []
        for offset in range(0, len(text), _CM_MAX_CHARS):
            chunk = text[offset : offset + _CM_MAX_CHARS]
            try:
                response = self._client.detect_phi(Text=chunk)
            except Exception as exc:
                if self._on_error is not None:
                    self._on_error(exc)
                return []
            for entity in response.get("Entities", []):
                start = int(entity.get("BeginOffset", 0)) + offset
                end = int(entity.get("EndOffset", 0)) + offset
                if end <= start:
                    continue
                hits.append(
                    Hit(
                        phi_type=str(entity.get("Type", "PHI")),
                        start=start,
                        end=end,
                        value=text[start:end],
                        confidence=float(entity.get("Score", 0.5)),
                        source="aws_comprehend_medical",
                    )
                )
        return hits


_BACKENDS = {
    "aws_comprehend_medical": AWSComprehendMedicalDetector,
}


def build_cloud_detector(
    backend: str,
    on_error: Callable[[Exception], None] | None = None,
) -> Any:
    """Instantiate the detector for a ``detector_backend`` policy value."""
    try:
        cls = _BACKENDS[backend]
    except KeyError:
        raise ValueError(
            f"unknown detector_backend {backend!r}; supported: {sorted(_BACKENDS)}"
        ) from None
    return cls(on_error=on_error)
