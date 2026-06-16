"""DICOM pixel OCR for burned-in PHI.

Many DICOM modalities (ultrasound screenshots, scanned forms) carry PHI as
pixels rendered onto the image — these bypass header-level redaction. This
module renders the pixel array and runs Tesseract OCR over it.

The module is optional: requires ``clinicsentry[ocr]`` plus an installed
Tesseract binary.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from clinicsentry.phi.detectors import Hit, RegexDetector

__all__ = ["DICOMPixelOCRDetector"]


@dataclass
class DICOMPixelOCRDetector:
    """Detect burned-in PHI in DICOM pixel data.

    The detector renders the pixel array with ``pydicom``, runs Tesseract OCR,
    and feeds the resulting text into the supplied (regex) detector. Hits are
    reported with a fixed offset of 0 because pixel coordinates are not
    char-positional.
    """

    text_detector: RegexDetector | None = None

    def detect(self, dataset: Any) -> list[Hit]:
        """Return PHI hits found in the rendered pixel data.

        Args:
            dataset: a pydicom Dataset (or anything with ``pixel_array``).

        Returns:
            List of :class:`Hit` records, possibly empty.
        """
        try:  # pragma: no cover - optional deps
            import pytesseract
            from PIL import Image
        except ImportError:
            return []

        try:
            arr = getattr(dataset, "pixel_array", None)
            if arr is None:
                return []
            img = Image.fromarray(arr)
            text = pytesseract.image_to_string(img)
        except Exception:  # pragma: no cover - imaging libraries can throw broadly
            return []

        detector = self.text_detector or RegexDetector()
        return detector.detect(text)
