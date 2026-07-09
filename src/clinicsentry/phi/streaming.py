"""Stateful redaction for token-streamed LLM output.

``StreamRedactor.push`` emits redacted text as soon as a boundary is provable;
``flush`` drains the remainder. The safety argument: the last ``holdback``
characters of the buffer are never emitted, and any identifier whose total
length is at most ``holdback`` therefore cannot have started inside an
already-emitted region while still being incomplete — its visible prefix would
have to be longer than ``holdback``. Detected hits that cross the emit
boundary (e.g. a long URL still streaming in) pull the boundary back to the
hit start.

Identifiers longer than ``holdback`` (default 128 chars) are the documented
limitation; raise ``holdback`` if your traffic contains them.
"""

from __future__ import annotations

from collections.abc import Callable

from clinicsentry.phi.detectors import Hit

__all__ = ["StreamRedactor"]

DEFAULT_HOLDBACK = 128


class StreamRedactor:
    """Incremental redactor over a chunked text stream.

    Built by :meth:`PHIFirewall.stream_redactor`; not constructed directly.
    """

    def __init__(
        self,
        detect: Callable[[str], list[Hit]],
        redact: Callable[[str, list[Hit]], str],
        on_hits: Callable[[list[Hit]], None] | None = None,
        holdback: int = DEFAULT_HOLDBACK,
    ) -> None:
        if holdback < 16:
            raise ValueError("holdback must be >= 16")
        self._detect = detect
        self._redact = redact
        self._on_hits = on_hits
        self._holdback = holdback
        self._buffer = ""
        self._closed = False

    def push(self, chunk: str) -> str:
        """Add a chunk; return whatever text is now provably safe to emit."""
        if self._closed:
            raise RuntimeError("StreamRedactor already flushed")
        self._buffer += chunk
        emit_end = len(self._buffer) - self._holdback
        if emit_end <= 0:
            return ""
        hits = self._detect(self._buffer)
        for h in hits:
            if h.start < emit_end < h.end:
                emit_end = h.start
        if emit_end <= 0:
            return ""
        head_hits = [h for h in hits if h.end <= emit_end]
        head = self._buffer[:emit_end]
        self._buffer = self._buffer[emit_end:]
        if head_hits and self._on_hits is not None:
            self._on_hits(head_hits)
        return self._redact(head, head_hits)

    def flush(self) -> str:
        """Redact and return everything still buffered; ends the stream."""
        self._closed = True
        tail, self._buffer = self._buffer, ""
        if not tail:
            return ""
        hits = self._detect(tail)
        if hits and self._on_hits is not None:
            self._on_hits(hits)
        return self._redact(tail, hits)
