"""S3 archival audit backend.

Writes one JSONL object per session under ``s3://<bucket>/<prefix>/<session>.jsonl``.
Uses S3 Object Lock in compliance mode for write-once semantics when configured
on the bucket. The backend is intentionally write-once-per-session: the file is
finalized at ``flush(session_id)`` time, which is invoked on ``end_session``.

For mixed deployments, pair :class:`S3AuditBackend` with a hot store
(SQLite/Postgres) and use this as the cold archive:

```python
hot = PostgresAuditBackend(DSN)
cold = S3AuditBackend(bucket="audit-archive", prefix="clinicsentry/")
guard = ClinicSentry(audit_backend=ChainedAuditBackend([hot, cold]))
```
"""

from __future__ import annotations

import io
import json
from collections.abc import Iterator
from datetime import UTC
from typing import Any

from clinicsentry.audit.backend import AuditBackend
from clinicsentry.types import AuditEvent

__all__ = ["S3AuditBackend", "ChainedAuditBackend"]


class S3AuditBackend(AuditBackend):
    """Append events into per-session JSONL objects in an S3 bucket."""

    def __init__(
        self,
        bucket: str,
        prefix: str = "clinicsentry/",
        *,
        client: Any = None,
        flush_every: int = 1,
        object_lock_mode: str | None = None,
        retention_days: int = 2555,  # ~7 years
    ) -> None:
        """Configure the S3 client and write strategy.

        Args:
            bucket: target S3 bucket.
            prefix: key prefix inside the bucket.
            client: pre-configured ``boto3.client('s3')`` (optional).
            flush_every: number of events buffered between PUTs.
            object_lock_mode: one of ``"GOVERNANCE"`` / ``"COMPLIANCE"`` /
                ``None``. If set, applied to each PUT.
            retention_days: object-lock retention window in days.
        """
        if client is None:
            try:  # pragma: no cover - optional dep
                import boto3
            except ImportError as exc:  # pragma: no cover
                raise ImportError(
                    "S3AuditBackend requires boto3. Install: `pip install 'clinicsentry[s3]'`."
                ) from exc
            client = boto3.client("s3")

        self._client = client
        self._bucket = bucket
        self._prefix = prefix.rstrip("/") + "/"
        self._flush_every = max(1, flush_every)
        self._object_lock_mode = object_lock_mode
        self._retention_days = retention_days
        self._buffers: dict[str, list[AuditEvent]] = {}

    def _key(self, session_id: str) -> str:
        """Compute the S3 key for ``session_id``."""
        return f"{self._prefix}{session_id}.jsonl"

    def append(self, event: AuditEvent) -> None:
        """Buffer the event; flush when the configured threshold is crossed."""
        buf = self._buffers.setdefault(event.session_id, [])
        buf.append(event)
        if len(buf) >= self._flush_every:
            self.flush(event.session_id)

    def flush(self, session_id: str) -> None:
        """Persist the per-session buffer to a single S3 object."""
        events = self._buffers.get(session_id, [])
        if not events:
            return
        body = io.BytesIO()
        for ev in events:
            body.write((json.dumps(ev.to_dict(), default=str) + "\n").encode())
        body.seek(0)

        kwargs: dict[str, Any] = {
            "Bucket": self._bucket,
            "Key": self._key(session_id),
            "Body": body.getvalue(),
            "ContentType": "application/x-ndjson",
        }
        if self._object_lock_mode is not None:  # pragma: no cover - requires real S3
            from datetime import datetime, timedelta

            kwargs["ObjectLockMode"] = self._object_lock_mode
            kwargs["ObjectLockRetainUntilDate"] = datetime.now(UTC) + timedelta(
                days=self._retention_days
            )
        self._client.put_object(**kwargs)
        # Keep buffer for potential re-flush; production deployments typically
        # treat ``flush`` as final and call it once at end_session.

    def read_session(self, session_id: str) -> Iterator[AuditEvent]:
        """Stream events for ``session_id`` from S3 (or local buffer if unflushed)."""
        if session_id in self._buffers and self._buffers[session_id]:
            yield from self._buffers[session_id]
            return
        obj = self._client.get_object(Bucket=self._bucket, Key=self._key(session_id))
        body = obj["Body"].read()
        from clinicsentry.audit.backend import _event_from_dict

        for line in body.decode().splitlines():
            if not line.strip():
                continue
            yield _event_from_dict(json.loads(line))

    def _iter_session_ids(self) -> Iterator[str]:
        """List session ids by enumerating S3 keys under the prefix."""
        paginator = self._client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self._bucket, Prefix=self._prefix):
            for obj in page.get("Contents") or []:
                key: str = obj["Key"]
                if key.endswith(".jsonl"):
                    yield key.removeprefix(self._prefix).removesuffix(".jsonl")


class ChainedAuditBackend(AuditBackend):
    """Fan-out backend that appends each event to every wrapped backend.

    Reads are served by the **first** backend that yields any events for a
    session (typically the hot tier). Use this to combine a low-latency
    operational store with a long-term archive.
    """

    def __init__(self, backends: list[AuditBackend]) -> None:
        """Store ``backends`` in call order."""
        if not backends:
            raise ValueError("ChainedAuditBackend requires at least one backend")
        self._backends = list(backends)

    def append(self, event: AuditEvent) -> None:
        """Append to every backend in order, surfacing the first error."""
        for backend in self._backends:
            backend.append(event)

    def read_session(self, session_id: str) -> Iterator[AuditEvent]:
        """Return events from the first backend with a non-empty result."""
        for backend in self._backends:
            events = list(backend.read_session(session_id))
            if events:
                yield from events
                return

    def _iter_session_ids(self) -> Iterator[str]:
        """Union session ids across all backends."""
        seen: set[str] = set()
        for backend in self._backends:
            for sid in backend._iter_session_ids():
                if sid not in seen:
                    seen.add(sid)
                    yield sid
