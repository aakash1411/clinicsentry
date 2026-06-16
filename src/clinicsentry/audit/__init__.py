"""Regulatory Audit Trail (Module 3)."""

from clinicsentry.audit.backend import (
    AuditBackend,
    FileAuditBackend,
    InMemoryAuditBackend,
    SqliteAuditBackend,
)
from clinicsentry.audit.chain import AuditChain
from clinicsentry.audit.otel import OTELAuditBackend
from clinicsentry.audit.report import build_report
from clinicsentry.audit.s3 import ChainedAuditBackend, S3AuditBackend

__all__ = [
    "AuditBackend",
    "AuditChain",
    "FileAuditBackend",
    "InMemoryAuditBackend",
    "SqliteAuditBackend",
    "ChainedAuditBackend",
    "OTELAuditBackend",
    "S3AuditBackend",
    "build_report",
]
