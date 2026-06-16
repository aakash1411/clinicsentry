"""Structured-logging helper using structlog when present, else stdlib JSON."""

from __future__ import annotations

import json
import logging
from typing import Any

__all__ = ["get_logger", "JsonFormatter"]


class JsonFormatter(logging.Formatter):
    """Minimal JSON formatter (no PHI ever in records — ADR-0008/13)."""

    def format(self, record: logging.LogRecord) -> str:
        """Render the record as a JSON object."""
        payload: dict[str, Any] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S.%f"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        for k, v in record.__dict__.items():
            if k in {
                "name",
                "msg",
                "args",
                "levelname",
                "levelno",
                "pathname",
                "filename",
                "module",
                "exc_info",
                "exc_text",
                "stack_info",
                "lineno",
                "funcName",
                "created",
                "msecs",
                "relativeCreated",
                "thread",
                "threadName",
                "processName",
                "process",
                "message",
                "asctime",
            }:
                continue
            payload[k] = v
        return json.dumps(payload, default=str)


def get_logger(name: str = "clinicsentry") -> Any:
    """Return a structlog logger if available, else a JSON-formatted stdlib logger."""
    try:
        import structlog

        return structlog.get_logger(name)
    except ImportError:
        logger = logging.getLogger(name)
        if not logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(JsonFormatter())
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger
