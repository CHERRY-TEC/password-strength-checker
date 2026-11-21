"""Structured logging for the Password Strength Checker.

Operational events (startup, persistence, API access, warnings) are emitted as
JSON lines through the standard :mod:`logging` module.  User-facing terminal
rendering stays in :mod:`psc.ui`; this module is for diagnostics, auditing and
observability.  Passwords are never logged.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LOGGER_NAME = "psc"
_configured = False


class JsonFormatter(logging.Formatter):
    """Render each log record as a single JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        for key in ("event_name", "storage_format", "record_id", "record_count",
                    "endpoint", "status", "duration_ms", "path"):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, sort_keys=True)


class TextFormatter(logging.Formatter):
    """Human-readable formatter for interactive terminals."""

    def __init__(self) -> None:
        super().__init__("%(asctime)s %(levelname)-7s %(name)s | %(message)s")


def configure_logging(
    level: str = "INFO",
    log_file: Path | None = None,
    *,
    json_output: bool = True,
) -> logging.Logger:
    """Configure the ``psc`` logger idempotently and return it."""
    global _configured
    logger = logging.getLogger(LOGGER_NAME)
    if _configured:
        return logger

    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False
    for handler in list(logger.handlers):
        logger.removeHandler(handler)

    formatter: logging.Formatter = JsonFormatter() if json_output else TextFormatter()

    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(formatter)
    logger.addHandler(console)

    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    _configured = True
    logger.info("logging_configured", extra={"event_name": "logging.configured"})
    return logger


def shutdown_logging() -> None:
    """Flush and close all handlers (useful for tests and clean shutdown)."""
    global _configured
    logger = logging.getLogger(LOGGER_NAME)
    for handler in list(logger.handlers):
        handler.flush()
        handler.close()
        logger.removeHandler(handler)
    _configured = False


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a namespaced child logger under ``psc``."""
    base = logging.getLogger(LOGGER_NAME)
    if not base.handlers:
        configure_logging()
    return base.getChild(name) if name else base


def log_event(logger: logging.Logger, level: int, event: str, **fields: Any) -> None:
    """Log a named event with structured extra fields."""
    logger.log(level, event, extra={"event_name": event, **fields})
