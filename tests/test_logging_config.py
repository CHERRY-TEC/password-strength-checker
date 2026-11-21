"""Tests for structured JSON logging."""

import io
import json
import logging
import tempfile
import unittest
from pathlib import Path

from psc.logging_config import (
    JsonFormatter,
    configure_logging,
    get_logger,
    log_event,
    shutdown_logging,
)


class LoggingTests(unittest.TestCase):
    def make_record(self, message="record_saved"):
        record = logging.LogRecord(
            "psc.test", logging.INFO, __file__, 10, message, None, None
        )
        record.event_name = "storage.saved"
        record.record_count = 12
        return record

    def test_json_formatter_produces_parseable_output(self):
        payload = json.loads(JsonFormatter().format(self.make_record()))
        self.assertEqual(payload["event"], "record_saved")
        self.assertEqual(payload["event_name"], "storage.saved")
        self.assertEqual(payload["record_count"], 12)
        self.assertEqual(payload["level"], "INFO")
        self.assertIn("timestamp", payload)

    def test_password_is_never_part_of_a_log_event(self):
        record = self.make_record("password_checked")
        output = JsonFormatter().format(record)
        self.assertNotIn("hunter2", output)

    def test_log_event_sets_structured_fields(self):
        stream = io.StringIO()
        logger = logging.getLogger("psc.test.event")
        logger.handlers.clear()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        log_event(logger, logging.INFO, "password.checked", record_id=4, score=88)
        payload = json.loads(stream.getvalue().strip())
        self.assertEqual(payload["event_name"], "password.checked")
        self.assertEqual(payload["record_id"], 4)

    def test_configure_logging_creates_file(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "psc.log"
            logger = configure_logging("INFO", path)
            logger.info("test_event", extra={"event_name": "test.event"})
            try:
                logger.handlers[-1].flush()
                self.assertTrue(path.is_file())
                self.assertIn("test_event", path.read_text(encoding="utf-8"))
            finally:
                shutdown_logging()

    def test_get_logger_namespaced(self):
        self.assertEqual(get_logger("storage").name, "psc.storage")


if __name__ == "__main__":
    unittest.main()
