"""Tests for Markdown, text, CSV and PNG report exports."""

import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from psc.analyzer import analyze_password
from psc.exporter import export_csv, export_markdown, export_text_audit
from psc.models import PasswordRecord
from psc.summary import build_summary


def make_records():
    return [
        PasswordRecord(
            1, "Campus WiFi", datetime(2026, 1, 2, 3, 4).isoformat(),
            analyze_password("password"),
        ),
        PasswordRecord(
            2, "Banking", datetime(2026, 1, 3, 4, 5).isoformat(),
            analyze_password("X9#mL2@vT7!qR4$p"),
        ),
    ]


class ExporterTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp_dir.name)
        self.records = make_records()
        self.summary = build_summary(self.records)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_markdown_report(self):
        path = export_markdown(self.records, self.summary, self.folder / "report.md")
        text = path.read_text(encoding="utf-8")
        self.assertIn("# Password Strength Checker", text)
        self.assertIn("## Executive Summary", text)
        self.assertIn("Campus WiFi", text)
        self.assertIn("Very Strong", text)
        self.assertIn("2 records", text.replace("Total analysed records: 2", "2 records"))
        self.assertNotIn("X9#mL2", text)

    def test_text_audit_log(self):
        path = export_text_audit(self.records, self.summary, self.folder / "audit.txt")
        text = path.read_text(encoding="utf-8")
        self.assertIn("PLAIN-TEXT AUDIT LOG", text)
        self.assertIn("RECORD DETAIL", text)
        self.assertIn("#   1 |", text)
        self.assertNotIn("X9#mL2", text)

    def test_csv_report(self):
        path = export_csv(self.records, self.folder / "records.csv")
        text = path.read_text(encoding="utf-8")
        header = text.splitlines()[0]
        self.assertIn("id,label,checked_at,score,rating", header)
        self.assertIn("Campus WiFi", text)
        self.assertIn("Banking", text)
        self.assertNotIn("X9#mL2", text)
        self.assertEqual(len(text.splitlines()), 3)  # header + 2 records

    def test_empty_records_export_gracefully(self):
        report = build_summary([])
        path = export_markdown([], report, self.folder / "empty.md")
        self.assertIn("Total analysed records: 0", path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
