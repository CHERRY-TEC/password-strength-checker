"""Tests for summary aggregation and threshold indicators."""

from datetime import datetime
import unittest

from psc.analyzer import analyze_password
from psc.models import AnalysisResult, PasswordRecord
from psc.summary import build_alerts, build_summary, rating_distribution


def make_record(record_id, password, label=None, when=None):
    return PasswordRecord(
        id=record_id,
        label=label or f"Account {record_id}",
        checked_at=when or datetime(2026, 1, 2, 3, 4).isoformat(),
        analysis=analyze_password(password),
    )


class SummaryTests(unittest.TestCase):
    def test_empty_summary(self):
        report = build_summary([])
        self.assertEqual(report.total, 0)
        self.assertEqual(report.average_score, 0.0)
        self.assertIsNone(report.min_score)
        self.assertEqual(build_alerts(report)[0][0], "info")

    def test_core_metrics(self):
        records = [
            make_record(1, "password", when="2026-01-01T10:00:00"),
            make_record(2, "X9#mL2@vT7!qR4$p", when="2026-01-02T10:00:00"),
        ]
        report = build_summary(records)
        self.assertEqual(report.total, 2)
        self.assertEqual(report.min_score, records[0].score)
        self.assertEqual(report.max_score, records[1].score)
        self.assertEqual(report.strongest.id, 2)
        self.assertEqual(report.weakest.id, 1)
        self.assertEqual(report.per_day["2026-01-01"], 1)
        self.assertEqual(report.per_day["2026-01-02"], 1)
        self.assertAlmostEqual(report.average_score, (records[0].score + records[1].score) / 2, places=1)

    def test_weak_strong_counts_and_rates(self):
        records = [
            make_record(1, "password"),
            make_record(2, "123456"),
            make_record(3, "X9#mL2@vT7!qR4$p"),
            make_record(4, "vL8!qZ#2wR@6tY&1c"),
        ]
        report = build_summary(records)
        self.assertEqual(report.weak_count, 2)
        self.assertEqual(report.strong_count, 2)
        self.assertEqual(report.weak_rate, 0.5)
        self.assertEqual(report.strong_rate, 0.5)

    def test_character_coverage_and_issue_counts(self):
        records = [make_record(1, "Password1"), make_record(2, "Password1")]
        report = build_summary(records)
        self.assertEqual(report.class_counts["Uppercase"], 2)
        self.assertEqual(report.class_counts["Digits"], 2)
        self.assertEqual(report.class_counts["Symbols"], 0)
        self.assertGreater(sum(report.common_issues.values()), 0)

    def test_alerts_include_critical_flags(self):
        records = [make_record(i, "password") for i in range(1, 6)]
        records.append(make_record(6, "a"))  # score 17 -> Very Weak band
        alerts = build_alerts(build_summary(records))
        levels = [level for level, _ in alerts]
        self.assertIn("critical", levels)
        self.assertTrue(any("weak" in message.lower() for _, message in alerts))
        self.assertTrue(any("Very Weak" in message for _, message in alerts))

    def test_distribution_has_stable_order(self):
        report = build_summary([])
        self.assertEqual(
            [name for name, _ in rating_distribution(report)],
            ["Very Strong", "Strong", "Fair", "Weak", "Very Weak"],
        )

    def test_records_with_identical_scores_break_ties_by_id(self):
        analysis = AnalysisResult.from_dict(analyze_password("Password1").to_dict())
        records = [
            PasswordRecord(5, "Five", "2026-01-01T00:00:00", analysis),
            PasswordRecord(2, "Two", "2026-01-01T00:00:00", analysis),
        ]
        report = build_summary(records)
        self.assertEqual(report.strongest.id, 2)
        self.assertEqual(report.weakest.id, 2)


if __name__ == "__main__":
    unittest.main()
