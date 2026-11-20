"""Tests for defensive model parsing and clamping."""

import unittest

from psc.analyzer import analyze_password
from psc.models import AnalysisResult, PasswordRecord


class ModelTests(unittest.TestCase):
    def test_analysis_from_dict_clamps_and_coerces(self):
        result = AnalysisResult.from_dict({
            "score": 999,
            "rating": "Very Strong",
            "length": -5,
            "has_upper": "yes",
            "has_lower": 0,
            "has_digit": True,
            "has_special": "false",
            "char_classes": 42,
            "entropy_bits": "abc",
            "crack_time": None,
            "issues": ["issue one", "", "issue two"],
            "suggestions": "single suggestion",
        })
        self.assertEqual(result.score, 100)
        self.assertEqual(result.length, 0)
        self.assertTrue(result.has_upper)
        self.assertFalse(result.has_lower)
        self.assertTrue(result.has_digit)
        self.assertFalse(result.has_special)
        self.assertEqual(result.char_classes, 4)
        self.assertEqual(result.entropy_bits, 0.0)
        self.assertEqual(result.crack_time, "unknown")
        self.assertEqual(result.issues, ["issue one", "issue two"])
        self.assertEqual(result.suggestions, ["single suggestion"])

    def test_analysis_from_dict_rejects_non_mapping(self):
        with self.assertRaises(ValueError):
            AnalysisResult.from_dict("not a dict")

    def test_record_from_dict_validation(self):
        valid = {
            "id": 1,
            "label": "Valid",
            "checked_at": "2026-01-02T03:04:05",
            "analysis": analyze_password("Password1").to_dict(),
        }
        record = PasswordRecord.from_dict(valid)
        self.assertEqual(record.id, 1)
        self.assertEqual(record.label, "Valid")

        for field, bad_value in (
            ("id", "abc"), ("id", 0), ("checked_at", "not-a-date"), ("checked_at", ""),
        ):
            payload = dict(valid)
            payload[field] = bad_value
            with self.subTest(field=field, value=bad_value):
                with self.assertRaises(ValueError):
                    PasswordRecord.from_dict(payload)

    def test_record_label_sanitised(self):
        valid = {
            "id": 2,
            "label": "  Clean\x00Label  ",
            "checked_at": "2026-01-02T03:04:05",
            "analysis": analyze_password("Password1").to_dict(),
        }
        self.assertEqual(PasswordRecord.from_dict(valid).label, "CleanLabel")

    def test_matches_searches_all_searchable_fields(self):
        record = PasswordRecord(
            1, "Campus WiFi", "2026-01-02T03:04:05", analyze_password("password")
        )
        self.assertTrue(record.matches(["campus"]))
        self.assertTrue(record.matches(["weak"]))
        self.assertTrue(record.matches(["common", "password"]))
        self.assertFalse(record.matches(["nonexistent"]))

    def test_round_trip_dict_is_stable(self):
        record = PasswordRecord(7, "Account", "2026-01-02T03:04:05", analyze_password("P@ssw0rd"))
        self.assertEqual(PasswordRecord.from_dict(record.to_dict()).to_dict(), record.to_dict())


if __name__ == "__main__":
    unittest.main()
