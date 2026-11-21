"""Tests for the novel Structural Drift Index algorithm."""

import unittest

from psc.analyzer import analyze_password
from psc.novelty import (
    compare,
    distance,
    fingerprint,
    length_band,
    portfolio_diversity,
)


def analysis_for(password):
    return analyze_password(password).to_dict()


class NoveltyTests(unittest.TestCase):
    def test_length_bands(self):
        self.assertEqual([length_band(n) for n in (1, 7, 8, 11, 12, 15, 16, 23, 24, 40)],
                         [0, 0, 1, 1, 2, 2, 3, 3, 4, 4])

    def test_fingerprint_is_deterministic_and_non_reversible(self):
        first = fingerprint(analysis_for("X9#mL2@vT7!qR4$p"))
        second = fingerprint(analysis_for("X9#mL2@vT7!qR4$p"))
        self.assertEqual(first, second)
        self.assertNotIn("X9#mL2", str(first.to_dict()))
        self.assertEqual(set(first.to_dict()),
                         {"length", "classes", "entropy", "repetition", "pool", "pattern_mask"})

    def test_distance_is_bounded_symmetric_and_zero_for_identical(self):
        a = fingerprint(analysis_for("password"))
        b = fingerprint(analysis_for("X9#mL2@vT7!qR4$p"))
        self.assertEqual(distance(a, a), 0.0)
        self.assertEqual(distance(a, b), distance(b, a))
        self.assertGreaterEqual(distance(a, b), 0.0)
        self.assertLessEqual(distance(a, b), 1.0)

    def test_compare_with_empty_history(self):
        report = compare(analysis_for("password"), [])
        self.assertIsNone(report.nearest_id)
        self.assertEqual(report.distance, 1.0)
        self.assertEqual(report.diversity, 1.0)
        self.assertIn("baseline", report.advice)

    def test_compare_finds_nearest_structural_match(self):
        target = analysis_for("aaaaaaaaaaaaaaaaaaaa")
        history = [
            (1, analysis_for("X9#mL2@vT7!qR4$p")),
            (2, analysis_for("aaaaaaaaaaaaaaaaaaaa")),
            (3, analysis_for("correct horse battery staple")),
        ]
        report = compare(target, history)
        self.assertEqual(report.nearest_id, 2)
        self.assertGreater(report.similarity, 0.99)
        self.assertGreaterEqual(report.personal_risk, 0)
        self.assertLessEqual(report.personal_risk, 100)
        self.assertTrue(report.advice)

    def test_portfolio_diversity_bounds(self):
        self.assertEqual(portfolio_diversity([]), 1.0)
        self.assertEqual(portfolio_diversity([analysis_for("password")]), 1.0)
        varied = portfolio_diversity([
            analysis_for("password"),
            analysis_for("X9#mL2@vT7!qR4$p"),
            analysis_for("aaaaaaaaaaaaaaaaaaaa"),
        ])
        self.assertGreater(varied, 0.0)
        self.assertLessEqual(varied, 1.0)

    def test_report_serialises(self):
        report = compare(analysis_for("password"), [(1, analysis_for("password"))])
        payload = report.to_dict()
        self.assertEqual(set(payload),
                         {"nearest_id", "distance", "similarity", "diversity",
                          "personal_risk", "advice"})


if __name__ == "__main__":
    unittest.main()
