"""Tests for zxcvbn-style spatial, date and repeat heuristic matchers."""

import unittest

from psc.analyzer import analyze_password
from psc.heuristics import (
    collect_matches,
    date_matches,
    minimum_entropy,
    pattern_names,
    repeat_matches,
    spatial_matches,
)


class HeuristicTests(unittest.TestCase):
    def test_spatial_matches_keyboard_walks(self):
        matches = spatial_matches("qwertyuiop123")
        self.assertTrue(matches)
        self.assertTrue(any(match.kind.startswith("spatial") for match in matches))
        self.assertTrue(all(match.entropy > 0 for match in matches))

    def test_spatial_matches_require_minimum_length(self):
        self.assertEqual(spatial_matches("asd", minimum_length=4), [])
        self.assertTrue(spatial_matches("asdf", minimum_length=4))

    def test_date_matches_years_and_dates(self):
        self.assertEqual([match.kind for match in date_matches("1990")], ["year"])
        self.assertTrue(any(match.kind == "date" for match in date_matches("01/01/1990")))

    def test_repeat_matches_multi_character_units(self):
        matches = repeat_matches("abababab")
        self.assertTrue(matches)
        self.assertEqual(matches[0].token[:2], "ab")

    def test_collect_matches_is_deduplicated(self):
        matches = collect_matches("aaaaaaaaaaaaaaaaaaaa")
        keys = [(match.kind, match.token) for match in matches]
        self.assertEqual(len(keys), len(set(keys)))

    def test_minimum_entropy_and_pattern_names(self):
        matches = collect_matches("qwertyuiop123")
        self.assertIsNotNone(minimum_entropy(matches))
        self.assertIn("spatial", pattern_names(matches))

    def test_analyzer_exposes_patterns(self):
        result = analyze_password("qwertyuiop123")
        self.assertIn("spatial", result.patterns)
        self.assertIn("keyboard walk", " ".join(result.issues).lower())
        self.assertIn("patterns", result.to_dict())

    def test_analyzer_detects_date_pattern(self):
        result = analyze_password("01011990")
        self.assertIn("date", result.patterns)

    def test_no_patterns_for_random_password(self):
        self.assertEqual(analyze_password("vL8!qZ#2wR@6tY&1c").patterns, [])


if __name__ == "__main__":
    unittest.main()
