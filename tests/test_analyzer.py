"""Unit tests for the core password analysis engine."""

import unittest

from psc.analyzer import analyze_password, explain_rules


class AnalyzerTests(unittest.TestCase):
    def test_empty_password_is_handled(self):
        result = analyze_password("")
        self.assertEqual(result.score, 0)
        self.assertEqual(result.rating, "Very Weak")
        self.assertTrue(any("Empty" in issue for issue in result.issues))

    def test_common_password_is_weak(self):
        result = analyze_password("password")
        self.assertLess(result.score, 40)
        self.assertTrue(any("common" in issue.lower() for issue in result.issues))

    def test_very_strong_password_scores_high(self):
        result = analyze_password("X9#mL2@vT7!qR4$p")
        self.assertGreaterEqual(result.score, 80)
        self.assertEqual(result.rating, "Very Strong")
        self.assertEqual(result.char_classes, 4)

    def test_character_flags_are_correct(self):
        result = analyze_password("Ab1!")
        self.assertTrue(result.has_upper)
        self.assertTrue(result.has_lower)
        self.assertTrue(result.has_digit)
        self.assertTrue(result.has_special)

    def test_sequence_and_repetition_are_flagged(self):
        sequence = analyze_password("abcdefghijklmnop")
        repeated = analyze_password("aaaaaaaaaaaaaaaaaaaa")
        self.assertTrue(any("sequence" in issue.lower() for issue in sequence.issues))
        self.assertTrue(any("repetition" in issue.lower() for issue in repeated.issues))

    def test_password_is_not_present_in_result(self):
        secret = "Un1que!Secret#42"
        result = analyze_password(secret)
        serialised = str(result.to_dict())
        self.assertNotIn(secret, serialised)

    def test_explain_rules_returns_structured_rules(self):
        rules = explain_rules()
        self.assertGreaterEqual(len(rules), 5)
        for rule in rules:
            self.assertIn("title", rule)
            self.assertIn("rule", rule)
            self.assertIn("why", rule)

    def test_non_string_input_is_coerced(self):
        result = analyze_password(1234)
        self.assertIsInstance(result.score, int)


if __name__ == "__main__":
    unittest.main()
