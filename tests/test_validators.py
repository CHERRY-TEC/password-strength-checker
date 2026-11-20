"""Unit tests for the defensive terminal input wrappers."""

import unittest
from unittest.mock import patch

from psc.validators import read_choice, read_int, read_text, read_yes_no


class ValidatorTests(unittest.TestCase):
    def test_read_text_loops_until_valid(self):
        answers = ["", "   ", "A", "Valid Label"]
        with patch("builtins.input", side_effect=answers):
            value = read_text("Label: ", min_len=3, max_len=20)
        self.assertEqual(value, "Valid Label")

    def test_read_text_allows_blank_when_requested(self):
        with patch("builtins.input", return_value="   "):
            self.assertEqual(read_text("Keyword: ", allow_blank=True), "")

    def test_read_text_strips_control_characters(self):
        with patch("builtins.input", return_value="Clean\x00Label"):
            self.assertEqual(read_text("Label: "), "CleanLabel")

    def test_read_int_enforces_range_and_accepts_default(self):
        with patch("builtins.input", side_effect=["abc", "999", "5"]):
            self.assertEqual(read_int("Value", low=1, high=10), 5)
        with patch("builtins.input", return_value=""):
            self.assertEqual(read_int("Value", low=1, high=10, default=7), 7)
        with patch("builtins.input", return_value=""):
            self.assertIsNone(read_int("Value", low=1, high=10, allow_blank=True))

    def test_read_choice_is_case_insensitive(self):
        with patch("builtins.input", side_effect=["bad", " Y "]):
            self.assertEqual(read_choice("Choice", ["y", "n"]), "y")

    def test_read_yes_no_defaults(self):
        with patch("builtins.input", return_value=""):
            self.assertTrue(read_yes_no("Continue?", default=True))
        with patch("builtins.input", return_value=""):
            self.assertFalse(read_yes_no("Continue?", default=False))
        with patch("builtins.input", side_effect=["maybe", "yes"]):
            self.assertTrue(read_yes_no("Continue?"))


if __name__ == "__main__":
    unittest.main()
