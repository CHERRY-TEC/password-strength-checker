"""Property-style invariant tests over the full sample dataset and all backends.

These complement the narrow unit tests by asserting that rules hold for every
seed record, every storage backend and every export format.
"""

import tempfile
import unittest
from pathlib import Path

from psc.analyzer import analyze_password, explain_rules
from psc.config import SCHEMA_VERSION
from psc.exporter import export_csv, export_markdown, export_text_audit
from psc.models import PasswordRecord
from psc.seed_data import generate_records
from psc.sqlite_store import SQLiteStore
from psc.storage import CSVStore, JSONStore
from psc.summary import build_summary, rating_distribution


DISTINCTIVE_SECRETS = (
    "X9#mL2@vT7!qR4$p",
    "vL8!qZ#2wR@6tY&1c",
    "Purple-Coffee-Mountain-42",
    "Tr0ub4dor&3",
)


class InvariantTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = generate_records(46)

    def test_every_sample_record_has_a_valid_analysis(self):
        for record in self.records:
            with self.subTest(record=record.id):
                analysis = record.analysis
                self.assertGreaterEqual(analysis.score, 0)
                self.assertLessEqual(analysis.score, 100)
                self.assertGreaterEqual(analysis.entropy_bits, 0)
                self.assertTrue(analysis.crack_time)
                self.assertLessEqual(analysis.char_classes, 4)
                self.assertLessEqual(len(analysis.suggestions), 6)
                self.assertLessEqual(len(analysis.patterns), 4)

    def test_rating_always_matches_score_band(self):
        bands = [(20, "Very Weak"), (40, "Weak"), (60, "Fair"), (80, "Strong"), (101, "Very Strong")]
        for record in self.records:
            expected = next(label for ceiling, label in bands if record.score < ceiling)
            self.assertEqual(record.rating, expected, record.label)

    def test_no_password_material_in_serialised_records(self):
        for password in DISTINCTIVE_SECRETS:
            serialised = str(analyze_password(password).to_dict())
            self.assertNotIn(password, serialised)

    def test_rules_are_stable_and_unique(self):
        rules = explain_rules()
        self.assertEqual(len(rules), len({rule["title"] for rule in rules}))
        self.assertTrue(all(rule["rule"] and rule["why"] for rule in rules))

    def test_summary_invariants_across_dataset_sizes(self):
        for count in (0, 1, 7, 46):
            report = build_summary(self.records[:count])
            self.assertEqual(report.total, count)
            self.assertEqual(sum(v for _, v in rating_distribution(report)), count)
            self.assertEqual(report.weak_count + report.strong_count <= count, True)
            self.assertGreaterEqual(report.average_score, 0)

    def test_all_backends_preserve_the_full_dataset(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            stores = [
                JSONStore(base / "records.json"),
                CSVStore(base / "records.csv"),
                SQLiteStore(base / "records.sqlite3"),
            ]
            for store in stores:
                with self.subTest(backend=store.name):
                    store.save(self.records)
                    restored, warnings = store.load()
                    self.assertEqual(warnings, [])
                    self.assertEqual(
                        [record.to_dict() for record in restored],
                        [record.to_dict() for record in self.records],
                    )

    def test_exports_never_contain_a_sample_password(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            report = build_summary(self.records)
            documents = [
                export_markdown(self.records, report, base / "r.md").read_text(encoding="utf-8"),
                export_text_audit(self.records, report, base / "r.txt").read_text(encoding="utf-8"),
                export_csv(self.records, base / "r.csv").read_text(encoding="utf-8"),
            ]
            for password in DISTINCTIVE_SECRETS:
                for document in documents:
                    self.assertNotIn(password, document)

    def test_json_payload_declares_schema_version(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "records.json"
            store = JSONStore(path)
            store.save(self.records)
            payload = __import__("json").loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema_version"], SCHEMA_VERSION)
            self.assertEqual(len(payload["records"]), len(self.records))


if __name__ == "__main__":
    unittest.main()
