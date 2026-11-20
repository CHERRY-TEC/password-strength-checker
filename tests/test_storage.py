"""Unit tests for JSON/CSV persistence and corruption recovery."""

import json
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from psc.analyzer import analyze_password
from psc.models import PasswordRecord
from psc.storage import CSVStore, JSONStore


def make_record(record_id: int = 1, label: str = "Test account") -> PasswordRecord:
    return PasswordRecord(
        id=record_id,
        label=label,
        checked_at=datetime.now().isoformat(timespec="seconds"),
        analysis=analyze_password("Str0ng!Pass#2024"),
    )


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_json_round_trip(self):
        store = JSONStore(self.folder / "records.json")
        records, warnings = store.load()
        self.assertEqual(records, [])
        self.assertEqual(len(warnings), 1)

        store.save([make_record(1), make_record(2)])
        restored, warnings = store.load()
        self.assertEqual(warnings, [])
        self.assertEqual(len(restored), 2)
        self.assertEqual(restored[0].label, "Test account")
        self.assertEqual(restored[1].analysis.score, make_record().analysis.score)

    def test_csv_round_trip(self):
        store = CSVStore(self.folder / "records.csv")
        store.save([make_record(1, "CSV account")])
        restored, warnings = store.load()
        self.assertEqual(warnings, [])
        self.assertEqual(len(restored), 1)
        self.assertEqual(restored[0].label, "CSV account")
        self.assertEqual(restored[0].analysis.rating, "Very Strong")

    def test_corrupt_json_is_recovered(self):
        path = self.folder / "records.json"
        path.write_text("{ this is not json", encoding="utf-8")
        records, warnings = JSONStore(path).load()
        self.assertEqual(records, [])
        self.assertTrue(any("Corrupt JSON" in warning for warning in warnings))
        self.assertIn("records", json.loads(path.read_text(encoding="utf-8")))
        self.assertTrue(list(self.folder.glob("records.json.corrupt.*")))

    def test_invalid_json_rows_are_skipped(self):
        path = self.folder / "records.json"
        path.write_text(
            json.dumps({"schema_version": 1, "records": [make_record(1).to_dict(), {"id": "bad"}]}),
            encoding="utf-8",
        )
        records, warnings = JSONStore(path).load()
        self.assertEqual(len(records), 1)
        self.assertTrue(any("Skipped record" in warning for warning in warnings))

    def test_bad_csv_header_is_not_modified_when_not_repairing(self):
        path = self.folder / "legacy.csv"
        original = "id,label,foo\n1,Example,bar\n"
        path.write_text(original, encoding="utf-8")
        records, warnings = CSVStore(path).load(repair=False)
        self.assertEqual(records, [])
        self.assertTrue(any("missing columns" in warning for warning in warnings))
        self.assertEqual(path.read_text(encoding="utf-8"), original)

    def test_csv_row_errors_are_reported(self):
        path = self.folder / "records.csv"
        CSVStore(path).save([make_record(1)])
        text = path.read_text(encoding="utf-8").replace("1,Test account,", "not-an-id,Test account,")
        path.write_text(text, encoding="utf-8")
        records, warnings = CSVStore(path).load(repair=False)
        self.assertEqual(records, [])
        self.assertTrue(any("Skipped CSV row" in warning for warning in warnings))


if __name__ == "__main__":
    unittest.main()
