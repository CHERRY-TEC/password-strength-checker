"""Tests for the transactional SQLite persistence backend."""

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import datetime
from pathlib import Path

from psc.analyzer import analyze_password
from psc.models import PasswordRecord
from psc.sqlite_store import SQLiteStore
from psc.storage import JSONStore


def make_record(record_id: int = 1, label: str = "Test account") -> PasswordRecord:
    return PasswordRecord(
        id=record_id,
        label=label,
        checked_at=datetime.now().isoformat(timespec="seconds"),
        analysis=analyze_password("Str0ng!Pass#2024"),
    )


class SQLiteStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.path = Path(self.temp_dir.name) / "records.sqlite3"
        self.store = SQLiteStore(self.path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_missing_file_creates_clean_database(self):
        records, warnings = self.store.load()
        self.assertEqual(records, [])
        self.assertEqual(len(warnings), 1)
        self.assertIn("Created new SQLite database", warnings[0])
        self.assertTrue(self.path.is_file())

    def test_schema_is_created_with_version(self):
        self.store.save([make_record()])
        with closing(sqlite3.connect(self.path)) as connection:
            version = connection.execute(
                "SELECT value FROM meta WHERE key='schema_version'"
            ).fetchone()[0]
            tables = {
                row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
        self.assertEqual(version, "1")
        self.assertIn("records", tables)
        self.assertIn("meta", tables)

    def test_round_trip_preserves_all_fields(self):
        original = [make_record(1, "First"), make_record(2, "Second")]
        self.store.save(original)
        restored, warnings = self.store.load()
        self.assertEqual(warnings, [])
        self.assertEqual(len(restored), 2)
        self.assertEqual(restored[0].to_dict(), original[0].to_dict())
        self.assertEqual(restored[1].analysis.issues, original[1].analysis.issues)

    def test_save_replaces_all_records(self):
        self.store.save([make_record(1), make_record(2), make_record(3)])
        self.store.save([make_record(9)])
        records, _ = self.store.load()
        self.assertEqual([record.id for record in records], [9])
        self.assertEqual(self.store.count(), 1)

    def test_invalid_json_row_is_skipped_with_warning(self):
        self.store.save([make_record(1)])
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute(
                "INSERT INTO records(id, label, checked_at, analysis) VALUES(?, ?, ?, ?)",
                (2, "Broken", "not-a-date", "{}"),
            )
            connection.commit()
        records, warnings = self.store.load()
        self.assertEqual([record.id for record in records], [1])
        self.assertTrue(any("Skipped database row" in warning for warning in warnings))
        self.assertEqual(self.store.count(), 1)  # cleaned state persisted

    def test_corrupt_database_is_recovered(self):
        self.path.write_bytes(b"this is not a sqlite database at all")
        records, warnings = SQLiteStore(self.path).load()
        self.assertEqual(records, [])
        self.assertTrue(any("Corrupt SQLite database" in warning for warning in warnings))
        self.assertTrue(list(self.path.parent.glob("records.sqlite3.corrupt.*")))
        self.assertEqual(self.store.count(), 0)

    def test_password_material_is_never_stored(self):
        secret = "Un1que!Secret#42"
        record = make_record(1)
        record.analysis = analyze_password(secret)
        self.store.save([record])
        raw = self.path.read_bytes().decode("utf-8", errors="ignore")
        self.assertNotIn(secret, raw)

    def test_count_on_missing_file_is_zero(self):
        self.assertEqual(self.store.count(), 0)

    def test_json_record_dicts_load_into_sqlite(self):
        """Records are portable: JSON-sourced dicts load cleanly into SQLite."""
        json_path = self.path.parent / "records.json"
        json_store = JSONStore(json_path)
        expected = [make_record(1, "Portable")]
        json_store.save(expected)
        payload = json.loads(json_path.read_text(encoding="utf-8"))["records"]
        restored = [PasswordRecord.from_dict(item) for item in payload]
        self.store.save(restored)
        self.assertEqual(self.store.load()[0][0].to_dict(), expected[0].to_dict())


if __name__ == "__main__":
    unittest.main()
