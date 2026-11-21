"""SQLite persistence backend built on the Python standard library.

Complements the JSON and CSV backends with a real, indexed, transactional data
store.  Every row is validated through ``PasswordRecord.from_dict`` on read,
so a damaged or hand-edited database cannot crash the application: bad rows are
skipped with a warning and the cleaned state is written back.

Only analysis metadata is stored - never the password itself.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from .config import APP_NAME, SCHEMA_VERSION
from .models import PasswordRecord
from .patterns import StorageStrategy
from .storage import StorageError, _backup_file


class SQLiteStore(StorageStrategy):
    """Read/write records from a transactional SQLite database."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    @property
    def name(self) -> str:
        return "sqlite"

    def exists(self) -> bool:
        return self.path.is_file()

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), timeout=30)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self, connection: sqlite3.Connection) -> None:
        """Create the schema if needed and stamp the schema version."""
        # The default rollback journal avoids WAL/SHM sidecar locks on Windows
        # and keeps a single database file easy to back up and recover.
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS meta ("
            "key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS records ("
            "id INTEGER PRIMARY KEY CHECK(id > 0), "
            "label TEXT NOT NULL, "
            "checked_at TEXT NOT NULL, "
            "analysis TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_records_checked_at ON records(checked_at)"
        )
        connection.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )
        connection.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES('generated_by', ?)",
            (APP_NAME,),
        )
        connection.commit()

    def _remove_database_files(self) -> None:
        """Remove the database and its WAL/SHM sidecars before rebuilding."""
        for suffix in ("", "-wal", "-shm"):
            Path(str(self.path) + suffix).unlink(missing_ok=True)

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def save(self, records: list[PasswordRecord]) -> None:
        """Replace all stored records atomically inside one transaction."""
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with closing(self._connect()) as connection:
                self._initialize(connection)
                connection.execute("BEGIN")
                connection.execute("DELETE FROM records")
                connection.executemany(
                    "INSERT INTO records(id, label, checked_at, analysis) "
                    "VALUES(?, ?, ?, ?)",
                    [
                        (
                            record.id,
                            record.label,
                            record.checked_at,
                            json.dumps(
                                record.analysis.to_dict(),
                                ensure_ascii=False,
                                separators=(",", ":"),
                            ),
                        )
                        for record in records
                    ],
                )
                connection.commit()
        except sqlite3.Error as exc:
            raise StorageError(f"Could not write {self.path}: {exc}") from exc
        except OSError as exc:
            raise StorageError(f"Could not create {self.path}: {exc}") from exc

    def load(self) -> tuple[list[PasswordRecord], list[str]]:
        """Load records, returning ``(records, warnings)``.

        Missing or corrupt files are rebuilt as clean databases and reported
        through *warnings* instead of raising.
        """
        warnings: list[str] = []

        if not self.exists():
            self.save([])
            return [], [f"Created new SQLite database: {self.path}"]

        try:
            with closing(self._connect()) as connection:
                self._initialize(connection)
                version_row = connection.execute(
                    "SELECT value FROM meta WHERE key='schema_version'"
                ).fetchone()
                version = version_row["value"] if version_row else None
                rows = connection.execute(
                    "SELECT id, label, checked_at, analysis FROM records ORDER BY id"
                ).fetchall()
        except sqlite3.DatabaseError as exc:
            backup = _backup_file(self.path)
            self._remove_database_files()
            self.save([])
            return [], [
                f"Corrupt SQLite database ({exc}). Backup saved to {backup}; "
                "rebuilt an empty database."
            ]
        except OSError as exc:
            return [], [f"Could not read {self.path}: {exc}"]

        if version != str(SCHEMA_VERSION):
            warnings.append(
                f"Schema version {version!r} differs from expected {SCHEMA_VERSION}; "
                "attempting best-effort load."
            )

        records: list[PasswordRecord] = []
        seen_ids: set[int] = set()
        for index, row in enumerate(rows, start=1):
            try:
                payload: Any = json.loads(row["analysis"])
                data = {
                    "id": row["id"],
                    "label": row["label"],
                    "checked_at": row["checked_at"],
                    "analysis": payload,
                }
                record = PasswordRecord.from_dict(data)
            except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
                warnings.append(f"Skipped database row #{index}: {exc}")
                continue
            if record.id in seen_ids:
                warnings.append(f"Skipped database row #{index}: duplicate id {record.id}")
                continue
            seen_ids.add(record.id)
            records.append(record)

        if warnings:
            self.save(records)  # persist the cleaned-up state
        return records, warnings

    def count(self) -> int:
        """Return the number of valid records without deserialising them."""
        if not self.exists():
            return 0
        try:
            with closing(self._connect()) as connection:
                return int(connection.execute("SELECT COUNT(*) FROM records").fetchone()[0])
        except sqlite3.DatabaseError:
            return 0
