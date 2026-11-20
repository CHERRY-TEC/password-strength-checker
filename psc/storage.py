"""Local persistence for password-strength records.

Two interchangeable backends are provided: JSON (default) and CSV.  Both:

* create a clean template when the file is missing or empty;
* back up and recover from corrupt JSON / malformed CSV instead of crashing;
* validate every row through ``PasswordRecord.from_dict`` and skip bad rows
  with a descriptive warning;
* write atomically (temporary file + ``os.replace``) so a crash cannot leave a
  half-written record file.

Only analysis metadata is stored - never the password itself.
"""

from __future__ import annotations

import csv
import json
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

from .config import APP_NAME, SCHEMA_VERSION
from .models import PasswordRecord

CSV_FIELDS: tuple[str, ...] = (
    "id",
    "label",
    "checked_at",
    "score",
    "rating",
    "length",
    "has_upper",
    "has_lower",
    "has_digit",
    "has_special",
    "char_classes",
    "entropy_bits",
    "crack_time",
    "issues",
    "suggestions",
)


class StorageError(Exception):
    """Raised when a storage operation cannot be completed."""


def _atomic_write_text(path: Path, text: str) -> None:
    """Write *text* to *path* atomically using a sibling temporary file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise StorageError(f"Could not write {path}: {exc}") from exc


def _backup_file(path: Path) -> Path:
    """Copy a corrupt file aside with a timestamped ``.corrupt`` suffix."""
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    destination = path.with_name(f"{path.name}.corrupt.{stamp}")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)
    except OSError:
        return path
    return destination


def _row_from_csv(row: dict[str, str]) -> dict[str, Any]:
    """Convert a CSV row of strings into the mapping expected by the model."""
    def as_list(value: str) -> list[str]:
        value = (value or "").strip()
        if not value:
            return []
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return [part.strip() for part in value.split(";") if part.strip()]
        return parsed if isinstance(parsed, list) else []

    return {
        "id": row.get("id", ""),
        "label": row.get("label", ""),
        "checked_at": row.get("checked_at", ""),
        "analysis": {
            "score": row.get("score", 0),
            "rating": row.get("rating", ""),
            "length": row.get("length", 0),
            "has_upper": row.get("has_upper", False),
            "has_lower": row.get("has_lower", False),
            "has_digit": row.get("has_digit", False),
            "has_special": row.get("has_special", False),
            "char_classes": row.get("char_classes", 0),
            "entropy_bits": row.get("entropy_bits", 0),
            "crack_time": row.get("crack_time", ""),
            "issues": as_list(row.get("issues", "")),
            "suggestions": as_list(row.get("suggestions", "")),
        },
    }


def _row_to_csv(record: PasswordRecord) -> dict[str, str]:
    """Convert a record into a flat CSV row of strings."""
    analysis = record.analysis.to_dict()
    return {
        "id": str(record.id),
        "label": record.label,
        "checked_at": record.checked_at,
        "score": str(analysis["score"]),
        "rating": analysis["rating"],
        "length": str(analysis["length"]),
        "has_upper": str(analysis["has_upper"]),
        "has_lower": str(analysis["has_lower"]),
        "has_digit": str(analysis["has_digit"]),
        "has_special": str(analysis["has_special"]),
        "char_classes": str(analysis["char_classes"]),
        "entropy_bits": str(analysis["entropy_bits"]),
        "crack_time": analysis["crack_time"],
        "issues": json.dumps(analysis["issues"], ensure_ascii=False),
        "suggestions": json.dumps(analysis["suggestions"], ensure_ascii=False),
    }


# --------------------------------------------------------------------------- #
# JSON backend
# --------------------------------------------------------------------------- #

class JSONStore:
    """Read/write records from a single structured JSON document."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def exists(self) -> bool:
        return self.path.is_file()

    def save(self, records: list[PasswordRecord]) -> None:
        """Persist all *records*, replacing the previous document."""
        payload = {
            "schema_version": SCHEMA_VERSION,
            "generated_by": APP_NAME,
            "saved_at": datetime.now().isoformat(timespec="seconds"),
            "note": "Analysis metadata only - passwords are never stored.",
            "records": [record.to_dict() for record in records],
        }
        _atomic_write_text(
            self.path,
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        )

    def load(self) -> tuple[list[PasswordRecord], list[str]]:
        """Load records, returning ``(records, warnings)``.

        Missing, empty or corrupt files are replaced with a clean template and
        reported through *warnings* rather than raising.
        """
        warnings: list[str] = []

        if not self.exists():
            self.save([])
            return [], [f"Created new record file: {self.path}"]

        try:
            text = self.path.read_text(encoding="utf-8")
        except OSError as exc:
            backup = _backup_file(self.path)
            self.save([])
            return [], [f"Could not read {self.path} ({exc}); backup: {backup}"]

        if not text.strip():
            self.save([])
            return [], [f"{self.path.name} was empty; rebuilt an empty template."]

        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            backup = _backup_file(self.path)
            self.save([])
            return [], [
                f"Corrupt JSON detected at line {exc.lineno} ({exc.msg}). "
                f"Backup saved to {backup}; started with an empty template."
            ]

        if not isinstance(payload, dict):
            backup = _backup_file(self.path)
            self.save([])
            return [], [f"Unexpected JSON structure in {self.path.name}; backup: {backup}"]

        version = payload.get("schema_version")
        if version != SCHEMA_VERSION:
            warnings.append(
                f"Schema version {version!r} differs from expected {SCHEMA_VERSION}; "
                "attempting best-effort load."
            )

        raw_records = payload.get("records", [])
        if not isinstance(raw_records, list):
            warnings.append("'records' field is not a list; loaded 0 records.")
            raw_records = []

        records: list[PasswordRecord] = []
        seen_ids: set[int] = set()
        for index, raw in enumerate(raw_records, start=1):
            try:
                record = PasswordRecord.from_dict(raw)
            except (ValueError, TypeError, KeyError) as exc:
                warnings.append(f"Skipped record #{index}: {exc}")
                continue
            if record.id in seen_ids:
                warnings.append(f"Skipped record #{index}: duplicate id {record.id}")
                continue
            seen_ids.add(record.id)
            records.append(record)

        if warnings:
            self.save(records)  # persist the cleaned-up state
        return records, warnings


# --------------------------------------------------------------------------- #
# CSV backend
# --------------------------------------------------------------------------- #

class CSVStore:
    """Read/write records from a flat CSV file with header validation."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def exists(self) -> bool:
        return self.path.is_file()

    def save(self, records: list[PasswordRecord]) -> None:
        """Persist all *records* to CSV with a validated header row."""
        path = self.path
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name + ".tmp")
        try:
            with temporary.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=list(CSV_FIELDS))
                writer.writeheader()
                for record in records:
                    writer.writerow(_row_to_csv(record))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        except OSError as exc:
            temporary.unlink(missing_ok=True)
            raise StorageError(f"Could not write {path}: {exc}") from exc

    def load(self, *, repair: bool = True) -> tuple[list[PasswordRecord], list[str]]:
        """Load records from CSV, returning ``(records, warnings)``.

        When *repair* is False (used by the bulk importer) invalid files are
        reported but never modified.
        """
        warnings: list[str] = []

        if not self.exists():
            if repair:
                self.save([])
                return [], [f"Created new record file: {self.path}"]
            return [], [f"CSV file not found: {self.path}"]

        try:
            with self.path.open("r", encoding="utf-8", newline="") as handle:
                reader = csv.DictReader(handle)
                fieldnames = reader.fieldnames or []
                missing = [name for name in CSV_FIELDS if name not in fieldnames]
                if missing:
                    if not repair:
                        return [], [
                            f"CSV header is missing columns: {', '.join(missing)}."
                        ]
                    backup = _backup_file(self.path)
                    self.save([])
                    return [], [
                        f"CSV header is missing columns: {', '.join(missing)}. "
                        f"Backup saved to {backup}; started with an empty template."
                    ]
                rows = list(reader)
        except (OSError, csv.Error) as exc:
            if not repair:
                return [], [f"Could not read {self.path}: {exc}"]
            backup = _backup_file(self.path)
            self.save([])
            return [], [f"Could not read {self.path} ({exc}); backup: {backup}"]

        records: list[PasswordRecord] = []
        seen_ids: set[int] = set()
        for index, row in enumerate(rows, start=1):
            if not any((value or "").strip() for value in row.values() if isinstance(value, str)):
                continue  # ignore completely blank lines
            try:
                record = PasswordRecord.from_dict(_row_from_csv(row))
            except (ValueError, TypeError, KeyError) as exc:
                warnings.append(f"Skipped CSV row {index}: {exc}")
                continue
            if record.id in seen_ids:
                warnings.append(f"Skipped CSV row {index}: duplicate id {record.id}")
                continue
            seen_ids.add(record.id)
            records.append(record)

        return records, warnings
