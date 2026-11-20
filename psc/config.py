"""Configuration constants for the Password Strength Checker.

All paths are resolved relative to the project root (the parent of the ``psc``
package) so the application behaves the same no matter which directory it is
launched from.
"""

from __future__ import annotations

import os
from pathlib import Path

# --------------------------------------------------------------------------- #
# Application identity
# --------------------------------------------------------------------------- #
APP_NAME: str = "Password Strength Checker"
APP_VERSION: str = "1.0.0"
SCHEMA_VERSION: int = 1

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #
BASE_DIR: Path = Path(__file__).resolve().parent.parent
DATA_DIR: Path = BASE_DIR / "data"
EXPORT_DIR: Path = BASE_DIR / "exports"
TESTS_DIR: Path = BASE_DIR / "tests"

JSON_PATH: Path = DATA_DIR / "records.json"
CSV_PATH: Path = DATA_DIR / "records.csv"
SQLITE_PATH: Path = DATA_DIR / "records.sqlite3"

# --------------------------------------------------------------------------- #
# Input constraints
# --------------------------------------------------------------------------- #
MIN_PASSWORD_LENGTH: int = 1
MAX_PASSWORD_LENGTH: int = 256
MIN_LABEL_LENGTH: int = 1
MAX_LABEL_LENGTH: int = 60

# --------------------------------------------------------------------------- #
# Display / behaviour
# --------------------------------------------------------------------------- #
PAGE_SIZE: int = 10
DEFAULT_SEED_COUNT: int = 40
SEED_COUNT_MIN: int = 30
SEED_COUNT_MAX: int = 50

# Warning thresholds used by the summary / indicator module.
WEAK_SCORE_THRESHOLD: int = 40          # scores below this are "weak"
CRITICAL_WEAK_RATE: float = 0.40        # >40% weak records -> critical flag
SHORT_LENGTH_WARNING: int = 10          # average length below this -> flag

# Offline guessing rate used for the crack-time estimate (guesses / second).
GUESSES_PER_SECOND: float = 1.0e9

# Environment switches
NO_COLOR: bool = bool(os.environ.get("NO_COLOR"))

SUPPORTED_FORMATS: tuple[str, ...] = ("json", "csv", "sqlite")
