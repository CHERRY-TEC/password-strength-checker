"""Foundational data structures for the Password Strength Checker.

These dataclasses model a password *analysis* and a stored *record*.  The raw
password string is deliberately absent from both: only derived characteristics
are modelled, which is what makes local persistence safe.

Every ``from_dict`` constructor is defensive: it validates types, clamps numeric
ranges and raises ``ValueError`` with a clear message when a field cannot be
trusted.  The storage layer relies on this behaviour to skip corrupt rows
without crashing the application.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable

# --------------------------------------------------------------------------- #
# Defensive coercion helpers
# --------------------------------------------------------------------------- #

def _as_int(value: Any, *, default: int, low: int, high: int) -> int:
    """Return *value* as an int clamped to ``[low, high]`` or *default*."""
    if isinstance(value, bool):
        return default
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, number))


def _as_float(value: Any, *, default: float, low: float, high: float) -> float:
    """Return *value* as a float clamped to ``[low, high]`` or *default*."""
    if isinstance(value, bool):
        return default
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    if number != number:  # NaN guard
        return default
    return max(low, min(high, number))


def _as_bool(value: Any) -> bool:
    """Interpret common boolean representations without raising."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return False


def _as_text(value: Any, *, default: str = "", limit: int = 200) -> str:
    """Return a sanitised, length-limited string."""
    if value is None:
        return default
    text = str(value)
    # Strip control characters (except nothing - labels are single-line).
    text = "".join(ch for ch in text if ch.isprintable())
    return text[:limit]


def _as_str_list(value: Any, *, limit: int = 20) -> list[str]:
    """Return a list of short printable strings."""
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)):
        return []
    result: list[str] = []
    for item in value:
        text = _as_text(item, limit=120)
        if text:
            result.append(text)
        if len(result) >= limit:
            break
    return result


# --------------------------------------------------------------------------- #
# Analysis result
# --------------------------------------------------------------------------- #

@dataclass
class AnalysisResult:
    """Derived facts about one password.  Contains no password material."""

    score: int
    rating: str
    length: int
    has_upper: bool
    has_lower: bool
    has_digit: bool
    has_special: bool
    char_classes: int
    entropy_bits: float
    crack_time: str
    issues: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)
    patterns: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a JSON/CSV friendly dictionary."""
        return {
            "score": self.score,
            "rating": self.rating,
            "length": self.length,
            "has_upper": self.has_upper,
            "has_lower": self.has_lower,
            "has_digit": self.has_digit,
            "has_special": self.has_special,
            "char_classes": self.char_classes,
            "entropy_bits": round(float(self.entropy_bits), 2),
            "crack_time": self.crack_time,
            "issues": list(self.issues),
            "suggestions": list(self.suggestions),
            "patterns": list(self.patterns),
        }

    @classmethod
    def from_dict(cls, data: Any) -> "AnalysisResult":
        """Build an ``AnalysisResult`` from untrusted mapping data."""
        if not isinstance(data, dict):
            raise ValueError("analysis must be an object")
        rating = _as_text(data.get("rating"), default="Unknown", limit=32)
        if not rating:
            rating = "Unknown"
        return cls(
            score=_as_int(data.get("score"), default=0, low=0, high=100),
            rating=rating,
            length=_as_int(data.get("length"), default=0, low=0, high=10000),
            has_upper=_as_bool(data.get("has_upper")),
            has_lower=_as_bool(data.get("has_lower")),
            has_digit=_as_bool(data.get("has_digit")),
            has_special=_as_bool(data.get("has_special")),
            char_classes=_as_int(data.get("char_classes"), default=0, low=0, high=4),
            entropy_bits=_as_float(
                data.get("entropy_bits"), default=0.0, low=0.0, high=100000.0
            ),
            crack_time=_as_text(
                data.get("crack_time"), default="unknown", limit=40
            ),
            issues=_as_str_list(data.get("issues")),
            suggestions=_as_str_list(data.get("suggestions")),
            patterns=_as_str_list(data.get("patterns")),
        )


# --------------------------------------------------------------------------- #
# Stored record
# --------------------------------------------------------------------------- #

@dataclass
class PasswordRecord:
    """One persisted password-strength check (never the password itself)."""

    id: int
    label: str
    checked_at: str
    analysis: AnalysisResult

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a JSON-friendly dictionary."""
        return {
            "id": self.id,
            "label": self.label,
            "checked_at": self.checked_at,
            "analysis": self.analysis.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: Any) -> "PasswordRecord":
        """Build a ``PasswordRecord`` from untrusted mapping data."""
        if not isinstance(data, dict):
            raise ValueError("record must be an object")

        raw_id = data.get("id")
        if isinstance(raw_id, bool) or not str(raw_id).strip().lstrip("-").isdigit():
            raise ValueError("record id must be an integer")
        record_id = int(raw_id)
        if record_id < 1:
            raise ValueError("record id must be positive")

        label = _as_text(data.get("label"), default="Untitled", limit=60).strip()
        if not label:
            label = "Untitled"

        checked_at = _as_text(data.get("checked_at"), limit=40)
        if not checked_at:
            raise ValueError("checked_at is missing")
        try:
            datetime.fromisoformat(checked_at)
        except ValueError as exc:
            raise ValueError(f"checked_at is not an ISO timestamp: {checked_at!r}") from exc

        analysis = AnalysisResult.from_dict(data.get("analysis"))
        return cls(id=record_id, label=label, checked_at=checked_at, analysis=analysis)

    @property
    def score(self) -> int:
        return self.analysis.score

    @property
    def rating(self) -> str:
        return self.analysis.rating

    def matches(self, tokens: Iterable[str]) -> bool:
        """Return True when any keyword appears in searchable record fields."""
        haystack = " ".join(
            [
                self.label,
                self.rating,
                self.checked_at,
                " ".join(self.analysis.issues),
                " ".join(self.analysis.suggestions),
            ]
        ).lower()
        return any(token in haystack for token in tokens)
