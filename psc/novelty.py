"""Structural Drift Index (SDI) - a novel, privacy-preserving risk algorithm.

Most password meters score each password in isolation.  SDI adds an adaptive
dimension: it derives a compact *structural fingerprint* from an analysis (no
password characters, hashes or reversible data) and measures how close a new
password is, structurally, to the user's own checked history.

Why this is a contribution
--------------------------
1. **Non-reversible fingerprinting.** Only banded, derived features are kept,
   so history can be used for risk analysis without retaining any secret.
2. **Hybrid distance metric.** Weighted banded L1 distance over numeric
   structure is combined with Jaccard distance over a pattern bitmask, giving
   a bounded [0, 1] structural distance.
3. **Portfolio diversity.** Average pairwise distance over a history gives a
   measurable variety score for the whole dataset.
4. **Explainable adaptive risk.** A composite risk score and plain-language
   advice explain why a password is riskier *for this user*, not in general.

The algorithm is deterministic, dependency-free and has an identical browser
implementation in ``site/analyzer.js``.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

# Band limits for structural features.
LENGTH_LIMITS = (8, 12, 16, 24)
ENTROPY_STEP = 16.0
POOL_SCALE = 10.0
NUMERIC_WEIGHTS = (0.25, 0.20, 0.25, 0.15, 0.15)
NUMERIC_MAXIMA = (4.0, 4.0, 6.0, 1.0, 3.0)
PATTERN_WEIGHT = 0.25
NUMERIC_WEIGHT = 0.75

PATTERN_BITS = {
    "spatial": 1,
    "date": 2,
    "repeat": 4,
    "common": 8,
    "sequence": 16,
}


def length_band(length: int) -> int:
    """Map a character count to one of five bands."""
    band = 0
    for limit in LENGTH_LIMITS:
        if length >= limit:
            band += 1
        else:
            break
    return band


@dataclass(frozen=True)
class StructuralFingerprint:
    """A compact, non-reversible structural signature of an analysis."""

    length: int
    classes: int
    entropy: int
    repetition: int
    pool: int
    pattern_mask: int

    def to_dict(self) -> dict[str, int]:
        return {
            "length": self.length,
            "classes": self.classes,
            "entropy": self.entropy,
            "repetition": self.repetition,
            "pool": self.pool,
            "pattern_mask": self.pattern_mask,
        }

    @classmethod
    def from_dict(cls, data: dict[str, int]) -> "StructuralFingerprint":
        return cls(
            length=int(data["length"]),
            classes=int(data["classes"]),
            entropy=int(data["entropy"]),
            repetition=int(data["repetition"]),
            pool=int(data["pool"]),
            pattern_mask=int(data["pattern_mask"]),
        )


def fingerprint(analysis: dict) -> StructuralFingerprint:
    """Derive a fingerprint from an ``AnalysisResult.to_dict()`` mapping."""
    patterns = set(analysis.get("patterns", []))
    issues = " ".join(analysis.get("issues", [])).lower()
    if "common password" in issues:
        patterns.add("common")
    if "sequence" in issues or "keyboard" in issues:
        patterns.add("spatial")

    length = int(analysis.get("length", 0))
    entropy = float(analysis.get("entropy_bits", 0.0))
    mask = 0
    for name, bit in PATTERN_BITS.items():
        if name in patterns:
            mask |= bit

    return StructuralFingerprint(
        length=length_band(length),
        classes=max(0, min(4, int(analysis.get("char_classes", 0)))),
        entropy=max(0, min(6, int(entropy // ENTROPY_STEP))),
        repetition=1 if "repeat" in patterns else 0,
        pool=max(0, min(3, int(entropy / max(length, 1) * POOL_SCALE))),
        pattern_mask=mask,
    )


def jaccard_bits(left: int, right: int) -> float:
    """Jaccard distance between two pattern bitmasks."""
    union = left | right
    if union == 0:
        return 0.0
    return 1.0 - (left & right).bit_count() / union.bit_count()


def distance(left: StructuralFingerprint, right: StructuralFingerprint) -> float:
    """Return a bounded structural distance in ``[0, 1]``."""
    a = (left.length, left.classes, left.entropy, left.repetition, left.pool)
    b = (right.length, right.classes, right.entropy, right.repetition, right.pool)
    numeric = sum(
        weight * min(1.0, abs(x - y) / maximum)
        for weight, maximum, x, y in zip(NUMERIC_WEIGHTS, NUMERIC_MAXIMA, a, b)
    ) / sum(NUMERIC_WEIGHTS)
    mask = jaccard_bits(left.pattern_mask, right.pattern_mask)
    return round(NUMERIC_WEIGHT * numeric + PATTERN_WEIGHT * mask, 4)


@dataclass(frozen=True)
class DriftReport:
    """Result of comparing one analysis against a checked history."""

    nearest_id: int | None
    distance: float
    similarity: float
    diversity: float
    personal_risk: int
    advice: str

    def to_dict(self) -> dict:
        return {
            "nearest_id": self.nearest_id,
            "distance": self.distance,
            "similarity": self.similarity,
            "diversity": self.diversity,
            "personal_risk": self.personal_risk,
            "advice": self.advice,
        }


def _advice(similarity: float) -> str:
    if similarity >= 0.85:
        return "Structurally very close to a previous check - try a different character mix."
    if similarity >= 0.65:
        return "Noticeable structural overlap with your history - consider more variety."
    return "Distinct structure compared with your history - good variety."


def compare(
    analysis: dict,
    history: list[tuple[int, dict]],
) -> DriftReport:
    """Compare *analysis* with ``(record_id, analysis_dict)`` history pairs."""
    current = fingerprint(analysis)
    if not history:
        return DriftReport(None, 1.0, 0.0, 1.0, 100 - int(analysis.get("score", 0)),
                           "No history yet - this check establishes your baseline.")

    scored = [(distance(current, fingerprint(item)), record_id) for record_id, item in history]
    best_distance, nearest_id = min(scored)
    similarity = round(1.0 - best_distance, 4)
    diversity = portfolio_diversity([item for _, item in history])
    # JS Math.round and Python round differ on .5 (banker's rounding); use an
    # explicit half-up rule so both engines produce identical outputs.
    raw_risk = (100 - int(analysis.get("score", 0))) * 0.7 + similarity * 30
    risk = min(100, int(math.floor(raw_risk + 0.5)))
    return DriftReport(nearest_id, best_distance, similarity, round(diversity, 4),
                       risk, _advice(similarity))


def portfolio_diversity(analyses: list[dict]) -> float:
    """Average pairwise structural distance; 1.0 means maximally varied."""
    if len(analyses) < 2:
        return 1.0
    prints = [fingerprint(item) for item in analyses]
    total = 0.0
    pairs = 0
    for index, left in enumerate(prints):
        for right in prints[index + 1:]:
            total += distance(left, right)
            pairs += 1
    return round(total / pairs, 4)
