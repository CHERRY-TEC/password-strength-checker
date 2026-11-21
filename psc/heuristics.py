"""Advanced password heuristics inspired by zxcvbn-style pattern matching.

The base analyzer already checks dictionary words, simple sequences and raw
repetition.  This module adds three pluggable matchers:

* **spatial matching** - walks across QWERTY, Dvorak and numeric keypad graphs;
* **date matching** - common numeric date and year formats;
* **repeat matching** - repeated multi-character units such as ``ababab``.

Each matcher returns :class:`PatternMatch` objects with an estimated entropy.
The analyzer keeps the lowest estimate as an additional signal, which makes
structurally predictable passwords score realistically even when they are long.
"""

from __future__ import annotations

import math
import re
from collections import defaultdict
from dataclasses import dataclass

Graph = dict[str, set[str]]


@dataclass(frozen=True)
class PatternMatch:
    """One detected structural pattern and its entropy estimate."""

    kind: str
    token: str
    entropy: float


QWERTY_ROWS = ("1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm")
DVORAK_ROWS = ("1234567890", "'.,pyfgcrl", "aoeuidhtns", ";qjkxbmwvz")
KEYPAD_ROWS = ("789", "456", "123", "0")


def build_graph(rows: tuple[str, ...]) -> Graph:
    """Build an undirected adjacency graph from staggered keyboard rows."""
    graph: Graph = defaultdict(set)
    for row_index, row in enumerate(rows):
        for column, char in enumerate(row):
            if column > 0:
                graph[char].add(row[column - 1])
            if column < len(row) - 1:
                graph[char].add(row[column + 1])
            if row_index + 1 < len(rows):
                below = rows[row_index + 1]
                offset = 1 if len(row) > len(below) else 0
                for shift in (0, 1):
                    neighbour_column = column - shift + offset
                    if 0 <= neighbour_column < len(below):
                        neighbour = below[neighbour_column]
                        graph[char].add(neighbour)
                        graph[neighbour].add(char)
    return dict(graph)


SPATIAL_GRAPHS: dict[str, Graph] = {
    "qwerty": build_graph(QWERTY_ROWS),
    "dvorak": build_graph(DVORAK_ROWS),
    "keypad": build_graph(KEYPAD_ROWS),
}

DATE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("date", re.compile(r"\d{2}[/-]\d{2}[/-]\d{4}")),
    ("date", re.compile(r"(?:19|20)\d{2}[01]\d[0-3]\d")),
    ("date", re.compile(r"[0-3]\d[01]\d(?:19|20)\d{2}")),
    ("year", re.compile(r"(?:19|20)\d{2}")),
)


def spatial_matches(password: str, minimum_length: int = 4) -> list[PatternMatch]:
    """Detect consecutive keyboard walks of at least *minimum_length* keys."""
    lowered = password.lower()
    results: list[PatternMatch] = []
    for name, graph in SPATIAL_GRAPHS.items():
        best = ""
        for start in range(len(lowered)):
            for end in range(start + minimum_length, len(lowered) + 1):
                token = lowered[start:end]
                if all(b in graph.get(a, set()) for a, b in zip(token, token[1:])):
                    if len(token) > len(best):
                        best = token
                else:
                    break
        if best:
            # zxcvbn-style estimate: graph size + walk length + turn allowance.
            entropy = math.log2(max(len(graph), 2)) + math.log2(len(best)) + 2.0
            results.append(PatternMatch(f"spatial:{name}", best, round(entropy, 2)))
    return results


def date_matches(password: str) -> list[PatternMatch]:
    """Detect numeric dates and standalone years."""
    results: list[PatternMatch] = []
    for kind, pattern in DATE_PATTERNS:
        for match in pattern.finditer(password):
            token = match.group(0)
            entropy = math.log2(365 * 200) if kind == "date" else math.log2(200)
            results.append(PatternMatch(kind, token, round(entropy, 2)))
    return results


def repeat_matches(password: str, minimum_unit: int = 1) -> list[PatternMatch]:
    """Detect contiguous repetition of a short character unit."""
    results: list[PatternMatch] = []
    length = len(password)
    for unit_length in range(minimum_unit, min(5, length // 2) + 1):
        for start in range(length):
            unit = password[start:start + unit_length]
            if len(unit) < unit_length:
                continue
            repeats = 1
            while password[start + repeats * unit_length:start + (repeats + 1) * unit_length] == unit:
                repeats += 1
            if repeats >= 3 or (repeats >= 2 and unit_length >= 2):
                token = unit * repeats
                entropy = math.log2(26 ** unit_length) + math.log2(repeats)
                results.append(PatternMatch("repeat", token, round(entropy, 2)))
    return unique_matches(results)


def unique_matches(matches: list[PatternMatch]) -> list[PatternMatch]:
    """Drop duplicate ``(kind, token)`` pairs while preserving order."""
    seen: set[tuple[str, str]] = set()
    unique: list[PatternMatch] = []
    for match in matches:
        key = (match.kind, match.token)
        if key not in seen:
            seen.add(key)
            unique.append(match)
    return unique


def collect_matches(password: str) -> list[PatternMatch]:
    """Run every matcher and return the combined, deduplicated matches."""
    return unique_matches(
        spatial_matches(password) + date_matches(password) + repeat_matches(password)
    )


def minimum_entropy(matches: list[PatternMatch]) -> float | None:
    """Return the strongest (lowest) entropy estimate from *matches*."""
    return min((match.entropy for match in matches), default=None)


def pattern_names(matches: list[PatternMatch]) -> list[str]:
    """Return sorted unique pattern labels for explainability output."""
    return sorted({match.kind.split(":", 1)[0] for match in matches})
