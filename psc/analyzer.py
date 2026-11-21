"""Core business logic: local password evaluation and rule explanations.

The analyser never writes the password anywhere.  ``analyze_password`` is a
pure function: it receives a string, computes derived facts, and returns an
:class:`~psc.models.AnalysisResult`.  The caller is responsible for discarding
the original password as soon as possible.
"""

from __future__ import annotations

import math
import re
from collections import Counter

from .config import GUESSES_PER_SECOND
from .heuristics import collect_matches, minimum_entropy, pattern_names
from .models import AnalysisResult

# --------------------------------------------------------------------------- #
# Reference data used for heuristics
# --------------------------------------------------------------------------- #

SPECIAL_CHARS: frozenset[str] = frozenset(
    "!@#$%^&*()-_=+[]{};:'\",.<>/?\\|`~"
)

COMMON_PASSWORDS: frozenset[str] = frozenset(
    {
        "password", "password1", "password123", "passw0rd", "p@ssword",
        "123456", "1234567", "12345678", "123456789", "1234567890",
        "qwerty", "qwerty123", "qwertyuiop", "abc123", "abc12345",
        "letmein", "welcome", "welcome1", "admin", "admin123",
        "iloveyou", "monkey", "dragon", "sunshine", "princess",
        "football", "baseball", "soccer", "master", "shadow",
        "superman", "batman", "trustno1", "654321", "111111",
        "000000", "1q2w3e4r", "zaq12wsx", "correcthorsebatterystaple",
        "p@ssw0rd", "password1!", "abcabc", "qwerty123",
    }
)

# Common leetspeak substitutions used when checking against the wordlist.
_LEET_TRANSLATION = str.maketrans({"@": "a", "0": "o", "1": "i", "3": "e", "$": "s", "!": "i"})

ALPHABET_SEQUENCES: tuple[str, ...] = (
    "abcdefghijklmnopqrstuvwxyz",
    "zyxwvutsrqponmlkjihgfedcba",
)

KEYBOARD_SEQUENCES: tuple[str, ...] = (
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "1qaz", "2wsx", "3edc", "0987654321",
)

RATING_BANDS: tuple[tuple[int, str], ...] = (
    (20, "Very Weak"),
    (40, "Weak"),
    (60, "Fair"),
    (80, "Strong"),
    (101, "Very Strong"),
)


# --------------------------------------------------------------------------- #
# Helper functions
# --------------------------------------------------------------------------- #

def _char_pool(password: str) -> int:
    """Size of the character pool the password draws from."""
    pool = 0
    if any(ch.islower() for ch in password):
        pool += 26
    if any(ch.isupper() for ch in password):
        pool += 26
    if any(ch.isdigit() for ch in password):
        pool += 10
    if any(ch in SPECIAL_CHARS for ch in password):
        pool += len(SPECIAL_CHARS)
    return max(pool, 1)


def _has_sequence(password: str) -> bool:
    """Detect simple alphabetical / keyboard / numeric runs of length >= 3."""
    lower = password.lower()

    for source in ALPHABET_SEQUENCES + KEYBOARD_SEQUENCES:
        for index in range(len(source) - 2):
            if source[index:index + 3] in lower:
                return True

    digits = "".join(ch for ch in password if ch.isdigit())
    for index in range(len(digits) - 2):
        a, b, c = (int(d) for d in digits[index:index + 3])
        if (b == a + 1 and c == b + 1) or (b == a - 1 and c == b - 1):
            return True
    return False


def _repetition_ratio(password: str) -> float:
    """Fraction of characters that are repeats of an earlier character."""
    if not password:
        return 0.0
    return (len(password) - len(Counter(password))) / len(password)


def _has_common_word(password: str) -> bool:
    """Detect wordlist passwords, including simple leetspeak and digit padding."""
    lowered = password.lower()
    candidates = {lowered, lowered.translate(_LEET_TRANSLATION)}
    candidates |= {value.rstrip("0123456789!?") for value in candidates}

    for candidate in candidates:
        if not candidate:
            continue
        if candidate in COMMON_PASSWORDS:
            return True
        # Catches "Password1" and other lightly padded variants.
        for word in COMMON_PASSWORDS:
            if len(word) >= 6 and word in candidate:
                return True
    return False


def _rating_for_score(score: int) -> str:
    for ceiling, label in RATING_BANDS:
        if score < ceiling:
            return label
    return "Very Strong"


def _format_duration(seconds: float) -> str:
    """Turn a duration in seconds into a friendly, bounded string."""
    if seconds < 1:
        return "less than a second"
    if seconds > 4.35e17:  # older than the universe - no useful precision
        return "longer than the age of the universe"

    names = ("seconds", "minutes", "hours", "days", "years", "thousand years")
    divisors = (60.0, 60.0, 24.0, 365.0, 1000.0)
    value = seconds
    index = 0
    for index, divisor in enumerate(divisors):
        if value < divisor:
            break
        value /= divisor
    else:
        value = seconds / (60.0 * 60.0 * 24.0 * 365.0 * 1000.0)
        index = 5

    if value >= 1000:
        return f"over {int(value):,} {names[index]}"
    return f"about {max(1, int(round(value)))} {names[index]}"


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def analyze_password(password: str) -> AnalysisResult:
    """Analyse *password* locally and return its derived strength report.

    The password itself is never returned, logged or persisted.  An empty or
    non-string input is handled gracefully so callers cannot crash the engine.
    """
    if not isinstance(password, str):
        password = str(password)

    length = len(password)
    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = any(ch in SPECIAL_CHARS for ch in password)
    char_classes = sum((has_upper, has_lower, has_digit, has_special))

    repetition = _repetition_ratio(password)
    sequence_found = _has_sequence(password)
    common_found = _has_common_word(password)
    matches = collect_matches(password)

    pool = _char_pool(password)
    entropy = length * math.log2(pool)
    entropy *= (1.0 - 0.5 * repetition)
    if sequence_found:
        entropy *= 0.60
    if common_found:
        entropy *= 0.30

    # Advanced matchers (keyboard walks, dates, repeated units) provide an
    # independent upper bound on real entropy, following zxcvbn's approach of
    # taking the weakest explanation of the password's structure.
    match_entropy = minimum_entropy(matches)
    if match_entropy is not None:
        entropy = min(entropy, match_entropy)
    entropy = max(0.0, round(entropy, 2))

    # Crack time estimate: an attacker tries half the search space on average.
    guesses = (2.0 ** entropy) / 2.0
    if guesses > 1.0e300:
        crack_time = "longer than the age of the universe"
    else:
        crack_time = _format_duration(guesses / GUESSES_PER_SECOND)

    # ------------------------------ scoring -------------------------------- #
    # Repetition and predictable patterns reduce the *effective* length: twenty
    # identical characters are no stronger than one.
    effective_length = length * (1.0 - repetition)
    if sequence_found:
        effective_length *= 0.50
    if common_found:
        effective_length *= 0.60

    length_points = (min(effective_length, 16.0) / 16.0) * 30.0
    class_points = (char_classes / 4.0) * 20.0
    entropy_points = (min(entropy, 80.0) / 80.0) * 30.0
    if sequence_found:
        entropy_points *= 0.50

    integrity_points = 20.0
    if length == 0:
        integrity_points = 0.0
    elif length < 4:
        integrity_points -= 12.0
    elif length < 8:
        integrity_points -= 6.0
    if common_found:
        integrity_points -= 12.0
    if sequence_found:
        integrity_points -= 10.0
    if repetition > 0.30:
        integrity_points -= 12.0
    if char_classes >= 3:
        integrity_points += 2.0
    if length >= 12:
        integrity_points += 2.0
    integrity_points = max(0.0, min(20.0, integrity_points))

    score = int(round(length_points + class_points + entropy_points + integrity_points))
    score = max(0, min(100, score))
    rating = _rating_for_score(score)

    # -------------------------- issues / advice ----------------------------- #
    issues: list[str] = []
    suggestions: list[str] = []

    if length == 0:
        issues.append("Empty password")
        suggestions.append("Choose a password with at least 12 characters.")
    else:
        if length < 8:
            noun = "character" if length == 1 else "characters"
            issues.append(f"Too short ({length} {noun}; 12+ recommended)")
            suggestions.append("Use at least 12 characters.")
        elif length < 12:
            suggestions.append("Aim for 12 or more characters for better resilience.")

        if char_classes < 3:
            issues.append(f"Only {char_classes} character type(s) used")
            suggestions.append("Mix uppercase, lowercase, digits and symbols.")
        if not has_upper and length:
            suggestions.append("Add at least one uppercase letter.")
        if not has_lower and length:
            suggestions.append("Add at least one lowercase letter.")
        if not has_digit and length:
            suggestions.append("Add at least one digit.")
        if not has_special and length:
            suggestions.append("Add at least one symbol (e.g. ! @ # $).")

        if common_found:
            issues.append("Matches or contains a common password / dictionary word")
            suggestions.append("Avoid common words and well-known passwords.")
        if sequence_found:
            issues.append("Contains a character sequence or keyboard pattern")
            suggestions.append("Avoid sequences such as 123, abc or qwerty.")
        if repetition > 0.30:
            issues.append(f"High character repetition ({repetition:.0%})")
            suggestions.append("Avoid repeated characters.")

        if any(match.kind.startswith("spatial") for match in matches):
            issues.append("Contains a keyboard walk pattern")
            suggestions.append("Avoid keyboard walks such as qwerty or 1qaz.")
        if any(match.kind == "date" for match in matches):
            issues.append("Contains a date or year pattern")
            suggestions.append("Avoid birthdays, anniversaries and years.")

    if not issues:
        suggestions.append("Good work! Use a unique password for each account.")

    return AnalysisResult(
        score=score,
        rating=rating,
        length=length,
        has_upper=has_upper,
        has_lower=has_lower,
        has_digit=has_digit,
        has_special=has_special,
        char_classes=char_classes,
        entropy_bits=entropy,
        crack_time=crack_time,
        issues=issues,
        suggestions=suggestions[:6],
        patterns=pattern_names(matches),
    )


def explain_rules() -> list[dict[str, str]]:
    """Return the basic strength rules as structured ``title/rule/why`` data."""
    return [
        {
            "title": "Length",
            "rule": "Use at least 12 characters; longer is stronger.",
            "why": "Every extra character multiplies the number of possible combinations.",
        },
        {
            "title": "Character variety",
            "rule": "Mix uppercase letters, lowercase letters, digits and symbols.",
            "why": "A larger character pool makes brute-force guesses far more expensive.",
        },
        {
            "title": "Avoid common passwords",
            "rule": "Never use dictionary words, names or passwords like 'password123'.",
            "why": "Attackers try these first using wordlists of leaked passwords.",
        },
        {
            "title": "Avoid patterns",
            "rule": "Skip sequences such as 1234, abcd and qwerty.",
            "why": "Predictable ordering dramatically reduces the search space.",
        },
        {
            "title": "Avoid repetition",
            "rule": "Do not repeat the same character many times.",
            "why": "Repetition lowers real entropy even when a password looks long.",
        },
        {
            "title": "Uniqueness",
            "rule": "Use a different password for every account.",
            "why": "One leaked site should not compromise all of your accounts.",
        },
        {
            "title": "Local processing",
            "rule": "This tool analyses passwords offline and stores only the result metadata.",
            "why": "Your password is never written to disk or sent anywhere.",
        },
    ]
