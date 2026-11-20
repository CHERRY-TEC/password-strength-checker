"""Realistic sample dataset for demos and end-to-end validation.

The dataset intentionally mixes normal entries, boundary values and edge cases
(empty password, single character, heavy repetition, sequences, common words)
so that validation and analytics are visibly exercised.

Only the *analyses* of these sample passwords are produced - the sample
password strings themselves are never written to storage.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta

from .analyzer import analyze_password
from .models import PasswordRecord

# (label, sample password) pairs covering weak -> very-strong and edge cases.
SAMPLE_DATA: tuple[tuple[str, str], ...] = (
    ("Campus WiFi guest", "password"),
    ("Old library card", "123456"),
    ("Dorm router", "qwerty"),
    ("Club signup", "abc123"),
    ("Lab workstation", "letmein"),
    ("Alumni portal", "welcome1"),
    ("Admin console", "admin"),
    ("Print kiosk", "111111"),
    ("Shared calendar", "sunshine"),
    ("Sports forum", "football"),
    ("Music account", "iloveyou"),
    ("Guest laptop", "dragon"),
    ("Weather app", "monkey"),
    ("Course forum", "student1"),
    ("Library catalogue", "Library2024"),
    ("Email backup", "Summer2023!"),
    ("Cloud drive", "P@ssw0rd"),
    ("Banking demo", "Tr0ub4dor&3"),
    ("Research wiki", "Science#2024"),
    ("Dev repository", "GitPush!42"),
    ("VPN client", "Blue$Sky77"),
    ("Phone hotspot", "Mobil3Data!"),
    ("Gaming account", "DragonSlayer99"),
    ("Photo storage", "Sunset@2024"),
    ("Notebook app", "Notes4Me!"),
    ("Messaging app", "Chat_Now_24"),
    ("Shopping cart", "BuyIt#2024"),
    ("Fitness tracker", "Run5K_Miles!"),
    ("Recipe box", "Cook@Home1"),
    ("Travel planner", "Trip2024!go"),
    ("Personal wiki", "correct horse battery staple"),
    ("Password manager", "X9#mL2@vT7!qR4$p"),
    ("Server SSH key", "vL8!qZ#2wR@6tY&1c"),
    ("Encryption test", "Zx7!Qp9#Lm2@Wn5$"),
    ("Security audit", "A1!b2@C3#D4$e5%"),
    ("Strong passphrase", "Purple-Coffee-Mountain-42"),
    ("Boundary: single char", "a"),
    ("Boundary: two chars", "a1"),
    ("Boundary: eight chars", "Abcdefg1"),
    ("Edge: empty password", ""),
    ("Edge: repeated chars", "aaaaaaaaaaaaaaaaaaaa"),
    ("Edge: repeated pair", "abababababababab"),
    ("Edge: alphabet run", "abcdefghijklmnop"),
    ("Edge: number run", "1234567890123456"),
    ("Edge: keyboard walk", "qwertyuiop123"),
    ("Edge: padded common", "!!password123!!"),
)


def generate_records(
    count: int = 40,
    *,
    start_id: int = 1,
    seed: int = 104,
) -> list[PasswordRecord]:
    """Generate *count* deterministic sample records (30-50 recommended)."""
    if count < 1:
        raise ValueError("count must be positive")

    rng = random.Random(seed)
    now = datetime.now().replace(microsecond=0)
    records: list[PasswordRecord] = []

    for index in range(count):
        base_label, sample_password = SAMPLE_DATA[index % len(SAMPLE_DATA)]
        cycle = index // len(SAMPLE_DATA)
        label = base_label if cycle == 0 else f"{base_label} ({cycle + 1})"
        checked_at = now - timedelta(
            days=rng.randint(0, 120),
            hours=rng.randint(0, 23),
            minutes=rng.randint(0, 59),
        )
        analysis = analyze_password(sample_password)
        records.append(
            PasswordRecord(
                id=start_id + index,
                label=label[:60],
                checked_at=checked_at.isoformat(timespec="seconds"),
                analysis=analysis,
            )
        )

    return records
