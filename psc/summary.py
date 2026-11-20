"""Executive summary generation and threshold warning indicators."""

from __future__ import annotations

import statistics
from collections import Counter
from dataclasses import dataclass, field

from .config import CRITICAL_WEAK_RATE, SHORT_LENGTH_WARNING, WEAK_SCORE_THRESHOLD
from .models import PasswordRecord


@dataclass
class SummaryReport:
    """Aggregated metrics computed from a collection of records."""

    total: int = 0
    average_score: float = 0.0
    median_score: float = 0.0
    min_score: int | None = None
    max_score: int | None = None
    average_length: float = 0.0
    rating_counts: Counter[str] = field(default_factory=Counter)
    class_counts: Counter[str] = field(default_factory=Counter)
    common_issues: Counter[str] = field(default_factory=Counter)
    per_day: Counter[str] = field(default_factory=Counter)
    strongest: PasswordRecord | None = None
    weakest: PasswordRecord | None = None
    weak_count: int = 0
    strong_count: int = 0

    @property
    def weak_rate(self) -> float:
        return self.weak_count / self.total if self.total else 0.0

    @property
    def strong_rate(self) -> float:
        return self.strong_count / self.total if self.total else 0.0


def build_summary(records: list[PasswordRecord]) -> SummaryReport:
    """Compute all metrics used by the analytics and export screens."""
    report = SummaryReport(total=len(records))
    if not records:
        return report

    scores = [record.score for record in records]
    lengths = [record.analysis.length for record in records]

    report.average_score = round(statistics.fmean(scores), 1)
    report.median_score = round(statistics.median(scores), 1)
    report.min_score = min(scores)
    report.max_score = max(scores)
    report.average_length = round(statistics.fmean(lengths), 1)

    for record in records:
        report.rating_counts[record.rating] += 1
        report.per_day[record.checked_at[:10]] += 1
        if record.score < WEAK_SCORE_THRESHOLD:
            report.weak_count += 1
        if record.score >= 80:
            report.strong_count += 1

        analysis = record.analysis
        for name, present in (
            ("Uppercase", analysis.has_upper),
            ("Lowercase", analysis.has_lower),
            ("Digits", analysis.has_digit),
            ("Symbols", analysis.has_special),
        ):
            if present:
                report.class_counts[name] += 1
        for issue in analysis.issues:
            report.common_issues[issue] += 1

    report.strongest = max(records, key=lambda r: (r.score, -r.id))
    report.weakest = min(records, key=lambda r: (r.score, r.id))
    return report


def build_alerts(report: SummaryReport) -> list[tuple[str, str]]:
    """Return ``(level, message)`` pairs for threshold warning indicators.

    ``level`` is one of ``"critical"``, ``"warning"`` or ``"info"``.
    """
    alerts: list[tuple[str, str]] = []

    if report.total == 0:
        alerts.append(("info", "No records yet - check a password to generate analytics."))
        return alerts

    if report.weak_rate > CRITICAL_WEAK_RATE:
        alerts.append(
            (
                "critical",
                f"{report.weak_rate:.0%} of records are weak "
                f"({report.weak_count}/{report.total}). Consider a password audit.",
            )
        )
    elif report.weak_count:
        alerts.append(
            ("warning", f"{report.weak_count} weak record(s) detected in the dataset.")
        )

    if report.average_length < SHORT_LENGTH_WARNING:
        alerts.append(
            (
                "warning",
                f"Average password length is only {report.average_length:.1f} characters "
                f"(recommended: 12+).",
            )
        )

    if report.min_score is not None and report.min_score < 20:
        alerts.append(
            (
                "critical",
                f"At least one record is in the 'Very Weak' band (score {report.min_score}).",
            )
        )

    if report.strong_rate >= 0.5:
        alerts.append(
            ("info", f"Good news: {report.strong_rate:.0%} of records are strong or very strong.")
        )

    if not alerts:
        alerts.append(("info", "All thresholds look healthy. No anomalies detected."))
    return alerts


def rating_distribution(report: SummaryReport) -> list[tuple[str, int]]:
    """Return rating bands in a stable display order."""
    order = ["Very Strong", "Strong", "Fair", "Weak", "Very Weak"]
    return [(name, report.rating_counts.get(name, 0)) for name in order]
