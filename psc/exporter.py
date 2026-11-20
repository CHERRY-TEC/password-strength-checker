"""Multi-format report export for external review.

Generates structured Markdown, a plain-text audit log, a standardised CSV
report and (when matplotlib is installed) a PNG chart.  The core application
has zero required dependencies - the chart exporter degrades gracefully with a
clear message when matplotlib is unavailable.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Sequence

from .config import APP_NAME, APP_VERSION
from .models import PasswordRecord
from .storage import CSVStore
from .summary import SummaryReport, build_alerts, rating_distribution


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def default_path(kind: str, extension: str, export_dir: Path) -> Path:
    """Build a timestamped export path such as ``summary-20260101-120000.md``."""
    export_dir.mkdir(parents=True, exist_ok=True)
    return export_dir / f"{kind}-{_timestamp()}.{extension}"


def export_markdown(
    records: Sequence[PasswordRecord],
    report: SummaryReport,
    path: Path,
) -> Path:
    """Write a structured Markdown report and return the path."""
    lines: list[str] = [
        f"# {APP_NAME} - Audit Report",
        "",
        f"- Generated: {datetime.now().isoformat(timespec='seconds')}",
        f"- Tool version: {APP_VERSION}",
        f"- Total analysed records: {report.total}",
        "- Security note: only analysis metadata is stored; passwords are never saved.",
        "",
        "## Executive Summary",
        "",
        "| Metric | Value |",
        "| --- | --- |",
        f"| Total records | {report.total} |",
        f"| Average score | {report.average_score}/100 |",
        f"| Median score | {report.median_score}/100 |",
        f"| Score range | {report.min_score} - {report.max_score} |",
        f"| Average length | {report.average_length:.1f} |",
        f"| Strong / very strong | {report.strong_count} ({report.strong_rate:.0%}) |",
        f"| Weak / very weak | {report.weak_count} ({report.weak_rate:.0%}) |",
        "",
        "## Rating Distribution",
        "",
        "| Rating | Count | Share |",
        "| --- | ---: | ---: |",
    ]
    for name, count in rating_distribution(report):
        share = count / report.total if report.total else 0
        lines.append(f"| {name} | {count} | {share:.0%} |")

    lines += ["", "## Threshold Indicators", ""]
    for level, message in build_alerts(report):
        lines.append(f"- **{level.upper()}**: {message}")

    lines += [
        "",
        "## All Records",
        "",
        "| ID | Label | Checked at | Score | Rating | Length | Issues |",
        "| ---: | --- | --- | ---: | --- | ---: | --- |",
    ]
    for record in records:
        issues = "; ".join(record.analysis.issues) or "-"
        issues = issues.replace("|", "\\|")
        label = record.label.replace("|", "\\|")
        lines.append(
            f"| {record.id} | {label} | {record.checked_at.replace('T', ' ')[:16]} | "
            f"{record.score} | {record.rating} | {record.analysis.length} | {issues} |"
        )

    if report.common_issues:
        lines += ["", "## Common Issues", "", "| Issue | Count |", "| --- | ---: |"]
        for issue, count in report.common_issues.most_common():
            lines.append(f"| {issue.replace('|', chr(92) + '|')} | {count} |")

    lines += ["", "---", f"*Generated locally by {APP_NAME} v{APP_VERSION}.*", ""]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def export_text_audit(
    records: Sequence[PasswordRecord],
    report: SummaryReport,
    path: Path,
) -> Path:
    """Write a plain-text, line-oriented audit log."""
    lines = [
        "=" * 72,
        f"{APP_NAME} - PLAIN-TEXT AUDIT LOG",
        f"Generated: {datetime.now().isoformat(timespec='seconds')}",
        "=" * 72,
        f"Records: {report.total}",
        f"Average score: {report.average_score}/100",
        f"Average length: {report.average_length:.1f}",
        f"Weak records: {report.weak_count}",
        "",
        "THRESHOLD INDICATORS",
        "-" * 72,
    ]
    for level, message in build_alerts(report):
        lines.append(f"[{level.upper():8}] {message}")
    lines += ["", "RECORD DETAIL", "-" * 72]
    for record in records:
        analysis = record.analysis
        lines.append(
            f"#{record.id:>4} | {record.label:<30} | {record.checked_at[:19]} | "
            f"score={record.score:>3} | {record.rating:<12} | len={analysis.length:>3}"
        )
        for issue in analysis.issues:
            lines.append(f"         - issue: {issue}")
    lines += ["", "=" * 72, f"End of audit log ({len(records)} records).", ""]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def export_csv(records: Sequence[PasswordRecord], path: Path) -> Path:
    """Write the standardised CSV report using the validated CSV backend."""
    CSVStore(path).save(list(records))
    return path


def export_chart_png(report: SummaryReport, path: Path) -> Path:
    """Render a rating-distribution PNG chart using matplotlib if available.

    Raises ``RuntimeError`` with an actionable message when the optional
    dependency is missing, so the caller can present a friendly fallback.
    """
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise RuntimeError(
            "matplotlib is not installed. Install it with 'pip install matplotlib' "
            "or use the built-in terminal chart in the analytics menu."
        ) from exc

    if report.total == 0:
        raise RuntimeError("There are no records to chart yet.")

    distribution = rating_distribution(report)
    names = [name for name, _ in distribution]
    counts = [count for _, count in distribution]
    colours = ["#2e7d32", "#66bb6a", "#f9a825", "#ef6c00", "#c62828"]

    figure, axis = plt.subplots(figsize=(8, 5))
    bars = axis.bar(names, counts, color=colours)
    axis.set_title(f"{APP_NAME} - Rating Distribution")
    axis.set_ylabel("Number of records")
    axis.set_xlabel("Strength rating")
    axis.spines["top"].set_visible(False)
    axis.spines["right"].set_visible(False)
    for bar, count in zip(bars, counts):
        axis.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height(),
            str(count),
            ha="center",
            va="bottom",
        )
    figure.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(path, dpi=150)
    plt.close(figure)
    return path
