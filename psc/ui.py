"""Terminal presentation layer: colours, banners, tables and reports."""

from __future__ import annotations

import os
import sys
from typing import Iterable, Sequence

from .config import APP_NAME, APP_VERSION, NO_COLOR, PAGE_SIZE
from .models import AnalysisResult, PasswordRecord
from .summary import SummaryReport, build_alerts, rating_distribution

# --------------------------------------------------------------------------- #
# ANSI colour support
# --------------------------------------------------------------------------- #

class Colors:
    """Named ANSI escape codes (empty strings when colour is disabled)."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    BG_BLUE = "\033[44m"

    _enabled = not NO_COLOR

    @classmethod
    def enable(cls) -> bool:
        """Enable ANSI colour where supported; returns the active state."""
        if os.name == "nt":
            try:
                import ctypes

                kernel32 = ctypes.windll.kernel32
                handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
                mode = ctypes.c_uint32()
                if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                    flag = 0x0004  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
                    if not mode.value & flag:
                        kernel32.SetConsoleMode(handle, mode.value | flag)
            except Exception:  # pragma: no cover - platform specific
                cls._enabled = False
        return cls._enabled

    @classmethod
    def paint(cls, text: object, *codes: str) -> str:
        """Wrap *text* in the given colour codes when colour is active."""
        raw = str(text)
        if not cls._enabled or not codes:
            return raw
        return "".join(codes) + raw + cls.RESET


def enable_color() -> bool:
    """Public initialiser called once at application startup."""
    return Colors.enable()


# --------------------------------------------------------------------------- #
# Low-level output helpers
# --------------------------------------------------------------------------- #

def clear() -> None:
    """Clear the terminal in a cross-platform way."""
    os.system("cls" if os.name == "nt" else "clear")


def divider(width: int = 72, char: str = "=") -> None:
    print(Colors.paint(char * width, Colors.DIM))


def section(title: str, width: int = 72) -> None:
    print()
    print(Colors.paint(f"--- {title} " + "-" * max(0, width - len(title) - 5), Colors.CYAN, Colors.BOLD))


def success(message: str) -> None:
    print(Colors.paint(f"  [OK] {message}", Colors.GREEN))


def warning(message: str) -> None:
    print(Colors.paint(f"  [!]  {message}", Colors.YELLOW))


def error(message: str) -> None:
    print(Colors.paint(f"  [X]  {message}", Colors.RED))


def info(message: str) -> None:
    print(Colors.paint(f"  [i]  {message}", Colors.BLUE))


def hint(message: str) -> None:
    print(Colors.paint(f"       {message}", Colors.DIM))


def pause(message: str = "Press Enter to continue...") -> None:
    """Wait for the user unless running non-interactively."""
    if sys.stdin.isatty():
        try:
            input(Colors.paint(f"\n  {message}", Colors.DIM))
        except EOFError:
            pass


def banner() -> None:
    """Print the branded welcome screen."""
    print()
    print(Colors.paint(r"   ____    _    ____  _   _ ____  _____ ____  _____ ____  ", Colors.CYAN, Colors.BOLD))
    print(Colors.paint(r"  |  _ \  / \  |  _ \| \ | / ___|| ____|  _ \| ____|  _ \ ", Colors.CYAN, Colors.BOLD))
    print(Colors.paint(r"  | |_) |/ _ \ | |_) |  \| \___ \|  _| | |_) |  _| | |_) |", Colors.CYAN, Colors.BOLD))
    print(Colors.paint(r"  |  __// ___ \|  __/|\ |\ |___) | |___|  _ <| |___|  _ < ", Colors.CYAN, Colors.BOLD))
    print(Colors.paint(r"  |_|  /_/   \_\_|   |_| \_|____/|_____|_| \_\_____|_| \_ ", Colors.CYAN, Colors.BOLD))
    print()
    print(Colors.paint(f"     {APP_NAME}  v{APP_VERSION}", Colors.BOLD, Colors.WHITE))
    print(Colors.paint("     Offline analysis  |  No passwords are ever stored", Colors.DIM))
    divider()


def menu(title: str, options: Sequence[tuple[str, str]]) -> None:
    """Render a numbered menu of ``(key, label)`` pairs."""
    section(title)
    for key, label in options:
        marker = Colors.paint(f"[{key}]", Colors.GREEN, Colors.BOLD)
        print(f"  {marker}  {label}")
    print()


def score_bar(score: int, width: int = 24) -> str:
    """Return an ASCII progress bar for a 0-100 score."""
    filled = max(0, min(width, int(round(score / 100 * width))))
    bar = "#" * filled + "-" * (width - filled)
    colour = Colors.GREEN if score >= 80 else Colors.YELLOW if score >= 40 else Colors.RED
    return Colors.paint(bar, colour)


def rating_colour(rating: str) -> str:
    """Map a rating label to an ANSI colour."""
    if rating in {"Strong", "Very Strong"}:
        return Colors.GREEN
    if rating == "Fair":
        return Colors.YELLOW
    return Colors.RED


# --------------------------------------------------------------------------- #
# Tables
# --------------------------------------------------------------------------- #

def _truncate(value: object, limit: int = 42) -> str:
    text = str(value)
    # Use ASCII-only ellipsis so legacy Windows consoles render it correctly.
    return text if len(text) <= limit else text[: limit - 2] + ".."


def print_table(
    headers: Sequence[str],
    rows: Sequence[Sequence[object]],
    *,
    page_size: int = PAGE_SIZE,
    title: str | None = None,
) -> None:
    """Print fixed-width columns with optional pagination for large results."""
    if title:
        section(title)
    if not rows:
        info("No records match the current view.")
        return

    string_rows = [[_truncate(cell) for cell in row] for row in rows]
    total_pages = max(1, (len(string_rows) + page_size - 1) // page_size)

    for page in range(total_pages):
        chunk = string_rows[page * page_size:(page + 1) * page_size]
        widths = [
            max(len(str(headers[i])), *(len(row[i]) for row in chunk))
            for i in range(len(headers))
        ]
        separator = "+" + "+".join("-" * (width + 2) for width in widths) + "+"

        print(separator)
        header_cells = " | ".join(
            Colors.paint(str(headers[i]).ljust(widths[i]), Colors.BOLD, Colors.CYAN)
            for i in range(len(headers))
        )
        print("| " + header_cells + " |")
        print(separator)
        for row in chunk:
            cells = " | ".join(str(row[i]).ljust(widths[i]) for i in range(len(headers)))
            print("| " + cells + " |")
        print(separator)
        print(Colors.paint(f"  Showing {page * page_size + len(chunk)} of {len(string_rows)} rows", Colors.DIM))

        if page + 1 < total_pages:
            if not sys.stdin.isatty():
                continue
            try:
                answer = input(Colors.paint("  [Enter] next page, 'q' to stop: ", Colors.DIM))
            except EOFError:
                break
            if answer.strip().lower() in {"q", "quit", "x"}:
                break


def records_table(records: Iterable[PasswordRecord]) -> list[list[object]]:
    """Build display rows for record listings."""
    return [
        [
            record.id,
            record.label,
            record.checked_at.replace("T", " ")[:16],
            f"{record.score}/100",
            record.rating,
            record.analysis.length,
            ", ".join(record.analysis.issues[:2]) or "-",
        ]
        for record in records
    ]


RECORD_HEADERS = ("ID", "Label", "Checked at", "Score", "Rating", "Len", "Top issues")


# --------------------------------------------------------------------------- #
# Analysis / summary reports
# --------------------------------------------------------------------------- #

def print_analysis(result: AnalysisResult) -> None:
    """Display one password analysis result in full."""
    section("ANALYSIS RESULT")
    colour = rating_colour(result.rating)
    print(f"  Score    : {Colors.paint(f'{result.score}/100', colour, Colors.BOLD)}")
    print(f"  Rating   : {Colors.paint(result.rating, colour, Colors.BOLD)}")
    print(f"  Strength : {score_bar(result.score)}")
    print()
    print("  Characteristics")
    print(f"    Length            : {result.length} characters")
    print(f"    Uppercase letters : {'Yes' if result.has_upper else 'No'}")
    print(f"    Lowercase letters : {'Yes' if result.has_lower else 'No'}")
    print(f"    Digits            : {'Yes' if result.has_digit else 'No'}")
    print(f"    Symbols           : {'Yes' if result.has_special else 'No'}")
    print(f"    Character classes : {result.char_classes} of 4")
    print(f"    Estimated entropy : {result.entropy_bits:.1f} bits")
    print(f"    Offline crack time: {result.crack_time}")

    if result.issues:
        section("ISSUES FOUND")
        for issue in result.issues:
            warning(issue)
    else:
        success("No strength issues detected.")

    if result.suggestions:
        section("SUGGESTIONS")
        for suggestion in result.suggestions:
            hint(f"- {suggestion}")


def _mini_bar(value: int, total: int, width: int = 20) -> str:
    filled = 0 if total == 0 else int(round(value / total * width))
    return "#" * filled + "-" * (width - filled)


def print_summary(report: SummaryReport) -> None:
    """Render the executive summary, distribution charts and warning flags."""
    section("EXECUTIVE SUMMARY")
    if report.total == 0:
        info("No records available. Check a password or seed sample data first.")
        return

    metrics = [
        ["Total records", report.total],
        ["Average score", f"{report.average_score}/100"],
        ["Median score", f"{report.median_score}/100"],
        ["Score range", f"{report.min_score} - {report.max_score}"],
        ["Average length", f"{report.average_length:.1f} chars"],
        ["Strong / very strong", f"{report.strong_count} ({report.strong_rate:.0%})"],
        ["Weak / very weak", f"{report.weak_count} ({report.weak_rate:.0%})"],
    ]
    print_table(["Metric", "Value"], metrics, page_size=999)

    section("RATING DISTRIBUTION")
    for name, count in rating_distribution(report):
        print(f"  {name:<14} {_mini_bar(count, report.total):<20} {count:>4}")

    section("CHARACTER CLASS COVERAGE")
    for name in ("Uppercase", "Lowercase", "Digits", "Symbols"):
        count = report.class_counts.get(name, 0)
        print(f"  {name:<12} {_mini_bar(count, report.total):<20} {count:>4}/{report.total}")

    if report.common_issues:
        section("MOST COMMON ISSUES")
        for issue, count in report.common_issues.most_common(6):
            print(f"  {count:>4}  {issue}")

    if report.per_day:
        section("ACTIVITY BY DAY (most recent)")
        for day, count in sorted(report.per_day.items(), reverse=True)[:8]:
            print(f"  {day}  {_mini_bar(count, report.total, 16)}  {count}")

    section("EXTREMES")
    if report.strongest:
        success(f"Strongest: #{report.strongest.id} '{report.strongest.label}' - {report.strongest.score}/100")
    if report.weakest:
        warning(f"Weakest  : #{report.weakest.id} '{report.weakest.label}' - {report.weakest.score}/100")

    section("THRESHOLD INDICATORS")
    for level, message in build_alerts(report):
        if level == "critical":
            error(message)
        elif level == "warning":
            warning(message)
        else:
            info(message)


def print_rules(rules: Sequence[dict[str, str]]) -> None:
    """Display the password strength rules as readable numbered entries."""
    section("BASIC PASSWORD STRENGTH RULES")
    for index, rule in enumerate(rules, start=1):
        print(Colors.paint(f"  {index}. {rule['title']}", Colors.BOLD, Colors.CYAN))
        print(f"     Rule:   {rule['rule']}")
        print(f"     Why:    {rule['why']}")
        print()
