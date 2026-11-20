"""Main application controller and navigation dispatch loop."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from . import ui
from .analyzer import analyze_password, explain_rules
from .config import (
    CSV_PATH,
    DATA_DIR,
    DEFAULT_SEED_COUNT,
    EXPORT_DIR,
    JSON_PATH,
    MAX_LABEL_LENGTH,
    SEED_COUNT_MAX,
    SEED_COUNT_MIN,
    SUPPORTED_FORMATS,
    WEAK_SCORE_THRESHOLD,
)
from .exporter import (
    default_path,
    export_chart_png,
    export_csv,
    export_markdown,
    export_text_audit,
)
from .models import PasswordRecord
from .seed_data import generate_records
from .storage import CSVStore, JSONStore, StorageError
from .summary import build_summary
from .validators import read_choice, read_int, read_path, read_text, read_yes_no, read_password

MENU_OPTIONS: tuple[tuple[str, str], ...] = (
    ("1", "Check a new password"),
    ("2", "List all records"),
    ("3", "Search / filter records"),
    ("4", "Analytics & executive summary"),
    ("5", "Export reports"),
    ("6", "Password strength rules"),
    ("7", "Import CSV dataset (bulk)"),
    ("8", "Seed sample data"),
    ("9", "Storage settings"),
    ("0", "Exit"),
)

EXPORT_OPTIONS: tuple[tuple[str, str], ...] = (
    ("1", "Markdown report (.md)"),
    ("2", "Plain-text audit log (.txt)"),
    ("3", "Standardised CSV report (.csv)"),
    ("4", "Rating chart image (.png, needs matplotlib)"),
    ("0", "Back to main menu"),
)

SETTINGS_OPTIONS: tuple[tuple[str, str], ...] = (
    ("1", "Switch storage format (JSON / CSV)"),
    ("2", "Save records now"),
    ("3", "Reload records from disk"),
    ("0", "Back to main menu"),
)

RATING_FILTERS: dict[str, str | None] = {
    "a": None,
    "v": "Very Weak",
    "w": "Weak",
    "f": "Fair",
    "s": "Strong",
    "x": "Very Strong",
}


class App:
    """Stateful console application with a menu-driven dispatch loop."""

    def __init__(
        self,
        json_path: Path = JSON_PATH,
        csv_path: Path = CSV_PATH,
        storage_format: str = "json",
    ) -> None:
        self.json_store = JSONStore(json_path)
        self.csv_store = CSVStore(csv_path)
        self.storage_format = storage_format if storage_format in SUPPORTED_FORMATS else "json"
        self.records: list[PasswordRecord] = []
        self.next_id: int = 1

    # ------------------------------------------------------------------ #
    # Infrastructure
    # ------------------------------------------------------------------ #

    @property
    def store(self) -> JSONStore | CSVStore:
        """Return the currently active storage backend."""
        return self.json_store if self.storage_format == "json" else self.csv_store

    def _persist(self) -> bool:
        """Save current records; return True on success."""
        try:
            self.store.save(self.records)
        except StorageError as exc:
            ui.error(str(exc))
            return False
        ui.success(f"Saved {len(self.records)} record(s) to {self.store.path}")
        return True

    def _recalculate_ids(self) -> None:
        self.next_id = max((record.id for record in self.records), default=0) + 1

    def _report_warnings(self, warnings: list[str]) -> None:
        for message in warnings:
            ui.warning(message)

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    def startup(self) -> None:
        """Prepare the terminal and load persisted state."""
        ui.enable_color()
        ui.clear()
        ui.banner()
        ui.info(f"Loading records from {self.store.path}")
        records, warnings = self.store.load()
        self.records = records
        self._report_warnings(warnings)
        self._recalculate_ids()
        if records:
            ui.success(f"Restored {len(records)} record(s) from local storage.")
        else:
            ui.info("No prior records found. A clean template is ready.")
        ui.hint("Tip: passwords are analysed in memory only - nothing sensitive is stored.")

    def run(self) -> None:
        """Run the interactive menu loop until the user exits."""
        self.startup()
        while True:
            ui.menu("MAIN MENU", MENU_OPTIONS)
            try:
                choice = read_choice("Choose an option", [key for key, _ in MENU_OPTIONS])
            except (KeyboardInterrupt, EOFError):
                print()
                choice = "0"

            if choice == "0":
                try:
                    confirm_exit = read_yes_no("Exit the application?", default=True)
                except (KeyboardInterrupt, EOFError):
                    confirm_exit = True  # an exhausted input stream means "exit"
                if confirm_exit:
                    ui.success("Goodbye - your records have been saved locally.")
                    break
                continue

            handler = getattr(self, f"_menu_{self._handler_name(choice)}", None)
            if handler is None:
                ui.error("Unknown option. Please try again.")
                continue
            try:
                handler()
            except (KeyboardInterrupt, EOFError):
                print()
                ui.info("Action cancelled. Returning to the main menu.")
            except StorageError as exc:
                ui.error(str(exc))
            except Exception as exc:  # noqa: BLE001 - keep the demo fault tolerant
                ui.error(f"Unexpected error: {exc}")

    @staticmethod
    def _handler_name(choice: str) -> str:
        return {
            "1": "check",
            "2": "list",
            "3": "search",
            "4": "analytics",
            "5": "export",
            "6": "rules",
            "7": "import",
            "8": "seed",
            "9": "settings",
        }[choice]

    # ------------------------------------------------------------------ #
    # Menu handlers
    # ------------------------------------------------------------------ #

    def _menu_check(self) -> None:
        ui.section("NEW PASSWORD CHECK")
        ui.hint("The label is a reminder only - never enter the password itself as the label.")
        label = read_text(
            "Label / account name: ",
            min_len=1,
            max_len=MAX_LABEL_LENGTH,
        )
        ui.hint("Your password is analysed locally and then discarded - it is never stored.")
        password = read_password("Enter password to analyse: ", confirm=True)
        result = analyze_password(password)
        del password  # drop the plaintext as soon as analysis is complete

        ui.print_analysis(result)

        record = PasswordRecord(
            id=self.next_id,
            label=label,
            checked_at=datetime.now().isoformat(timespec="seconds"),
            analysis=result,
        )
        self.next_id += 1
        self.records.append(record)
        self._persist()

        if result.score < WEAK_SCORE_THRESHOLD:
            ui.warning("THRESHOLD FLAG: this password is weak - consider changing it.")
        ui.pause()

    def _menu_list(self) -> None:
        ordered = sorted(self.records, key=lambda record: record.id, reverse=True)
        ui.print_table(
            ui.RECORD_HEADERS,
            ui.records_table(ordered),
            title=f"ALL RECORDS ({len(ordered)} total, newest first)",
        )
        ui.pause()

    def _menu_search(self) -> None:
        ui.section("SEARCH / FILTER RECORDS")
        keyword = read_text(
            "Keyword in label / rating / issues (blank = any): ",
            min_len=0,
            max_len=MAX_LABEL_LENGTH,
            allow_blank=True,
        )
        ui.hint("Rating: a=all, v=very weak, w=weak, f=fair, s=strong, x=very strong")
        rating_key = read_choice("Rating filter", list(RATING_FILTERS))
        wanted_rating = RATING_FILTERS[rating_key]
        minimum = read_int("Minimum score", low=0, high=100, allow_blank=True)

        tokens = keyword.lower().split()
        matches = [
            record
            for record in self.records
            if (not tokens or record.matches(tokens))
            and (wanted_rating is None or record.rating == wanted_rating)
            and (minimum is None or record.score >= minimum)
        ]
        matches.sort(key=lambda record: record.id, reverse=True)
        ui.print_table(
            ui.RECORD_HEADERS,
            ui.records_table(matches),
            title=f"SEARCH RESULTS ({len(matches)} match(es))",
        )
        ui.pause()

    def _menu_analytics(self) -> None:
        ui.section("ANALYTICS")
        report = build_summary(self.records)
        ui.print_summary(report)
        ui.pause()

    def _menu_export(self) -> None:
        if not self.records:
            ui.warning("There are no records to export yet.")
            return
        report = build_summary(self.records)
        ui.menu("EXPORT REPORTS", EXPORT_OPTIONS)
        choice = read_choice("Choose export format", [key for key, _ in EXPORT_OPTIONS])

        exporters = {
            "1": lambda path: export_markdown(self.records, report, path),
            "2": lambda path: export_text_audit(self.records, report, path),
            "3": lambda path: export_csv(self.records, path),
            "4": lambda path: export_chart_png(report, path),
        }
        if choice == "0":
            return
        specs = {
            "1": ("summary", "md", "Markdown report"),
            "2": ("audit", "txt", "Audit log"),
            "3": ("records", "csv", "CSV report"),
            "4": ("chart", "png", "Chart image"),
        }
        kind, extension, description = specs[choice]
        path = default_path(kind, extension, EXPORT_DIR)
        try:
            exporters[choice](path)
        except RuntimeError as exc:
            ui.warning(str(exc))
            return
        ui.success(f"{description} written to: {path}")
        ui.pause()

    def _menu_rules(self) -> None:
        ui.print_rules(explain_rules())
        ui.pause()

    def _menu_import(self) -> None:
        ui.section("BULK CSV IMPORT")
        default = str(DATA_DIR / "legacy_import.csv")
        raw_path = read_path("CSV file to import", default=default)
        source = Path(raw_path).expanduser()

        imported, warnings = CSVStore(source).load(repair=False)
        self._report_warnings(warnings)
        if not imported:
            ui.warning("No valid rows were found in that file. Nothing was imported.")
            ui.pause()
            return

        ui.success(f"Validated {len(imported)} row(s) from {source}.")
        if not read_yes_no("Add these records to the current dataset?", default=True):
            return

        for record in imported:
            record.id = self.next_id
            self.next_id += 1
            self.records.append(record)
        self._persist()
        ui.success(f"Imported {len(imported)} record(s).")
        ui.pause()

    def _menu_seed(self) -> None:
        ui.section("SEED SAMPLE DATA")
        ui.hint(f"Generates {SEED_COUNT_MIN}-{SEED_COUNT_MAX} realistic records with varied edge cases.")
        count = read_int(
            "Number of sample records",
            low=SEED_COUNT_MIN,
            high=SEED_COUNT_MAX,
            default=DEFAULT_SEED_COUNT,
        )
        assert count is not None
        replace = read_yes_no("Replace all existing records?", default=False)

        start_id = 1 if replace else self.next_id
        generated = generate_records(count, start_id=start_id)
        if replace:
            self.records = generated
        else:
            self.records.extend(generated)
        self._recalculate_ids()
        self._persist()
        ui.success(f"Seeded {count} sample record(s) ({'replaced' if replace else 'appended'}).")
        ui.hint("Try option 4 to see the generated analytics and warning indicators.")
        ui.pause()

    def _menu_settings(self) -> None:
        while True:
            ui.menu(
                f"STORAGE SETTINGS (active: {self.storage_format.upper()})",
                SETTINGS_OPTIONS,
            )
            choice = read_choice("Choose an option", [key for key, _ in SETTINGS_OPTIONS])
            if choice == "0":
                return
            if choice == "1":
                self._switch_format()
            elif choice == "2":
                self._persist()
            elif choice == "3":
                records, warnings = self.store.load()
                self.records = records
                self._report_warnings(warnings)
                self._recalculate_ids()
                ui.success(f"Reloaded {len(records)} record(s) from {self.store.path}.")

    def _switch_format(self) -> None:
        target_format = "csv" if self.storage_format == "json" else "json"
        target_store = self.csv_store if target_format == "csv" else self.json_store
        ui.info(f"Switching from {self.storage_format.upper()} to {target_format.upper()}...")
        target_records, warnings = target_store.load()
        self._report_warnings(warnings)

        if not target_records and self.records:
            if read_yes_no(
                "Target file is empty. Copy current records into the new format?",
                default=True,
            ):
                target_records = [PasswordRecord(**vars(record)) for record in self.records]
                self.storage_format = target_format
                self.records = target_records
                self._persist()
                ui.success(f"Migrated {len(self.records)} record(s) to {target_format.upper()}.")
                return

        self.storage_format = target_format
        self.records = target_records
        self._recalculate_ids()
        ui.success(
            f"Now using {target_format.upper()} ({len(self.records)} record(s) loaded from {target_store.path})."
        )


def run(storage_format: str = "json") -> None:
    """Convenience entry point used by ``main.py``."""
    App(storage_format=storage_format).run()
