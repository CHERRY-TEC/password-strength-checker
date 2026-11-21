"""Tests for the Strategy, Command and Observer pattern implementations."""

import tempfile
import unittest
from pathlib import Path

from psc.patterns import (
    CommandRegistry,
    EventBus,
    LoggingObserver,
    MenuCommand,
    StorageRegistry,
    default_event_bus,
)
from psc.sqlite_store import SQLiteStore
from psc.storage import CSVStore, JSONStore


class PatternTests(unittest.TestCase):
    def test_storage_strategy_registry(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            registry = StorageRegistry([
                JSONStore(base / "r.json"),
                CSVStore(base / "r.csv"),
                SQLiteStore(base / "r.sqlite3"),
            ])
            self.assertEqual(registry.names(), ("json", "csv", "sqlite"))
            self.assertIsInstance(registry.get("SQLITE"), SQLiteStore)
            self.assertIn("csv", registry)
            with self.assertRaises(KeyError):
                registry.get("yaml")

    def test_registry_rejects_duplicates(self):
        with tempfile.TemporaryDirectory() as folder:
            registry = StorageRegistry([JSONStore(Path(folder) / "a.json")])
            with self.assertRaises(ValueError):
                registry.register(JSONStore(Path(folder) / "b.json"))

    def test_command_registry_dispatches(self):
        calls = []
        registry = CommandRegistry([
            MenuCommand("1", "First", lambda: calls.append("first")),
            MenuCommand("2", "Second", lambda: calls.append("second")),
        ])
        self.assertEqual(registry.items(), (("1", "First"), ("2", "Second")))
        registry.get("2").execute()
        self.assertEqual(calls, ["second"])
        self.assertIsNone(registry.get("9"))

    def test_event_bus_notifies_subscribers(self):
        bus = EventBus()
        seen = []
        bus.subscribe("record.saved", lambda event: seen.append(event))
        bus.subscribe("*", lambda event: seen.append(event))
        event = bus.publish("record.saved", record_id=7)
        self.assertEqual(event.name, "record.saved")
        self.assertEqual(event.payload["record_id"], 7)
        self.assertEqual(len(seen), 2)
        self.assertEqual(bus.subscriber_count("record.saved"), 1)

    def test_default_bus_has_logging_observer(self):
        bus = default_event_bus()
        self.assertGreater(bus.subscriber_count("*"), 0)
        self.assertIsInstance(LoggingObserver().handle, object)

    def test_commands_in_app_are_registered(self):
        from psc.app import App

        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            app = App(base / "r.json", base / "r.csv", base / "r.sqlite3")
            self.assertEqual(len(app.commands.keys()), 9)
            self.assertIn("1", app.commands.keys())


if __name__ == "__main__":
    unittest.main()
