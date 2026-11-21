"""Reusable design patterns used by the application layer.

* **Strategy** - interchangeable storage backends behind one interface.
* **Command** - menu actions are objects, not string-built method lookups.
* **Observer** - domain events are published to subscribers such as the
  structured logger, keeping cross-cutting concerns out of the handlers.

These patterns replace ad-hoc dispatch with explicit, testable abstractions.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .logging_config import get_logger
from .models import PasswordRecord


# --------------------------------------------------------------------------- #
# Strategy
# --------------------------------------------------------------------------- #

class StorageStrategy(ABC):
    """Common interface implemented by every persistence backend."""

    name: str
    path: Path

    @abstractmethod
    def save(self, records: list[PasswordRecord]) -> None:
        """Persist all records."""

    @abstractmethod
    def load(self) -> tuple[list[PasswordRecord], list[str]]:
        """Return ``(records, warnings)``."""


class StorageRegistry:
    """Resolve storage strategies by name with explicit registration."""

    def __init__(self, strategies: Iterable[StorageStrategy] = ()) -> None:
        self._strategies: dict[str, StorageStrategy] = {}
        for strategy in strategies:
            self.register(strategy)

    def register(self, strategy: StorageStrategy) -> None:
        key = strategy.name.lower()
        if key in self._strategies:
            raise ValueError(f"storage strategy already registered: {key}")
        self._strategies[key] = strategy

    def get(self, name: str) -> StorageStrategy:
        try:
            return self._strategies[name.lower()]
        except KeyError as exc:
            raise KeyError(f"unknown storage strategy: {name}") from exc

    def names(self) -> tuple[str, ...]:
        return tuple(self._strategies)

    def __contains__(self, name: str) -> bool:
        return name.lower() in self._strategies


# --------------------------------------------------------------------------- #
# Command
# --------------------------------------------------------------------------- #

class Command(ABC):
    """An executable menu action with a stable key and display label."""

    key: str
    label: str

    @abstractmethod
    def execute(self) -> None:
        ...


@dataclass(frozen=True)
class MenuCommand(Command):
    """Adapter that turns a handler callable into a :class:`Command`."""

    key: str
    label: str
    handler: Callable[[], None]

    def execute(self) -> None:
        self.handler()


class CommandRegistry:
    """Ordered collection of commands with lookup by key."""

    def __init__(self, commands: Iterable[Command] = ()) -> None:
        self._commands: dict[str, Command] = {}
        for command in commands:
            self.register(command)

    def register(self, command: Command) -> None:
        if command.key in self._commands:
            raise ValueError(f"duplicate command key: {command.key}")
        self._commands[command.key] = command

    def get(self, key: str) -> Command | None:
        return self._commands.get(key)

    def items(self) -> tuple[tuple[str, str], ...]:
        return tuple((command.key, command.label) for command in self._commands.values())

    def keys(self) -> tuple[str, ...]:
        return tuple(self._commands)


# --------------------------------------------------------------------------- #
# Observer
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Event:
    """A named domain event with an immutable payload."""

    name: str
    payload: dict[str, Any] = field(default_factory=dict)


EventHandler = Callable[[Event], None]


class EventBus:
    """Publish/subscribe bus for application events."""

    def __init__(self) -> None:
        self._subscribers: dict[str, list[EventHandler]] = {}

    def subscribe(self, event_name: str, handler: EventHandler) -> None:
        self._subscribers.setdefault(event_name, []).append(handler)

    def publish(self, event_name: str, **payload: Any) -> Event:
        event = Event(event_name, dict(payload))
        for handler in list(self._subscribers.get(event_name, [])):
            handler(event)
        for handler in list(self._subscribers.get("*", [])):
            handler(event)
        return event

    def subscriber_count(self, event_name: str) -> int:
        return len(self._subscribers.get(event_name, []))


class LoggingObserver:
    """Forward every domain event to the structured logger."""

    def __init__(self, logger_name: str = "events") -> None:
        self.logger = get_logger(logger_name)

    def handle(self, event: Event) -> None:
        self.logger.info(
            event.name,
            extra={"event_name": event.name, **{
                key: value for key, value in event.payload.items()
                if isinstance(value, (str, int, float, bool))
            }},
        )


def default_event_bus() -> EventBus:
    """Create a bus with structured-logging already attached."""
    bus = EventBus()
    observer = LoggingObserver()
    bus.subscribe("*", observer.handle)
    return bus
