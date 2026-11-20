"""Centralised, defensive terminal input routines.

Every user value passes through one of these wrappers before it reaches the
business logic.  The wrappers loop until the input is valid, so malformed,
blank or out-of-range entries can never crash the application.
"""

from __future__ import annotations

import getpass
import re
import sys
from collections.abc import Sequence

from .config import MAX_LABEL_LENGTH, MAX_PASSWORD_LENGTH

# Characters that are never allowed inside a text label.
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def _clean_label(value: str) -> str:
    """Strip control characters and collapse surrounding whitespace."""
    return _CONTROL_CHARS.sub("", value).strip()


def read_text(
    prompt: str,
    *,
    min_len: int = 0,
    max_len: int = MAX_LABEL_LENGTH,
    pattern: str | None = None,
    allow_blank: bool = False,
) -> str:
    """Read a line of text, looping until it satisfies the constraints."""
    compiled = re.compile(pattern) if pattern else None
    while True:
        raw = input(prompt).strip()
        cleaned = _clean_label(raw)
        if not cleaned:
            if allow_blank:
                return ""
            print("  ! Input cannot be blank. Please try again.")
            continue
        if len(cleaned) < min_len:
            print(f"  ! Please enter at least {min_len} characters.")
            continue
        if len(cleaned) > max_len:
            print(f"  ! Please enter at most {max_len} characters.")
            continue
        if compiled and not compiled.fullmatch(cleaned):
            print("  ! Input contains invalid characters. Please try again.")
            continue
        return cleaned


def read_int(
    prompt: str,
    *,
    low: int,
    high: int,
    default: int | None = None,
    allow_blank: bool = False,
) -> int | None:
    """Read an integer within ``[low, high]``.

    A blank answer returns *default*, or ``None`` when *allow_blank* is set.
    """
    if allow_blank and default is None:
        hint = f" ({low}-{high}, blank = any)"
    elif default is None:
        hint = f" ({low}-{high})"
    else:
        hint = f" ({low}-{high}, blank = {default})"
    while True:
        raw = input(prompt + hint + ": ").strip()
        if not raw:
            if default is not None:
                return default
            if allow_blank:
                return None
        try:
            value = int(raw)
        except (TypeError, ValueError):
            print("  ! Please enter a whole number.")
            continue
        if not low <= value <= high:
            print(f"  ! Value must be between {low} and {high}.")
            continue
        return value


def read_choice(
    prompt: str,
    valid: Sequence[str],
    *,
    default: str | None = None,
) -> str:
    """Read a menu choice, matching case-insensitively against *valid*."""
    lookup = {option.lower(): option for option in valid}
    suffix = f" [{default}]" if default else ""
    while True:
        raw = input(prompt + suffix + ": ").strip().lower()
        if not raw and default is not None:
            return default
        if raw in lookup:
            return lookup[raw]
        options = "/".join(valid)
        print(f"  ! Please choose one of: {options}.")


def read_yes_no(prompt: str, *, default: bool | None = None) -> bool:
    """Read a yes/no answer; blank uses *default* (False when omitted)."""
    suffix = " [Y/n]" if default is True else " [y/N]" if default is False else " [y/n]"
    while True:
        raw = input(prompt + suffix + ": ").strip().lower()
        if not raw:
            return bool(default)
        if raw in {"y", "yes", "1", "true", "t"}:
            return True
        if raw in {"n", "no", "0", "false", "f"}:
            return False
        print("  ! Please answer 'y' or 'n'.")


def read_password(
    prompt: str = "Enter password: ",
    *,
    confirm: bool = True,
    max_length: int = MAX_PASSWORD_LENGTH,
) -> str:
    """Read a password without echo, optionally asking for confirmation.

    ``getpass`` is used where available; a plain ``input`` fallback keeps the
    routine working in restricted terminals.  The password is returned to the
    caller only so it can be analysed immediately and then discarded.
    """
    # Redirected/non-interactive stdin (scripts, CI, demos) cannot suppress
    # echo, and getpass may block waiting on the console. Use plain input there.
    def hidden_input(message: str) -> str:
        if not sys.stdin.isatty():
            return input(message)
        try:
            return getpass.getpass(message)
        except (EOFError, KeyboardInterrupt):
            raise
        except Exception:  # pragma: no cover - environment specific fallback
            return input(message)

    while True:
        value = hidden_input(prompt)

        if not value:
            print("  ! Password cannot be empty.")
            continue
        if len(value) > max_length:
            print(f"  ! Password must be at most {max_length} characters.")
            continue
        if "\x00" in value:
            print("  ! Password contains an invalid character.")
            continue

        if confirm:
            again = hidden_input("Confirm password: ")
            if again != value:
                print("  ! Passwords did not match. Please try again.")
                continue
        return value


def read_path(prompt: str, *, default: str) -> str:
    """Read a file path, using *default* when the user presses Enter."""
    raw = input(f"{prompt} [{default}]: ").strip()
    return raw or default


def safe_int(value: object, fallback: int = 0) -> int:
    """Non-interactive integer coercion used by importers and tests."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return fallback
