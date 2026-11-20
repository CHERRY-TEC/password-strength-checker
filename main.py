#!/usr/bin/env python3
"""Entry point for the Password Strength Checker.

Run with::

    python main.py

Optional flags::

    python main.py --format csv
    python main.py --no-color
    python main.py --web                 # launch the browser interface
    python main.py --web --open          # launch and open a browser tab
    python main.py --web --port 9000
"""

from __future__ import annotations

import argparse
import os
import sys

APP_NAME = "Password Strength Checker"
APP_VERSION = "1.0.0"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line options."""
    parser = argparse.ArgumentParser(
        prog="password-strength-checker",
        description=f"{APP_NAME} v{APP_VERSION} - offline password analysis.",
    )
    parser.add_argument(
        "--format",
        choices=("json", "csv"),
        default="json",
        help="storage backend to use on startup (default: json)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable ANSI colour output",
    )
    parser.add_argument(
        "--web",
        action="store_true",
        help="launch the local web interface instead of the console app",
    )
    parser.add_argument("--host", default="127.0.0.1", help="web bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="web port (default: 8765)")
    parser.add_argument("--open", action="store_true", help="open a browser tab with --web")
    parser.add_argument(
        "--version",
        action="version",
        version=f"{APP_NAME} {APP_VERSION}",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Launch the interactive application and return an exit status."""
    args = parse_args(argv)
    if args.no_color:
        os.environ["NO_COLOR"] = "1"

    # Import after environment flags are set so configuration picks them up.
    if args.web:
        from webui.server import serve  # noqa: PLC0415

        return serve(args.host, args.port, args.format, args.open)

    from psc.app import run  # noqa: PLC0415

    try:
        run(args.format)
    except KeyboardInterrupt:
        print("\nInterrupted. Goodbye!")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
