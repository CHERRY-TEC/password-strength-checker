#!/usr/bin/env python3
"""Run the complete test suite: Python core/API tests + browser engine tests.

Usage::

    python run_tests.py
"""

from __future__ import annotations

import shutil
import subprocess
import sys


def run(command: list[str], label: str) -> int:
    """Run a command, streaming its output, and return its exit status."""
    print(f"\n{'=' * 68}\n{label}\n{'=' * 68}", flush=True)
    result = subprocess.run(command, cwd=__import__("pathlib").Path(__file__).parent)
    return result.returncode


def main() -> int:
    status = 0
    status |= run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        "PYTHON TEST SUITE (core, models, storage, API, exports)",
    )

    if shutil.which("node"):
        status |= run(
            ["node", "--test", "site/analyzer.test.js"],
            "JAVASCRIPT TEST SUITE (browser analysis engine)",
        )
    else:
        print("\nNode.js not found - skipped JavaScript tests.")

    print("\n" + "=" * 68)
    print("ALL TESTS PASSED" if status == 0 else f"TEST FAILURES (exit {status})")
    print("=" * 68)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
