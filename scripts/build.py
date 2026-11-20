#!/usr/bin/env python3
"""Build and validation step for the static Vercel deployment.

This project needs no compilation. The build step instead guarantees that the
deployed browser engine stays byte-for-byte behaviourally identical to the
Python engine, and that every static asset required by the SPA is present.

Usage::

    python scripts/build.py
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "site"
REQUIRED_ASSETS = ("index.html", "styles.css", "app.js", "analyzer.js", "favicon.svg")
SAMPLES = [
    "", "a", "password", "abc123", "Password1", "P@ssw0rd",
    "vL8!qZ#2wR@6tY&1c", "correct horse battery staple",
    "aaaaaaaaaaaaaaaaaaaa", "abcdefghijklmnop", "1234567890123456",
]

PARITY_SCRIPT = """
global.window = global;
require(process.argv[2]);
const samples = JSON.parse(process.argv[3]);
console.log(JSON.stringify(samples.map((s) => [s, global.window.Analyzer.analyzePassword(s)])));
"""


def fail(message: str) -> int:
    print(f"BUILD FAILED: {message}")
    return 1


def main() -> int:
    missing = [name for name in REQUIRED_ASSETS if not (SITE / name).is_file()]
    if missing:
        return fail("missing static assets: " + ", ".join(missing))

    if not shutil.which("node"):
        return fail("Node.js is required to validate the browser engine")

    with tempfile.TemporaryDirectory() as folder:
        script = Path(folder) / "parity.js"
        script.write_text(PARITY_SCRIPT, encoding="utf-8")
        try:
            output = subprocess.check_output(
                ["node", str(script), str(SITE / "analyzer.js"), json.dumps(SAMPLES)],
                cwd=ROOT,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            return fail(f"browser engine failed to load: {exc}")

    browser_results = json.loads(output)

    sys.path.insert(0, str(ROOT))
    from psc.analyzer import analyze_password  # noqa: PLC0415

    mismatches = []
    for sample, browser in browser_results:
        python = analyze_password(sample).to_dict()
        if python != browser:
            mismatches.append(sample)
    if mismatches:
        return fail(f"engine parity mismatch for {mismatches!r}")

    total_bytes = sum((SITE / name).stat().st_size for name in REQUIRED_ASSETS)
    print(f"BUILD OK: {len(REQUIRED_ASSETS)} static assets, {total_bytes:,} bytes")
    print(f"ENGINE PARITY OK: {len(browser_results)} passwords matched Python engine")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
