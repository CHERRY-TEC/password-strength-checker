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
const A = global.window.Analyzer;
const samples = JSON.parse(process.argv[3]);
const analyses = samples.map((s) => [s, A.analyzePassword(s)]);
const history = analyses.slice(0, 4).map(([s, a], i) => ({ id: i + 1, analysis: a }));
const novelty = analyses.map(([s, a]) => [
  s, A.structuralDrift(a, history), A.structuralFingerprint(a),
  A.portfolioDiversity(history.map((h) => h.analysis))
]);
console.log(JSON.stringify({ analyses, novelty }));
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

    browser = json.loads(output)

    sys.path.insert(0, str(ROOT))
    from psc.analyzer import analyze_password  # noqa: PLC0415
    from psc.novelty import compare, fingerprint, portfolio_diversity  # noqa: PLC0415

    mismatches = []
    for sample, result in browser["analyses"]:
        if analyze_password(sample).to_dict() != result:
            mismatches.append(sample)
    if mismatches:
        return fail(f"engine parity mismatch for {mismatches!r}")

    history = [(index + 1, analyze_password(sample).to_dict())
               for index, sample in enumerate(SAMPLES[:4])]
    novelty_mismatches = []
    for sample, drift, printed, diversity in browser["novelty"]:
        analysis = analyze_password(sample).to_dict()
        expected = (
            compare(analysis, history).to_dict(),
            fingerprint(analysis).to_dict(),
            portfolio_diversity([item for _, item in history]),
        )
        if expected != (drift, printed, diversity):
            novelty_mismatches.append(sample)
    if novelty_mismatches:
        return fail(f"Structural Drift Index parity mismatch for {novelty_mismatches!r}")

    total_bytes = sum((SITE / name).stat().st_size for name in REQUIRED_ASSETS)
    print(f"BUILD OK: {len(REQUIRED_ASSETS)} static assets, {total_bytes:,} bytes")
    print(f"ENGINE PARITY OK: {len(browser['analyses'])} passwords matched Python engine")
    print(f"SDI PARITY OK: {len(browser['novelty'])} fingerprints and drift reports matched")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
