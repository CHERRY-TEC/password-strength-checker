# Software Requirements Specification

## 1. Purpose

Password Strength Checker is a local-first utility that evaluates password
characteristics, explains basic strength rules, and keeps a searchable history
of the **results** of past checks. It never stores the passwords themselves.

## 2. Stakeholders and constraints

- **Users:** students and staff who need a quick, offline strength check.
- **Constraint:** no password may be persisted or transmitted to third parties.
- **Constraint:** the Python core must run on the standard library only
  (Python 3.10+).

## 3. Functional requirements

| ID | Requirement | Implementation |
| --- | --- | --- |
| FR-1 | Interactive terminal interface | `psc/app.py` menu dispatcher |
| FR-2 | Defensive input validation | `psc/validators.py` wrappers (loops on invalid input) |
| FR-3 | Password evaluation engine | `psc/analyzer.py` (length, classes, common words, sequences, repetition, entropy, crack time) |
| FR-4 | Basic strength rule explanations | `Analyzer.explain_rules()` / menu 6 |
| FR-5 | Local persistence | `psc/storage.py` (JSON, CSV) and `psc/sqlite_store.py` (SQLite) |
| FR-6 | Record query and search | menu 3 and `GET /api/records` |
| FR-7 | Executive summary | `psc/summary.py`, analytics tab |
| FR-8 | Multi-format export | `psc/exporter.py` (MD, TXT, CSV, PNG) |
| FR-9 | Threshold warnings | `build_alerts()` and the check-screen flag |
| FR-10 | Web interface | `webui/server.py` (local) and `site/` (Vercel static build) |
| FR-11 | Bulk CSV import | `CSVStore.load(repair=False)` / Tools tab |
| FR-12 | Seed dataset | `psc/seed_data.py` (46 varied cases) |
| FR-13 | Advanced entropy heuristics | `psc/heuristics.py` spatial/date/repeat matchers |
| FR-14 | Structured logging | `psc/logging_config.py` JSON events + `--log-file` |
| FR-15 | API authentication | CSRF double-submit + optional bearer token |
| FR-16 | Design patterns | `psc/patterns.py` Strategy, Command and Observer |
| FR-17 | Novel adaptive risk analysis | `psc/novelty.py` Structural Drift Index (SDI) |

## 4. Data design

A stored record contains only derived metadata:

```
Record {
  id: integer
  label: string            (user supplied, never the password)
  checked_at: ISO-8601
  analysis: {
    score, rating, length, has_upper, has_lower, has_digit, has_special,
    char_classes, entropy_bits, crack_time, issues[], suggestions[]
  }
}
```

### Storage backends

| Backend | File | Characteristics |
| --- | --- | --- |
| JSON | `data/records.json` | Human-readable, schema versioned, atomic writes |
| CSV | `data/records.csv` | Flat, validated header, JSON-encoded list columns |
| SQLite | `data/records.sqlite3` | Transactional, indexed `[records(checked_at)]`, row-level validation, corrupt-file recovery |

All three are interchangeable at runtime through menu 9 (`--format json|csv|sqlite`)
and `POST /api/format`. Corrupt or missing files are backed up and rebuilt as
clean templates; individual invalid rows are skipped with descriptive warnings.

## 5. Non-functional requirements

- **Security:** loopback-only server, origin checks, double-submit CSRF,
  optional bearer token, CSP, static-file whitelist, body-size limit, structured
  logging that never records passwords, and no password in any persisted file.
- **Reliability:** central input validation, atomic JSON/CSV writes, SQLite
  transactions, defensive deserialisation, fault-tolerant menu loop.
- **Observability:** JSON log events with named `event_name` fields and optional
  file sink; domain events published through an observer bus.
- **Portability:** zero required third-party packages; matplotlib is optional
  and only used for PNG export.
- **Testability:** unit, integration and property-style invariant tests in
  Python plus Node tests for the browser engine; `python run_tests.py` runs
  everything.
- **Deployment:** `site/` is a static SPA deployed to Vercel; Vercel has no
  writable filesystem, so the cloud build keeps records in browser
  localStorage (metadata only). This is the deployment target, not a degraded
  fallback — the local build intentionally uses durable file/SQLite storage.

## 6. Novel Algorithm - Structural Drift Index

Conventional meters score a password in isolation. The Structural Drift Index
(SDI) adds an adaptive dimension without compromising the privacy guarantee.

- **Non-reversible fingerprint:** a six-feature structural signature (banded
  length, classes, entropy, repetition, pool and a pattern bitmask) is derived
  from an analysis. No raw characters, hashes or reversible data are retained.
- **Hybrid distance:** weighted banded L1 distance over numeric features is
  fused with Jaccard distance over the pattern bitmask into a bounded `[0, 1]`
  structural distance.
- **Adaptive advice:** the nearest prior structure, a personal risk score and
  plain-language guidance warn when a new password closely resembles a
  previously weak check.
- **Portfolio diversity:** average pairwise structural distance quantifies how
  varied a user's checked history is.

The algorithm is implemented once in Python (`psc/novelty.py`) and ported
identically to the browser (`site/analyzer.js`); `scripts/build.py` proves parity
of fingerprints and drift reports on every build.

## 7. Verification

- 92 Python tests covering analyzer, heuristics, the Structural Drift Index,
  design patterns, structured logging, models, all three storage backends,
  summaries, exporters, invariants and the HTTP API (including CSRF and
  bearer-token enforcement).
- 13 Node tests covering the browser engine, including exact parity with the
  Python engine across 11 representative passwords (`scripts/build.py`).
- Playwright browser tests for the local and deployed interfaces.
- GitHub Actions runs compile checks, the full suite and the build validation
  on every push and pull request.
