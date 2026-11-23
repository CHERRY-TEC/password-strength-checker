# Password Strength Checker

A beginner-friendly, **zero-dependency** Python 3.10+ console application that
evaluates password characteristics locally, explains basic strength rules, and
keeps a searchable history of the *results* — not the passwords.

---

## Security design (important)

The brief asks for both local record persistence **and** operation "without
storing passwords". Those requirements are reconciled as follows:

| Stored | Never stored |
| --- | --- |
| Score (0-100) and rating band | The password string |
| Length and character-class flags | Any reversible/hashed derivative |
| Entropy estimate and crack-time label | Keystroke / input history |
| Issue and suggestion text | Clipboard content |
| ISO timestamp and an optional user label | — |

The password is read with `getpass`, passed directly into a pure analysis
function, and discarded immediately. Nothing sensitive is ever written to
`data/`.

---

## Features

### Core
- **Interactive terminal UI** — branded welcome screen, numbered menus, ANSI
  colour (auto-detected; `--no-color` available).
- **Defensive validation** — every input passes through central wrappers that
  loop on blank, non-numeric, out-of-range, over-long or malformed values.
- **Analysis engine** — length, character variety, common-password and
  sequence/repetition heuristics, entropy and an offline crack-time estimate.
- **Local persistence** — atomic JSON (default) or CSV storage with schema
  checks, corrupt-file backup, and per-row error reporting.
- **Query & search** — keyword plus rating and minimum-score filters.
- **Executive summary** — totals, averages, distributions, trends and
  threshold warning indicators.

### Stretch
- **Multi-format export** — Markdown, plain-text audit log, standard CSV, and
  an optional PNG chart (matplotlib only when installed).
- **Threshold indicators** — weak-score flags during entry and critical
  warnings when the dataset crosses configured limits.
- **Bulk CSV import** — validates legacy datasets row-by-row with a detailed
  error log and never rewrites the source file.
- **Seed data** — 30-50 realistic records covering normal, boundary and edge
  cases for a repeatable demo.

---

## Live deployment

| Platform | Link |
| --- | --- |
| Live web app (Vercel) | https://password-strength-checker-theta-puce.vercel.app |
| Source code (GitHub) | https://github.com/CHERRY-TEC/password-strength-checker |

The deployed site is the self-contained build in `site/`. Vercel is serverless
and has no writable local filesystem, so the cloud build runs the analysis in
the browser (a faithful port of `psc/analyzer.py`, verified against the Python
engine) and keeps record metadata in browser `localStorage`. Passwords are
still never stored or transmitted. The local console and `webui` server keep
using the Python engine with JSON/CSV file persistence.

`vercel.json` sets `outputDirectory` to `site` and applies a strict
Content-Security-Policy.

> The Vercel project lives under the **cherry** team and is connected to this
> GitHub repository. Pushes to `master` trigger a production deployment.
> You can also redeploy manually with `vercel --prod`.

---

## Quick start

```powershell
cd C:\Users\HANMANTH\PasswordStrengthChecker
python main.py
```

Optional flags:

```powershell
python main.py --format csv      # start with the CSV backend
python main.py --no-color        # plain output
python --version                 # 3.10+ required; 3.12 tested
```

No `pip install` step is needed for the core application.

---

## Web interface

A browser UI is included. It uses a local HTTP server built on Python's
standard library and the **same** analysis engine as the console app — there is
no duplicated logic and nothing to install.

```powershell
python main.py --web
# then open http://localhost:8765
```

Useful variants:

```powershell
python main.py --web --open          # open a browser tab automatically
python main.py --web --port 9000
python main.py --web --format csv
```

Or run the server module directly:

```powershell
python -m webui.server --port 8765 --open
```

### Web features

| Tab | What it does |
| --- | --- |
| **Check** | Live strength preview as you type, score ring, characteristics, issues and suggestions. Passwords are analysed with `persist: false` (no record written); only **Save check** stores the result. A header toggle switches between dark and light themes and remembers the choice. |
| **Records** | Search/filter by keyword, rating and minimum score, paginated table, record detail view and delete. |
| **Analytics** | Metric cards, CSS bar charts, rating distribution, character coverage, common issues, activity and threshold alerts. |
| **Tools** | Seed sample data, bulk CSV import with row-error counts, JSON/CSV switching, reload from disk, report downloads (MD/TXT/CSV/PNG) and the strength-rule reference. |

### Web security notes

- The server binds to `127.0.0.1` by default. Remote access is opt-in with
  `--host 0.0.0.0` (use only on a trusted network).
- Passwords travel only to this local loopback process and are analysed in
  memory; they are never logged or written to disk. Live preview explicitly
  saves nothing.
- Static files come from a fixed whitelist, request bodies are size-limited,
  cross-origin writes are rejected, and every response carries a strict
  Content-Security-Policy.

---

## Main menu

```
[1] Check a new password
[2] List all records
[3] Search / filter records
[4] Analytics & executive summary
[5] Export reports
[6] Password strength rules
[7] Import CSV dataset (bulk)
[8] Seed sample data
[9] Storage settings
[0] Exit
```

---

## Suggested 2-minute demo

1. Launch `python main.py` — the welcome screen shows restored state.
2. Choose **8 → Seed sample data**, accept 40 and replace existing records.
3. Choose **4 → Analytics** to show summary tables, distributions and warning flags.
4. Choose **1 → Check a new password**: enter a label, then intentionally enter
   mismatched passwords once to show validation recovery, then `password` to
   show a weak-score threshold flag.
5. Choose **3 → Search** with a rating filter (e.g. `v`) to demonstrate retrieval.
6. Choose **5 → Export reports → 1** and open the generated Markdown file.
7. Exit and relaunch to prove persistence; optionally switch to CSV in **9**.

---

## Storage formats

`data/records.json`

```json
{
  "schema_version": 1,
  "generated_by": "Password Strength Checker",
  "saved_at": "2026-11-20T12:00:00",
  "note": "Analysis metadata only - passwords are never stored.",
  "records": [
    {
      "id": 1,
      "label": "Campus WiFi guest",
      "checked_at": "2026-11-20T10:30:00",
      "analysis": {
        "score": 8, "rating": "Very Weak", "length": 8,
        "has_upper": false, "has_lower": true, "has_digit": false,
        "has_special": false, "char_classes": 1,
        "entropy_bits": 22.4, "crack_time": "about 1 second",
        "issues": ["..."], "suggestions": ["..."]
      }
    }
  ]
}
```

`data/records.csv` uses a flat header with the analysis fields expanded into
columns; list fields are JSON-encoded strings.

`data/records.sqlite3` is a transactional database (`sqlite3` from the standard
library) with an indexed `checked_at` column, row-level validation and
automatic recovery from a corrupt file. It is the recommended backend for
larger datasets.

All three backends are interchangeable via **9 → Switch storage format** or
`--format json|csv|sqlite`; switching migrates existing records when the target
store is empty. Corrupt or missing files are backed up
(`.corrupt.<timestamp>`) and rebuilt as clean templates; individual bad rows
are skipped with a warning instead of crashing the program.

---

## Project structure

```
PasswordStrengthChecker/
├── main.py                 # CLI entry point
├── README.md
├── requirements.txt        # stdlib only; matplotlib optional
├── psc/
│   ├── __init__.py
│   ├── config.py           # constants, paths, thresholds
│   ├── models.py           # AnalysisResult, PasswordRecord + schema checks
│   ├── analyzer.py         # scoring, heuristics, rule explanations
│   ├── validators.py       # defensive input wrappers
│   ├── storage.py          # JSONStore, CSVStore, atomic writes, recovery
│   ├── sqlite_store.py     # transactional SQLite backend
│   ├── summary.py          # metrics, alerts, distributions
│   ├── exporter.py         # Markdown / text / CSV / PNG exports
│   ├── ui.py               # colours, banners, tables, report rendering
│   ├── seed_data.py        # 46 realistic sample cases
│   └── app.py              # menu dispatch controller
├── webui/
│   ├── __init__.py
│   ├── server.py           # stdlib HTTP server + JSON API
│   └── static/             # index.html, styles.css, app.js, favicon.svg
├── site/                   # self-contained static build deployed to Vercel
│   ├── index.html
│   ├── styles.css
│   ├── analyzer.js         # browser port of the Python engine
│   ├── app.js              # SPA controller + localStorage + exports
│   ├── analyzer.test.js    # Node tests for the browser engine
│   └── favicon.svg
├── docs/
│   ├── API.md              # full HTTP API reference
│   └── SRS.md              # requirements and design decisions
├── scripts/
│   └── build.py            # static build validation + engine parity check
├── .github/workflows/ci.yml  # tests + build on every push / PR
├── package.json            # zero-dependency npm scripts
├── run_tests.py            # runs Python + JavaScript suites
├── vercel.json             # outputDirectory = site, security headers
├── data/                   # created on first run
├── exports/                # generated reports
└── tests/
    ├── test_analyzer.py
    ├── test_models.py
    ├── test_storage.py
    ├── test_sqlite_store.py
    ├── test_summary.py
    ├── test_exporter.py
    ├── test_heuristics.py
    ├── test_patterns.py
    ├── test_logging_config.py
    ├── test_web_api.py
    └── test_validators.py
```

---

## Engineering enhancements

Four cross-cutting concerns were strengthened to meet the evaluation rubric:

### Structured logging

Operational events use the standard `logging` module with a JSON formatter
(`psc/logging_config.py`). Log records carry `timestamp`, `level`, `event_name`,
`storage_format`, `record_id`, `record_count` and endpoint details. User-facing
terminal rendering remains in `psc/ui.py`; diagnostics never include passwords.

```powershell
python main.py --log-level DEBUG --log-file data/psc.log
python main.py --web --log-file data/webui.log
```

### Advanced entropy heuristics

`psc/heuristics.py` adds pluggable matchers inspired by zxcvbn:

- **Spatial matching** across QWERTY, Dvorak and numeric-keypad adjacency graphs.
- **Date/year matching** for common numeric formats.
- **Repeat matching** for multi-character units such as `ababab`.

The weakest matcher estimate bounds the entropy, and detected `patterns` are
returned in the analysis result for explainability. The browser port implements
the identical heuristics; `scripts/build.py` verifies parity.

### API authentication

The local server uses double-submit CSRF protection: visiting `/` sets a
`psc_sid` (HttpOnly) cookie and a readable `psc_csrf` cookie, and every write
must echo the value in the `X-CSRF-Token` header. An optional shared-secret
bearer token can be enabled with `--token` or `PSC_API_TOKEN`; the browser is
then prompted once for the token printed in the server console. Origin checks
still apply.

```powershell
python main.py --web --token my-secret-token
```

### Novel contribution — Structural Drift Index (SDI)

`psc/novelty.py` implements an adaptive, **privacy-preserving risk algorithm**
that is not a copy of an existing password-strength method:

1. It derives a compact, **non-reversible structural fingerprint** (banded
   length, classes, entropy, repetition, pool and a pattern bitmask) from an
   analysis — no characters, hashes or reversible data are retained.
2. A **hybrid distance metric** combines weighted banded L1 distance with
   Jaccard distance over the pattern bitmask to produce a bounded `[0, 1]`
   structural distance.
3. It reports the **nearest prior structure**, a **personal risk score** and an
   explainable recommendation — warning when a new password is structurally
   close to a previously weak check.
4. **Portfolio diversity** measures variety across the entire history.

The same algorithm runs in the browser (`site/analyzer.js`), and the build step
verifies exact parity of fingerprints and drift reports. It is surfaced in both
web UIs as an "Adaptive Risk" card and in analytics as a diversity metric.

### Design patterns

`psc/patterns.py` formalises the architecture:

| Pattern | Use |
| --- | --- |
| Strategy | Storage backends behind a `StorageStrategy` interface and `StorageRegistry` |
| Command | Menu actions are `MenuCommand` objects in a `CommandRegistry` |
| Observer | Domain events published to an `EventBus`, with a structured `LoggingObserver` |

---

## Testing

Run everything (Python + JavaScript):

```powershell
python run_tests.py
```

Individual suites:

```powershell
python -m unittest discover -s tests -v   # Python core, models, storage, API
npm test                                  # browser engine (Node built-in test runner)
python scripts/build.py                   # static build + Python/JS engine parity
```

Coverage includes analysis edge cases, model coercion, all three storage
backends, corrupt-file recovery, bad-row skipping, summaries, exports, every
input wrapper and all HTTP endpoints (including format switching and CORS
rejection). GitHub Actions runs compile checks, the full suite and the build
validation on every push and PR.

See [docs/API.md](docs/API.md) for the HTTP API and
[docs/SRS.md](docs/SRS.md) for the requirements specification.

---

## Optional chart dependency

The PNG export uses `matplotlib` only when requested:

```powershell
pip install matplotlib
```

Without it, option **5 → 4** prints an actionable message and the built-in
ASCII distribution chart in the analytics screen remains fully functional.
