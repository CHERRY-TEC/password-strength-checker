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
| **Check** | Live strength preview as you type, score ring, characteristics, issues and suggestions. Passwords are analysed with `persist: false` (no record written); only **Save check** stores the result. |
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
columns; list fields are JSON-encoded strings. Both backends are
interchangeable via **9 → Switch storage format**.

Corrupt or missing files are backed up (`.corrupt.<timestamp>`) and rebuilt as
clean templates; individual bad rows are skipped with a warning instead of
crashing the program.

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
│   └── favicon.svg
├── vercel.json             # outputDirectory = site, security headers
├── data/                   # created on first run
├── exports/                # generated reports
└── tests/
    ├── test_analyzer.py
    ├── test_storage.py
    └── test_validators.py
```

---

## Testing

```powershell
python -m unittest discover -s tests -v
```

The suite covers analysis edge cases, JSON/CSV round-trips, corrupt-file
recovery, bad-row skipping and every input wrapper.

---

## Optional chart dependency

The PNG export uses `matplotlib` only when requested:

```powershell
pip install matplotlib
```

Without it, option **5 → 4** prints an actionable message and the built-in
ASCII distribution chart in the analytics screen remains fully functional.
