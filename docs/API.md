# API Reference

The local web UI (`webui/server.py`) exposes a JSON API on `http://127.0.0.1:8765`.
The deployed Vercel build is fully client-side (`site/`) and does not expose
these endpoints; it uses the same analysis rules via `site/analyzer.js`.

## Conventions

- Request bodies: `Content-Type: application/json`, maximum 64 KB.
- Successful responses: `{"ok": true, ...}` with HTTP 200.
- Errors: `{"ok": false, "error": "message"}` with a 4xx/5xx status.
- All responses include `Cache-Control: no-store`, `X-Content-Type-Options:
  nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` and a strict
  `Content-Security-Policy`.
- Passwords appear only in the body of `POST /api/analyze`. They are analysed
  in memory, never logged, and never written to storage.

## Endpoints

### `GET /`

Returns `index.html`. The files `/styles.css`, `/app.js` and `/favicon.svg` are
also served. All other paths return 404 — static files come from a fixed
whitelist, so path traversal is not possible.

### `GET /api/state`

Returns active storage state.

```json
{
  "ok": true,
  "format": "json",
  "total": 40,
  "json_path": ".../data/records.json",
  "csv_path": ".../data/records.csv",
  "sqlite_path": ".../data/records.sqlite3",
  "formats": ["json", "csv", "sqlite"],
  "warnings": [],
  "max_password_length": 256
}
```

### `POST /api/analyze`

Analyses a password. When `persist` is `false` (live preview), no record is
created and nothing is written to disk. When `persist` is `true`, `label` is
required and the analysis metadata is saved.

```json
{ "password": "Tr0ub4dor&3", "label": "Banking demo", "persist": true }
```

```json
{
  "ok": true,
  "analysis": {
    "score": 85,
    "rating": "Very Strong",
    "length": 11,
    "has_upper": true, "has_lower": true, "has_digit": true, "has_special": true,
    "char_classes": 4,
    "entropy_bits": 55.12,
    "crack_time": "about 2 days",
    "issues": [],
    "suggestions": ["Good work! Use a unique password for each account."]
  },
  "persisted": true,
  "flag": false,
  "record": { "id": 41, "label": "Banking demo", "checked_at": "...", "analysis": { ... } },
  "total": 41
}
```

`flag` is `true` when the score is below the weak threshold (40).

**Errors:** 400 for empty/overlong password or missing label on save.

### `GET /api/records`

Query parameters (all optional):

| Parameter | Description |
| --- | --- |
| `q` | Space-separated keywords matched against label, rating, timestamp, issues and suggestions |
| `rating` | Exact rating, e.g. `Very Weak` |
| `min_score` | Inclusive minimum score, 0-100 |

```json
{ "ok": true, "records": [ { "id": 41, "label": "...", "checked_at": "...", "analysis": { ... } } ], "total": 1 }
```

### `GET /api/summary`

Returns aggregated metrics, distributions, alerts and record extremes.

```json
{
  "ok": true,
  "summary": {
    "total": 40,
    "average_score": 52.7,
    "median_score": 53.5,
    "min_score": 0,
    "max_score": 100,
    "average_length": 9.9,
    "weak_count": 17,
    "strong_count": 15,
    "weak_rate": 0.425,
    "rating_distribution": [{ "name": "Very Strong", "count": 15 }],
    "class_coverage": { "Uppercase": 22, "Lowercase": 37 },
    "common_issues": [{ "issue": "...", "count": 15 }],
    "per_day": [{ "day": "2026-11-20", "count": 3 }],
    "alerts": [{ "level": "critical", "message": "..." }],
    "strongest": { "...": "..." },
    "weakest": { "...": "..." }
  }
}
```

### `GET /api/rules`

Returns the strength-rule reference: `{"ok": true, "rules": [{"title", "rule", "why"}]}`.

### `GET /api/export?kind=<md|txt|csv|png>`

Streams a generated report as a file download with `X-Filename`. PNG export
requires matplotlib; without it the endpoint returns 400 with an explanation.
MD/TXT/CSV always work with the standard library only.

### `POST /api/seed`

```json
{ "count": 40, "replace": true }
```

Generates deterministic sample records (1-200). Returns `added`, `total` and
`replace`.

### `POST /api/import`

```json
{ "path": "data/legacy_import.csv" }
```

Validates a legacy CSV row by row without modifying it. Returns `imported`,
`total` and `messages` (including one `Skipped CSV row N: ...` message per bad
row). 404 if the file does not exist.

### `POST /api/format`

```json
{ "format": "sqlite" }
```

Switches the active backend (`json`, `csv`, `sqlite`). If the target store is
empty, existing records are migrated into it. Returns `format`, `total` and
`messages`.

### `POST /api/reload`

Reloads records from the active backend. Returns `total` and `messages`.

### `DELETE /api/records/<id>`

Deletes one record and persists the change. Returns `deleted` and `total`.
404 if the id does not exist.

## Error codes

| Status | Meaning |
| --- | --- |
| 400 | Malformed JSON, wrong content type, invalid parameter or export without matplotlib |
| 403 | Cross-origin write rejected (unless remote mode is enabled with `--host`) |
| 404 | Unknown endpoint, missing import file or missing record |
| 500 | Storage failure or unexpected server error |
