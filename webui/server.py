"""Zero-dependency local HTTP server for the Password Strength Checker.

The browser talks to this loopback server over JSON.  Passwords are analysed by
the very same :func:`psc.analyzer.analyze_password` engine as the console app,
in memory only.  With ``persist: false`` (used for live preview) no record is
created and nothing is written to disk; only an explicit "Save check" stores
the analysis metadata.

Security notes:
    * Binds to 127.0.0.1 by default; remote binding is opt-in via ``--host``.
    * Request bodies are size-limited and must be JSON.
    * Static files come from a fixed whitelist (no path traversal).
    * A strict Content-Security-Policy is sent on every response.
    * Cross-origin POSTs are rejected unless remote mode is enabled.
    * Passwords are never logged.
"""

from __future__ import annotations

import argparse
import hmac
import json
import os
import secrets
import tempfile
import threading
import webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from psc.analyzer import analyze_password, explain_rules
from psc.config import (
    CSV_PATH,
    EXPORT_DIR,
    JSON_PATH,
    MAX_LABEL_LENGTH,
    MAX_PASSWORD_LENGTH,
    SQLITE_PATH,
    SUPPORTED_FORMATS,
    WEAK_SCORE_THRESHOLD,
)
from psc.exporter import export_chart_png, export_csv, export_markdown, export_text_audit
from psc.logging_config import configure_logging
from psc.models import PasswordRecord
from psc.novelty import compare as compare_drift
from psc.novelty import portfolio_diversity
from psc.seed_data import generate_records
from psc.sqlite_store import SQLiteStore
from psc.storage import CSVStore, JSONStore, StorageError
from psc.summary import build_alerts, build_summary, rating_distribution

STATIC_DIR = Path(__file__).resolve().parent / "static"
STATIC_FILES = {"index.html", "styles.css", "app.js", "favicon.svg"}
MIME_TYPES = {
    "index.html": "text/html; charset=utf-8",
    "styles.css": "text/css; charset=utf-8",
    "app.js": "application/javascript; charset=utf-8",
    "favicon.svg": "image/svg+xml",
}
MAX_BODY_BYTES = 64 * 1024
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "::ffff:127.0.0.1"}


# --------------------------------------------------------------------------- #
# Application state shared by all request handlers
# --------------------------------------------------------------------------- #

class WebState:
    """Holds records and storage backends, guarded by a re-entrant lock."""

    def __init__(
        self,
        storage_format: str = "json",
        json_path: Path = JSON_PATH,
        csv_path: Path = CSV_PATH,
        sqlite_path: Path = SQLITE_PATH,
    ) -> None:
        self.json_store = JSONStore(json_path)
        self.csv_store = CSVStore(csv_path)
        self.sqlite_store = SQLiteStore(sqlite_path)
        self.storage_format = (
            storage_format if storage_format in SUPPORTED_FORMATS else "json"
        )
        self.records: list[PasswordRecord] = []
        self.next_id = 1
        self.startup_warnings: list[str] = []
        self.lock = threading.RLock()
        self.load()

    def store_for(self, storage_format: str) -> JSONStore | CSVStore | SQLiteStore:
        """Resolve a format name to its concrete backend instance."""
        return {
            "json": self.json_store,
            "csv": self.csv_store,
            "sqlite": self.sqlite_store,
        }[storage_format]

    @property
    def store(self) -> JSONStore | CSVStore | SQLiteStore:
        return self.store_for(self.storage_format)

    def load(self) -> list[str]:
        """(Re)load records from the active backend."""
        with self.lock:
            records, warnings = self.store.load()
            self.records = records
            self.startup_warnings = list(warnings)
            self.next_id = max((record.id for record in records), default=0) + 1
            return warnings

    def save(self) -> None:
        with self.lock:
            self.store.save(self.records)

    def find(self, record_id: int) -> PasswordRecord | None:
        with self.lock:
            return next((record for record in self.records if record.id == record_id), None)


# --------------------------------------------------------------------------- #
# Serialisation helpers
# --------------------------------------------------------------------------- #

def _summary_payload(records: list[PasswordRecord]) -> dict:
    report = build_summary(records)
    return {
        "total": report.total,
        "average_score": report.average_score,
        "median_score": report.median_score,
        "min_score": report.min_score,
        "max_score": report.max_score,
        "average_length": report.average_length,
        "weak_count": report.weak_count,
        "strong_count": report.strong_count,
        "weak_rate": round(report.weak_rate, 3),
        "strong_rate": round(report.strong_rate, 3),
        "rating_distribution": [
            {"name": name, "count": count} for name, count in rating_distribution(report)
        ],
        "class_coverage": dict(report.class_counts),
        "common_issues": [
            {"issue": issue, "count": count}
            for issue, count in report.common_issues.most_common(8)
        ],
        "per_day": [
            {"day": day, "count": count}
            for day, count in sorted(report.per_day.items(), reverse=True)[:10]
        ],
        "alerts": [{"level": level, "message": message} for level, message in build_alerts(report)],
        "structural_diversity": portfolio_diversity(
            [record.analysis.to_dict() for record in records]
        ),
        "strongest": report.strongest.to_dict() if report.strongest else None,
        "weakest": report.weakest.to_dict() if report.weakest else None,
    }


def _clean_label(raw: object) -> str:
    """Sanitise a user label without raising."""
    text = "" if raw is None else str(raw)
    text = "".join(char for char in text if char.isprintable())
    return text.strip()[:MAX_LABEL_LENGTH]


# --------------------------------------------------------------------------- #
# HTTP handler
# --------------------------------------------------------------------------- #

class Handler(BaseHTTPRequestHandler):
    """Routes API calls and serves the whitelisted static frontend files."""

    server_version = "PSC-Web/1.0"

    # Keep the console tidy and, critically, never log request bodies.
    def log_message(self, fmt: str, *args: object) -> None:
        return

    @property
    def state(self) -> WebState:
        return self.server.state  # type: ignore[attr-defined]

    # ---------------------------- response helpers ------------------------- #

    def _security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'",
        )
        self.send_header("Cache-Control", "no-store")

    def _send(
        self,
        status: int,
        body: bytes,
        content_type: str,
        extra: dict[str, str] | list[tuple[str, str]] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self._security_headers()
        headers = extra.items() if isinstance(extra, dict) else (extra or [])
        for key, value in headers:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8")

    def _error(self, status: int, message: str) -> None:
        self._json(status, {"ok": False, "error": message})

    def _check_origin(self) -> bool:
        """Block cross-origin writes unless remote mode was explicitly enabled."""
        if getattr(self.server, "allow_remote", False):
            return True
        origin = self.headers.get("Origin")
        if not origin:
            return True
        parsed = urlparse(origin)
        if parsed.scheme != "http":
            return False
        if (parsed.hostname or "").lower() not in LOCAL_HOSTS:
            return False
        port = self.server.server_address[1]  # type: ignore[attr-defined]
        return not parsed.port or parsed.port == port

    def _read_json(self) -> dict:
        content_type = self.headers.get("Content-Type", "")
        if "application/json" not in content_type:
            raise ValueError("Expected an application/json request body")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Invalid Content-Length") from exc
        if length <= 0 or length > MAX_BODY_BYTES:
            raise ValueError("Request body is empty or too large")
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("Request body must be a JSON object")
        return payload

    def _static(self, filename: str) -> None:
        if filename not in STATIC_FILES:
            self._error(404, "Not found")
            return
        path = STATIC_DIR / filename
        try:
            body = path.read_bytes()
        except OSError:
            self._error(404, f"Missing static asset: {filename}")
            return
        extra_headers: list[tuple[str, str]] = []
        if filename == "index.html":
            session = secrets.token_urlsafe(24)
            extra_headers.extend([
                ("Set-Cookie", f"psc_sid={session}; HttpOnly; SameSite=Strict; Path=/"),
                ("Set-Cookie", f"psc_csrf={session}; SameSite=Strict; Path=/"),
            ])
        self._send(200, body, MIME_TYPES[filename], extra_headers)

    # ------------------------------ authentication ------------------------- #

    def _cookie(self, name: str) -> str:
        """Read a cookie value from the request headers."""
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            key, _, value = part.strip().partition("=")
            if key == name:
                return value
        return ""

    def _check_bearer(self) -> bool:
        """Validate the optional shared-secret bearer token."""
        expected = getattr(self.server, "auth_token", None)
        if not expected:
            return True
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return False
        return hmac.compare_digest(header[7:], expected)

    def _check_csrf(self) -> bool:
        """Validate the double-submit CSRF cookie/header pair."""
        session = self._cookie("psc_sid")
        csrf_cookie = self._cookie("psc_csrf")
        csrf_header = self.headers.get("X-CSRF-Token", "")
        return bool(
            session
            and csrf_cookie
            and csrf_header
            and hmac.compare_digest(session, csrf_cookie)
            and hmac.compare_digest(session, csrf_header)
        )

    def _check_write_security(self) -> bool:
        """Require origin checks, bearer token and CSRF double-submit."""
        return self._check_origin() and self._check_bearer() and self._check_csrf()

    # -------------------------------- GET ---------------------------------- #

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            if path == "/":
                return self._static("index.html")
            if path.lstrip("/") in STATIC_FILES:
                return self._static(path.lstrip("/"))

            if path == "/api/config.js":
                required = "true" if getattr(self.server, "auth_token", None) else "false"
                return self._send(
                    200,
                    f"window.PSC_AUTH_REQUIRED = {required};\n".encode("utf-8"),
                    "application/javascript; charset=utf-8",
                )

            if path.startswith("/api/") and not self._check_bearer():
                return self._error(401, "Bearer token required")

            if path == "/api/state":
                with self.state.lock:
                    return self._json(200, {
                        "ok": True,
                        "format": self.state.storage_format,
                        "auth_required": bool(getattr(self.server, "auth_token", None)),
                        "total": len(self.state.records),
                        "json_path": str(self.state.json_store.path),
                        "csv_path": str(self.state.csv_store.path),
                        "sqlite_path": str(self.state.sqlite_store.path),
                        "formats": list(SUPPORTED_FORMATS),
                        "warnings": self.state.startup_warnings,
                        "max_password_length": MAX_PASSWORD_LENGTH,
                    })

            if path == "/api/records":
                params = parse_qs(parsed.query)
                tokens = params.get("q", [""])[0].strip().lower().split()
                rating = params.get("rating", [""])[0]
                try:
                    minimum = int(params["min_score"][0]) if params.get("min_score") else None
                except ValueError:
                    return self._error(400, "min_score must be a number")
                with self.state.lock:
                    matches = [
                        record for record in self.state.records
                        if (not tokens or record.matches(tokens))
                        and (not rating or record.rating == rating)
                        and (minimum is None or record.score >= minimum)
                    ]
                    matches.sort(key=lambda record: record.id, reverse=True)
                    return self._json(200, {
                        "ok": True,
                        "records": [record.to_dict() for record in matches],
                        "total": len(matches),
                    })

            if path == "/api/summary":
                with self.state.lock:
                    return self._json(200, {"ok": True, "summary": _summary_payload(list(self.state.records))})

            if path == "/api/rules":
                return self._json(200, {"ok": True, "rules": explain_rules()})

            if path == "/api/export":
                return self._export(parse_qs(parsed.query))

            self._error(404, "Unknown endpoint")
        except StorageError as exc:
            self._error(500, str(exc))
        except Exception as exc:  # noqa: BLE001 - keep the server alive
            self._error(500, f"Server error: {exc}")

    def _export(self, params: dict[str, list[str]]) -> None:
        kind = params.get("kind", ["md"])[0]
        specs = {
            "md": ("md", "text/markdown; charset=utf-8", export_markdown),
            "txt": ("txt", "text/plain; charset=utf-8", export_text_audit),
            "csv": ("csv", "text/csv; charset=utf-8", export_csv),
            "png": ("png", "image/png", export_chart_png),
        }
        if kind not in specs:
            return self._error(400, "Unknown export format")
        extension, content_type, exporter = specs[kind]
        EXPORT_DIR.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.NamedTemporaryFile(
            dir=EXPORT_DIR, suffix=f".{extension}", delete=False
        )
        temp_path = Path(temporary.name)
        temporary.close()
        try:
            with self.state.lock:
                records = list(self.state.records)
            if kind == "md":
                exporter(records, build_summary(records), temp_path)
            elif kind == "txt":
                exporter(records, build_summary(records), temp_path)
            elif kind == "csv":
                exporter(records, temp_path)
            else:
                exporter(build_summary(records), temp_path)
            body = temp_path.read_bytes()
        except RuntimeError as exc:
            return self._error(400, str(exc))
        except Exception as exc:  # noqa: BLE001
            return self._error(500, f"Export failed: {exc}")
        finally:
            temp_path.unlink(missing_ok=True)

        filename = f"password-report-{datetime.now():%Y%m%d-%H%M%S}.{extension}"
        self._send(200, body, content_type, {"X-Filename": filename})

    # ------------------------------- POST ---------------------------------- #

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        path = urlparse(self.path).path
        if not self._check_origin():
            return self._error(403, "Cross-origin requests are not allowed")
        if not self._check_bearer():
            return self._error(401, "Bearer token required")
        if not self._check_csrf():
            return self._error(403, "CSRF token missing or invalid")
        try:
            data = self._read_json()
        except (ValueError, json.JSONDecodeError) as exc:
            return self._error(400, str(exc))

        try:
            if path == "/api/analyze":
                return self._analyze(data)
            if path == "/api/reload":
                return self._reload(data)
            if path == "/api/seed":
                return self._seed(data)
            if path == "/api/format":
                return self._switch_format(data)
            if path == "/api/import":
                return self._import(data)
            self._error(404, "Unknown endpoint")
        except StorageError as exc:
            self._error(500, str(exc))
        except Exception as exc:  # noqa: BLE001
            self._error(500, f"Server error: {exc}")

    def _analyze(self, data: dict) -> None:
        password = data.get("password")
        if not isinstance(password, str) or not password:
            return self._error(400, "Password cannot be empty")
        if len(password) > MAX_PASSWORD_LENGTH:
            return self._error(400, f"Password is longer than {MAX_PASSWORD_LENGTH} characters")

        persist = bool(data.get("persist", False))
        label = _clean_label(data.get("label"))
        if persist and not label:
            return self._error(400, "A label is required when saving a check")

        result = analyze_password(password)
        del password  # plaintext is never kept or written anywhere

        with self.state.lock:
            history = [
                (record.id, record.analysis.to_dict())
                for record in self.state.records
            ]
        drift = compare_drift(result.to_dict(), history)

        payload: dict = {
            "ok": True,
            "analysis": result.to_dict(),
            "drift": drift.to_dict(),
            "persisted": persist,
            "flag": result.score < WEAK_SCORE_THRESHOLD,
        }
        if persist:
            with self.state.lock:
                record = PasswordRecord(
                    id=self.state.next_id,
                    label=label,
                    checked_at=datetime.now().isoformat(timespec="seconds"),
                    analysis=result,
                )
                self.state.next_id += 1
                self.state.records.append(record)
                self.state.save()
            payload["record"] = record.to_dict()
            payload["total"] = len(self.state.records)
        self._json(200, payload)

    def _reload(self, data: dict) -> None:
        messages = self.state.load()
        with self.state.lock:
            total = len(self.state.records)
        self._json(200, {"ok": True, "total": total, "messages": messages})

    def _seed(self, data: dict) -> None:
        try:
            count = int(data.get("count", 40))
        except (TypeError, ValueError):
            return self._error(400, "count must be a number")
        if not 1 <= count <= 200:
            return self._error(400, "count must be between 1 and 200")
        replace = bool(data.get("replace", False))
        with self.state.lock:
            generated = generate_records(count, start_id=1 if replace else self.state.next_id)
            if replace:
                self.state.records = generated
            else:
                self.state.records.extend(generated)
            self.state.next_id = max(record.id for record in self.state.records) + 1
            self.state.save()
            total = len(self.state.records)
        self._json(200, {"ok": True, "added": count, "total": total, "replace": replace})

    def _switch_format(self, data: dict) -> None:
        requested = str(data.get("format", "")).lower()
        if requested not in SUPPORTED_FORMATS:
            return self._error(400, "format must be one of: " + ", ".join(SUPPORTED_FORMATS))
        if requested == self.state.storage_format:
            return self._json(200, {"ok": True, "format": requested, "messages": []})

        target_store = self.state.store_for(requested)
        target_records, messages = target_store.load()
        migrated = False
        with self.state.lock:
            if not target_records and self.state.records:
                target_records = [PasswordRecord(**vars(record)) for record in self.state.records]
                migrated = True
            self.state.storage_format = requested
            self.state.records = target_records
            self.state.next_id = max((record.id for record in target_records), default=0) + 1
            self.state.save()
            total = len(self.state.records)
        if migrated:
            messages.append(f"Migrated {total} record(s) to {requested.upper()}.")
        self._json(200, {"ok": True, "format": requested, "total": total, "messages": messages})

    def _import(self, data: dict) -> None:
        raw_path = str(data.get("path", "")).strip()
        if not raw_path:
            return self._error(400, "A file path is required")
        source = Path(raw_path).expanduser()
        if not source.is_file():
            return self._error(404, f"File not found: {source}")
        imported, warnings = CSVStore(source).load(repair=False)
        if not imported:
            return self._json(200, {
                "ok": True, "imported": 0, "total": len(self.state.records),
                "messages": warnings + ["No valid rows found; nothing was imported."],
            })
        with self.state.lock:
            for record in imported:
                record.id = self.state.next_id
                self.state.next_id += 1
                self.state.records.append(record)
            self.state.save()
            total = len(self.state.records)
        self._json(200, {
            "ok": True, "imported": len(imported), "total": total,
            "messages": warnings + [f"Imported {len(imported)} record(s)."],
        })

    # ------------------------------ DELETE --------------------------------- #

    def do_DELETE(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        path = urlparse(self.path).path
        if not self._check_origin():
            return self._error(403, "Cross-origin requests are not allowed")
        if not self._check_bearer():
            return self._error(401, "Bearer token required")
        if not self._check_csrf():
            return self._error(403, "CSRF token missing or invalid")
        if not path.startswith("/api/records/"):
            return self._error(404, "Unknown endpoint")
        try:
            record_id = int(path.rsplit("/", 1)[1])
        except ValueError:
            return self._error(400, "Invalid record id")
        with self.state.lock:
            before = len(self.state.records)
            self.state.records = [record for record in self.state.records if record.id != record_id]
            if len(self.state.records) == before:
                return self._error(404, f"Record #{record_id} not found")
            self.state.save()
            total = len(self.state.records)
        self._json(200, {"ok": True, "deleted": record_id, "total": total})


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def serve(
    host: str = "127.0.0.1",
    port: int = 8765,
    storage_format: str = "json",
    open_browser: bool = False,
    token: str | None = None,
    log_level: str = "INFO",
    log_file: Path | None = None,
) -> int:
    """Start the local web server and block until interrupted."""
    logger = configure_logging(log_level, log_file)
    state = WebState(storage_format)
    try:
        server = ThreadingHTTPServer((host, port), Handler)
    except OSError as exc:
        logger.error("server_start_failed", extra={
            "event_name": "server.start_failed", "path": f"{host}:{port}",
        })
        print(f"Could not start the web server on {host}:{port}: {exc}")
        return 1
    server.state = state  # type: ignore[attr-defined]
    server.allow_remote = host not in LOCAL_HOSTS  # type: ignore[attr-defined]
    server.auth_token = token or None  # type: ignore[attr-defined]
    server.daemon_threads = True
    logger.info("server_started", extra={
        "event_name": "server.started", "storage_format": storage_format,
        "record_count": len(state.records), "path": f"{host}:{port}",
    })

    url = f"http://{'localhost' if host in LOCAL_HOSTS else host}:{port}/"
    logger.info("web_interface_ready", extra={
        "event_name": "web.ready", "path": url,
        "storage_format": state.storage_format,
    })
    for warning in state.startup_warnings:
        logger.warning("startup_warning", extra={
            "event_name": "storage.warning", "message": warning,
        })
    # One user-facing line; all diagnostics go through structured logging.
    print(f"  Password Strength Checker web UI: {url}")
    if token:
        print(f"  API token: {token}")

    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("web_interface_stopped", extra={"event_name": "web.stopped"})
    finally:
        server.server_close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Password Strength Checker web interface")
    parser.add_argument("--host", default="127.0.0.1", help="bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="port (default: 8765)")
    parser.add_argument("--format", choices=SUPPORTED_FORMATS, default="json")
    parser.add_argument("--open", action="store_true", help="open a browser automatically")
    parser.add_argument("--token", default=None,
                        help="require this bearer token on API requests (or set PSC_API_TOKEN)")
    parser.add_argument("--log-level", default="INFO",
                        choices=("DEBUG", "INFO", "WARNING", "ERROR"))
    parser.add_argument("--log-file", default=None, help="write structured JSON logs to this file")
    args = parser.parse_args(argv)
    token = args.token or os.environ.get("PSC_API_TOKEN") or None
    log_file = Path(args.log_file).expanduser() if args.log_file else None
    return serve(args.host, args.port, args.format, args.open, token, args.log_level, log_file)


if __name__ == "__main__":
    raise SystemExit(main())
