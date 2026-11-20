"""End-to-end tests for the local JSON HTTP API."""

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from webui.server import Handler, WebState


class WebAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        base = Path(cls.temp_dir.name)
        cls.state = WebState(
            "json",
            base / "records.json",
            base / "records.csv",
            base / "records.sqlite3",
        )
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.server.state = cls.state
        cls.server.allow_remote = False
        cls.server.daemon_threads = True
        cls.base_url = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        cls.temp_dir.cleanup()

    def setUp(self):
        """Give every test a clean, JSON-backed dataset."""
        with self.state.lock:
            self.state.storage_format = "json"
            self.state.records = []
            self.state.next_id = 1
            self.state.save()

    def request(self, path, method="GET", body=None, headers=None):
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request_headers = dict(headers or {})
        if data is not None:
            request_headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.base_url + path, data=data, headers=request_headers, method=method
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, dict(response.headers), response.read()

    def test_static_index_and_assets(self):
        status, headers, body = self.request("/")
        self.assertEqual(status, 200)
        self.assertIn(b"Password Strength Checker", body)
        self.assertIn("Content-Security-Policy", headers)
        status, _, body = self.request("/app.js")
        self.assertEqual(status, 200)
        self.assertIn(b"renderResult", body)
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.request("/main.py")  # not in static whitelist
        self.assertEqual(caught.exception.code, 404)

    def test_state_endpoint(self):
        status, _, body = self.request("/api/state")
        payload = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(payload["format"], "json")
        self.assertIn("sqlite", payload["formats"])
        self.assertTrue(payload["sqlite_path"].endswith("records.sqlite3"))

    def test_preview_does_not_persist(self):
        before = json.loads(self.request("/api/state")[2])["total"]
        status, _, body = self.request("/api/analyze", "POST", {
            "password": "password", "label": "", "persist": False,
        })
        payload = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(payload["analysis"]["rating"], "Weak")
        self.assertFalse(payload["persisted"])
        self.assertTrue(payload["flag"])
        after = json.loads(self.request("/api/state")[2])["total"]
        self.assertEqual(before, after)

    def test_save_persists_and_can_be_searched_and_deleted(self):
        status, _, body = self.request("/api/analyze", "POST", {
            "password": "X9#mL2@vT7!qR4$p", "label": "API test record", "persist": True,
        })
        payload = json.loads(body)
        self.assertEqual(status, 200)
        record_id = payload["record"]["id"]

        status, _, body = self.request("/api/records?q=API%20test&rating=Very%20Strong&min_score=90")
        results = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(results["total"], 1)
        self.assertEqual(results["records"][0]["id"], record_id)

        status, _, body = self.request(f"/api/records/{record_id}", "DELETE")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["total"], 0)

    def test_validation_errors(self):
        for body, expected in (
            ({"password": "", "persist": False}, 400),
            ({"password": "x", "label": "", "persist": True}, 400),
            ({"password": "x" * 300, "persist": False}, 400),
        ):
            with self.subTest(body=body):
                with self.assertRaises(urllib.error.HTTPError) as caught:
                    self.request("/api/analyze", "POST", body)
                self.assertEqual(caught.exception.code, expected)

    def test_summary_rules_and_export(self):
        self.request("/api/seed", "POST", {"count": 30, "replace": True})
        status, _, body = self.request("/api/summary")
        summary = json.loads(body)["summary"]
        self.assertEqual(status, 200)
        self.assertEqual(summary["total"], 30)
        self.assertEqual(len(summary["rating_distribution"]), 5)

        status, _, body = self.request("/api/rules")
        self.assertEqual(status, 200)
        self.assertGreaterEqual(len(json.loads(body)["rules"]), 5)

        status, headers, body = self.request("/api/export?kind=md")
        self.assertEqual(status, 200)
        self.assertIn("text/markdown", headers["Content-Type"])
        self.assertIn(b"# Password Strength Checker", body)
        self.assertTrue(headers["X-Filename"].endswith(".md"))

    def test_format_switch_to_sqlite_and_back(self):
        self.request("/api/seed", "POST", {"count": 12, "replace": True})
        status, _, body = self.request("/api/format", "POST", {"format": "sqlite"})
        payload = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(payload["format"], "sqlite")
        self.assertEqual(payload["total"], 12)

        summary = json.loads(self.request("/api/summary")[2])["summary"]
        self.assertEqual(summary["total"], 12)

        status, _, body = self.request("/api/format", "POST", {"format": "json"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["total"], 12)

    def test_reload_endpoint(self):
        status, _, body = self.request("/api/reload", "POST", {})
        self.assertEqual(status, 200)
        self.assertIn("total", json.loads(body))

    def test_cross_origin_post_is_rejected(self):
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.request("/api/analyze", "POST", {"password": "x", "persist": False},
                         headers={"Origin": "http://evil.example"})
        self.assertEqual(caught.exception.code, 403)


if __name__ == "__main__":
    unittest.main()
