"""
test_integration.py - End-to-end integration tests.

Sprint 13: Tests the full pipeline working together:
  Client -> Proxy -> Rules -> Brute-force -> ML -> Target -> Log -> Dashboard

These tests need both DVWA and SecureShield running.
They verify the complete system behaves correctly, not just individual parts.

Also includes edge case testing and latency measurement.
"""

import pytest
import requests
import time
import sqlite3
import os

PROXY_URL = "http://localhost:5000"
TARGET_URL = "http://localhost:8080"
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "secureshield.db")


def is_service_running(url):
    try:
        requests.get(url, timeout=3)
        return True
    except requests.exceptions.ConnectionError:
        return False


# skip everything if services aren't running
pytestmark = pytest.mark.skipif(
    not is_service_running(PROXY_URL) or not is_service_running(TARGET_URL),
    reason="Both SecureShield (port 5000) and DVWA (port 8080) must be running"
)


class TestFullPipeline:
    """Test the complete request flow from client to target and back."""

    def test_legitimate_get_flows_through(self):
        """Normal GET request should reach DVWA and return its response."""
        resp = requests.get(f"{PROXY_URL}/login.php")
        assert resp.status_code == 200
        assert "DVWA" in resp.text

    def test_legitimate_post_flows_through(self):
        """Normal POST should reach DVWA."""
        resp = requests.post(
            f"{PROXY_URL}/login.php",
            data={"username": "admin", "password": "password", "Login": "Login"},
            allow_redirects=False,
        )
        assert resp.status_code == 302

    def test_sqli_blocked_before_reaching_target(self):
        """SQLi in query string should be blocked — never reaches DVWA."""
        resp = requests.get(
            f"{PROXY_URL}/vulnerabilities/sqli/",
            params={"id": "' UNION SELECT null,null --", "Submit": "Submit"},
            allow_redirects=False,
        )
        assert resp.status_code == 403
        assert "SQL Injection" in resp.text

    def test_xss_blocked_before_reaching_target(self):
        """XSS in query string should be blocked."""
        resp = requests.get(
            f"{PROXY_URL}/vulnerabilities/xss_r/",
            params={"name": "<script>alert(1)</script>"},
            allow_redirects=False,
        )
        assert resp.status_code == 403
        assert "XSS" in resp.text

    def test_sqli_in_post_body_blocked(self):
        """SQLi in POST body should be blocked."""
        resp = requests.post(
            f"{PROXY_URL}/vulnerabilities/sqli/",
            data={"id": "1' OR 1=1 --", "Submit": "Submit"},
            allow_redirects=False,
        )
        assert resp.status_code == 403

    def test_xss_in_post_body_blocked(self):
        """XSS in POST body should be blocked."""
        resp = requests.post(
            f"{PROXY_URL}/vulnerabilities/xss_s/",
            data={"txtName": "test", "mtxMessage": "<img src=x onerror=alert(1)>"},
            allow_redirects=False,
        )
        assert resp.status_code == 403

    def test_dashboard_accessible_while_proxy_running(self):
        """Dashboard should work without interfering with proxy."""
        resp = requests.get(f"{PROXY_URL}/dashboard/")
        assert resp.status_code == 200
        assert "SecureShield" in resp.text

    def test_dashboard_logs_accessible(self):
        """Log viewer should work."""
        resp = requests.get(f"{PROXY_URL}/dashboard/logs")
        assert resp.status_code == 200

    def test_dashboard_blocklist_accessible(self):
        """Blocklist page should work."""
        resp = requests.get(f"{PROXY_URL}/dashboard/blocklist")
        assert resp.status_code == 200

    def test_pdf_report_generates(self):
        """PDF report should download successfully."""
        resp = requests.get(f"{PROXY_URL}/dashboard/report")
        assert resp.status_code == 200
        assert resp.headers.get("Content-Type", "").startswith("application/pdf") or \
               "octet-stream" in resp.headers.get("Content-Type", "")


class TestEdgeCases:
    """Test unusual inputs that might break the proxy."""

    def test_empty_query_string(self):
        """Request with no parameters should pass through."""
        resp = requests.get(f"{PROXY_URL}/login.php")
        assert resp.status_code == 200

    def test_very_long_url(self):
        """Very long URL shouldn't crash the proxy."""
        long_path = "A" * 2000
        resp = requests.get(f"{PROXY_URL}/{long_path}", allow_redirects=False)
        # should get some response, not a crash
        assert resp.status_code in [200, 302, 403, 404, 414]

    def test_special_characters_in_url(self):
        """URLs with special chars should be handled."""
        resp = requests.get(
            f"{PROXY_URL}/test",
            params={"q": "hello & goodbye <world>"},
            allow_redirects=False,
        )
        assert resp.status_code in [200, 302, 403, 404]

    def test_null_bytes_in_input(self):
        """Null bytes shouldn't crash the proxy."""
        resp = requests.get(
            f"{PROXY_URL}/test",
            params={"q": "hello\x00world"},
            allow_redirects=False,
        )
        assert resp.status_code in [200, 302, 400, 403, 404]

    def test_unicode_input(self):
        """Unicode characters should pass through without crashing."""
        resp = requests.get(
            f"{PROXY_URL}/test",
            params={"q": "こんにちは世界 🌍"},
            allow_redirects=False,
        )
        assert resp.status_code in [200, 302, 404]

    def test_large_post_body(self):
        """Large POST body should be handled (possibly blocked, not crash)."""
        large_body = "x" * 50000
        resp = requests.post(
            f"{PROXY_URL}/test",
            data={"field": large_body},
            allow_redirects=False,
        )
        assert resp.status_code in [200, 302, 403, 404, 413]

    def test_multiple_rapid_requests(self):
        """Sending requests quickly shouldn't crash the proxy."""
        for i in range(20):
            resp = requests.get(f"{PROXY_URL}/login.php", allow_redirects=False)
            assert resp.status_code in [200, 302]

    def test_concurrent_different_paths(self):
        """Different paths in sequence should all work."""
        paths = ["/login.php", "/", "/setup.php", "/about.php", "/instructions.php"]
        for path in paths:
            resp = requests.get(f"{PROXY_URL}{path}", allow_redirects=False)
            # any valid HTTP response is fine — just don't crash
            assert 100 <= resp.status_code < 600


class TestLatencyMeasurement:
    """Measure the proxy overhead to document in the report."""

    def test_average_latency_under_500ms(self):
        """Proxy overhead should stay under 500ms on average."""
        times = []
        for _ in range(20):
            start = time.time()
            requests.get(f"{PROXY_URL}/login.php", allow_redirects=False)
            elapsed = time.time() - start
            times.append(elapsed)

        avg = sum(times) / len(times)
        max_time = max(times)
        min_time = min(times)

        print(f"\n  Latency over 20 requests:")
        print(f"    Average: {avg*1000:.1f}ms")
        print(f"    Min: {min_time*1000:.1f}ms")
        print(f"    Max: {max_time*1000:.1f}ms")

        assert avg < 0.5, f"Average latency {avg*1000:.1f}ms exceeds 500ms"

    def test_proxy_overhead_vs_direct(self):
        """Compare proxy response time to direct target response time."""
        # time through proxy
        proxy_times = []
        for _ in range(10):
            start = time.time()
            requests.get(f"{PROXY_URL}/login.php", allow_redirects=False)
            proxy_times.append(time.time() - start)

        # time direct to target
        direct_times = []
        for _ in range(10):
            start = time.time()
            requests.get(f"{TARGET_URL}/login.php", allow_redirects=False)
            direct_times.append(time.time() - start)

        proxy_avg = sum(proxy_times) / len(proxy_times)
        direct_avg = sum(direct_times) / len(direct_times)
        overhead = proxy_avg - direct_avg

        print(f"\n  Proxy vs Direct comparison (10 requests each):")
        print(f"    Direct to DVWA: {direct_avg*1000:.1f}ms avg")
        print(f"    Through proxy: {proxy_avg*1000:.1f}ms avg")
        print(f"    Proxy overhead: {overhead*1000:.1f}ms")

        # overhead should be reasonable (under 200ms)
        assert overhead < 0.2, f"Proxy overhead {overhead*1000:.1f}ms seems too high"


class TestLoggingVerification:
    """Verify that events are actually being written to the database."""

    def test_allowed_request_logged(self):
        """An allowed request should appear in the database."""
        # make a request
        requests.get(f"{PROXY_URL}/login.php")

        # check database
        if os.path.exists(DB_PATH):
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM security_events WHERE request_url LIKE '%login%' AND outcome='allow' ORDER BY id DESC LIMIT 1"
            ).fetchone()
            conn.close()

            assert row is not None
            assert row["request_method"] == "GET"
            assert row["outcome"] == "allow"

    def test_blocked_request_logged_with_details(self):
        """A blocked request should be logged with detection info."""
        requests.get(f"{PROXY_URL}/test", params={"id": "' OR 1=1 --"})

        if os.path.exists(DB_PATH):
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM security_events WHERE outcome='block' ORDER BY id DESC LIMIT 1"
            ).fetchone()
            conn.close()

            assert row is not None
            assert row["outcome"] == "block"
            assert row["detection_method"] in ["rule_sqli", "rule_xss", "bruteforce", "ml"]
            assert row["details"] is not None
