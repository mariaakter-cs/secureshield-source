"""
Tests for the database layer (models.py).

These test that events get logged correctly and that the query
functions return what I expect. Uses a temporary database so
the real one doesn't get cluttered with test data.
"""

import pytest
import os
import sys
import time
import requests

# point the database at a temp file for testing
import config
config.DATABASE_PATH = os.path.join(os.path.dirname(__file__), "test_secureshield.db")

from app.models import init_db, log_event, get_events, get_stats, get_db


PROXY_URL = "http://localhost:5000"
TARGET_URL = "http://localhost:8080"


def is_service_running(url):
    try:
        requests.get(url, timeout=3)
        return True
    except requests.exceptions.ConnectionError:
        return False


@pytest.fixture(autouse=True)
def fresh_db():
    """Start each test with a clean database."""
    init_db()
    yield
    # clean up after
    if os.path.exists(config.DATABASE_PATH):
        os.remove(config.DATABASE_PATH)


class TestLogEvent:
    """Test that log_event writes correctly to the database."""

    def test_basic_event_logged(self):
        log_event("192.168.1.1", "GET", "/login.php")
        events = get_events()
        assert len(events) == 1
        assert events[0]["source_ip"] == "192.168.1.1"
        assert events[0]["request_method"] == "GET"
        assert events[0]["request_url"] == "/login.php"
        assert events[0]["outcome"] == "allow"
        assert events[0]["detection_method"] == "none"

    def test_blocked_event_logged(self):
        log_event("10.0.0.5", "POST", "/search",
                  body="q=' OR 1=1 --",
                  detection_method="rule_sqli",
                  outcome="block",
                  details="matched UNION pattern")
        events = get_events()
        assert events[0]["outcome"] == "block"
        assert events[0]["detection_method"] == "rule_sqli"
        assert events[0]["details"] == "matched UNION pattern"
        assert events[0]["request_body"] == "q=' OR 1=1 --"

    def test_body_truncation(self):
        long_body = "A" * 5000
        log_event("127.0.0.1", "POST", "/upload", body=long_body)
        events = get_events()
        # should be truncated to 2000 + the truncation marker
        assert len(events[0]["request_body"]) < 2100
        assert "[truncated]" in events[0]["request_body"]

    def test_multiple_events_ordered(self):
        log_event("1.1.1.1", "GET", "/page1")
        log_event("2.2.2.2", "GET", "/page2")
        log_event("3.3.3.3", "GET", "/page3")
        events = get_events()
        # most recent first
        assert events[0]["source_ip"] == "3.3.3.3"
        assert events[2]["source_ip"] == "1.1.1.1"

    def test_timestamp_populated(self):
        log_event("127.0.0.1", "GET", "/test")
        events = get_events()
        assert events[0]["timestamp"] is not None
        assert "2026" in events[0]["timestamp"]  # basic sanity check


class TestGetEvents:
    """Test filtering and pagination."""

    def test_filter_by_outcome(self):
        log_event("1.1.1.1", "GET", "/ok", outcome="allow")
        log_event("2.2.2.2", "GET", "/bad", outcome="block",
                  detection_method="rule_sqli")
        log_event("3.3.3.3", "GET", "/ok2", outcome="allow")

        blocked = get_events(outcome="block")
        assert len(blocked) == 1
        assert blocked[0]["source_ip"] == "2.2.2.2"

    def test_filter_by_detection_method(self):
        log_event("1.1.1.1", "GET", "/a", outcome="block",
                  detection_method="rule_sqli")
        log_event("2.2.2.2", "GET", "/b", outcome="block",
                  detection_method="rule_xss")
        log_event("3.3.3.3", "GET", "/c", outcome="block",
                  detection_method="rule_sqli")

        sqli_events = get_events(detection_method="rule_sqli")
        assert len(sqli_events) == 2

    def test_limit_works(self):
        for i in range(20):
            log_event(f"10.0.0.{i}", "GET", f"/page{i}")
        events = get_events(limit=5)
        assert len(events) == 5


class TestGetStats:
    """Test the stats summary function."""

    def test_empty_db_stats(self):
        stats = get_stats()
        assert stats["total"] == 0
        assert stats["allowed"] == 0
        assert stats["blocked"] == 0

    def test_stats_with_mixed_events(self):
        log_event("1.1.1.1", "GET", "/ok", outcome="allow")
        log_event("2.2.2.2", "GET", "/bad", outcome="block",
                  detection_method="rule_sqli")
        log_event("3.3.3.3", "GET", "/bad2", outcome="block",
                  detection_method="rule_xss")
        log_event("4.4.4.4", "GET", "/ok2", outcome="allow")

        stats = get_stats()
        assert stats["total"] == 4
        assert stats["allowed"] == 2
        assert stats["blocked"] == 2
        assert stats["breakdown"]["rule_sqli"] == 1
        assert stats["breakdown"]["rule_xss"] == 1


class TestLatency:
    """Check that logging doesn't add too much overhead."""

    @pytest.mark.skipif(
        not is_service_running(TARGET_URL),
        reason="DVWA not running"
    )
    @pytest.mark.skipif(
        not is_service_running(PROXY_URL),
        reason="SecureShield not running"
    )
    def test_proxy_latency_acceptable(self):
        """Proxy overhead should be under 500ms per request.
        This is generous — in practice it's usually under 50ms."""
        times = []
        for _ in range(10):
            start = time.time()
            requests.get(f"{PROXY_URL}/login.php", allow_redirects=False)
            elapsed = time.time() - start
            times.append(elapsed)

        avg = sum(times) / len(times)
        # average should be under 500ms (half a second)
        assert avg < 0.5, f"Average latency too high: {avg:.3f}s"
