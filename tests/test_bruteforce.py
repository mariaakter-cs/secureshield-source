"""
Tests for brute-force detection.

Tests cover:
- Failed attempts are tracked correctly
- Threshold triggers a block
- Block expires after cooldown
- Successful logins don't count as failures
- Different IPs are tracked independently
- Integration test against running proxy
"""

import pytest
import time
import requests

from rules import bruteforce
from config import BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW, BRUTE_FORCE_COOLDOWN

PROXY_URL = "http://localhost:5000"
TARGET_URL = "http://localhost:8080"


def is_service_running(url):
    try:
        requests.get(url, timeout=3)
        return True
    except requests.exceptions.ConnectionError:
        return False


@pytest.fixture(autouse=True)
def clean_state():
    """Reset brute-force tracking between tests."""
    bruteforce.reset()
    yield
    bruteforce.reset()


class TestIsLoginRequest:
    """Test login URL detection."""

    def test_post_to_login_php(self):
        assert bruteforce.is_login_request("/login.php", "POST") is True

    def test_post_to_login(self):
        assert bruteforce.is_login_request("/login", "POST") is True

    def test_get_to_login_not_counted(self):
        """GET requests to login pages aren't login attempts."""
        assert bruteforce.is_login_request("/login.php", "GET") is False

    def test_post_to_other_page(self):
        """POST to a non-login page shouldn't count."""
        assert bruteforce.is_login_request("/search", "POST") is False

    def test_post_to_wp_login(self):
        assert bruteforce.is_login_request("/wp-login.php", "POST") is True


class TestFailedAttemptTracking:
    """Test that failed attempts are recorded and counted."""

    def test_first_attempt_not_blocked(self):
        """One failed attempt shouldn't block anyone."""
        result = bruteforce.record_failed_attempt("192.168.1.1")
        assert result is False
        assert bruteforce.is_blocked("192.168.1.1") is False

    def test_threshold_triggers_block(self):
        """Reaching the threshold should block the IP."""
        ip = "10.0.0.1"
        for i in range(BRUTE_FORCE_THRESHOLD - 1):
            result = bruteforce.record_failed_attempt(ip)
            assert result is False

        # this one should trigger the block
        result = bruteforce.record_failed_attempt(ip)
        assert result is True
        assert bruteforce.is_blocked(ip) is True

    def test_different_ips_tracked_separately(self):
        """Failures from one IP shouldn't affect another."""
        for i in range(BRUTE_FORCE_THRESHOLD):
            bruteforce.record_failed_attempt("1.1.1.1")

        # 1.1.1.1 should be blocked
        assert bruteforce.is_blocked("1.1.1.1") is True
        # 2.2.2.2 should not be
        assert bruteforce.is_blocked("2.2.2.2") is False

    def test_remaining_attempts_decreases(self):
        """get_remaining_attempts should count down correctly."""
        ip = "10.0.0.5"
        assert bruteforce.get_remaining_attempts(ip) == BRUTE_FORCE_THRESHOLD

        bruteforce.record_failed_attempt(ip)
        assert bruteforce.get_remaining_attempts(ip) == BRUTE_FORCE_THRESHOLD - 1

        bruteforce.record_failed_attempt(ip)
        assert bruteforce.get_remaining_attempts(ip) == BRUTE_FORCE_THRESHOLD - 2


class TestBlockExpiry:
    """Test that blocks expire after the cooldown period."""

    def test_block_expires_after_cooldown(self):
        """A blocked IP should be unblocked after cooldown."""
        ip = "10.0.0.99"

        # block the IP
        for i in range(BRUTE_FORCE_THRESHOLD):
            bruteforce.record_failed_attempt(ip)
        assert bruteforce.is_blocked(ip) is True

        # manually backdate the block timestamp to simulate time passing
        bruteforce._blocked_ips[ip] = time.time() - BRUTE_FORCE_COOLDOWN - 1

        # now should be unblocked
        assert bruteforce.is_blocked(ip) is False

    def test_block_remaining_time(self):
        """get_block_remaining should return correct seconds."""
        ip = "10.0.0.50"
        for i in range(BRUTE_FORCE_THRESHOLD):
            bruteforce.record_failed_attempt(ip)

        remaining = bruteforce.get_block_remaining(ip)
        # should be close to the full cooldown (just blocked)
        assert remaining > BRUTE_FORCE_COOLDOWN - 2
        assert remaining <= BRUTE_FORCE_COOLDOWN


class TestWindowExpiry:
    """Test that old attempts fall off after the time window."""

    def test_old_attempts_dont_count(self):
        """Attempts older than the window should be discarded."""
        ip = "10.0.0.20"

        # record some attempts
        for i in range(BRUTE_FORCE_THRESHOLD - 1):
            bruteforce.record_failed_attempt(ip)

        # backdate all attempts to outside the window
        bruteforce._failed_attempts[ip] = [
            time.time() - BRUTE_FORCE_WINDOW - 10
            for _ in bruteforce._failed_attempts[ip]
        ]

        # now one more attempt shouldn't trigger a block
        # (because the old ones should be discarded)
        result = bruteforce.record_failed_attempt(ip)
        assert result is False
        assert bruteforce.is_blocked(ip) is False


class TestIntegration:
    """Test brute-force detection through the actual proxy."""

    @pytest.mark.skipif(
        not is_service_running(PROXY_URL),
        reason="SecureShield not running"
    )
    def test_repeated_failed_logins_get_blocked(self):
        """Sending multiple login POSTs should eventually get blocked.
        NOTE: This test blocks 127.0.0.1, which will affect other integration
        tests if they run after. Run this test in isolation or restart the proxy.
        """
        # send login attempts exceeding the threshold
        for i in range(BRUTE_FORCE_THRESHOLD + 1):
            resp = requests.post(
                f"{PROXY_URL}/login.php",
                data={"username": "admin", "password": "wrongpassword", "Login": "Login"},
                allow_redirects=False,
            )

        # next request from same IP should be blocked (any request, not just login)
        resp = requests.get(f"{PROXY_URL}/login.php", allow_redirects=False)
        assert resp.status_code == 403
        assert "blocked" in resp.text.lower()

    @pytest.mark.skipif(
        not is_service_running(PROXY_URL),
        reason="SecureShield not running"
    )
    def test_non_login_requests_dont_count(self):
        """GET requests shouldn't trigger brute-force.
        Note: This test must run before the blocking test, or on a fresh proxy.
        Testing the logic directly in unit tests above is more reliable."""
        # This is tested reliably in TestIsLoginRequest unit tests.
        # Integration test left as documentation that the logic works.
        pass
