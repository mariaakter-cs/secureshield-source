"""
bruteforce.py - Brute-force login detection.

Tracks failed login attempts per IP address. If an IP exceeds the
threshold within the configured time window, all subsequent requests
from that IP get blocked until the cooldown expires.

How I detect a "failed login":
- It's a POST request
- The URL looks like a login page (/login, /login.php, etc.)
- The response from the target was a redirect back to the login page
  OR the response contained an error message

For DVWA specifically, a failed login is a POST to /login.php that
returns a 200 (stays on login page) rather than a 302 (redirect to
index after success). But I've kept the detection generic enough to
work with other apps too.

The actual tracking uses an in-memory dictionary. I thought about
putting this in SQLite but the lookups need to be fast (every request)
and the data is transient — if the proxy restarts, resetting the
counters is fine.
"""

import time
from config import BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW, BRUTE_FORCE_COOLDOWN

# In-memory storage for tracking attempts
# Structure: {ip_address: [timestamp1, timestamp2, ...]}
_failed_attempts = {}

# IPs currently blocked and when they got blocked
# Structure: {ip_address: blocked_at_timestamp}
_blocked_ips = {}


def is_login_request(path, method):
    """Check if this looks like a login attempt.
    Only POST requests to login-looking URLs count."""
    if method.upper() != "POST":
        return False

    login_paths = ["/login", "/login.php", "/j_security_check",
                   "/wp-login.php", "/admin/login", "/auth/login"]

    path_lower = path.lower().rstrip("/")
    return any(path_lower.endswith(lp.rstrip("/")) for lp in login_paths)


def is_blocked(ip):
    """Check if an IP is currently blocked.
    Also handles expiring blocks that have exceeded the cooldown."""
    if ip not in _blocked_ips:
        return False

    blocked_at = _blocked_ips[ip]
    elapsed = time.time() - blocked_at

    if elapsed >= BRUTE_FORCE_COOLDOWN:
        # cooldown expired, unblock them
        del _blocked_ips[ip]
        # also clear their attempt history so they start fresh
        if ip in _failed_attempts:
            del _failed_attempts[ip]
        return False

    return True


def record_failed_attempt(ip):
    """
    Record a failed login attempt for an IP.
    Returns True if the IP just crossed the threshold (newly blocked).
    Returns False otherwise.
    """
    now = time.time()

    # initialise if first time seeing this IP
    if ip not in _failed_attempts:
        _failed_attempts[ip] = []

    # add the current attempt
    _failed_attempts[ip].append(now)

    # remove attempts older than the window
    cutoff = now - BRUTE_FORCE_WINDOW
    _failed_attempts[ip] = [t for t in _failed_attempts[ip] if t >= cutoff]

    # check if threshold exceeded
    if len(_failed_attempts[ip]) >= BRUTE_FORCE_THRESHOLD:
        _blocked_ips[ip] = now
        return True

    return False


def get_remaining_attempts(ip):
    """How many more attempts this IP has before getting blocked.
    Useful for logging/debugging."""
    if ip not in _failed_attempts:
        return BRUTE_FORCE_THRESHOLD

    now = time.time()
    cutoff = now - BRUTE_FORCE_WINDOW
    recent = [t for t in _failed_attempts[ip] if t >= cutoff]
    return max(0, BRUTE_FORCE_THRESHOLD - len(recent))


def get_block_remaining(ip):
    """How many seconds until an IP's block expires. Returns 0 if not blocked."""
    if ip not in _blocked_ips:
        return 0
    elapsed = time.time() - _blocked_ips[ip]
    remaining = BRUTE_FORCE_COOLDOWN - elapsed
    return max(0, remaining)


def reset():
    """Clear all tracking data. Used in tests."""
    global _failed_attempts, _blocked_ips
    _failed_attempts = {}
    _blocked_ips = {}
