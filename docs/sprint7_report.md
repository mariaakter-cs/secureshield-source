# Sprint 7 Report — Brute-Force Login Detection

**Sprint dates:** 07 September – 13 September 2026  
**Objective:** Implement IP-based brute-force detection with configurable threshold and cooldown. Test against DVWA.

---

## What I built

A brute-force detection module (`rules/bruteforce.py`) that tracks how many times each IP address submits a login form within a rolling time window. If they exceed the threshold, every request from that IP gets blocked until the cooldown expires.

---

## How it works

1. A request comes in.
2. The proxy checks: is this IP already blocked? If yes → 403 immediately.
3. If not blocked, the request passes through to DVWA normally.
4. After forwarding, the proxy checks: was this a POST to a login page?
5. If yes → record the attempt. If the count for this IP now exceeds the threshold within the time window → block the IP.

The next request from that IP (any request, not just login) will be blocked.

---

## Configuration

Three settings in `config.py`:

| Setting | Default | Meaning |
| --- | --- | --- |
| `BRUTE_FORCE_THRESHOLD` | 5 | How many login POSTs before blocking |
| `BRUTE_FORCE_WINDOW` | 600 (10 min) | Only count attempts within this window |
| `BRUTE_FORCE_COOLDOWN` | 1800 (30 min) | How long the block lasts |

So by default: 5 login attempts in 10 minutes = blocked for 30 minutes.

---

## Design decisions

**Why count all login POSTs, not just failed ones?**

DVWA returns HTTP 302 for both successful and failed logins (it redirects back to login.php either way and handles auth via session). I can't reliably distinguish success from failure by status code alone. Rather than parsing the response body for error messages (which would be DVWA-specific), I count every POST to a login URL. A real user rarely submits the login form more than 2-3 times in a row. 5 is a generous threshold.

**Why in-memory rather than SQLite?**

Speed. The brute-force check runs on every request (not just login POSTs — I need to check if the IP is blocked). SQLite would add a database query to every single request. An in-memory dictionary lookup is essentially instant. The downside is that blocking state resets if the proxy restarts, but that's acceptable for this project's scope.

**Why block ALL requests from the IP, not just login attempts?**

Because an attacker who's brute-forcing the login is a confirmed threat. Letting them continue browsing the rest of the application while only blocking login attempts doesn't make security sense. A real WAF would block the IP entirely.

---

## Login URL detection

The module recognises these as login URLs:
- `/login`
- `/login.php`
- `/j_security_check`
- `/wp-login.php`
- `/admin/login`
- `/auth/login`

Only POST requests to these URLs count. GET requests (loading the login page) don't count because that's normal browsing.

---

## Test results

14 tests covering the brute-force module:

| Category | Tests | What they verify |
| --- | --- | --- |
| Login URL detection | 5 | POST to login paths detected; GET and other paths not counted |
| Attempt tracking | 4 | Attempts recorded correctly; threshold triggers block; IPs independent; counter decrements |
| Block expiry | 2 | Block expires after cooldown; remaining time calculated correctly |
| Window expiry | 1 | Old attempts outside the window get discarded |
| Integration | 2 | Actual HTTP test confirms blocking works end-to-end |

Note: the brute-force integration test needs to run separately from other integration tests because it blocks 127.0.0.1 (the test client's IP), which would cause subsequent tests to fail. This is documented in the test file.

```bash
# run unit tests (always safe)
pytest tests/test_bruteforce.py -k "not Integration" -v

# run brute-force integration test (blocks the IP, run separately)
pytest tests/test_bruteforce.py -k "test_repeated_failed_logins" -v
```

---

## Problem I ran into

Originally I tried to detect failed logins by checking if DVWA returned HTTP 200 (stays on login page) vs 302 (redirect after success). But DVWA actually returns 302 for both — it redirects to `login.php` on failure and `index.php` on success. Both are 302s.

I considered parsing the `Location` header or the response body for error messages, but that would make my code DVWA-specific. The simpler approach (count all login POSTs) is more generic and the threshold is generous enough that a legitimate user won't trigger it.

---

## Files changed/created

| File | Change |
| --- | --- |
| `rules/bruteforce.py` | Rewritten — full implementation with tracking, blocking, expiry |
| `app/proxy.py` | Modified — added brute-force check before forwarding + attempt recording after |
| `tests/test_bruteforce.py` | New — 14 tests (unit + integration) |

---

## Sprint 7 milestone status

**M7: Brute-force detection operational; correctly blocks IPs exceeding threshold.** ✓ Complete.
