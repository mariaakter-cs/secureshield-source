# Sprint 13 Report — Integration Testing

**Sprint dates:** 19 October – 25 October 2026  
**Objective:** End-to-end integration testing; edge cases; measure latency; fix defects.

---

## What I did

Wrote a comprehensive integration test suite (`tests/test_integration.py`) that tests the entire system as a connected whole — not individual modules in isolation, but the full pipeline: client → proxy → detection → target → logging → dashboard.

---

## Test categories

### 1. Full Pipeline Tests (10 tests)

Verified the complete flow works correctly:
- Legitimate GET and POST requests reach DVWA and come back
- SQLi in query string and POST body gets blocked (403)
- XSS in query string and POST body gets blocked (403)
- Dashboard pages (stats, logs, blocklist) all accessible while proxy runs
- PDF report generates successfully

### 2. Edge Case Tests (8 tests)

Tried to break the proxy with unusual inputs:

| Edge Case | Result |
| --- | --- |
| Empty query string | Passes through fine |
| Very long URL (2000 chars) | Handled gracefully (404 from target) |
| Special characters (& < >) | Handled without crashing |
| Null bytes in input | Handled without crashing |
| Unicode (Japanese, emoji) | Handled without crashing |
| Large POST body (50KB) | Handled without crashing |
| 20 rapid sequential requests | All succeed |
| Different paths in sequence | All get valid responses |

No crashes or hangs on any edge case. The proxy is stable.

### 3. Latency Measurement (2 tests)

This is what the charter asked me to verify:

| Metric | Result |
| --- | --- |
| Average proxy response time | **13.5ms** |
| Min response time | 12.8ms |
| Max response time | 14.9ms |
| Direct-to-DVWA time | 8.4ms |
| **Proxy overhead** | **5.4ms** |

The proxy adds about 5ms per request. That's negligible — the application remains completely usable. The overhead comes from: regex rule matching, brute-force lookup, and SQLite write. All extremely fast operations.

### 4. Logging Verification (2 tests)

Confirmed that:
- Allowed requests create a database row with `outcome='allow'`
- Blocked requests create a row with `outcome='block'`, correct `detection_method`, and details about what matched

---

## Defects found and fixed

No defects found during integration testing. The system works as expected end-to-end. Previous sprints caught issues early (gzip header bug in Sprint 3, DVWA login response issue in Sprint 7) so by this point the pipeline is solid.

---

## Test execution

```bash
# needs both services running
docker-compose up -d
./venv/bin/python run.py &
./venv/bin/python -m pytest tests/test_integration.py -v -s
```

All 22 integration tests pass in 2.16 seconds.

---

## Total test suite summary

| Test File | Tests | What it covers |
| --- | --- | --- |
| test_proxy.py | 11 | Proxy forwarding, headers, error handling |
| test_models.py | 11 | Database logging, filtering, stats, latency |
| test_rules.py | 33 | SQLi detection, XSS detection, false positives |
| test_bruteforce.py | 14 | IP tracking, threshold, cooldown, expiry |
| test_integration.py | 22 | Full pipeline, edge cases, latency, logging |
| **Total** | **91** | |

---

## Files created

| File | Purpose |
| --- | --- |
| `tests/test_integration.py` | 22 end-to-end integration tests |
| `docs/sprint13_report.md` | This report |

---

## Sprint 13 milestone status

**M13: Full pipeline integration verified; defects resolved.** ✓ Complete (zero defects found).
