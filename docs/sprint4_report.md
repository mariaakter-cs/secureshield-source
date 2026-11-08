# Sprint 4 Report — SQLite Logging

**Sprint dates:** 17 August – 23 August 2026  
**Objective:** Implement SQLite database schema and log all requests with full metadata. Verify no significant latency added.

---

## What I built

I created a persistent logging layer (`app/models.py`) that writes every request to an SQLite database. Whether a request is allowed through or blocked by the detection rules (in later sprints), it gets a row in the `security_events` table. This gives me a complete audit trail that the dashboard will read from later.

---

## Database schema

One table called `security_events`:

| Column | Type | Purpose |
| --- | --- | --- |
| id | INTEGER (auto) | Primary key |
| timestamp | TEXT | When the request came in (YYYY-MM-DD HH:MM:SS) |
| source_ip | TEXT | Client IP address |
| request_method | TEXT | GET, POST, etc. |
| request_url | TEXT | Full path including query string |
| request_body | TEXT (nullable) | POST body content, capped at 2000 chars |
| detection_method | TEXT | What caught it: 'none', 'rule_sqli', 'rule_xss', 'bruteforce', 'ml' |
| outcome | TEXT | 'allow' or 'block' |
| details | TEXT (nullable) | Extra info — which rule matched, ML confidence, etc. |

I chose to store the full URL including query parameters because that's where SQLi payloads typically appear in GET requests (e.g., `?id=1' OR 1=1 --`). Without logging the query string, I'd lose critical evidence of what the attacker actually sent.

---

## How it connects to the proxy

In `app/proxy.py`, the `log_request()` function now does two things:
1. Prints to the console (so I can see what's happening in real time during development)
2. Calls `log_event()` to write the same data to SQLite

This dual approach means I get immediate feedback during testing but also have a permanent record for the dashboard and reports later.

The database gets initialised automatically when the app starts (`init_db()` is called in the app factory). If the file already exists, the `CREATE TABLE IF NOT EXISTS` means it won't wipe existing data.

---

## Design decisions

**Why SQLite?** No setup required. I don't need to install MySQL or PostgreSQL — the database is just a file. Since SecureShield is a single-process proxy, I don't have concurrency issues that would require a full database server.

**Why WAL mode?** I enabled Write-Ahead Logging (`PRAGMA journal_mode=WAL`) which lets the dashboard read from the database at the same time the proxy is writing to it without locking conflicts. This matters once the dashboard is running alongside the proxy.

**Why truncate the body at 2000 chars?** Some POST bodies (like file uploads) could be massive. I don't want the database growing to gigabytes during testing. 2000 characters is enough to capture any attack payload while keeping the DB manageable.

**Why log allowed requests too?** Because I need to measure false positive rate later. If I only logged blocks, I'd have no way to verify that legitimate traffic is passing through correctly.

---

## Query functions for the dashboard

I built these now even though the dashboard isn't until Sprint 11, because it was easy to do while I had the schema in mind:

- `get_events(limit, offset, outcome, detection_method)` — paginated event retrieval with optional filters
- `get_stats()` — returns total, allowed, blocked counts and a breakdown by detection type

---

## Latency verification

The charter says to verify no significant latency is added. I wrote an automated test that:
1. Sends 10 requests through the proxy
2. Times each one
3. Asserts the average stays under 500ms

In practice the average is well under 50ms — the SQLite write adds negligible overhead because it's just an INSERT into a local file.

---

## Test results

11 tests covering the database layer:

| Test | What it checks |
| --- | --- |
| test_basic_event_logged | A simple GET gets stored with correct fields |
| test_blocked_event_logged | Blocked events store detection_method and details |
| test_body_truncation | Bodies over 2000 chars get truncated |
| test_multiple_events_ordered | Most recent events come first |
| test_timestamp_populated | Timestamp is set automatically |
| test_filter_by_outcome | Can query just blocked or allowed events |
| test_filter_by_detection_method | Can query by detection type |
| test_limit_works | Pagination works correctly |
| test_empty_db_stats | Stats return zeros on empty database |
| test_stats_with_mixed_events | Stats calculation is correct |
| test_proxy_latency_acceptable | Average response time < 500ms |

All passing. Run with:
```bash
pytest tests/test_models.py -v
```

---

## Files changed/created

| File | Change |
| --- | --- |
| `app/models.py` | Rewritten — database schema, `log_event()`, `get_events()`, `get_stats()` |
| `app/__init__.py` | Modified — calls `init_db()` on startup |
| `app/proxy.py` | Modified — `log_request()` now writes to SQLite; logs full URL with query string; error cases also logged |
| `.gitignore` | Modified — added `*.db-shm` and `*.db-wal` |
| `tests/test_models.py` | New — 11 tests for the database layer |

---

## Sprint 4 milestone status

**M4: SQLite logging operational; all requests logged with complete metadata.** ✓ Complete.
