# Sprint 5 Report — SQL Injection Detection

**Sprint dates:** 24 August – 30 August 2026  
**Objective:** Develop regex-based SQLi detection rules and achieve ≥ 90% detection on a defined test set.

---

## What I built

I wrote a rule engine (`rules/sqli.py`) that checks every incoming request for SQL injection patterns. It inspects both the URL query string and the POST body before the request gets forwarded to DVWA. If a match is found, the request is blocked with a 403 response and logged to the database.

The engine contains 23 compiled regex patterns grouped into categories:

| Category | What it catches | Example |
| --- | --- | --- |
| UNION-based | Attempts to extract data from other tables | `' UNION SELECT null,null --` |
| Error-based | Functions that force DB errors to leak info | `EXTRACTVALUE(1,CONCAT(...))` |
| Boolean-blind | True/false conditions to infer data | `' OR '1'='1` |
| Time-based | Delay functions to confirm injection blind | `SLEEP(5)`, `WAITFOR DELAY`, `pg_sleep()` |
| Stacked queries | Multiple statements via semicolons | `; DROP TABLE users --` |
| Comment evasion | SQL comments used to break queries | `/* ... */`, `-- ` |
| Tautologies | Always-true conditions for auth bypass | `' OR 1=1`, `OR TRUE` |
| Obfuscation | Encoding functions to hide payloads | `CHAR()`, `CONCAT()`, `HEX()` |
| Recon | Attempts to enumerate the database | `information_schema` |

All patterns use case-insensitive matching since attackers commonly mix case (e.g., `UnIoN SeLeCt`) to evade simple filters.

---

## How it integrates with the proxy

In `app/proxy.py`, before any request is forwarded, I added:

1. URL-decode the query string (using `urllib.parse.unquote_plus`) — this turns `%27` back into `'` and `+` back into spaces so the patterns can actually match.
2. URL-decode the POST body the same way.
3. Pass both to `sqli_scan(query_text, body_text)`.
4. If a match comes back, block the request and log it with `detection_method="rule_sqli"` and the matched pattern in `details`.

---

## Test results

I tested against 30 known SQLi payloads covering all the categories above, and 26 legitimate inputs that contain words like "select", "or", "drop", "union" in normal English context.

**Detection rate: 96.7% (29/30 payloads caught)**

The one missed payload was `admin'/*` — a very short probe that just appends a quote and opens a block comment. It's borderline between a legitimate typo and an attack. I decided not to write a rule that triggers on any single quote followed by `/*` because that would likely cause false positives. In practice, this payload alone wouldn't extract data — it's just a probe to see if the app errors.

**False positive rate: 0.0% (0/26 legitimate inputs wrongly blocked)**

None of the normal inputs triggered the rules, including tricky ones like:
- "My name is O'Brien" (apostrophe in a name)
- "The OR gate in electronics is useful" (the word OR in normal text)
- "I need to select a new plan" (the word SELECT in everyday use)
- "It's a union of two ideas" (the word UNION used normally)

---

## Testing approach

I wrote three levels of tests:

1. **Unit tests** — call `check_sqli()` directly with payload strings, verify it returns a match dict or None.
2. **Detection rate test** — loads all 30 payloads from a file, runs each through the detector, asserts ≥ 90%.
3. **Integration tests** — sends actual HTTP requests to the proxy with SQLi payloads and confirms it returns 403.

Tests can be run with:
```bash
pytest tests/test_rules.py -v
```

---

## What I'd improve if I had more time

- Add more payloads to the test set, especially encoded/obfuscated ones.
- The `admin'/*` miss could be caught by a rule for `'` followed by `/*`, but I'd need to test that doesn't trigger on legitimate inputs first.
- Could add logging of which specific rule fired, not just the category — useful for tuning later.
- The rules are checked sequentially; if performance became an issue with thousands of requests per second I'd need to optimise, but for this project's scale it's not a concern.

---

## Files changed/created

| File | Change |
| --- | --- |
| `rules/sqli.py` | New — 23 regex rules + `check_sqli()` and `scan_request()` functions |
| `app/proxy.py` | Modified — added SQLi scanning before forwarding, URL-decoding |
| `tests/test_rules.py` | New — 17 tests (detection rate, false positives, integration) |
| `tests/payloads/sqli_payloads.txt` | New — 30 test SQLi payloads |
| `tests/payloads/legitimate_inputs.txt` | New — 26 legitimate test inputs |

---

## Sprint 5 milestone status

**M5: SQLi detection rules operational; ≥ 90% detection rate achieved.** ✓ Complete.
