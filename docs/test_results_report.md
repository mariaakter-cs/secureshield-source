# SecureShield — Test Results Report

**Project:** SecureShield Web Application Firewall  
**Student:** Maria Akter  
**Test Date:** 26 October – 08 November 2026  
**Test Environment:** DVWA (Docker, localhost:8080) via SecureShield proxy (localhost:5000)

---

## 1. Executive Summary

SecureShield was tested against 45 structured test cases (15 SQLi attacks, 15 XSS attacks, 15 legitimate requests) plus a brute-force login simulation. All four success criteria targets were met:

| Criterion | Target | Achieved | Status |
| --- | --- | --- | --- |
| SQLi detection rate | ≥ 90% | **93.3%** | ✓ Pass |
| XSS detection rate | ≥ 90% | **100%** | ✓ Pass |
| False positive rate | ≤ 10% | **0%** | ✓ Pass |
| Brute-force detection | Functional | **Pass** | ✓ Pass |
| ML classifier accuracy | ≥ 90% | **97.2%** | ✓ Pass |
| Proxy latency | Usable | **5.4ms overhead** | ✓ Pass |

---

## 2. Detection Rate Results

### 2.1 SQL Injection Detection

**Result: 14/15 payloads blocked = 93.3%**

| # | Payload | Blocked | Category |
| --- | --- | --- | --- |
| 1 | `' OR '1'='1` | ✓ | tautology |
| 2 | `' OR 1=1 --` | ✓ | boolean + comment |
| 3 | `' UNION SELECT null,null,null --` | ✓ | union |
| 4 | `1; DROP TABLE users --` | ✓ | stacked query |
| 5 | `' AND SLEEP(5) --` | ✓ | time-based |
| 6 | `' AND EXTRACTVALUE(...)` | ✓ | error-based |
| 7 | `1' OR '1'='1' /*` | ✓ | tautology + comment |
| 8 | `admin' --` | ✗ | short probe |
| 9 | `' UNION ALL SELECT username,password FROM users --` | ✓ | union |
| 10 | `'; WAITFOR DELAY '0:0:5' --` | ✓ | time-based |
| 11 | `1 OR 1=1` | ✓ | boolean |
| 12 | `' AND 1=CONVERT(int,(SELECT @@version)) --` | ✓ | error-based |
| 13 | `' UNION SELECT null,table_name FROM information_schema.tables --` | ✓ | recon |
| 14 | `1' AND BENCHMARK(5000000,SHA1('test')) --` | ✓ | time-based |
| 15 | `' OR 'x'='x` | ✓ | tautology |

**Analysis of missed payload:** `admin' --` is a 10-character string containing only a quote and a line comment. It doesn't include SQL keywords (SELECT, UNION, OR, AND) or function calls that the regex rules look for. Writing a rule to catch "any quote followed by --" would risk false positives on legitimate inputs containing apostrophes and dashes. The trade-off was acceptable since this payload alone cannot extract data — it's just a probe.

### 2.2 XSS Detection

**Result: 15/15 payloads blocked = 100%**

All 15 XSS payloads were correctly blocked. Detection was achieved through:
- Script tag rules: 6 payloads
- Event handler rules: 5 payloads
- javascript: protocol rules: 3 payloads
- Dangerous tag rules: 1 payload

### 2.3 Combined Confusion Matrix

|  | Predicted Malicious | Predicted Benign |
| --- | --- | --- |
| **Actually Malicious** (30 attacks) | 29 (TP) | 1 (FN) |
| **Actually Benign** (15 requests) | 0 (FP) | 15 (TN) |

- **Accuracy:** 97.8% (44/45)
- **Precision:** 100% (29/29 — every block was justified)
- **Recall:** 96.7% (29/30 — missed one attack)
- **F1 Score:** 98.3%

---

## 3. False Positive Analysis

**Result: 0/15 legitimate inputs incorrectly blocked = 0%**

Tested inputs that specifically contained words appearing in attack payloads:

| Input | Contains | Triggered? |
| --- | --- | --- |
| My name is O'Brien | apostrophe | No |
| My flight is OR1234 | word "OR" | No |
| Table 5 is reserved | word "table" | No |
| I want to order 5 items | word "order" | No |
| search for blue shoes | normal search | No |
| page=2&sort=date | URL parameters | No |
| username=admin&password=password123 | login-like | No |

The zero false positive rate confirms the regex rules are specific enough to avoid triggering on normal English text that happens to contain SQL/JS keywords.

---

## 4. Brute-Force Detection Results

**Result: PASS**

| Attempt | HTTP Response | Status |
| --- | --- | --- |
| 1 | 302 (forwarded) | Counting |
| 2 | 302 (forwarded) | Counting |
| 3 | 302 (forwarded) | Counting |
| 4 | 302 (forwarded) | Counting |
| 5 | 302 (forwarded) | Threshold reached |
| 6 | 403 (blocked) | **IP blocked** |

The 5th attempt triggered the threshold. The 6th request (and all subsequent requests from that IP) received 403. After the cooldown period (30 minutes), the IP would be automatically unblocked.

---

## 5. ML Classifier Results

**Result: 97.2% accuracy on held-out test set**

| Metric | Value |
| --- | --- |
| Accuracy | 97.2% |
| Precision | 95.2% |
| Recall | 100% |
| F1 Score | 97.6% |
| Cross-validation (5-fold) | 99.3% ± 1.4% |

The ML classifier operates as a backup layer. In the attack simulation, all attacks were caught by the regex rules before reaching the ML layer. The ML model's value is in catching novel/obfuscated attacks that bypass rules.

---

## 6. Latency Results

**Result: 5.4ms average proxy overhead**

| Metric | Value |
| --- | --- |
| Direct to DVWA (avg) | 8.4ms |
| Through SecureShield proxy (avg) | 13.5ms |
| **Proxy overhead** | **5.4ms** |
| Min response time | 12.8ms |
| Max response time | 14.9ms |

The 5.4ms overhead includes: URL decoding, 23 SQLi regex checks, 31 XSS regex checks, brute-force lookup, and SQLite write. This is negligible — the application remains fully usable.

---

## 7. Success Criteria Comparison

| ID | Criterion from Charter | Target | Result | Met? |
| --- | --- | --- | --- | --- |
| SC1 | Proxy forwards legitimate traffic | 100% | 100% (15/15) | ✓ |
| SC2 | SQLi detection rate | ≥ 90% | 93.3% | ✓ |
| SC3 | XSS detection rate | ≥ 90% | 100% | ✓ |
| SC4 | Brute-force blocking | Correct | Pass | ✓ |
| SC5 | ML classifier accuracy | ≥ 90% | 97.2% | ✓ |
| SC6 | False positive rate | Documented & minimised | 0% | ✓ |
| SC7 | Logging completeness | 100% | 100% | ✓ |
| SC8 | Dashboard and PDF reporting | Functional & accurate | Pass | ✓ |
| SC9 | Ethical compliance | Documented | Pass | ✓ |

**All 9 success criteria met.**

---

## 8. Limitations and Known Issues

1. **Short SQLi probes** (like `admin' --`) are not detected because they don't contain identifiable SQL patterns. This is by design — catching them would require rules loose enough to generate false positives.

2. **ML confidence threshold** means some borderline attacks may pass through if below 0.7 confidence. This is the intended trade-off — fewer false positives at the cost of potentially missing edge cases.

3. **Brute-force counts all login POSTs**, not just failed ones. A user who legitimately submits the login form 5 times in 10 minutes would be blocked. The threshold could be increased for production use.

4. **Single-threaded proxy** — under heavy concurrent load, response times would increase. This isn't relevant for the test environment but would matter in production.

---

## 9. Testing Methodology

- All testing conducted against DVWA running locally via Docker
- Test payloads sourced from OWASP testing guide and publicly available cheat sheets
- Legitimate inputs manually crafted to include words that appear in attack payloads
- Each test run on a fresh proxy instance with empty database
- Results recorded automatically to JSON for reproducibility
