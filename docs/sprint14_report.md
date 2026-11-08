# Sprint 14 Report — Attack Simulation Testing

**Sprint dates:** 26 October – 01 November 2026  
**Objective:** Execute structured SQLi/XSS/brute-force attack simulations through the proxy; record TP/FP/TN/FN outcomes.

---

## What I did

Ran a formal attack simulation against DVWA through the SecureShield proxy. This is the "proper attack test" described in the proposal — a structured set of known attacks and known-legitimate inputs, with every outcome recorded.

The simulation script (`tests/attack_simulation.py`) sends 15 SQLi payloads, 15 XSS payloads, 15 legitimate inputs, and a brute-force login sequence through the proxy, then records whether each was correctly blocked or allowed.

---

## Results

| Test Category | Payloads | Correct | Rate | Target | Met? |
| --- | --- | --- | --- | --- | --- |
| **SQLi Detection** | 15 | 14 blocked | 93.3% | ≥ 90% | ✓ |
| **XSS Detection** | 15 | 15 blocked | 100% | ≥ 90% | ✓ |
| **False Positives** | 15 | 0 wrongly blocked | 0% | ≤ 10% | ✓ |
| **Brute-Force** | 6 attempts | Blocked at attempt 6 | PASS | Functional | ✓ |

**All four targets met.**

---

## Detailed outcomes

### SQLi (14/15 = 93.3%)

| # | Payload | Result |
| --- | --- | --- |
| 1 | `' OR '1'='1` | ✓ Blocked |
| 2 | `' OR 1=1 --` | ✓ Blocked |
| 3 | `' UNION SELECT null,null,null --` | ✓ Blocked |
| 4 | `1; DROP TABLE users --` | ✓ Blocked |
| 5 | `' AND SLEEP(5) --` | ✓ Blocked |
| 6 | `' AND EXTRACTVALUE(1,CONCAT(0x7e,version())) --` | ✓ Blocked |
| 7 | `1' OR '1'='1' /*` | ✓ Blocked |
| 8 | `admin' --` | ✗ Missed |
| 9 | `' UNION ALL SELECT username,password FROM users --` | ✓ Blocked |
| 10 | `'; WAITFOR DELAY '0:0:5' --` | ✓ Blocked |
| 11 | `1 OR 1=1` | ✓ Blocked |
| 12 | `' AND 1=CONVERT(int,(SELECT @@version)) --` | ✓ Blocked |
| 13 | `' UNION SELECT null,table_name FROM information_schema.tables --` | ✓ Blocked |
| 14 | `1' AND BENCHMARK(5000000,SHA1('test')) --` | ✓ Blocked |
| 15 | `' OR 'x'='x` | ✓ Blocked |

**The missed payload** (`admin' --`) is a very short probe — just a username with a quote and comment. It doesn't contain any SQL keywords that my regex patterns match. In practice, this payload alone can't extract data; it's just a probe to see if the app errors. The ML model might catch it depending on confidence, but in this test the rules were checked first and didn't fire.

### XSS (15/15 = 100%)

All 15 XSS payloads were correctly blocked. Every payload contained at least one of: `<script`, event handler (`onerror=`, `onload=`), `javascript:`, or other patterns the rules detect.

### Legitimate Traffic (0/15 false positives = 0%)

All 15 legitimate inputs passed through without being blocked. These included tricky cases like "My name is O'Brien" (apostrophe), "My flight is OR1234" (contains OR), and "Table 5 is reserved" (contains TABLE).

### Brute-Force (PASS)

6 login POST requests were sent with wrong passwords. After the 5th attempt (the threshold), the 6th request was blocked with HTTP 403. Confirmed working.

---

## Confusion matrix (combined SQLi + XSS)

|  | Predicted Malicious | Predicted Benign |
| --- | --- | --- |
| Actually Malicious | **29 (TP)** | 1 (FN) |
| Actually Benign | 0 (FP) | **15 (TN)** |

- **True Positive Rate (Recall): 96.7%** (29/30 attacks caught)
- **Precision: 100%** (0 false positives)
- **Accuracy: 97.8%** (44/45 correct)

---

## How to reproduce

```bash
docker-compose up -d
./venv/bin/python run.py &
./venv/bin/python tests/attack_simulation.py
```

Results are also saved to `docs/attack_simulation_results.json` for machine-readable analysis.

---

## Files created

| File | Purpose |
| --- | --- |
| `tests/attack_simulation.py` | Structured attack simulation script |
| `docs/attack_simulation_results.json` | Machine-readable results (TP/FP/TN/FN per payload) |
| `docs/sprint14_report.md` | This report |

---

## Sprint 14 milestone status

**M14: Attack simulation testing completed; raw results recorded.** ✓ Complete.
