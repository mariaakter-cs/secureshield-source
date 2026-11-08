# Sprint 15 Report — Results Analysis

**Sprint dates:** 02 November – 08 November 2026  
**Objective:** Calculate detection rates, false positive rates, latency; compare results against success criteria.

---

## What I did

Pulled together all the quantitative data from Sprint 13 (latency measurement) and Sprint 14 (attack simulation) into a single test results report (`docs/test_results_report.md`). This document is the evidence that my system meets the targets I set in the charter.

---

## Key numbers

| Metric | Result |
| --- | --- |
| SQLi detection | 93.3% (14/15) |
| XSS detection | 100% (15/15) |
| False positives | 0% (0/15) |
| Combined accuracy | 97.8% (44/45) |
| Combined precision | 100% |
| Combined recall | 96.7% |
| Combined F1 | 98.3% |
| ML accuracy | 97.2% |
| Proxy overhead | 5.4ms |
| Brute-force | Pass |
| Success criteria met | 9/9 |

---

## What the test results report contains

1. Executive summary with pass/fail against each target
2. Full SQLi results — every payload listed with outcome and detection category
3. Full XSS results — all 15 blocked with detection method noted
4. Confusion matrix (TP/FP/TN/FN) with precision, recall, F1
5. False positive analysis — showing which tricky inputs were correctly allowed
6. Brute-force sequence showing each attempt and when blocking triggers
7. ML classifier metrics including cross-validation
8. Latency data (direct vs proxy comparison)
9. Success criteria checklist mapped directly to the charter
10. Limitations section — honest about what the system doesn't catch and why

---

## Why this matters for the mark

The charter listed 9 measurable success criteria. The test results report demonstrates — with numbers — that all 9 are met. This isn't just "it works" — it's "here's exactly how well it works, what it misses, and why I made the trade-offs I did."

The limitations section is particularly important. A marker expects you to know your system's weaknesses, not pretend it's perfect.

---

## Files created

| File | Purpose |
| --- | --- |
| `docs/test_results_report.md` | Formal test results document (the main deliverable for this sprint) |
| `docs/sprint15_report.md` | This sprint report |

---

## Sprint 15 milestone status

**M15: Test results analysed; metrics calculated; test report drafted.** ✓ Complete.
