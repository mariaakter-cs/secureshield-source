# Architecture Notes

Quick reference for how the system fits together. I'll add more detail as I build each part.

## How requests flow through the system

```text
Browser/Client
     |
     v
SecureShield (Flask, port 5000)
     |
     |--- Check 1: Does it match SQLi/XSS regex rules?
     |         yes -> block + log
     |
     |--- Check 2: Has this IP hit the brute-force threshold?
     |         yes -> block + log
     |
     |--- Check 3: Does the ML model flag it?
     |         yes (high confidence) -> block + log
     |
     v
Forward to DVWA (port 8080)
     |
     v
Log the decision to SQLite either way
     |
     v
Dashboard reads from the same database
```

## Where everything lives

| What | File | When I built it |
| --- | --- | --- |
| Reverse proxy | `app/proxy.py` | Sprint 3 |
| Database/logging | `app/models.py` | Sprint 4 |
| SQLi rules | `rules/sqli.py` | Sprint 5 |
| XSS rules | `rules/xss.py` | Sprint 6 |
| Brute-force tracker | `rules/bruteforce.py` | Sprint 7 |
| ML training script | `ml/train.py` | Sprints 8-9 |
| ML prediction | `ml/predict.py` | Sprint 9 |
| Dashboard | `app/dashboard.py` | Sprint 11 |
| PDF reports | (part of dashboard) | Sprint 12 |

## Key decisions

- **Why Flask?** It's simple enough that I can focus on the security logic rather than fighting the framework. I considered Django but it felt like overkill for this.
- **Why regex for rules?** I need to be able to show exactly what pattern matched and why something was blocked. Regex makes the rules transparent and easy to test individually.
- **Why Logistic Regression and not something fancier?** The input (HTTP payloads) is short text. TF-IDF + LR is a well-known approach for text classification and it's fast. Using a neural network here would be hard to justify for strings that are usually under 200 characters.
- **Why SQLite?** Zero setup. I don't need concurrent writes from multiple servers — it's just one proxy logging decisions. A full database server would be unnecessary overhead.
