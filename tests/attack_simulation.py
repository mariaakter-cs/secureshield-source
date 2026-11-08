"""
attack_simulation.py - Structured attack simulation test.

Sprint 14: This isn't a pytest test — it's a simulation script that runs
a defined set of attacks and legitimate requests through the proxy, records
every outcome (TP, FP, TN, FN), and outputs a results summary.

This is the formal "attack test" described in the proposal. The results
from this script go directly into the final test report.

MUST be run with both DVWA and SecureShield running:
    docker-compose up -d
    ./venv/bin/python run.py &
    ./venv/bin/python tests/attack_simulation.py
"""

import requests
import json
import os
import time
from datetime import datetime

PROXY_URL = "http://localhost:5000"

# ─────────────────────────────────────────────────────────────
# TEST PAYLOADS — defined attacks and legitimate traffic
# ─────────────────────────────────────────────────────────────

SQLI_ATTACKS = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "' UNION SELECT null,null,null --",
    "1; DROP TABLE users --",
    "' AND SLEEP(5) --",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,version())) --",
    "1' OR '1'='1' /*",
    "admin' --",
    "' UNION ALL SELECT username,password FROM users --",
    "'; WAITFOR DELAY '0:0:5' --",
    "1 OR 1=1",
    "' AND 1=CONVERT(int,(SELECT @@version)) --",
    "' UNION SELECT null,table_name FROM information_schema.tables --",
    "1' AND BENCHMARK(5000000,SHA1('test')) --",
    "' OR 'x'='x",
]

XSS_ATTACKS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert('XSS')>",
    "<iframe src='javascript:alert(1)'>",
    "javascript:alert(document.cookie)",
    "<script>document.write('hacked')</script>",
    "<img src=x onerror=eval('alert(1)')>",
    "<input onfocus=alert(1) autofocus>",
    "<a href='javascript:alert(1)'>click</a>",
    "<div onmouseover=alert(1)>hover</div>",
    "<script>window.location='http://evil.com'</script>",
    "<object data='javascript:alert(1)'>",
    "<embed src='javascript:alert(1)'>",
    "'\"><script>alert(1)</script>",
]

LEGITIMATE_REQUESTS = [
    "hello world",
    "john.smith@email.com",
    "My name is O'Brien",
    "I want to order 5 items",
    "search for blue shoes",
    "page=2&sort=date",
    "username=admin&password=password123",
    "The meeting is at 3pm",
    "Product ID: 12345",
    "Please update my phone number",
    "What time does the store open?",
    "London to Manchester train",
    "Filter by price range",
    "My flight is OR1234",
    "Table 5 is reserved",
]


def run_simulation():
    """Run the full attack simulation and collect results."""
    print("=" * 70)
    print("SecureShield Attack Simulation Test")
    print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Target: DVWA via proxy at {PROXY_URL}")
    print("=" * 70)

    results = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "sqli": {"tp": 0, "fn": 0, "payloads": []},
        "xss": {"tp": 0, "fn": 0, "payloads": []},
        "legitimate": {"tn": 0, "fp": 0, "payloads": []},
        "bruteforce": {"detected": False},
    }

    # ─── SQLi Attacks (should be BLOCKED) ───
    print(f"\n{'─'*70}")
    print(f"1. SQL INJECTION ATTACKS ({len(SQLI_ATTACKS)} payloads)")
    print(f"{'─'*70}")

    for payload in SQLI_ATTACKS:
        resp = requests.get(
            f"{PROXY_URL}/vulnerabilities/sqli/",
            params={"id": payload, "Submit": "Submit"},
            allow_redirects=False,
        )
        blocked = resp.status_code == 403
        status = "BLOCKED ✓" if blocked else "MISSED ✗"

        if blocked:
            results["sqli"]["tp"] += 1
        else:
            results["sqli"]["fn"] += 1

        results["sqli"]["payloads"].append({
            "payload": payload,
            "status_code": resp.status_code,
            "blocked": blocked,
        })
        print(f"  [{status}] {payload[:55]}")

    # ─── XSS Attacks (should be BLOCKED) ───
    print(f"\n{'─'*70}")
    print(f"2. CROSS-SITE SCRIPTING ATTACKS ({len(XSS_ATTACKS)} payloads)")
    print(f"{'─'*70}")

    for payload in XSS_ATTACKS:
        resp = requests.get(
            f"{PROXY_URL}/vulnerabilities/xss_r/",
            params={"name": payload},
            allow_redirects=False,
        )
        blocked = resp.status_code == 403
        status = "BLOCKED ✓" if blocked else "MISSED ✗"

        if blocked:
            results["xss"]["tp"] += 1
        else:
            results["xss"]["fn"] += 1

        results["xss"]["payloads"].append({
            "payload": payload,
            "status_code": resp.status_code,
            "blocked": blocked,
        })
        print(f"  [{status}] {payload[:55]}")

    # ─── Legitimate Requests (should be ALLOWED) ───
    print(f"\n{'─'*70}")
    print(f"3. LEGITIMATE REQUESTS ({len(LEGITIMATE_REQUESTS)} inputs)")
    print(f"{'─'*70}")

    for text in LEGITIMATE_REQUESTS:
        resp = requests.get(
            f"{PROXY_URL}/vulnerabilities/sqli/",
            params={"id": text, "Submit": "Submit"},
            allow_redirects=False,
        )
        blocked = resp.status_code == 403
        status = "ALLOWED ✓" if not blocked else "FALSE POS ✗"

        if not blocked:
            results["legitimate"]["tn"] += 1
        else:
            results["legitimate"]["fp"] += 1

        results["legitimate"]["payloads"].append({
            "input": text,
            "status_code": resp.status_code,
            "blocked": blocked,
        })
        print(f"  [{status}] {text[:55]}")

    # ─── Brute-Force Simulation ───
    print(f"\n{'─'*70}")
    print(f"4. BRUTE-FORCE SIMULATION (6 rapid login attempts)")
    print(f"{'─'*70}")

    for i in range(6):
        resp = requests.post(
            f"{PROXY_URL}/login.php",
            data={"username": "admin", "password": f"wrong{i}", "Login": "Login"},
            allow_redirects=False,
        )
        print(f"  Attempt {i+1}: HTTP {resp.status_code}")

    # check if blocked now
    resp = requests.get(f"{PROXY_URL}/login.php", allow_redirects=False)
    if resp.status_code == 403:
        results["bruteforce"]["detected"] = True
        print(f"  → IP BLOCKED ✓ (brute-force detection triggered)")
    else:
        print(f"  → NOT BLOCKED ✗ (got {resp.status_code})")

    # ─── Summary ───
    print(f"\n{'='*70}")
    print("RESULTS SUMMARY")
    print(f"{'='*70}")

    sqli_rate = results["sqli"]["tp"] / len(SQLI_ATTACKS) * 100
    xss_rate = results["xss"]["tp"] / len(XSS_ATTACKS) * 100
    fp_rate = results["legitimate"]["fp"] / len(LEGITIMATE_REQUESTS) * 100

    print(f"\n  SQLi Detection Rate:     {results['sqli']['tp']}/{len(SQLI_ATTACKS)} = {sqli_rate:.1f}%")
    print(f"  XSS Detection Rate:      {results['xss']['tp']}/{len(XSS_ATTACKS)} = {xss_rate:.1f}%")
    print(f"  False Positive Rate:     {results['legitimate']['fp']}/{len(LEGITIMATE_REQUESTS)} = {fp_rate:.1f}%")
    print(f"  Brute-Force Detection:   {'PASS' if results['bruteforce']['detected'] else 'FAIL'}")

    print(f"\n  Targets met:")
    print(f"    SQLi ≥ 90%: {'✓ YES' if sqli_rate >= 90 else '✗ NO'}")
    print(f"    XSS ≥ 90%:  {'✓ YES' if xss_rate >= 90 else '✗ NO'}")
    print(f"    FP ≤ 10%:   {'✓ YES' if fp_rate <= 10 else '✗ NO'}")
    print(f"    Brute-force: {'✓ YES' if results['bruteforce']['detected'] else '✗ NO'}")

    # save results to JSON
    results["summary"] = {
        "sqli_detection_rate": round(sqli_rate, 1),
        "xss_detection_rate": round(xss_rate, 1),
        "false_positive_rate": round(fp_rate, 1),
        "bruteforce_detected": results["bruteforce"]["detected"],
        "all_targets_met": sqli_rate >= 90 and xss_rate >= 90 and fp_rate <= 10 and results["bruteforce"]["detected"],
    }

    output_path = os.path.join(os.path.dirname(__file__), "..", "docs", "attack_simulation_results.json")
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n  Full results saved to: docs/attack_simulation_results.json")


if __name__ == "__main__":
    run_simulation()
