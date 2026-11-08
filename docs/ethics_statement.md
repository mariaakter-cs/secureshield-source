# Ethics Statement and Testing Authorisation

**Project:** SecureShield  
**Student:** Maria Akter  
**Date:** [Date]

---

## Declaration

I, Maria Akter, declare that all security testing conducted as part of this project will stay within the boundaries described below. I understand that testing against systems without authorisation is a criminal offence under the Computer Misuse Act 1990.

---

## Approved Testing Environment

| Environment | Details |
| --- | --- |
| Primary: DVWA (local) | Running as a Docker container on my own laptop (localhost:8080) |
| Secondary (if approved): | [To be specified if supervisor approves an additional target] |

Nothing else gets tested. No exceptions.

---

## What I will and won't do

1. I won't test against anything I haven't been given written permission for.
2. I won't try to actually exploit vulnerabilities beyond confirming my detection works.
3. I won't use any real personal data — everything is synthetic test payloads.
4. I won't send test data to any external system.
5. I won't try to access anyone else's accounts or data.
6. I'll keep evidence of my testing authorisation for the whole project.
7. The proxy target address is hard-coded so I can't accidentally forward to something outside scope.

---

## What testing actually involves

- Sending known SQLi strings (like `' OR 1=1 --`) through the proxy to see if my rules catch them.
- Sending known XSS payloads (like `<script>alert(1)</script>`) to test the XSS rules.
- Simulating repeated failed logins from one IP to test brute-force detection.
- Sending normal requests to check for false positives.
- Timing requests to measure how much latency the proxy adds.

---

## Data handling

- The SQLite database only contains synthetic test traffic that I generated myself.
- It stays on my laptop and doesn't get shared anywhere.
- No real user data is involved at any point.

---

## Signatures

| | |
| --- | --- |
| Student: | _________________________ |
| Name: | Maria Akter |
| Date: | _________________ |
| | |
| Supervisor: | _________________________ |
| Name: | [Supervisor's Name] |
| Date: | _________________ |

---

**Notes from supervisor:**

*[Space for any additional conditions or approvals]*
