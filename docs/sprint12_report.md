# Sprint 12 Report — PDF Reporting and IP Blocklist

**Sprint dates:** 12 October – 18 October 2026  
**Objective:** Implement PDF report generation and IP blocklist management page.

---

## What I built

Two features this sprint:
1. **PDF report generation** — downloadable security summary report
2. **IP blocklist management page** — view blocked IPs and manually unblock them

---

## PDF Reports

Clicking "Download Report" in the dashboard navbar generates a PDF using fpdf2 and sends it as a file download. The report contains:

- **Header** — project name, generation timestamp
- **Summary** — total requests, allowed, blocked, block rate percentage
- **Detection breakdown** — counts by type (SQLi rules, XSS rules, brute-force, ML)
- **Top blocked IPs** — the 10 IPs with the most blocked requests
- **Recent blocked events** — table of the last 20 blocked requests with timestamp, IP, method, URL, and detection method

The report reads from the same SQLite database as the dashboard, so it always reflects current data. Each download gets a unique filename with a timestamp so I don't overwrite previous reports.

### How it works technically

I created a custom FPDF class (`SecurityReport`) that handles the header and footer on every page. The `generate_report()` function runs SQL queries to gather the data, then builds the PDF section by section. The file saves to the `reports/` directory and Flask's `send_file()` returns it as a download.

---

## IP Blocklist Page

Accessible at `/dashboard/blocklist`. Shows:
- All currently blocked IPs
- When they were blocked
- How much time remains until the block expires
- An "Unblock" button to manually release an IP early

The unblock action removes the IP from both the blocked list and the failed-attempts tracker, so they start fresh.

This page is useful during testing — if I accidentally block myself (127.0.0.1) during brute-force testing, I can unblock without restarting the proxy.

---

## Dashboard navigation update

The navbar now has four items:
- **Stats** — overview page (Sprint 11)
- **Logs** — event log viewer (Sprint 11)
- **Blocklist** — IP blocklist management (this sprint)
- **Download Report** — generates and downloads PDF (this sprint)

---

## Problem I ran into

The PDF was initially saving to a path relative to `app/` (because `reports.py` lives inside the `app/` directory). The `reports/` folder is at the project root, not inside `app/`. Fixed by using `os.path.dirname(os.path.dirname(__file__))` to get back to the project root before joining with "reports".

---

## Files created/changed

| File | Change |
| --- | --- |
| `app/reports.py` | New — PDF generation with SecurityReport class |
| `app/dashboard.py` | Modified — added /blocklist, /blocklist/unblock, /report routes |
| `app/templates/dashboard/blocklist.html` | New — blocklist page template |
| `app/templates/dashboard/base.html` | Modified — added Blocklist and Report links to nav |
| `app/__init__.py` | Modified — passes brute-force config to templates |

---

## Sprint 12 milestone status

**M12: PDF reporting and blocklist management fully functional.** ✓ Complete.
