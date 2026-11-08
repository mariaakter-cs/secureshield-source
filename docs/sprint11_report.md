# Sprint 11 Report — Admin Dashboard

**Sprint dates:** 05 October – 11 October 2026  
**Objective:** Build an admin dashboard with statistics page and log viewer with filtering. Bootstrap 5 interface.

---

## What I built

A web dashboard accessible at `/dashboard/` that reads from the same SQLite database as the proxy and shows:
1. A **statistics overview** — total requests, allowed, blocked, and breakdown by detection type
2. A **log viewer** — filterable table of all security events with pagination

---

## Pages

### /dashboard/ — Stats

Shows three cards at the top:
- Total requests processed
- Allowed requests (green)
- Blocked requests (red)

Below that, if there are blocks, a table shows the breakdown by detection method (SQLi rules, XSS rules, brute-force, ML) with colour-coded badges. Also shows the block rate as a percentage and links to filtered log views.

### /dashboard/logs — Log Viewer

A table listing all security events with columns:
- Timestamp
- Source IP
- HTTP Method
- URL (truncated to 60 chars with full text in title tooltip)
- Outcome (ALLOWED/BLOCKED badge)
- Detection method (colour-coded badge)
- Details (which rule matched, ML confidence, etc.)

Filtering by:
- Outcome (all / allowed / blocked)
- Detection method (all / SQLi / XSS / brute-force / ML / none)

Pagination: 50 events per page with Previous/Next links.

---

## Technical decisions

**Why Bootstrap 5 from CDN?** I don't want to spend time writing CSS when the focus of this project is the security logic. Bootstrap gives me a decent-looking responsive layout for free. Loading from CDN means no build step and the files stay small.

**How does the dashboard coexist with the proxy?** The proxy has a catch-all route (`/<path:path>`) that forwards everything to DVWA. I added a check at the top of `forward_request()`: if the path starts with "dashboard", it returns `None` and lets Flask fall through to the dashboard blueprint. The dashboard is registered with `url_prefix="/dashboard"` so its routes take priority for that path.

**Why is the dashboard on the same port?** Simplicity. Running a separate server just for the dashboard adds complexity without benefit for a single-user prototype. In a real system you'd probably put the dashboard on a different port or behind authentication.

---

## What it looks like

The stats page shows something like:

```
┌─────────────────────────────────────────────────┐
│  [5]              [3]              [2]           │
│  Total Requests   Allowed          Blocked      │
├─────────────────────────────────────────────────┤
│  Detection Breakdown:                           │
│  SQLi Rules  → 1                                │
│  XSS Rules   → 1                                │
│  Block rate: 40.0%                              │
└─────────────────────────────────────────────────┘
```

The log viewer shows a table with filter dropdowns at the top and colour-coded badges making it easy to scan for blocked events.

---

## Files created/changed

| File | Change |
| --- | --- |
| `app/dashboard.py` | New — stats and logs routes |
| `app/templates/dashboard/base.html` | New — base template with nav, Bootstrap CDN |
| `app/templates/dashboard/stats.html` | New — statistics overview page |
| `app/templates/dashboard/logs.html` | New — log viewer with filters and pagination |
| `app/__init__.py` | Modified — registered dashboard blueprint |
| `app/proxy.py` | Modified — skip forwarding for /dashboard paths |

---

## What's left for Sprint 12

- PDF report generation (fpdf2)
- IP blocklist management page (view/unblock IPs)

The dashboard foundation is here; Sprint 12 adds the reporting and blocklist features on top.

---

## Sprint 11 milestone status

**M11: Dashboard operational with statistics and log viewer.** ✓ Complete.
