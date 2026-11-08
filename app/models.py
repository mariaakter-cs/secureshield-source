"""
models.py - Database setup and logging functions.

Uses SQLite because it needs zero configuration and I don't need
anything more complex for a single-user proxy. Every request that
comes through the proxy gets a row in the security_events table,
regardless of whether it was allowed or blocked.
"""

import sqlite3
import os
from datetime import datetime
from config import DATABASE_PATH


def get_db():
    """Get a connection to the SQLite database.
    Creates the file if it doesn't exist yet."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row  # so I can access columns by name
    conn.execute("PRAGMA journal_mode=WAL")  # better concurrent read performance
    return conn


def init_db():
    """Create the tables if they don't already exist.
    Called once when the app starts up."""
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            request_method TEXT NOT NULL,
            request_url TEXT NOT NULL,
            request_body TEXT,
            detection_method TEXT NOT NULL DEFAULT 'none',
            outcome TEXT NOT NULL DEFAULT 'allow',
            details TEXT
        )
    """)
    conn.commit()
    conn.close()


def log_event(source_ip, method, url, body=None,
              detection_method="none", outcome="allow", details=None):
    """
    Write a security event to the database.

    This gets called from the proxy for every single request —
    both allowed and blocked ones. That way I have a complete
    record of everything that passed through.

    Args:
        source_ip: where the request came from
        method: GET, POST, etc.
        url: the path that was requested
        body: request body (for POST requests), truncated to 2000 chars
        detection_method: what caught it — 'none', 'rule_sqli', 'rule_xss',
                         'bruteforce', or 'ml'
        outcome: 'allow' or 'block'
        details: extra info like which rule matched or ML confidence score
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # truncate body if it's massive — don't want to bloat the DB
    if body and len(body) > 2000:
        body = body[:2000] + "...[truncated]"

    conn = get_db()
    conn.execute(
        """INSERT INTO security_events
           (timestamp, source_ip, request_method, request_url,
            request_body, detection_method, outcome, details)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (timestamp, source_ip, method, url, body,
         detection_method, outcome, details)
    )
    conn.commit()
    conn.close()


def get_events(limit=100, offset=0, outcome=None, detection_method=None):
    """
    Fetch logged events. Used by the dashboard later.
    Can filter by outcome (allow/block) or detection method.
    """
    conn = get_db()
    query = "SELECT * FROM security_events WHERE 1=1"
    params = []

    if outcome:
        query += " AND outcome = ?"
        params.append(outcome)
    if detection_method:
        query += " AND detection_method = ?"
        params.append(detection_method)

    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = conn.execute(query, params).fetchall()
    conn.close()
    return rows


def get_stats():
    """
    Get summary counts for the dashboard.
    Returns total requests, blocked count, and breakdown by detection type.
    """
    conn = get_db()

    total = conn.execute(
        "SELECT COUNT(*) FROM security_events"
    ).fetchone()[0]

    blocked = conn.execute(
        "SELECT COUNT(*) FROM security_events WHERE outcome = 'block'"
    ).fetchone()[0]

    allowed = total - blocked

    # breakdown by detection method (only blocked ones)
    breakdown = conn.execute(
        """SELECT detection_method, COUNT(*) as count
           FROM security_events
           WHERE outcome = 'block'
           GROUP BY detection_method"""
    ).fetchall()

    conn.close()

    return {
        "total": total,
        "allowed": allowed,
        "blocked": blocked,
        "breakdown": {row["detection_method"]: row["count"] for row in breakdown}
    }
