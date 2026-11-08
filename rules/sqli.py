"""
sqli.py - SQL Injection detection rules.

These patterns are based on common SQLi attack signatures I found in
the OWASP testing guide and various payload lists. They cover:

- UNION-based injection (extracting data from other tables)
- Error-based injection (forcing DB errors to leak info)
- Boolean-based blind (true/false conditions to infer data)
- Time-based blind (SLEEP/WAITFOR to confirm injection)
- Stacked queries (running multiple statements with ;)
- Comment-based evasion (using -- or /* */ to break queries)
- Tautologies (OR 1=1 type always-true conditions)

I'm using re.IGNORECASE on all of them because attackers mix case
to try and bypass filters (e.g., UnIoN SeLeCt).

Important: these check the raw input text. URL-decoded values come
in already decoded by Flask, so I don't need to handle %27 etc. here.
"""

import re

# Each rule is a tuple: (pattern, category, description)
# The pattern is compiled with IGNORECASE for case-insensitive matching.

SQLI_RULES = [
    # --- UNION-based ---
    (re.compile(r"union\s+(all\s+)?select", re.IGNORECASE),
     "union", "UNION SELECT statement"),

    (re.compile(r"union\s+(all\s+)?select\s+null", re.IGNORECASE),
     "union", "UNION SELECT NULL (column enumeration)"),

    # --- Error-based ---
    (re.compile(r"extractvalue\s*\(", re.IGNORECASE),
     "error", "EXTRACTVALUE function (MySQL error-based)"),

    (re.compile(r"updatexml\s*\(", re.IGNORECASE),
     "error", "UPDATEXML function (MySQL error-based)"),

    (re.compile(r"convert\s*\(.*using", re.IGNORECASE),
     "error", "CONVERT with USING (error-based)"),

    # --- Boolean-based blind ---
    (re.compile(r"['\"]\s*(or|and)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", re.IGNORECASE),
     "boolean", "Boolean condition (e.g., ' OR '1'='1)"),

    (re.compile(r"['\"]\s*(or|and)\s+.*?--", re.IGNORECASE),
     "boolean", "Boolean with comment terminator"),

    (re.compile(r"(or|and)\s+\d+\s*=\s*\d+", re.IGNORECASE),
     "boolean", "Numeric tautology (e.g., OR 1=1)"),

    # --- Time-based blind ---
    (re.compile(r"sleep\s*\(\s*\d+\s*\)", re.IGNORECASE),
     "time", "SLEEP() function (MySQL time-based)"),

    (re.compile(r"benchmark\s*\(", re.IGNORECASE),
     "time", "BENCHMARK() function (MySQL time-based)"),

    (re.compile(r"waitfor\s+delay", re.IGNORECASE),
     "time", "WAITFOR DELAY (MSSQL time-based)"),

    (re.compile(r"pg_sleep\s*\(", re.IGNORECASE),
     "time", "pg_sleep() (PostgreSQL time-based)"),

    # --- Stacked queries ---
    (re.compile(r";\s*(drop|alter|create|insert|update|delete|truncate)\s", re.IGNORECASE),
     "stacked", "Stacked query with destructive command"),

    (re.compile(r";\s*select\s", re.IGNORECASE),
     "stacked", "Stacked SELECT query"),

    # --- Comment-based evasion ---
    (re.compile(r"/\*.*?\*/", re.IGNORECASE | re.DOTALL),
     "comment", "SQL block comment (could hide payload)"),

    (re.compile(r"--\s*$", re.MULTILINE),
     "comment", "SQL line comment at end"),

    # --- Common SQL keywords in suspicious context ---
    (re.compile(r"'\s*;\s*--", re.IGNORECASE),
     "generic", "Quote-semicolon-comment (query termination)"),

    (re.compile(r"(select|insert|update|delete|drop|alter)\s+.*(from|into|table|database)", re.IGNORECASE),
     "generic", "SQL DML/DDL statement pattern"),

    (re.compile(r"information_schema", re.IGNORECASE),
     "recon", "information_schema access (DB enumeration)"),

    (re.compile(r"(char|chr|concat|hex|unhex)\s*\(", re.IGNORECASE),
     "obfuscation", "String function (possible obfuscation)"),

    # --- Tautologies (always-true) ---
    (re.compile(r"'\s*or\s+'[^']*'\s*=\s*'", re.IGNORECASE),
     "tautology", "String tautology (e.g., ' or 'a'='a)"),

    (re.compile(r"'\s*or\s+1\s*=\s*1", re.IGNORECASE),
     "tautology", "Numeric tautology with quote (e.g., ' or 1=1)"),

    (re.compile(r"or\s+true\b", re.IGNORECASE),
     "tautology", "OR TRUE condition"),
]


def check_sqli(text):
    """
    Check a string for SQL injection patterns.

    Args:
        text: the string to inspect (could be a query param value,
              POST body, URL path, etc.)

    Returns:
        None if clean, or a dict with match details if SQLi detected:
        {"category": str, "description": str, "matched": str}
    """
    if not text:
        return None

    for pattern, category, description in SQLI_RULES:
        match = pattern.search(text)
        if match:
            return {
                "category": category,
                "description": description,
                "matched": match.group(0),
            }

    return None


def scan_request(query_string, body):
    """
    Scan both the query string and body for SQLi.
    Returns the first match found, or None if clean.

    I check query string first because GET-based SQLi is the most
    common pattern in DVWA (the id parameter).
    """
    # check query string
    result = check_sqli(query_string)
    if result:
        result["source"] = "query_string"
        return result

    # check POST body
    result = check_sqli(body)
    if result:
        result["source"] = "body"
        return result

    return None
