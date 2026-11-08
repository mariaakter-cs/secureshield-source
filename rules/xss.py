"""
xss.py - Cross-Site Scripting detection rules.

XSS is trickier to detect than SQLi because there are so many ways to
inject JavaScript. Attackers use different tags, event handlers, encoding,
and even obscure HTML attributes to sneak scripts past filters.

My rules cover:
- Script tags (the obvious one)
- Event handlers (onerror, onload, onmouseover, onfocus, etc.)
- javascript: protocol in href/src/action attributes
- Data URIs with script content
- Expression/eval/Function calls in suspicious contexts
- DOM manipulation methods (document.cookie, document.write, etc.)
- SVG/math/iframe/object/embed tags (used to bypass tag-based filters)
- Encoded payloads (HTML entities, hex encoding)

All case-insensitive since <SCRIPT> works the same as <script>.
"""

import re

XSS_RULES = [
    # --- Script tags ---
    (re.compile(r"<\s*script\b", re.IGNORECASE),
     "script_tag", "<script> tag injection"),

    (re.compile(r"</\s*script\s*>", re.IGNORECASE),
     "script_tag", "</script> closing tag"),

    # --- Event handlers ---
    # These are the main ones attackers use. There are dozens of event
    # handlers but these cover the most common attack vectors.
    (re.compile(r"\bon\w+\s*=", re.IGNORECASE),
     "event_handler", "Event handler attribute (onXXX=)"),

    # --- javascript: protocol ---
    (re.compile(r"javascript\s*:", re.IGNORECASE),
     "js_protocol", "javascript: protocol (href/src injection)"),

    # --- vbscript: protocol (IE specific but still in payloads) ---
    (re.compile(r"vbscript\s*:", re.IGNORECASE),
     "vbs_protocol", "vbscript: protocol"),

    # --- data: URI with script content ---
    (re.compile(r"data\s*:\s*text/html", re.IGNORECASE),
     "data_uri", "data: URI with text/html (possible script injection)"),

    # --- Dangerous JS functions ---
    (re.compile(r"\balert\s*\(", re.IGNORECASE),
     "js_function", "alert() function call"),

    (re.compile(r"\bconfirm\s*\(", re.IGNORECASE),
     "js_function", "confirm() function call"),

    (re.compile(r"\bprompt\s*\(", re.IGNORECASE),
     "js_function", "prompt() function call"),

    (re.compile(r"\beval\s*\(", re.IGNORECASE),
     "js_function", "eval() function call"),

    (re.compile(r"\bsetTimeout\s*\(", re.IGNORECASE),
     "js_function", "setTimeout() with possible code execution"),

    (re.compile(r"\bsetInterval\s*\(", re.IGNORECASE),
     "js_function", "setInterval() with possible code execution"),

    (re.compile(r"\bFunction\s*\(", re.IGNORECASE),
     "js_function", "Function() constructor (code execution)"),

    # --- DOM access patterns ---
    (re.compile(r"document\s*\.\s*cookie", re.IGNORECASE),
     "dom_access", "document.cookie access (session theft)"),

    (re.compile(r"document\s*\.\s*write", re.IGNORECASE),
     "dom_access", "document.write() (DOM injection)"),

    (re.compile(r"document\s*\.\s*location", re.IGNORECASE),
     "dom_access", "document.location manipulation"),

    (re.compile(r"window\s*\.\s*location", re.IGNORECASE),
     "dom_access", "window.location manipulation"),

    (re.compile(r"\.innerHTML\s*=", re.IGNORECASE),
     "dom_access", "innerHTML assignment (DOM injection)"),

    # --- Dangerous HTML tags (used to bypass <script> filters) ---
    (re.compile(r"<\s*iframe\b", re.IGNORECASE),
     "dangerous_tag", "<iframe> tag (can load external scripts)"),

    (re.compile(r"<\s*object\b", re.IGNORECASE),
     "dangerous_tag", "<object> tag (can embed malicious content)"),

    (re.compile(r"<\s*embed\b", re.IGNORECASE),
     "dangerous_tag", "<embed> tag (can load external plugins)"),

    (re.compile(r"<\s*svg\b.*?\bon\w+\s*=", re.IGNORECASE | re.DOTALL),
     "dangerous_tag", "<svg> with event handler"),

    (re.compile(r"<\s*img\b[^>]*\bon\w+\s*=", re.IGNORECASE),
     "dangerous_tag", "<img> with event handler (e.g., onerror)"),

    (re.compile(r"<\s*body\b[^>]*\bon\w+\s*=", re.IGNORECASE),
     "dangerous_tag", "<body> with event handler"),

    (re.compile(r"<\s*marquee\b[^>]*\bon\w+\s*=", re.IGNORECASE),
     "dangerous_tag", "<marquee> with event handler"),

    (re.compile(r"<\s*details\b[^>]*\bon\w+\s*=", re.IGNORECASE),
     "dangerous_tag", "<details> with event handler"),

    # --- Encoded/obfuscated XSS ---
    (re.compile(r"&#x?[0-9a-f]+;", re.IGNORECASE),
     "encoding", "HTML entity encoding (possible obfuscated XSS)"),

    (re.compile(r"\\x[0-9a-f]{2}", re.IGNORECASE),
     "encoding", "Hex escape sequence (JS string obfuscation)"),

    (re.compile(r"\\u[0-9a-f]{4}", re.IGNORECASE),
     "encoding", "Unicode escape (JS string obfuscation)"),

    # --- Expression-based (older IE but still in test sets) ---
    (re.compile(r"expression\s*\(", re.IGNORECASE),
     "expression", "CSS expression() (IE-specific XSS)"),
]


def check_xss(text):
    """
    Check a string for XSS patterns.

    Returns None if clean, or a dict with details if XSS found:
    {"category": str, "description": str, "matched": str}
    """
    if not text:
        return None

    for pattern, category, description in XSS_RULES:
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
    Scan query string and body for XSS.
    Returns first match or None.
    """
    result = check_xss(query_string)
    if result:
        result["source"] = "query_string"
        return result

    result = check_xss(body)
    if result:
        result["source"] = "body"
        return result

    return None
