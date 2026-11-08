# Sprint 3 Report — Reverse Proxy

**Sprint dates:** 10 August – 16 August 2026  
**Objective:** Build a Flask reverse proxy that intercepts all HTTP traffic, preserves headers/body/params, and forwards to DVWA.

---

## What I built

The core of SecureShield — a reverse proxy (`app/proxy.py`) that sits between the browser and DVWA. Every request to `localhost:5000` gets intercepted, inspected (for now just logged), and forwarded to DVWA on `localhost:8080`. The response comes back through the same path.

This is the component that everything else hooks into. The detection rules, brute-force monitor, and ML classifier will all be inserted into the `forward_request()` function in later sprints.

---

## How it works

1. Client sends a request to `http://localhost:5000/anything`
2. Flask catches it (all paths, all HTTP methods)
3. The proxy rebuilds the request: same method, same headers (minus hop-by-hop), same params, same body, same cookies
4. Forwards it to `http://localhost:8080/anything`
5. Gets the response back from DVWA
6. Strips problematic headers from the response
7. Returns the response to the client

From the browser's perspective, it looks like it's talking directly to DVWA. The proxy is transparent.

---

## Technical details

**Blueprint architecture:** I used Flask blueprints to keep the proxy routes separate. This means when I add the dashboard later, it won't interfere — it'll just be another blueprint on a different URL prefix.

**Catch-all routes:** Two route decorators handle everything:
- `"/"` with `defaults={"path": ""}` catches the root
- `"/<path:path>"` catches every other path

Both accept all HTTP methods (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD).

**Header handling:** I had to deal with two sets of excluded headers:

- *Request headers* — things like `Host`, `Connection`, `Keep-Alive` that are specific to the client-proxy connection and shouldn't be forwarded.
- *Response headers* — the big problem was `Content-Encoding`. The Python `requests` library automatically decompresses gzip responses, so by the time I have `resp.content` it's already plain HTML. But the original `Content-Encoding: gzip` header is still there. If I pass that along, the browser tries to decompress already-decompressed content and throws a zlib error. Removing `Content-Encoding` and `Content-Length` from the response fixed it.

**Error handling:** Three types of failure are caught:
- `ConnectionError` → 502 (target unreachable — DVWA probably isn't running)
- `Timeout` → 504 (target took too long, 30-second limit)
- Any other `RequestException` → 500 (catch-all)

**Console logging:** Every request prints a line showing timestamp, decision (ALLOW/BLOCK/ERROR), source IP, method, path, and status code. This gives immediate visibility during development. Will be replaced with SQLite logging in Sprint 4.

---

## Problems I ran into

The gzip issue was the main one. When I first tested, `curl` worked fine because it doesn't send `Accept-Encoding: gzip` by default. But when I ran the pytest suite (which uses the `requests` library, which does send that header), all the tests that read `response.text` failed with a zlib decompression error. 

Root cause: DVWA was sending back gzip-compressed responses. The `requests` library in my proxy decompressed them automatically, but I was still forwarding the `Content-Encoding: gzip` header. So the test client's `requests` library saw that header and tried to decompress the already-decompressed bytes.

Fix: strip `content-encoding` and `content-length` from proxied responses. The content is already decoded, and the length will be different anyway since it's no longer compressed.

---

## Test results

11 integration tests, all passing:

| Category | Tests | What they verify |
| --- | --- | --- |
| Forwarding | 7 | GET forwards correctly, POST preserves body, params preserved, 404s pass through, content matches, repeated requests stable |
| Headers | 2 | Custom headers forwarded, Content-Type preserved in response |
| Error handling | 2 | Path traversal attempts don't crash the proxy, large query strings handled |

Run with:
```bash
# DVWA and SecureShield both need to be running
docker-compose up -d
python run.py &
pytest tests/test_proxy.py -v
```

---

## Files changed/created

| File | Change |
| --- | --- |
| `app/proxy.py` | Rewritten — full reverse proxy implementation |
| `app/__init__.py` | Modified — registers the proxy blueprint |
| `tests/test_proxy.py` | Rewritten — 11 integration tests |
| `requirements.txt` | Modified — added pytest |

---

## What's left for the proxy to be complete

The proxy currently forwards everything — it doesn't block anything yet. That's by design. The detection pipeline will be inserted in Sprints 5–9:

```python
# This placeholder in forward_request() is where rules go:
# if is_sqli(...):  → Sprint 5
# if is_xss(...):   → Sprint 6
# if is_brute_force(...): → Sprint 7
# if ml_predicts_malicious(...): → Sprint 9
```

---

## Sprint 3 milestone status

**M3: Reverse proxy operational (pass-through mode).** ✓ Complete.
