#!/usr/bin/env python3
"""Light, non-intrusive manual security checks (Assignment Part 3.4).

Usage: manual_checks.py <target-url> <evidence-dir>
Writes: manual-checks.json / manual-checks.md / manual-checks.html
Only a handful of ordinary GET/HEAD/OPTIONS requests are sent. No exploitation is attempted.
"""
import datetime
import html
import http.client
import json
import re
import socket
import ssl
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse

UA = "Mozilla/5.0 (X11; Linux x86_64) ZAP-Assessment-ManualChecks/1.0 (educational coursework)"
TIMEOUT = 15
MAX_BODY = 400_000

results = []  # {id, title, status, detail}


def add(cid, title, status, detail=""):
    results.append({"id": cid, "title": title, "status": status, "detail": detail})


def fetch(url, method="GET"):
    """One request, no redirect following. Returns dict (status, headers, body) or {error}."""
    u = urlparse(url)
    port = u.port or (443 if u.scheme == "https" else 80)
    path = (u.path or "/") + (("?" + u.query) if u.query else "")
    for verify in (True, False):
        try:
            if u.scheme == "https":
                ctx = ssl.create_default_context() if verify else ssl._create_unverified_context()
                conn = http.client.HTTPSConnection(u.hostname, port, timeout=TIMEOUT, context=ctx)
            else:
                conn = http.client.HTTPConnection(u.hostname, port, timeout=TIMEOUT)
            conn.request(method, path, headers={"User-Agent": UA, "Accept": "*/*"})
            r = conn.getresponse()
            body = b"" if method in ("HEAD", "OPTIONS", "TRACE") else r.read(MAX_BODY)
            out = {"status": r.status, "headers": r.getheaders(), "body": body,
                   "cert_unverified": not verify}
            conn.close()
            return out
        except ssl.SSLError as e:
            if not verify or u.scheme != "https":
                return {"error": f"SSL error: {e}"}
        except Exception as e:  # noqa: BLE001
            return {"error": f"{type(e).__name__}: {e}"}
    return {"error": "unreachable"}


def hget(headers, name):
    return [v for k, v in headers if k.lower() == name.lower()]


def follow(url, limit=5):
    chain, cur = [], url
    for _ in range(limit + 1):
        r = fetch(cur)
        if "error" in r:
            chain.append((cur, r["error"]))
            return chain, r
        chain.append((cur, r["status"]))
        loc = hget(r["headers"], "Location")
        if r["status"] in (301, 302, 303, 307, 308) and loc:
            cur = urljoin(cur, loc[0])
            continue
        return chain, r
    return chain, r


class Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.comments, self.forms, self.scripts, self.metas = [], [], [], {}
        self._form = None

    def handle_comment(self, data):
        d = data.strip()
        if d:
            self.comments.append(d[:160])

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._form = {"action": a.get("action", ""), "method": (a.get("method") or "GET").upper(), "inputs": []}
            self.forms.append(self._form)
        elif tag in ("input", "textarea", "select") and self._form is not None:
            self._form["inputs"].append({"name": a.get("name", ""), "type": a.get("type", tag),
                                         "autocomplete": a.get("autocomplete", "")})
        elif tag == "script" and a.get("src"):
            self.scripts.append({"src": a["src"], "integrity": bool(a.get("integrity"))})
        elif tag == "meta" and a.get("name"):
            self.metas[a["name"].lower()] = a.get("content", "")

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None


def main():
    target = sys.argv[1].rstrip("/") + "/"
    outdir = Path(sys.argv[2])
    outdir.mkdir(parents=True, exist_ok=True)
    u = urlparse(target)
    origin = f"{u.scheme}://{u.netloc}"

    # M1 - reachability + redirect chain
    chain, final = follow(target)
    if "error" in final:
        add("M1", "Target reachable", "FAIL", final["error"])
        return finish(target, outdir, {})
    add("M1", "Redirect chain", "INFO", " -> ".join(f"{c[0]} [{c[1]}]" for c in chain))
    fu = urlparse(chain[-1][0])
    hdrs = final["headers"]
    body = final["body"].decode("utf-8", "replace")
    https_final = fu.scheme == "https"

    # M2 - security headers
    csp = hget(hdrs, "Content-Security-Policy")
    xfo = hget(hdrs, "X-Frame-Options")
    checks = [
        ("Content-Security-Policy", bool(csp)),
        ("X-Frame-Options", bool(xfo)),
        ("X-Content-Type-Options", any("nosniff" in v.lower() for v in hget(hdrs, "X-Content-Type-Options"))),
        ("Strict-Transport-Security", bool(hget(hdrs, "Strict-Transport-Security"))),
        ("Referrer-Policy", bool(hget(hdrs, "Referrer-Policy"))),
        ("Permissions-Policy", bool(hget(hdrs, "Permissions-Policy"))),
    ]
    for name, ok in checks:
        if name == "Strict-Transport-Security" and not https_final:
            add("M2", f"Header {name}", "FAIL", "Site is served over plain HTTP, so HSTS cannot apply.")
        else:
            add("M2", f"Header {name}", "PASS" if ok else "FAIL",
                "; ".join(hget(hdrs, name)) if ok else "Header not present in response.")

    # M3 - clickjacking (header-based verdict; screenshots.py adds the visual iframe test)
    framed_ok = bool(xfo) or any("frame-ancestors" in v.lower() for v in csp)
    add("M3", "Clickjacking protection (X-Frame-Options / CSP frame-ancestors)",
        "PASS" if framed_ok else "FAIL",
        "Framing restricted." if framed_ok else "Page can be embedded in a third-party iframe (see screenshot 02).")

    # M4 - information disclosure headers
    for h in ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator", "Via"):
        v = hget(hdrs, h)
        if v:
            add("M4", f"Header {h} discloses technology", "WARN", "; ".join(v))

    # M5 - cookies
    cookies = hget(hdrs, "Set-Cookie")
    if not cookies:
        add("M5", "Cookies set on first response", "INFO", "No Set-Cookie header on the landing page.")
    for c in cookies:
        low = c.lower()
        flags = {"Secure": "secure" in low, "HttpOnly": "httponly" in low, "SameSite": "samesite" in low}
        missing = [k for k, v in flags.items() if not v]
        add("M5", f"Cookie {c.split('=')[0]}", "FAIL" if missing else "PASS",
            ("Missing flags: " + ", ".join(missing)) if missing else "Secure, HttpOnly and SameSite present.")

    # M6 - transport security
    if u.scheme == "http":
        hu = f"https://{u.netloc}/"
        r = fetch(hu)
        add("M6", "HTTPS available", "FAIL" if "error" in r else "PASS",
            r["error"] if "error" in r else f"HTTPS answered with status {r['status']}.")
        add("M6", "Landing page served over HTTPS", "PASS" if https_final else "FAIL",
            "Final URL: " + chain[-1][0])
    if https_final:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((fu.hostname, fu.port or 443), timeout=TIMEOUT) as s:
                with ctx.wrap_socket(s, server_hostname=fu.hostname) as t:
                    cert = t.getpeercert()
                    exp = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                    days = (exp - datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)).days
                    add("M6", "TLS handshake", "PASS", f"{t.version()}, cipher {t.cipher()[0]}; certificate valid, "
                        f"expires {exp:%Y-%m-%d} ({days} days)")
        except Exception as e:  # noqa: BLE001
            add("M6", "TLS handshake", "FAIL", f"{type(e).__name__}: {e}")

    # M7 - HTTP methods
    r = fetch(origin + "/", "OPTIONS")
    if "error" not in r:
        allow = hget(r["headers"], "Allow")
        add("M7", "OPTIONS / (allowed methods)", "INFO", "; ".join(allow) if allow else f"status {r['status']}, no Allow header")
    r = fetch(origin + "/", "TRACE")
    if "error" not in r:
        add("M7", "TRACE method", "FAIL" if r["status"] == 200 else "PASS", f"status {r['status']}")

    # M8 - well-known files
    for p in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt"):
        r = fetch(origin + p)
        if "error" in r:
            add("M8", p, "INFO", r["error"])
            continue
        txt = r["body"].decode("utf-8", "replace")
        if r["status"] == 200 and p == "/robots.txt":
            dis = [l for l in txt.splitlines() if l.lower().startswith("disallow") and l.split(":", 1)[-1].strip() not in ("", "/")]
            add("M8", p, "WARN" if dis else "INFO", ("Disallow entries reveal paths: " + ", ".join(l.split(":", 1)[1].strip() for l in dis[:15])) if dis else "Present, no sensitive-looking entries.")
        else:
            add("M8", p, "INFO", f"status {r['status']}")

    # M9 - small sensitive-path probe (status only)
    for p in ("/admin/", "/backup/", "/.git/HEAD", "/.env", "/phpinfo.php", "/server-status", "/images/", "/downloads/"):
        r = fetch(origin + p)
        if "error" in r:
            continue
        t = r["body"].decode("utf-8", "replace")
        listing = any(k in t for k in ("Index of /", "Directory listing for", "Parent Directory"))
        bad = r["status"] == 200 and (listing or p in ("/.git/HEAD", "/.env", "/phpinfo.php", "/server-status"))
        add("M9", f"Path {p}", "FAIL" if bad else "INFO",
            f"status {r['status']}" + (" - DIRECTORY LISTING ENABLED" if listing and r["status"] == 200 else ""))

    # M10 - HTML review
    pg = Page()
    try:
        pg.feed(body)
    except Exception:  # noqa: BLE001
        pass
    if pg.comments:
        add("M10", "HTML comments left in page source", "WARN", " | ".join(pg.comments[:5]))
    if pg.metas.get("generator"):
        add("M10", "Generator meta tag discloses software", "WARN", pg.metas["generator"])
    ext = [s for s in pg.scripts if urlparse(urljoin(chain[-1][0], s["src"])).netloc not in ("", fu.netloc) and not s["integrity"]]
    if ext:
        add("M10", "External scripts without Subresource Integrity", "WARN", ", ".join(s["src"] for s in ext[:5]))
    if https_final and re.search(r"""(?:src|href)=["']http://""", body, re.I):
        add("M10", "Mixed content (http:// resources on an https page)", "FAIL", "Found http:// src/href references.")
    for i, f in enumerate(pg.forms, 1):
        names = [x["name"].lower() for x in f["inputs"]]
        has_pw = any(x["type"] == "password" for x in f["inputs"])
        has_csrf = any(("csrf" in n or "token" in n or "nonce" in n) for n in names)
        act = urljoin(chain[-1][0], f["action"]) if f["action"] else chain[-1][0]
        notes = []
        if f["method"] == "POST" and not has_csrf:
            notes.append("POST form without an obvious anti-CSRF token")
        if has_pw and urlparse(act).scheme == "http":
            notes.append("password field submitted over HTTP")
        if has_pw and not any(x["autocomplete"] in ("off", "new-password", "current-password") for x in f["inputs"] if x["type"] == "password"):
            notes.append("password field without autocomplete hint")
        add("M10", f"Form #{i} ({f['method']} {act})", "WARN" if notes else "INFO",
            "; ".join(notes) if notes else f"{len(f['inputs'])} inputs")
    if not pg.forms:
        add("M10", "Forms on landing page", "INFO", "None found.")

    finish(target, outdir, {"redirect_chain": chain, "clickjacking_protected": framed_ok})


def finish(target, outdir, extra):
    meta = {"target": target, "generated_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            **{k: v for k, v in extra.items()}}
    (outdir / "manual-checks.json").write_text(json.dumps({"meta": meta, "results": results}, indent=2, default=str))
    icon = {"PASS": "PASS", "FAIL": "FAIL", "WARN": "WARN", "INFO": "INFO"}
    md = [f"# Manual security checks - {target}", "", f"Generated (UTC): {meta['generated_utc']}", "",
          "| ID | Check | Result | Detail |", "|---|---|---|---|"]
    for r in results:
        md.append(f"| {r['id']} | {r['title']} | {icon[r['status']]} | {r['detail'].replace('|', '/')} |")
    (outdir / "manual-checks.md").write_text("\n".join(md) + "\n")
    colour = {"PASS": "#1a7f37", "FAIL": "#cf222e", "WARN": "#9a6700", "INFO": "#57606a"}
    rows = "".join(
        f"<tr><td>{html.escape(r['id'])}</td><td>{html.escape(r['title'])}</td>"
        f"<td style='color:{colour[r['status']]};font-weight:700'>{r['status']}</td><td>{html.escape(r['detail'])}</td></tr>"
        for r in results)
    (outdir / "manual-checks.html").write_text(
        "<!doctype html><meta charset=utf-8><title>Manual checks</title><style>"
        "body{font:14px system-ui,sans-serif;margin:24px;color:#1f2328}table{border-collapse:collapse;width:100%}"
        "td,th{border:1px solid #d0d7de;padding:6px 10px;text-align:left;vertical-align:top}th{background:#f6f8fa}</style>"
        f"<h2>Manual security checks</h2><p>Target: <b>{html.escape(target)}</b> &middot; {meta['generated_utc']} UTC</p>"
        f"<table><tr><th>ID</th><th>Check</th><th>Result</th><th>Detail</th></tr>{rows}</table>")
    for r in results:
        print(f"[{r['status']}] {r['id']} {r['title']}: {r['detail'][:140]}")


if __name__ == "__main__":
    main()
