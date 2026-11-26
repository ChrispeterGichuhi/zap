#!/usr/bin/env python3
"""Capture screenshot evidence with headless Chromium.

Usage: screenshots.py <target-url> <evidence-dir> <zap-report-html>
Produces evidence/screenshots/01..05 PNG files and evidence/clickjack-test.html
"""
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

target, evidence, report = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
shots = evidence / "screenshots"
shots.mkdir(parents=True, exist_ok=True)

clickjack = evidence / "clickjack-test.html"
clickjack.write_text(f"""<!doctype html><meta charset=utf-8><title>Clickjacking test</title>
<body style="font-family:system-ui;margin:20px">
<h3>Clickjacking test page (attacker-controlled page)</h3>
<p>Target <code>{target}</code> is loaded inside an &lt;iframe&gt;. If the target page renders below, it can be framed
(no X-Frame-Options / frame-ancestors protection). If the frame is blank or shows a refusal, framing is blocked.</p>
<iframe src="{target}" width="1100" height="520" style="border:3px solid #cf222e"></iframe>
</body>""")


def run(name, fn):
    try:
        fn()
        print("ok  ", name)
    except Exception as e:  # noqa: BLE001
        print("FAIL", name, type(e).__name__, str(e)[:200])


with sync_playwright() as p:
    browser = p.chromium.launch()
    ctx = browser.new_context(viewport={"width": 1366, "height": 900}, ignore_https_errors=True)
    page = ctx.new_page()

    def s1():
        page.goto(target, wait_until="load", timeout=45000)
        page.screenshot(path=str(shots / "01-target-homepage.png"))

    def s2():
        page.goto(clickjack.resolve().as_uri(), wait_until="load", timeout=45000)
        page.wait_for_timeout(4000)
        page.screenshot(path=str(shots / "02-clickjacking-iframe-test.png"), full_page=True)

    def s3():
        page.goto((evidence / "manual-checks.html").resolve().as_uri())
        page.screenshot(path=str(shots / "03-manual-checks.png"), full_page=True)

    def s4():
        page.goto(report.resolve().as_uri(), wait_until="load")
        page.screenshot(path=str(shots / "04-zap-report-summary.png"), full_page=False)
        page.screenshot(path=str(shots / "05-zap-report-full.png"), full_page=True)

    for n, f in (("homepage", s1), ("clickjacking", s2), ("manual-checks", s3), ("zap-report", s4)):
        run(n, f)
    browser.close()
