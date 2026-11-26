#!/usr/bin/env python3
"""Turn ZAP's JSON report into report-ready tables (Assignment Parts 3.5, 4, 5).

Usage: build_evidence.py <report_json.json> <evidence-dir> [github-step-summary-file]
Writes: findings.csv, findings-summary.md, risk-distribution.png (if matplotlib is installed)
"""
import csv
import html
import json
import re
import sys
from collections import Counter
from pathlib import Path

RISK = {"3": "High", "2": "Medium", "1": "Low", "0": "Informational"}
CONF = {"4": "User Confirmed", "3": "High", "2": "Medium", "1": "Low", "0": "False Positive"}


def clean(s, limit=None):
    s = re.sub(r"<[^>]+>", " ", s or "")
    s = html.unescape(re.sub(r"\s+", " ", s)).strip()
    return s[:limit] + "..." if limit and len(s) > limit else s


def main():
    report = json.loads(Path(sys.argv[1]).read_text())
    out = Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    summary_file = sys.argv[3] if len(sys.argv) > 3 else None

    findings = []
    for site in report.get("site", []):
        for a in site.get("alerts", []):
            inst = a.get("instances", [])
            first = inst[0] if inst else {}
            findings.append({
                "site": site.get("@name", ""),
                "name": a.get("name") or a.get("alert", ""),
                "risk": RISK.get(str(a.get("riskcode")), "?"),
                "riskcode": int(a.get("riskcode", 0)),
                "confidence": CONF.get(str(a.get("confidence")), a.get("confidence", "")),
                "cwe": a.get("cweid", ""),
                "wasc": a.get("wascid", ""),
                "plugin": a.get("pluginid", ""),
                "count": int(a.get("count", len(inst) or 0)),
                "example_url": first.get("uri", ""),
                "method": first.get("method", ""),
                "param": first.get("param", ""),
                "evidence": clean(first.get("evidence", ""), 200),
                "description": clean(a.get("desc")),
                "solution": clean(a.get("solution")),
                "reference": clean(a.get("reference")),
            })
    findings.sort(key=lambda f: (-f["riskcode"], -f["count"], f["name"]))

    with open(out / "findings.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(findings[0].keys()) if findings else ["name"])
        w.writeheader()
        w.writerows(findings)

    counts = Counter(f["risk"] for f in findings)
    md = ["# ZAP findings summary", "",
          f"ZAP version: {report.get('@version', '?')} | generated: {report.get('@generated', '?')}",
          f"Targets: {', '.join(sorted({f['site'] for f in findings})) or 'n/a'}", "",
          "## Alerts by risk", "", "| Risk | Alert types |", "|---|---|"]
    for r in ("High", "Medium", "Low", "Informational"):
        md.append(f"| {r} | {counts.get(r, 0)} |")
    md += ["", f"Total alert types: **{len(findings)}**", "",
           "## All alerts", "", "| # | Alert | Risk | Confidence | CWE | Instances | Example URL |", "|---|---|---|---|---|---|---|"]
    for i, f in enumerate(findings, 1):
        md.append(f"| {i} | {f['name']} | {f['risk']} | {f['confidence']} | {f['cwe']} | {f['count']} | {f['example_url']} |")

    real = [f for f in findings if f["riskcode"] >= 1 and f["confidence"] != "False Positive"]
    md += ["", f"## Report candidates (Low risk and above): {len(real)}",
           "The assignment needs at least 5 real vulnerabilities. Review each one for false positives before using it.", ""]
    for i, f in enumerate(real, 1):
        md += [f"### F{i}. {f['name']}", "",
               f"- **Risk / confidence:** {f['risk']} / {f['confidence']}",
               f"- **CWE / WASC:** {f['cwe']} / {f['wasc']}   |   **ZAP rule:** {f['plugin']}",
               f"- **Instances:** {f['count']}   |   **Example:** `{f['method']} {f['example_url']}`"
               + (f"  (param `{f['param']}`)" if f["param"] else ""),
               f"- **Evidence:** {f['evidence'] or 'n/a'}",
               f"- **What ZAP says:** {f['description']}",
               f"- **Recommended fix (ZAP):** {f['solution']}", ""]
    (out / "findings-summary.md").write_text("\n".join(md) + "\n")

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        labels = ["High", "Medium", "Low", "Informational"]
        colors = ["#cf222e", "#d4a72c", "#0969da", "#8c959f"]
        fig, ax = plt.subplots(figsize=(6, 3.4), dpi=160)
        vals = [counts.get(l, 0) for l in labels]
        bars = ax.bar(labels, vals, color=colors)
        ax.bar_label(bars)
        ax.set_ylabel("Alert types")
        ax.set_title("ZAP alerts by risk level")
        for s in ("top", "right"):
            ax.spines[s].set_visible(False)
        fig.tight_layout()
        fig.savefig(out / "risk-distribution.png")
    except Exception as e:  # noqa: BLE001
        print("chart skipped:", e)

    if summary_file:
        with open(summary_file, "a") as fh:
            fh.write("## ZAP assessment\n\n| Risk | Alert types |\n|---|---|\n")
            for r in ("High", "Medium", "Low", "Informational"):
                fh.write(f"| {r} | {counts.get(r, 0)} |\n")
            fh.write("\nDownload the **zap-evidence** artifact for the full bundle.\n\n")
            fh.write("| Alert | Risk | Instances |\n|---|---|---|\n")
            for f in findings[:25]:
                fh.write(f"| {f['name']} | {f['risk']} | {f['count']} |\n")
    print(f"{len(findings)} alert types; {len(real)} report candidates")


if __name__ == "__main__":
    main()
