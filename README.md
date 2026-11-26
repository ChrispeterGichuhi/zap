# Web Application Security Assessment with OWASP ZAP (Git + GitHub Actions)

One click in GitHub produces the scan, the manual-check results, screenshots, logs and report-ready finding tables.

## Run it

```bash
git init && git add . && git commit -m "ZAP assessment pipeline"
git branch -M main
git remote add origin https://github.com/<you>/zap-scan.git
git push -u origin main
```

1. GitHub -> **Actions** -> **ZAP Security Assessment** -> **Run workflow**.
2. Choose the inputs (see "Choosing a target" below), then run. A full scan takes about 10-60 minutes.
3. Open the finished run -> **Artifacts** -> download **zap-evidence**. The run's Summary page also shows the risk table.

Re-runs are versioned by Actions, so the history of every scan stays in Git/GitHub.

## Choosing a target (Part 2)

| Mode | What it scans | When to use it |
|---|---|---|
| `url` + `authorized = yes` | The public URL you type in | Only if you have permission (instructor approval or a site that explicitly invites testing). Fill in `TARGET_AUTHORIZATION.md` and keep it in the repo. |
| `juice-shop` | OWASP Juice Shop started inside the runner | No permission risk at all. Everyone scanning the same default app risks the "same website = 0 marks" rule, so tell your instructor what you chose. |

An active scan sends attack traffic. Do not tick `authorized` for a site you do not own or have written approval to test.

## Where each assignment part is covered

| Part | Requirement | Produced by | File in the evidence bundle |
|---|---|---|---|
| 1.1 | Install ZAP from the official source | Pulls the official ZAP image, logs digest and version | `01-zap-setup.log` |
| 1.2 | Learn the UI and basic functions | ZAP CLI help dump. For the GUI, use the optional desktop job or your own screenshots | `01-zap-setup.log`, `screenshots/10-*.png` |
| 2.2 | Document the target URL | Target step | `00-target.md` |
| 3.1 | Launch ZAP | `zap.sh -version` in the log, GUI screenshot if enabled | `01-zap-setup.log`, `screenshots/10-*.png` |
| 3.2 | Configure ZAP for the target | Scan options written out | `02-zap-config.txt`, `screenshots/11-*.png` |
| 3.3 | Automated scan | `zap-full-scan.py` (spider, AJAX spider, active scan) | `03-zap-scan-console.log`, `zap-out/report_*.{html,json,md,xml}` |
| 3.4 | Manual assessment | `manual_checks.py` plus the clickjacking iframe test | `manual-checks.{md,json,html}`, `clickjack-test.html`, `screenshots/02,03` |
| 3.5 | Document findings with evidence (5 or more) | `build_evidence.py` | `findings-summary.md`, `findings.csv`, `risk-distribution.png`, `screenshots/04,05` |
| 4 | Analysis, exploitation, impact, mitigation | ZAP description and solution per finding, pre-filled | `findings-summary.md` (you add your own analysis) |
| 5 | Report | You, with Claude: send the evidence bundle | |
| 6 | Presentation | Built from the same bundle | |

## Still manual (about 10 minutes)

- Take 3 screenshots of the ZAP desktop app on your own machine: installer or About box, main window, target entered in Automated Scan. The CI job cannot prove you personally installed it.
- Put your name, university, course and instructor on the report cover.
- Review every finding for false positives before you list it as a vulnerability.

## Repo layout

```
.github/workflows/zap-assessment.yml   the pipeline
scripts/manual_checks.py               headers, cookies, TLS, methods, robots.txt, forms, directory listing
scripts/screenshots.py                 homepage, clickjacking iframe test, checks table, ZAP report
scripts/build_evidence.py              ZAP JSON -> CSV, markdown tables, risk chart
TARGET_AUTHORIZATION.md                permission record template
```
