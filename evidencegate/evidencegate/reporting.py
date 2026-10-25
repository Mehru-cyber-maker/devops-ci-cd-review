"""Portable reports. Untrusted values are escaped for HTML and spreadsheets."""

import csv
from html import escape
import json
from pathlib import Path


def csv_cell(value):
    value = str(value)
    # Prevent formulas when a spreadsheet opens attacker-supplied identifiers.
    return "'" + value if value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")) else value


def write_report(report: dict, directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    with (directory / "findings.csv").open("w", newline="", encoding="utf-8") as handle:
        fields = ["id", "category", "status", "message", "action"]
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows({k: csv_cell(c[k]) for k in fields} for c in report["checks"])
    rows = "".join(
        f'<tr class="{c["status"]}"><td>{escape(c["id"])}</td><td>{escape(c["category"])}</td>'
        f'<td><b>{escape(c["status"].upper())}</b></td><td>{escape(c["message"])}'
        f'<small>{escape(c["action"])}</small></td></tr>' for c in report["checks"])
    vulns = "".join(
        f'<tr><td>{escape(v["id"])}</td><td>{escape(v["package"])}</td><td>{escape(v["severity"])}</td></tr>'
        for v in report["vulnerabilities"])
    limits = "".join(f"<li>{escape(s)}</li>" for s in report["limitations"])
    content = f'''<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<title>EvidenceGate report</title><style>
body{{font:16px/1.55 system-ui,sans-serif;background:#f2f5fa;color:#172c44;margin:0}}
main{{max-width:1100px;margin:40px auto;padding:28px;background:white;border-radius:14px}}
h1{{margin-bottom:4px}}.sub,small{{color:#526477}}.badge{{display:inline-block;padding:8px 16px;border-radius:6px;background:#dceee8}}
.block{{background:#fce2de;color:#a32622}}code{{word-break:break-all}}table{{width:100%;border-collapse:collapse;font-size:14px;margin:20px 0}}
td,th{{text-align:left;padding:12px;border-bottom:1px solid #dce3ec;vertical-align:top}}th{{background:#edf2f8}}
small{{display:block;margin-top:4px}}tr.fail td:first-child{{border-left:3px solid #c54e3e}}li{{margin:8px 0}}
button{{padding:9px 14px;border:1px solid #b6c5d6;border-radius:6px;background:white;cursor:pointer}}
@media print{{button{{display:none}}main{{margin:0;padding:0}}tr{{break-inside:avoid}}}}
</style><main><p class="sub">STUDENT RESEARCH PROTOTYPE · OFFLINE REPORT</p>
<h1>EvidenceGate</h1><p>Consistency checks for CI/CD security evidence.</p>
<h2 class="badge {'block' if report['decision'] == 'BLOCK' else ''}">{report['decision']}</h2>
<p>{report['summary']['passed']} of {report['summary']['total']} checks passed · {escape(report['assessed_at'])}</p>
<p><strong>Selected artifact SHA-256</strong><br><code>{escape(report['artifact_sha256'])}</code></p>
<p>PASS means the supplied claims satisfy the configured policy. Signatures and software behavior are not verified.</p>
<button id="toggle" type="button">Show failed checks only</button>
<table><thead><tr><th>Rule</th><th>Category</th><th>Status</th><th>Finding and action</th></tr></thead><tbody>{rows}</tbody></table>
<h2>Supplied vulnerability findings</h2>
{'<table><tr><th>ID</th><th>Package</th><th>Severity</th></tr>' + vulns + '</table>' if vulns else '<p>No vulnerability findings in the supported scan record. Check scan validity above.</p>'}
<h2>Interpretation limits</h2><ul>{limits}</ul>
<script>let failedOnly=false;document.getElementById('toggle').addEventListener('click',function(){{
failedOnly=!failedOnly;document.querySelectorAll('tr.pass').forEach(r=>r.hidden=failedOnly);
this.textContent=failedOnly?'Show all checks':'Show failed checks only';}});</script></main></html>'''
    (directory / "index.html").write_text(content, encoding="utf-8")
