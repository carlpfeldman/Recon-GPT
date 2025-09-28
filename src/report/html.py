# src/report/html.py
import sqlite3, html
from pathlib import Path

STYLE = """
body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Inter,Arial,sans-serif;margin:24px;}
h1{margin-bottom:0} .muted{color:#666} .chip{display:inline-block;padding:2px 8px;border-radius:12px;background:#eee;margin-right:6px}
table{border-collapse:collapse;width:100%;margin-top:10px}
th,td{border-bottom:1px solid #eee;padding:8px;text-align:left;font-size:14px}
th{background:#fafafa}
.sev-high{color:#b00020}.sev-medium{color:#b26b00}.sev-low{color:#2f6f2f}
pre{background:#0b1020;color:#e8eaf6;padding:12px;border-radius:8px;overflow:auto}
"""

def _sev_class(s):
  s = (s or "").lower()
  if "high" in s or "critical" in s: return "sev-high"
  if "med" in s: return "sev-medium"
  return "sev-low"

def generate(db_path: str, run_id: str, out_html: str):
  con = sqlite3.connect(db_path)
  cur = con.cursor()
  r = cur.execute("SELECT target, created_ts FROM runs WHERE id=?", (run_id,)).fetchone()
  target, ts = (r or ("?", 0))
  subs = cur.execute("SELECT host FROM subs WHERE run_id=? ORDER BY host", (run_id,)).fetchall()
  http = cur.execute("SELECT url,status,title,techs FROM http WHERE run_id=? ORDER BY url", (run_id,)).fetchall()
  nuc  = cur.execute("SELECT id,url,template,severity,name,matcher FROM nuclei WHERE run_id=? ORDER BY severity DESC", (run_id,)).fetchall()

  html_rows = []
  html_rows.append(f"<html><head><meta charset='utf-8'><title>Recon Report - {html.escape(target)}</title><style>{STYLE}</style></head><body>")
  html_rows.append(f"<h1>Recon Report</h1><div class='muted'>Run: {html.escape(run_id)} • Target: {html.escape(target)}</div>")

  # Summary
  html_rows.append("<h2>Summary</h2>")
  html_rows.append(f"<div class='chip'>Subdomains: {len(subs)}</div><div class='chip'>HTTP hosts: {len(http)}</div><div class='chip'>Findings: {len(nuc)}</div>")

  # Findings
  html_rows.append("<h2>Findings</h2>")
  if not nuc:
    html_rows.append("<div class='muted'>No nuclei findings.</div>")
  else:
    html_rows.append("<table><tr><th>Severity</th><th>Template</th><th>Name</th><th>URL</th><th>Matcher</th></tr>")
    for (_id,url,template,sev,name,matcher) in nuc:
      html_rows.append(
        f"<tr><td class='{_sev_class(sev)}'>{html.escape(sev or '')}</td>"
        f"<td>{html.escape(template or '')}</td>"
        f"<td>{html.escape(name or '')}</td>"
        f"<td>{html.escape(url or '')}</td>"
        f"<td>{html.escape(matcher or '')}</td></tr>"
      )
    html_rows.append("</table>")

  # HTTP inventory
  html_rows.append("<h2>HTTP Inventory</h2>")
  if not http:
    html_rows.append("<div class='muted'>No HTTP services discovered.</div>")
  else:
    html_rows.append("<table><tr><th>Status</th><th>URL</th><th>Title</th><th>Techs</th></tr>")
    for (url,status,title,techs) in http:
      html_rows.append(f"<tr><td>{status or ''}</td><td>{html.escape(url or '')}</td><td>{html.escape(title or '')}</td><td>{html.escape(techs or '')}</td></tr>")
    html_rows.append("</table>")

  # Subdomain list
  html_rows.append("<h2>Subdomains</h2>")
  if not subs:
    html_rows.append("<div class='muted'>No subdomains.</div>")
  else:
    html_rows.append("<pre>")
    for (h,) in subs:
      html_rows.append(html.escape(h))
    html_rows.append("</pre>")

  html_rows.append("</body></html>")
  Path(out_html).write_text("\n".join(html_rows), encoding="utf-8")
  return out_html
