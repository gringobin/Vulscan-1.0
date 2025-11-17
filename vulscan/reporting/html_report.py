# html_report.py
from datetime import datetime
import html
import os

ASCII_LOGO = r"""
██╗   ██╗██╗   ██╗██╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
██║   ██║██║   ██║██║     ██╔════╝██╔════╝██╔══██╗████╗  ██║
██║   ██║██║   ██║██║     ███████╗██║     ███████║██╔██╗ ██║
╚██╗ ██╔╝██║   ██║██║     ╚════██║██║     ██╔══██║██║╚██╗██║
 ╚████╔╝ ╚██████╔╝███████╗███████║╚██████╗██║  ██║██║ ╚████║
  ╚═══╝   ╚═════╝ ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
                       V U L S C A N   v2.0
"""

HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Vulscan Report - {target}</title>
<style>
body {{ font-family: Arial, Helvetica, sans-serif; margin: 20px; color:#222; }}
pre.logo {{ font-family: monospace; font-size: 12px; line-height: 12px; background:#111; color:#0f0; padding:10px; border-radius:4px; }}
h1 {{ margin-top: 10px; }}
.section {{ margin-top: 18px; }}
.table {{ border-collapse: collapse; width:100%; }}
.table th, .table td {{ border:1px solid #ddd; padding:8px; text-align:left; }}
.table th {{ background:#f4f4f4; }}
.small {{ font-size:12px; color:#666; }}
.badge {{ display:inline-block; padding:3px 7px; border-radius:4px; font-weight:600; }}
.cvss-high {{ background:#d9534f; color:#fff; }}
.cvss-med {{ background:#f0ad4e; color:#000; }}
.cvss-low {{ background:#5cb85c; color:#fff; }}
</style>
</head>
<body>
<pre class="logo">{logo}</pre>
<h1>Vulscan Vulnerability Report</h1>
<div class="small">Target: {target} | Generated: {generated}</div>

<div class="section">
  <h2>Summary</h2>
  <p>Open ports: <strong>{open_ports}</strong> &nbsp; CVEs found: <strong>{cve_count}</strong></p>
</div>

<div class="section">
  <h2>Open Ports</h2>
  <table class="table">
    <thead><tr><th>Port</th><th>Service</th><th>Version / Banner</th></tr></thead>
    <tbody>
    {ports_rows}
    </tbody>
  </table>
</div>

<div class="section">
  <h2>Vulnerabilities (top)</h2>
  <table class="table">
    <thead><tr><th>CVE</th><th>CVSS</th><th>Sources</th><th>Description</th></tr></thead>
    <tbody>
    {cve_rows}
    </tbody>
  </table>
</div>

</body>
</html>
"""

def _fmt_cvss_badge(cvss):
    try:
        s = float(cvss)
    except:
        return '<span class="badge small">n/a</span>'
    if s >= 9.0:
        return f'<span class="badge cvss-high">{s}</span>'
    if s >= 7.0:
        return f'<span class="badge cvss-med">{s}</span>'
    return f'<span class="badge cvss-low">{s}</span>'

def export_html(target, scan_info, cve_list, outpath):
    generated = datetime.utcnow().isoformat() + "Z"
    ports_rows = ""
    for p in scan_info:
        port = html.escape(str(p.get("port") or ""))
        service = html.escape(str(p.get("service") or ""))
        version = html.escape(str(p.get("version") or ""))[:200]
        ports_rows += f"<tr><td>{port}</td><td>{service}</td><td>{version}</td></tr>\n"

    cve_rows = ""
    for c in cve_list:
        cid = html.escape(c.get("id") or "")
        cvss = c.get("cvss")
        cvss_badge = _fmt_cvss_badge(cvss)
        sources = html.escape(", ".join(c.get("sources") or []))[:200]
        summary = html.escape((c.get("summary") or "")[:300])
        cve_rows += f"<tr><td>{cid}</td><td>{cvss_badge}</td><td>{sources}</td><td>{summary}</td></tr>\n"

    html_text = HTML_TEMPLATE.format(
        logo=ASCII_LOGO,
        target=html.escape(target),
        generated=generated,
        open_ports=len(scan_info),
        cve_count=len(cve_list),
        ports_rows=ports_rows,
        cve_rows=cve_rows
    )

    try:
        with open(outpath, "w", encoding="utf-8") as f:
            f.write(html_text)
        return True
    except Exception:
        return False
