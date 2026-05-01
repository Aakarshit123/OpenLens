# modules/report_gen.py
"""
Report Generator Module
Generates HTML and JSON reports from OSINT scan results.
- Dorks section: only shows dorks that have confirmed results (has_results=True),
  with unknown-status dorks in a separate collapsible section.
- Includes directory busting and JS/API endpoint sections.
"""

import json
import os
from datetime import datetime
from pathlib import Path


class ReportGenerator:
    def __init__(self, target: str, results: dict, output_dir: str = "reports"):
        self.target = target
        self.results = results
        self.output_dir = output_dir
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        Path(output_dir).mkdir(parents=True, exist_ok=True)

    def generate_json(self) -> str:
        path = os.path.join(self.output_dir, f"{self.target}_{self.timestamp}.json")
        payload = {
            "target": self.target,
            "scan_time": datetime.now().isoformat(),
            "results": self.results
        }
        with open(path, "w") as f:
            json.dump(payload, f, indent=2, default=str)
        return path

    # ── Section builders ──────────────────────────────────────────────────────

    def _dns_section(self) -> str:
        dns_data = self.results.get("dns", {})
        if not dns_data:
            return "<p class='empty'>No DNS data collected.</p>"

        # Support both old flat-list format and new structured dict format
        if isinstance(dns_data, list):
            records = [r for r in dns_data if r["type"] not in ("WHOIS", "IP_INFO")]
            whois   = next((r["value"] for r in dns_data if r["type"] == "WHOIS"), {})
            ip_info = next((r["value"] for r in dns_data if r["type"] == "IP_INFO"), {})
        else:
            records = dns_data.get("records", [])
            whois   = dns_data.get("whois", {})
            ip_info = dns_data.get("ip_info", {})

        if not records and not whois and not ip_info:
            return "<p class='empty'>No DNS data collected.</p>"

        rows = ""
        for r in records:
            val = r["value"] if isinstance(r["value"], str) else json.dumps(r["value"], indent=2)
            rows += f"<tr><td class='tag'>{r['type']}</td><td>{val}</td><td>{r.get('ttl','')}</td></tr>"

        whois_rows = "".join(
            f"<tr><td class='tag'>{k.replace('_',' ').title()}</td><td>{v}</td></tr>"
            for k, v in whois.items() if k != "error"
        ) if whois else ""

        return f"""
        <div class='subsection'>
            <h3>DNS Records ({len(records)})</h3>
            <table><thead><tr><th>Type</th><th>Value</th><th>TTL</th></tr></thead>
            <tbody>{rows if rows else "<tr><td colspan='3' class='empty'>No DNS records found.</td></tr>"}</tbody></table>
        </div>
        <div class='subsection'>
            <h3>IP Info</h3>
            <p><strong>IP Address:</strong> {ip_info.get('ip','N/A')}</p>
            <p><strong>Reverse DNS:</strong> {ip_info.get('reverse_dns','N/A')}</p>
        </div>
        <div class='subsection'>
            <h3>WHOIS Information</h3>
            <table><thead><tr><th>Field</th><th>Value</th></tr></thead>
            <tbody>{whois_rows if whois_rows else "<tr><td colspan='2' class='empty'>No WHOIS data.</td></tr>"}</tbody></table>
        </div>
        """

    def _subdomain_section(self) -> str:
        subs = self.results.get("subdomains", [])
        if not subs:
            return "<p class='empty'>No subdomains found.</p>"
        rows = "".join(
            f"<tr><td>{s['subdomain']}</td><td>{s['ip']}</td><td><span class='badge'>{s['source']}</span></td></tr>"
            for s in subs
        )
        return f"""
        <table><thead><tr><th>Subdomain</th><th>IP</th><th>Source</th></tr></thead>
        <tbody>{rows}</tbody></table>"""

    def _email_section(self) -> str:
        emails = self.results.get("emails", [])
        if not emails:
            return "<p class='empty'>No emails harvested.</p>"
        rows = "".join(
            f"<tr><td>{e['email']}</td><td>{e.get('first_name','')} {e.get('last_name','')}</td>"
            f"<td>{e.get('position','')}</td><td><span class='badge'>{e.get('source','')}</span></td></tr>"
            for e in emails
        )
        return f"""
        <table><thead><tr><th>Email</th><th>Name</th><th>Position</th><th>Source</th></tr></thead>
        <tbody>{rows}</tbody></table>"""

    def _shodan_section(self) -> str:
        ports = self.results.get("shodan", [])
        if not ports:
            return "<p class='empty'>No Shodan data (API key required).</p>"
        rows = ""
        for p in ports:
            vulns = ", ".join(p.get("vulns", [])) or "None"
            vuln_class = "vuln-cell danger" if p.get("vulns") else "vuln-cell"
            rows += (f"<tr><td>{p.get('port')}</td><td>{p.get('protocol')}</td>"
                     f"<td>{p.get('service')}</td><td>{p.get('product','')} {p.get('version','')}</td>"
                     f"<td class='{vuln_class}'>{vulns}</td></tr>")
        return f"""
        <table><thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Product</th><th>CVEs</th></tr></thead>
        <tbody>{rows}</tbody></table>"""

    def _dorks_section(self) -> str:
        """
        Only show dorks with confirmed results (has_results=True).
        Dorks with has_results=None (unknown/blocked) go in a separate collapsible.
        Dorks with has_results=False are omitted entirely.
        """
        dorks = self.results.get("dorks", [])
        if not dorks:
            return "<p class='empty'>No dorks generated.</p>"

        confirmed = [d for d in dorks if d.get("has_results") is True]
        unknown = [d for d in dorks if d.get("has_results") is None]

        html = ""

        if confirmed:
            # Group confirmed by category
            cats = {}
            for d in confirmed:
                cats.setdefault(d["category"], []).append(d)
            for cat, items in cats.items():
                html += f"<h3 class='dork-cat'>{cat} <span class='dork-count'>{len(items)} hits</span></h3>"
                for item in items:
                    html += f"""
                    <div class='dork-card dork-hit'>
                        <div class='dork-desc'>{item['description']}</div>
                        <code>{item['query']}</code>
                        <a href='{item['url']}' target='_blank' class='dork-link'>Search on Google →</a>
                    </div>"""
        else:
            html += "<p class='empty'>No dorks returned confirmed results. See 'Unverified Queries' below.</p>"

        if unknown:
            html += f"""
            <details style='margin-top:20px'>
                <summary style='cursor:pointer;color:var(--muted);font-size:13px;padding:8px 0'>
                    ▶ {len(unknown)} unverified queries (Google blocked verification — open manually)
                </summary>
                <div style='margin-top:12px'>"""
            for item in unknown:
                html += f"""
                <div class='dork-card'>
                    <div class='dork-desc'>{item['description']}</div>
                    <code>{item['query']}</code>
                    <a href='{item['url']}' target='_blank' class='dork-link'>Search on Google →</a>
                </div>"""
            html += "</div></details>"

        return html

    def _breach_section(self) -> str:
        breaches = self.results.get("breach", [])
        if not breaches:
            return "<p class='empty'>No breach data (API key required or no emails found).</p>"
        html = ""
        for b in breaches:
            status = "🔴 BREACHED" if b.get("breached") else "🟢 Clean"
            status_class = "breached" if b.get("breached") else "clean"
            html += f"<div class='breach-card {status_class}'>"
            html += f"<div class='breach-email'>{b['email']} <span class='breach-status'>{status}</span></div>"
            if b.get("breaches"):
                html += "<ul class='breach-list'>"
                for breach in b["breaches"]:
                    html += f"<li><strong>{breach['name']}</strong> ({breach['breach_date']}) — {', '.join(breach['data_classes'][:4])}</li>"
                html += "</ul>"
            html += "</div>"
        return html

    def _dirb_section(self) -> str:
        hits = self.results.get("dirb", [])
        if not hits:
            return "<p class='empty'>No accessible directories or files found.</p>"

        status_colors = {200: "ok", 301: "redirect", 302: "redirect", 401: "warn", 403: "warn", 405: "warn"}
        rows = ""
        for h in hits:
            sc = h["status"]
            cls = status_colors.get(sc, "")
            redirect_cell = f'<a href="{h["redirect"]}" target="_blank" style="color:var(--accent2)">{h["redirect"][:60]}</a>' if h.get("redirect") else ""
            rows += (f"<tr>"
                     f"<td><a href='{h['url']}' target='_blank' style='color:var(--accent)'>{h['path']}</a></td>"
                     f"<td><span class='status-{cls}'>{sc} {h['status_label']}</span></td>"
                     f"<td>{h.get('content_type','')}</td>"
                     f"<td>{h.get('content_length',0):,}</td>"
                     f"<td>{redirect_cell}</td>"
                     f"</tr>")
        return f"""
        <table>
            <thead><tr><th>Path</th><th>Status</th><th>Content-Type</th><th>Size (bytes)</th><th>Redirect</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>"""

    def _jscan_section(self) -> str:
        data = self.results.get("jscan", {})
        if not data or (not data.get("js_files") and not data.get("api_endpoints")):
            return "<p class='empty'>No JS files found or scan not run.</p>"

        js_files = data.get("js_files", [])
        endpoints = data.get("api_endpoints", [])
        secrets = [e for e in endpoints if e.get("is_secret")]
        api_eps = [e for e in endpoints if not e.get("is_secret")]

        html = ""

        # JS files table
        if js_files:
            html += "<div class='subsection'><h3>Discovered JS Files</h3>"
            rows = ""
            for f in js_files:
                dl = "✅" if f["downloaded"] else "❌"
                rows += (f"<tr><td><a href='{f['url']}' target='_blank' style='color:var(--accent2);word-break:break-all'>{f['url']}</a></td>"
                         f"<td>{f['size_bytes']:,}</td><td>{f['endpoints_found']}</td><td>{dl}</td></tr>")
            html += f"""<table>
                <thead><tr><th>URL</th><th>Size (bytes)</th><th>Endpoints Found</th><th>Downloaded</th></tr></thead>
                <tbody>{rows}</tbody></table></div>"""

        # Secrets section (highlighted)
        if secrets:
            html += f"<div class='subsection'><h3 style='color:var(--red)'>⚠️ Potential Secrets / Hardcoded Credentials ({len(secrets)})</h3>"
            rows = ""
            for ep in secrets:
                rows += (f"<tr>"
                         f"<td><span class='badge badge-red'>{ep['type']}</span></td>"
                         f"<td style='font-family:var(--font-mono);color:var(--red);word-break:break-all'>{ep['value']}</td>"
                         f"<td style='word-break:break-all;color:var(--muted)'>{ep['source_js'].split('/')[-1]}</td>"
                         f"</tr>")
            html += f"""<table>
                <thead><tr><th>Type</th><th>Value</th><th>Source File</th></tr></thead>
                <tbody>{rows}</tbody></table></div>"""

        # API endpoints
        if api_eps:
            # Group by source JS
            by_source = {}
            for ep in api_eps:
                src = ep["source_js"]
                by_source.setdefault(src, []).append(ep)

            html += f"<div class='subsection'><h3>API Endpoints & Requests ({len(api_eps)} found)</h3>"
            for src, eps in by_source.items():
                filename = src.split("/")[-1] or src
                html += f"<p style='color:var(--accent2);font-size:12px;margin:12px 0 6px;font-family:var(--font-mono)'>{filename}</p>"
                rows = ""
                for ep in eps:
                    rows += (f"<tr>"
                             f"<td><span class='badge'>{ep['type']}</span></td>"
                             f"<td style='font-family:var(--font-mono);word-break:break-all'>{ep['value']}</td>"
                             f"</tr>")
                html += f"""<table>
                    <thead><tr><th>Method/Type</th><th>Endpoint / Value</th></tr></thead>
                    <tbody>{rows}</tbody></table>"""
            html += "</div>"

        return html

    # ── HTML generation ───────────────────────────────────────────────────────

    def generate_html(self) -> str:
        path = os.path.join(self.output_dir, f"{self.target}_{self.timestamp}.html")

        dorks = self.results.get("dorks", [])
        confirmed_dorks = sum(1 for d in dorks if d.get("has_results") is True)

        jscan = self.results.get("jscan", {})
        js_count = len(jscan.get("js_files", [])) if isinstance(jscan, dict) else 0
        ep_count = len(jscan.get("api_endpoints", [])) if isinstance(jscan, dict) else 0
        secret_count = sum(1 for e in jscan.get("api_endpoints", []) if e.get("is_secret")) if isinstance(jscan, dict) else 0
        dirb_count = len(self.results.get("dirb", []))

        # DNS: count only actual DNS records, not WHOIS/IP entries
        raw_dns = self.results.get("dns", {})
        if isinstance(raw_dns, dict):
            dns_record_count = len(raw_dns.get("records", []))
        else:
            dns_record_count = sum(1 for r in raw_dns if r.get("type") not in ("WHOIS", "IP_INFO"))

        total_findings = (
            len(self.results.get("subdomains", [])) +
            len(self.results.get("emails", [])) +
            dns_record_count +
            len(self.results.get("shodan", [])) +
            confirmed_dorks +
            dirb_count +
            ep_count
        )

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OSINT Report — {self.target}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');

  :root {{
    --bg: #0a0c10;
    --surface: #111318;
    --surface2: #181c24;
    --border: #1f2937;
    --accent: #00ff88;
    --accent2: #0ea5e9;
    --red: #ff4455;
    --yellow: #fbbf24;
    --text: #e2e8f0;
    --muted: #64748b;
    --font-mono: 'Share Tech Mono', monospace;
    --font-ui: 'Rajdhani', sans-serif;
  }}

  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ background: var(--bg); color: var(--text); font-family: var(--font-ui); font-size: 16px; line-height: 1.6; }}

  .header {{
    background: linear-gradient(135deg, #0a0c10 0%, #0d1117 100%);
    border-bottom: 1px solid var(--accent);
    padding: 40px 60px;
    position: relative; overflow: hidden;
  }}
  .header::before {{
    content: ''; position: absolute; top:0;left:0;right:0;bottom:0;
    background: repeating-linear-gradient(0deg, transparent, transparent 30px, rgba(0,255,136,0.02) 30px, rgba(0,255,136,0.02) 31px);
    pointer-events: none;
  }}
  .header-label {{ font-family: var(--font-mono); color: var(--accent); font-size: 12px; letter-spacing: 4px; text-transform: uppercase; margin-bottom: 8px; }}
  .header h1 {{ font-size: 42px; font-weight: 700; letter-spacing: 2px; color: #fff; }}
  .header h1 span {{ color: var(--accent); }}
  .header-meta {{ font-family: var(--font-mono); color: var(--muted); font-size: 13px; margin-top: 12px; display: flex; gap: 30px; flex-wrap: wrap; }}
  .header-meta span {{ color: var(--accent2); }}

  .stats-bar {{ background: var(--surface); border-bottom: 1px solid var(--border); padding: 20px 60px; display: flex; gap: 40px; flex-wrap: wrap; }}
  .stat {{ display: flex; flex-direction: column; }}
  .stat-num {{ font-size: 28px; font-weight: 700; color: var(--accent); font-family: var(--font-mono); }}
  .stat-num.danger {{ color: var(--red); }}
  .stat-label {{ font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; }}

  .container {{ max-width: 1200px; margin: 0 auto; padding: 40px 60px; }}

  .section {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 32px; overflow: hidden; }}
  .section-header {{ background: var(--surface2); padding: 16px 24px; display: flex; align-items: center; gap: 12px; border-bottom: 1px solid var(--border); }}
  .section-icon {{ font-size: 20px; }}
  .section-title {{ font-size: 18px; font-weight: 700; letter-spacing: 1px; color: #fff; flex: 1; }}
  .section-count {{ font-family: var(--font-mono); font-size: 13px; color: var(--accent); background: rgba(0,255,136,0.1); padding: 2px 10px; border-radius: 20px; }}
  .section-count.danger {{ color: var(--red); background: rgba(255,68,85,0.1); }}
  .section-body {{ padding: 24px; }}
  .subsection {{ margin-bottom: 28px; }}
  .subsection h3 {{ font-size: 14px; color: var(--accent2); text-transform: uppercase; letter-spacing: 2px; margin-bottom: 12px; padding-bottom: 6px; border-bottom: 1px solid var(--border); }}

  table {{ width: 100%; border-collapse: collapse; font-size: 14px; margin-bottom: 8px; }}
  th {{ background: var(--surface2); color: var(--muted); font-size: 11px; letter-spacing: 2px; text-transform: uppercase; padding: 10px 14px; text-align: left; border-bottom: 1px solid var(--border); }}
  td {{ padding: 10px 14px; border-bottom: 1px solid rgba(31,41,55,0.5); font-family: var(--font-mono); font-size: 13px; word-break: break-all; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: rgba(0,255,136,0.03); }}

  .tag {{ color: var(--accent2); font-weight: bold; white-space: nowrap; }}
  .badge {{ background: rgba(14,165,233,0.15); color: var(--accent2); padding: 2px 8px; border-radius: 4px; font-size: 11px; letter-spacing: 1px; white-space: nowrap; }}
  .badge-red {{ background: rgba(255,68,85,0.15); color: var(--red); }}
  .vuln-cell {{ color: var(--muted); }}
  .vuln-cell.danger {{ color: var(--red); font-weight: bold; }}

  /* Status codes */
  .status-ok {{ color: var(--accent); font-weight: bold; }}
  .status-redirect {{ color: var(--accent2); }}
  .status-warn {{ color: var(--yellow); }}

  /* Dork cards */
  .dork-cat {{ font-size: 14px; color: var(--accent2); text-transform: uppercase; letter-spacing: 2px; margin: 16px 0 8px; padding-bottom: 6px; border-bottom: 1px solid var(--border); }}
  .dork-count {{ font-size: 12px; background: rgba(0,255,136,0.1); color: var(--accent); padding: 2px 8px; border-radius: 10px; margin-left: 8px; }}
  .dork-card {{ background: var(--surface2); border: 1px solid var(--border); border-radius: 6px; padding: 14px 18px; margin-bottom: 10px; }}
  .dork-hit {{ border-left: 3px solid var(--accent); }}
  .dork-desc {{ font-size: 13px; color: var(--muted); margin-bottom: 6px; }}
  .dork-card code {{ display: block; font-family: var(--font-mono); font-size: 12px; color: var(--accent); margin-bottom: 8px; word-break: break-all; }}
  .dork-link {{ font-size: 12px; color: var(--accent2); text-decoration: none; }}
  .dork-link:hover {{ text-decoration: underline; }}

  /* Breach cards */
  .breach-card {{ background: var(--surface2); border-radius: 6px; padding: 14px 18px; margin-bottom: 10px; border-left: 3px solid var(--muted); }}
  .breach-card.breached {{ border-left-color: var(--red); }}
  .breach-card.clean {{ border-left-color: var(--accent); }}
  .breach-email {{ font-family: var(--font-mono); font-size: 14px; font-weight: bold; margin-bottom: 6px; }}
  .breach-status {{ font-size: 12px; margin-left: 8px; }}
  .breach-list {{ font-size: 13px; color: var(--muted); padding-left: 20px; }}
  .breach-list li {{ margin-bottom: 4px; }}

  .empty {{ color: var(--muted); font-style: italic; font-size: 14px; }}
  p {{ margin-bottom: 8px; font-size: 14px; }}

  .footer {{ text-align: center; padding: 40px; color: var(--muted); font-family: var(--font-mono); font-size: 12px; border-top: 1px solid var(--border); margin-top: 40px; }}
  .footer span {{ color: var(--accent); }}

  details summary {{ user-select: none; }}
  details summary::-webkit-details-marker {{ display: none; }}
</style>
</head>
<body>

<div class="header">
  <div class="header-label">// Powerd By OSINT</div>
  <h1>Target: <span>{self.target}</span></h1>
  <div class="header-meta">
    <div>Scan Date: <span>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span></div>
    <div>Modules Run: <span>{len(self.results)}</span></div>
    <div>Total Findings: <span>{total_findings}</span></div>
  </div>
</div>

<div class="stats-bar">
  <div class="stat"><div class="stat-num">{len(self.results.get('subdomains',[]))}</div><div class="stat-label">Subdomains</div></div>
  <div class="stat"><div class="stat-num">{len(self.results.get('emails',[]))}</div><div class="stat-label">Emails</div></div>
  <div class="stat"><div class="stat-num">{dns_record_count}</div><div class="stat-label">DNS Records</div></div>
  <div class="stat"><div class="stat-num">{len(self.results.get('shodan',[]))}</div><div class="stat-label">Open Ports</div></div>
  <div class="stat"><div class="stat-num">{confirmed_dorks}</div><div class="stat-label">Dork Hits</div></div>
  <div class="stat"><div class="stat-num">{dirb_count}</div><div class="stat-label">Dir Hits</div></div>
  <div class="stat"><div class="stat-num">{js_count}</div><div class="stat-label">JS Files</div></div>
  <div class="stat"><div class="stat-num">{ep_count}</div><div class="stat-label">API Endpoints</div></div>
  <div class="stat"><div class="stat-num {'danger' if secret_count else ''}">{secret_count}</div><div class="stat-label">Secrets Found</div></div>
</div>

<div class="container">

  <div class="section">
    <div class="section-header">
      <div class="section-icon">🌐</div>
      <div class="section-title">DNS & WHOIS</div>
      <div class="section-count">{dns_record_count} records</div>
    </div>
    <div class="section-body">{self._dns_section()}</div>
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-icon">🔍</div>
      <div class="section-title">Subdomain Enumeration</div>
      <div class="section-count">{len(self.results.get('subdomains',[]))} found</div>
    </div>
    <div class="section-body">{self._subdomain_section()}</div>
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-icon">📧</div>
      <div class="section-title">Email Harvesting</div>
      <div class="section-count">{len(self.results.get('emails',[]))} emails</div>
    </div>
    <div class="section-body">{self._email_section()}</div>
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-icon">🛰️</div>
      <div class="section-title">Shodan — Open Ports & Services</div>
      <div class="section-count">{len(self.results.get('shodan',[]))} services</div>
    </div>
    <div class="section-body">{self._shodan_section()}</div>
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-icon">🎯</div>
      <div class="section-title">Google Dork Queries</div>
      <div class="section-count">{confirmed_dorks} confirmed hits</div>
    </div>
    <div class="section-body">{self._dorks_section()}</div>
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-icon">📂</div>
      <div class="section-title">Directory Busting</div>
      <div class="section-count">{dirb_count} paths found</div>
    </div>
    <div class="section-body">{self._dirb_section()}</div>
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-icon">⚙️</div>
      <div class="section-title">JS Files & API Endpoint Extraction</div>
      <div class="section-count {'danger' if secret_count else ''}">{ep_count} endpoints · {secret_count} secrets</div>
    </div>
    <div class="section-body">{self._jscan_section()}</div>
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-icon">🔓</div>
      <div class="section-title">Data Breach Check</div>
      <div class="section-count">{len(self.results.get('breach',[]))} checked</div>
    </div>
    <div class="section-body">{self._breach_section()}</div>
  </div>

</div>

<div class="footer">
  Generated by <span>OSINT-EX Framework v2.0</span> — For authorized security research only.
</div>

</body>
</html>"""

        with open(path, "w") as f:
            f.write(html)
        return path
