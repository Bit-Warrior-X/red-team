"""
modules/report_generator.py
Generates HTML, JSON, and Markdown reports from scan results.
"""

import html
import json
import logging
from datetime import datetime
from urllib.parse import urlparse, urlunparse

from core.config import ScanConfig
from core.models import ScanResult, Vulnerability
from core.surface import aggregate_parameters, asset_to_dict

log = logging.getLogger("redscanner.report")

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLORS = {"critical": "#dc2626", "high": "#ea580c", "medium": "#d97706", "low": "#2563eb", "info": "#6b7280"}

# Limit rows in HTML/Markdown tables for readability (JSON is complete)
LIST_CAP = 250


def _cap_note(total: int, shown: int) -> str:
    if total <= shown:
        return ""
    return f"\n\n*… and {total - shown} more (see report.json for full lists).*"


class ReportGenerator:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.output_dir = config.output_dir

    def _rewrite_localhost_to_target(self, url: str) -> str:
        """Crawl fallbacks sometimes emit localhost; map to engagement base URL for real links."""
        if not url or not url.startswith(("http://", "https://")):
            return url
        try:
            p = urlparse(url)
            h = (p.hostname or "").lower()
            if h in ("localhost", "127.0.0.1") or (h and h.startswith("127.")):
                base = (self.config.base_url or f"http://{self.config.target}").rstrip("/")
                b = urlparse(base)
                path = p.path if p.path else "/"
                return urlunparse((b.scheme, b.netloc, path, p.params, p.query, p.fragment))
        except Exception:
            pass
        return url

    def _html_url_link(self, url: str) -> str:
        """Single-click <a> for http(s) URLs; escapes safely."""
        if not url:
            return ""
        href = self._rewrite_localhost_to_target(url)
        if href.startswith(("http://", "https://")):
            eh = html.escape(href, quote=True)
            el = html.escape(href)
            return (
                f'<a href="{eh}" target="_blank" rel="noopener noreferrer" '
                f'style="color:#38bdf8;text-decoration:underline;word-break:break-all">{el}</a>'
            )
        return html.escape(url)

    def _md_url_line(self, url: str) -> str:
        """Markdown bullet with clickable link."""
        h = self._rewrite_localhost_to_target(url)
        if h.startswith(("http://", "https://")):
            return f"- [{h}]({h})"
        return f"- `{url}`"

    def generate(self, results: ScanResult):
        self.output_dir.mkdir(parents=True, exist_ok=True)
        sorted_vulns = sorted(results.vulnerabilities, key=lambda v: SEVERITY_ORDER.get(v.severity, 5))

        self._generate_json(results, sorted_vulns)
        self._generate_markdown(results, sorted_vulns)
        self._generate_html(results, sorted_vulns)
        log.info(f"Reports written to {self.output_dir}")

    def _surface_payload(self, results: ScanResult, vulns: list[Vulnerability]) -> dict:
        params = aggregate_parameters(vulns, results.urls_scan_surface)
        return {
            "domains": results.domains,
            "domain_count": len(results.domains),
            "urls_crawled": results.urls_crawled,
            "urls_crawled_count": len(results.urls_crawled),
            "urls_historical": results.urls_historical,
            "urls_historical_count": len(results.urls_historical),
            "urls_scan_surface": results.urls_scan_surface,
            "urls_scan_surface_count": len(results.urls_scan_surface),
            "open_ports": results.open_ports,
            "open_port_count": len(results.open_ports),
            "http_assets": [asset_to_dict(a) for a in results.assets_discovered],
            "parameters_observed": params,
        }

    def _generate_json(self, results: ScanResult, vulns: list[Vulnerability]):
        surface = self._surface_payload(results, vulns)
        data = {
            "redscanner_version": "0.2",
            "scan_id": results.scan_id,
            "target": results.target,
            "strict_domain_reports": self.config.strict_domain_reports,
            "plan_title": self.config.plan_title,
            "plan_description": self.config.plan_description,
            "started_at": results.started_at.isoformat(),
            "finished_at": results.finished_at.isoformat() if results.finished_at else None,
            "modules_run": results.modules_run,
            "summary": self._severity_counts(vulns),
            "assets_discovered": len(results.assets_discovered),
            "methodology_frameworks": self.config.methodology_frameworks or None,
            "manual_phases": self.config.manual_phases or None,
            "research_references": self.config.research_references or None,
            "surface": surface,
            "vulnerabilities": [
                {
                    "type": v.vuln_type,
                    "severity": v.severity,
                    "url": v.url,
                    "parameter": v.parameter,
                    "payload": v.payload,
                    "evidence": v.evidence,
                    "description": v.description,
                    "remediation": v.remediation,
                    "cvss_score": v.cvss_score,
                    "cve_id": v.cve_id,
                    "tool": v.tool,
                }
                for v in vulns
            ],
        }
        path = self.output_dir / "report.json"
        path.write_text(json.dumps(data, indent=2))
        log.info(f"JSON report: {path}")

        surf_path = self.output_dir / "surface.json"
        surf_path.write_text(json.dumps(surface, indent=2))
        log.info(f"Surface JSON: {surf_path}")

    def _generate_markdown(self, results: ScanResult, vulns: list[Vulnerability]):
        counts = self._severity_counts(vulns)
        duration = ""
        if results.finished_at:
            duration = f"{(results.finished_at - results.started_at).total_seconds():.1f}s"

        params = aggregate_parameters(vulns, results.urls_scan_surface)

        lines = [
            f"# RedScanner Report — {results.target}",
            f"",
        ]
        if self.config.plan_title:
            lines.append(f"**Engagement:** {self.config.plan_title}")
            lines.append("")
        if self.config.plan_description:
            lines.append(self.config.plan_description)
            lines.append("")
        if self.config.methodology_frameworks:
            lines += ["## Methodology frameworks", ""]
            for fw in self.config.methodology_frameworks:
                lines.append(f"- {fw}")
            lines.append("")
        lines += [
            f"**Scan ID:** {results.scan_id}",
            f"**Date:** {results.started_at.strftime('%Y-%m-%d %H:%M')}",
            f"**Duration:** {duration}",
            f"**Modules:** {', '.join(results.modules_run)}",
            f"**HTTP assets (httpx):** {len(results.assets_discovered)}",
            f"",
        ]
        if self.config.strict_domain_reports:
            lines += [
                "**Domain scope:** The vulnerabilities section only includes findings whose URL host matches the target or its subdomains.",
                "",
            ]
        lines += [
            f"## Summary",
            f"",
            f"| Severity | Count |",
            f"|----------|-------|",
        ]
        for sev in ["critical", "high", "medium", "low", "info"]:
            lines.append(f"| {sev.capitalize()} | {counts.get(sev, 0)} |")

        # Attack surface
        lines += [
            "",
            "## Attack surface",
            "",
            f"- **Domains / hostnames:** {len(results.domains)}",
            f"- **Open ports (naabu):** {len(results.open_ports)}",
            f"- **Crawled URLs (recon):** {len(results.urls_crawled)}",
            f"- **Historical URLs (wayback/gau):** {len(results.urls_historical)}",
            f"- **Full scan URL list (nuclei + surface):** {len(results.urls_scan_surface)}",
            "",
        ]

        dom = results.domains[:LIST_CAP]
        lines.append("### Domains")
        lines.append("")
        for d in dom:
            lines.append(f"- `{d}`")
        lines.append(_cap_note(len(results.domains), len(dom)))

        if results.open_ports:
            lines += ["", "### Open ports", "", "| Host | Port | Protocol |", "|------|------|----------|"]
            for row in results.open_ports[:LIST_CAP]:
                lines.append(f"| {row.get('host','')} | {row.get('port','')} | {row.get('protocol','tcp')} |")
            lines.append(_cap_note(len(results.open_ports), min(len(results.open_ports), LIST_CAP)))

        lines += ["", "### HTTP services (httpx)", "", "| URL | IP | Port | Status | Title | Tech |", "|-----|-----|------|--------|-------|------|"]
        for a in results.assets_discovered[:LIST_CAP]:
            tech = ", ".join(a.tech[:5]) if a.tech else ""
            if len(tech) > 80:
                tech = tech[:77] + "..."
            port = str(a.port) if a.port is not None else ""
            title = (a.title or "")[:60].replace("|", "\\|")
            href = self._rewrite_localhost_to_target(a.url)
            url_cell = f"[{href}]({href})" if href.startswith(("http://", "https://")) else f"`{a.url}`"
            lines.append(
                f"| {url_cell} | {a.ip or ''} | {port} | {a.status_code or ''} | {title} | {tech} |"
            )
        lines.append(_cap_note(len(results.assets_discovered), min(len(results.assets_discovered), LIST_CAP)))

        cr = results.urls_crawled[:LIST_CAP]
        if cr:
            lines += ["", "### Crawled resources (clickable in HTML report)", ""]
            for u in cr:
                lines.append(self._md_url_line(u))
            lines.append(_cap_note(len(results.urls_crawled), len(cr)))

        hi = results.urls_historical[:LIST_CAP]
        if hi:
            lines += ["", "### Historical URLs (wayback / gau)", ""]
            for u in hi:
                lines.append(self._md_url_line(u))
            lines.append(_cap_note(len(results.urls_historical), len(hi)))

        ss = results.urls_scan_surface[:LIST_CAP]
        if ss:
            lines += ["", "### URLs in scanner scope", ""]
            for u in ss:
                lines.append(self._md_url_line(u))
            lines.append(_cap_note(len(results.urls_scan_surface), len(ss)))

        if params:
            lines += ["", "### Query parameters observed", "", "| Parameter | Occurrences | Example URLs | Tools |", "|-----------|-------------|--------------|-------|"]
            for p in params[:LIST_CAP]:
                ex = ", ".join(f"`{x}`" for x in p["example_urls"][:3])
                tools = ", ".join(p.get("tools") or [])
                lines.append(f"| `{p['name']}` | {p['occurrences']} | {ex} | {tools} |")
            lines.append(_cap_note(len(params), min(len(params), LIST_CAP)))

        if self.config.research_references:
            lines += ["## Tool / reference links", ""]
            for ref in self.config.research_references[:40]:
                lines.append(f"- {ref}")
            lines.append("")

        lines += ["", "## Vulnerabilities", ""]
        for i, v in enumerate(vulns, 1):
            lines.append(f"### {i}. [{v.severity.upper()}] {v.vuln_type}")
            lines.append(f"")
            vhref = self._rewrite_localhost_to_target(v.url)
            if vhref.startswith(("http://", "https://")):
                lines.append(f"- **URL:** [{vhref}]({vhref})")
            else:
                lines.append(f"- **URL:** {v.url}")
            if v.parameter:
                lines.append(f"- **Parameter:** {v.parameter}")
            if v.cve_id:
                lines.append(f"- **CVE:** {v.cve_id}")
            if v.cvss_score:
                lines.append(f"- **CVSS:** {v.cvss_score}")
            lines.append(f"- **Tool:** {v.tool}")
            lines.append(f"- **Description:** {v.description}")
            if v.evidence:
                lines.append(f"- **Evidence:** `{v.evidence[:200]}`")
            lines.append(f"- **Remediation:** {v.remediation}")
            lines.append("")

        path = self.output_dir / "report.md"
        path.write_text("\n".join(lines))
        log.info(f"Markdown report: {path}")

    def _generate_html(self, results: ScanResult, vulns: list[Vulnerability]):
        counts = self._severity_counts(vulns)
        duration = ""
        if results.finished_at:
            duration = f"{(results.finished_at - results.started_at).total_seconds():.1f}s"

        vuln_rows = ""
        for v in vulns:
            color = SEVERITY_COLORS.get(v.severity, "#6b7280")
            vuln_rows += f"""
            <tr>
                <td><span style="background:{color}22;color:{color};padding:2px 8px;border-radius:4px;font-weight:700;font-size:12px">{html.escape(str(v.severity))}</span></td>
                <td>{html.escape(str(v.vuln_type))}</td>
                <td style="word-break:break-all;max-width:300px;font-size:13px">{self._html_url_link(v.url)}</td>
                <td>{html.escape(str(v.parameter or '-'))}</td>
                <td>{html.escape(str(v.tool))}</td>
                <td style="font-size:13px">{html.escape((v.description or '')[:200])}</td>
            </tr>"""

        plan_ctx_html = ""
        if self.config.plan_title or self.config.plan_description or self.config.methodology_frameworks:
            parts = [
                "<div style='margin:12px 0 20px;padding:16px;background:#0f172a;border:1px solid #334155;border-radius:8px;font-size:13px;line-height:1.5'>"
            ]
            if self.config.plan_title:
                parts.append(f"<div style='font-weight:700;color:#f1f5f9;margin-bottom:8px'>{html.escape(self.config.plan_title)}</div>")
            if self.config.plan_description:
                parts.append(f"<p style='margin:0 0 12px;color:#94a3b8'>{html.escape(self.config.plan_description)}</p>")
            if self.config.methodology_frameworks:
                parts.append("<strong style='color:#94a3b8'>Frameworks</strong><ul style='margin:6px 0 0'>")
                for fw in self.config.methodology_frameworks:
                    parts.append(f"<li>{html.escape(fw)}</li>")
                parts.append("</ul>")
            parts.append("</div>")
            plan_ctx_html = "".join(parts)

        summary_cards = ""
        for sev in ["critical", "high", "medium", "low", "info"]:
            c = SEVERITY_COLORS[sev]
            count = counts.get(sev, 0)
            summary_cards += f'<div style="text-align:center;padding:16px 24px;background:{c}11;border:1px solid {c}33;border-radius:8px"><div style="font-size:28px;font-weight:800;color:{c}">{count}</div><div style="font-size:12px;color:{c};text-transform:uppercase;font-weight:600">{sev}</div></div>'

        def table_wrap(title: str, inner: str) -> str:
            return f"""<h2 style="color:#f1f5f9;font-size:18px;margin:28px 0 12px">{html.escape(title)}</h2>
<table>{inner}</table>"""

        # Domains
        dom_rows = ""
        for d in results.domains[:LIST_CAP]:
            dom_rows += f"<tr><td style='word-break:break-all'>{html.escape(d)}</td></tr>"
        domains_tbl = table_wrap(f"Domains ({len(results.domains)})", f"<tr><th>Hostname</th></tr>{dom_rows}")

        # Ports
        port_rows = ""
        for row in results.open_ports[:LIST_CAP]:
            port_rows += f"<tr><td>{html.escape(str(row.get('host','')))}</td><td>{row.get('port','')}</td><td>{html.escape(str(row.get('protocol','tcp')))}</td></tr>"
        ports_tbl = table_wrap(
            f"Open ports ({len(results.open_ports)})",
            f"<tr><th>Host</th><th>Port</th><th>Protocol</th></tr>{port_rows}" if port_rows else "<tr><td colspan='3'>No open ports recorded (run naabu module).</td></tr>",
        )

        # Assets
        asset_rows = ""
        for a in results.assets_discovered[:LIST_CAP]:
            tech = html.escape(", ".join(a.tech[:8]) if a.tech else "")
            asset_rows += f"""<tr>
                <td style="word-break:break-all;font-size:12px">{self._html_url_link(a.url)}</td>
                <td>{html.escape(str(a.ip or ''))}</td>
                <td>{a.port if a.port is not None else ''}</td>
                <td>{a.status_code if a.status_code is not None else ''}</td>
                <td style="max-width:200px;font-size:12px">{html.escape((a.title or '')[:80])}</td>
                <td style="font-size:11px;max-width:220px">{tech}</td>
                <td>{'yes' if a.alive else 'no'}</td>
            </tr>"""
        assets_tbl = table_wrap(
            f"HTTP services / assets ({len(results.assets_discovered)})",
            f"<tr><th>URL</th><th>IP</th><th>Port</th><th>HTTP</th><th>Title</th><th>Tech</th><th>Alive</th></tr>{asset_rows}" if asset_rows else "<tr><td colspan='7'>No httpx assets.</td></tr>",
        )

        def url_list_rows(urls: list[str], cap: int) -> str:
            rows = ""
            for u in urls[:cap]:
                rows += f"<tr><td style='word-break:break-all;font-size:12px'>{self._html_url_link(u)}</td></tr>"
            return rows

        crawl_tbl = table_wrap(
            f"Crawled URLs ({len(results.urls_crawled)})",
            f"<tr><th>URL</th></tr>{url_list_rows(results.urls_crawled, LIST_CAP)}" if results.urls_crawled else "<tr><td>No crawl output (recon crawl step).</td></tr>",
        )
        hist_tbl = table_wrap(
            f"Historical URLs — wayback/gau ({len(results.urls_historical)})",
            f"<tr><th>URL</th></tr>{url_list_rows(results.urls_historical, LIST_CAP)}" if results.urls_historical else "<tr><td>No historical URLs collected.</td></tr>",
        )
        scope_tbl = table_wrap(
            f"Scanner target URL list ({len(results.urls_scan_surface)})",
            f"<tr><th>URL</th></tr>{url_list_rows(results.urls_scan_surface, LIST_CAP)}" if results.urls_scan_surface else "<tr><td>No URLs in scope.</td></tr>",
        )

        params = aggregate_parameters(vulns, results.urls_scan_surface)
        param_rows = ""
        for p in params[:LIST_CAP]:
            ex_parts = []
            for x in p["example_urls"][:4]:
                ex_parts.append(self._html_url_link(x))
            ex = ", ".join(ex_parts)
            tools = html.escape(", ".join(p.get("tools") or []))
            param_rows += f"<tr><td><code>{html.escape(p['name'])}</code></td><td>{p['occurrences']}</td><td style='word-break:break-all;font-size:11px'>{ex}</td><td>{tools}</td></tr>"
        params_tbl = table_wrap(
            f"Query parameters observed ({len(params)})",
            f"<tr><th>Parameter</th><th>Count</th><th>Example URLs</th><th>Tools</th></tr>{param_rows}" if param_rows else "<tr><td colspan='4'>No query parameters extracted.</td></tr>",
        )

        surface_block = f"""
<div style="margin:24px 0">
{domains_tbl}
{ports_tbl}
{assets_tbl}
{crawl_tbl}
{hist_tbl}
{scope_tbl}
{params_tbl}
</div>
"""

        strict_note = ""
        if self.config.strict_domain_reports:
            strict_note = (
                "<p class=\"meta\"><strong>Domain scope:</strong> "
                "The vulnerabilities table only includes findings whose URL host matches the target or its subdomains.</p>"
            )

        html_page = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>RedScanner Report - {html.escape(results.target)}</title>
<style>
body {{ font-family: system-ui, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 24px; }}
.container {{ max-width: 1200px; margin: 0 auto; }}
h1 {{ color: #f1f5f9; font-size: 24px; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 8px; }}
th {{ text-align: left; padding: 10px 12px; background: #1e293b; color: #94a3b8; font-size: 11px; text-transform: uppercase; }}
td {{ padding: 8px 12px; border-bottom: 1px solid #1e293b; font-size: 14px; vertical-align: top; }}
tr:hover {{ background: #1e293b44; }}
.meta {{ color: #94a3b8; font-size: 14px; margin: 4px 0; }}
.cards {{ display: flex; gap: 12px; margin: 20px 0; flex-wrap: wrap; }}
a {{ cursor: pointer; }}
a:hover {{ color: #7dd3fc !important; }}
</style></head><body>
<div class="container">
<h1>RedScanner Report</h1>
<p class="meta"><strong>Target:</strong> {html.escape(results.target)} &nbsp; <strong>Scan ID:</strong> {html.escape(results.scan_id)} &nbsp; <strong>Date:</strong> {results.started_at.strftime('%Y-%m-%d %H:%M')} &nbsp; <strong>Duration:</strong> {html.escape(duration)}</p>
<p class="meta"><strong>Modules:</strong> {html.escape(', '.join(results.modules_run))} &nbsp; <strong>HTTP assets:</strong> {len(results.assets_discovered)} &nbsp; <strong>Findings:</strong> {len(vulns)}</p>
{strict_note}
{plan_ctx_html}
<div class="cards">{summary_cards}</div>
{surface_block}
<h2 style="color:#f1f5f9;font-size:18px;margin:28px 0 12px">Vulnerabilities</h2>
<table>
<tr><th>Severity</th><th>Type</th><th>URL</th><th>Param</th><th>Tool</th><th>Description</th></tr>
{vuln_rows}
</table>
<p class="meta" style="margin-top:24px">Full structured data: <code>report.json</code> and <code>surface.json</code></p>
</div></body></html>"""

        path = self.output_dir / "report.html"
        path.write_text(html_page)
        log.info(f"HTML report: {path}")

    def _severity_counts(self, vulns: list[Vulnerability]) -> dict:
        counts = {}
        for v in vulns:
            counts[v.severity] = counts.get(v.severity, 0) + 1
        return counts
