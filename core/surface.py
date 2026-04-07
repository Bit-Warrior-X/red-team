# ============================================================
# core/surface.py — derive domains, URLs, ports, params for reports
# ============================================================

from __future__ import annotations

import re
from collections import defaultdict
from urllib.parse import parse_qs, urlparse

from core.models import Asset, Vulnerability

TCP_URL = re.compile(r"^tcp://([^:]+):(\d+)\s*$", re.I)


def open_ports_from_vulns(vulns: list[Vulnerability]) -> list[dict]:
    rows: list[dict] = []
    for v in vulns:
        if v.vuln_type != "open_port":
            continue
        m = TCP_URL.match(v.url.strip())
        if m:
            rows.append({"host": m.group(1), "port": int(m.group(2)), "protocol": "tcp"})
    return rows


def query_param_names_from_url(url: str) -> list[str]:
    try:
        q = urlparse(url).query
        if not q:
            return []
        return list(parse_qs(q, keep_blank_values=True).keys())
    except Exception:
        return []


def aggregate_parameters(vulns: list[Vulnerability], urls: list[str]) -> list[dict]:
    """Parameter names with example URLs and optional tool tags."""
    by_param: dict[str, set[str]] = defaultdict(set)
    tool_by_param: dict[str, set[str]] = defaultdict(set)

    for v in vulns:
        if v.parameter:
            by_param[v.parameter].add(v.url)
            if v.tool:
                tool_by_param[v.parameter].add(v.tool)
        for pname in query_param_names_from_url(v.url):
            by_param[pname].add(v.url)
            if v.tool:
                tool_by_param[pname].add(v.tool)

    for u in urls:
        for pname in query_param_names_from_url(u):
            by_param[pname].add(u)

    rows: list[dict] = []
    for name in sorted(by_param.keys()):
        urls_sample = sorted(by_param[name])[:8]
        rows.append(
            {
                "name": name,
                "example_urls": urls_sample,
                "tools": sorted(tool_by_param.get(name, [])),
                "occurrences": len(by_param[name]),
            }
        )
    rows.sort(key=lambda x: -x["occurrences"])
    return rows


def asset_to_dict(a: Asset) -> dict:
    return {
        "url": a.url,
        "ip": a.ip,
        "port": a.port,
        "status_code": a.status_code,
        "title": a.title,
        "tech": a.tech,
        "alive": a.alive,
        "source": a.source,
    }
