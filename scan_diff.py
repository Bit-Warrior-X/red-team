#!/usr/bin/env python3
"""
scan_diff.py — Compare two RedScanner JSON reports and summarize changes.

Usage:
    python scan_diff.py <old_report.json> <new_report.json> [--output diff.json]

Shows:
    - New findings (in new but not old)
    - Resolved findings (in old but not new)
    - Unchanged findings
    - Surface changes (domains, ports, assets)

Useful for regression tracking between scans on the same target.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _finding_key(v: dict) -> tuple:
    """Stable identity for a finding (ignoring timestamp/raw_output)."""
    return (
        v.get("url", ""),
        v.get("vuln_type", ""),
        v.get("parameter", ""),
        v.get("evidence", ""),
        v.get("tool", ""),
    )


def _severity_rank(sev: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(sev, 5)


def load_report(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        print(f"Error: {path} is not a valid RedScanner report JSON", file=sys.stderr)
        sys.exit(1)
    return data


def diff_findings(old_vulns: list[dict], new_vulns: list[dict]) -> dict:
    old_keys = {_finding_key(v): v for v in old_vulns}
    new_keys = {_finding_key(v): v for v in new_vulns}

    added = [new_keys[k] for k in new_keys if k not in old_keys]
    resolved = [old_keys[k] for k in old_keys if k not in new_keys]
    unchanged = [new_keys[k] for k in new_keys if k in old_keys]

    added.sort(key=lambda v: _severity_rank(v.get("severity", "info")))
    resolved.sort(key=lambda v: _severity_rank(v.get("severity", "info")))

    return {
        "new_findings": added,
        "resolved_findings": resolved,
        "unchanged_findings": unchanged,
    }


def diff_surface(old_data: dict, new_data: dict) -> dict:
    """Compare surface sections between two reports."""
    old_surf = old_data.get("surface", {})
    new_surf = new_data.get("surface", {})

    def _set_diff(key: str) -> dict:
        old_set = set(old_surf.get(key, []))
        new_set = set(new_surf.get(key, []))
        return {
            "added": sorted(new_set - old_set),
            "removed": sorted(old_set - new_set),
            "unchanged_count": len(old_set & new_set),
        }

    old_ports = {f"{p['host']}:{p['port']}" for p in old_surf.get("open_ports", [])}
    new_ports = {f"{p['host']}:{p['port']}" for p in new_surf.get("open_ports", [])}

    return {
        "domains": _set_diff("domains"),
        "open_ports": {
            "added": sorted(new_ports - old_ports),
            "removed": sorted(old_ports - new_ports),
            "unchanged_count": len(old_ports & new_ports),
        },
        "crawled_urls": {
            "old_count": len(old_surf.get("urls_crawled", [])),
            "new_count": len(new_surf.get("urls_crawled", [])),
        },
        "historical_urls": {
            "old_count": len(old_surf.get("urls_historical", [])),
            "new_count": len(new_surf.get("urls_historical", [])),
        },
    }


def severity_summary(findings: list[dict]) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in findings:
        sev = v.get("severity", "info")
        if sev in counts:
            counts[sev] += 1
        else:
            counts["info"] += 1
    return counts


def format_text_report(old_data: dict, new_data: dict, diff: dict, surf_diff: dict) -> str:
    lines = []
    lines.append("=" * 64)
    lines.append("RedScanner Scan Diff Report")
    lines.append("=" * 64)
    lines.append(f"Old scan: {old_data.get('scan_id', '?')}  Target: {old_data.get('target', '?')}")
    lines.append(f"New scan: {new_data.get('scan_id', '?')}  Target: {new_data.get('target', '?')}")
    lines.append("")

    # Findings summary
    new_f = diff["new_findings"]
    res_f = diff["resolved_findings"]
    unch_f = diff["unchanged_findings"]

    lines.append(f"Findings: {len(new_f)} new, {len(res_f)} resolved, {len(unch_f)} unchanged")
    lines.append("")

    if new_f:
        lines.append("--- NEW FINDINGS ---")
        ns = severity_summary(new_f)
        lines.append(f"  Critical: {ns['critical']}  High: {ns['high']}  Medium: {ns['medium']}  Low: {ns['low']}  Info: {ns['info']}")
        for v in new_f:
            lines.append(f"  [{v.get('severity', '?').upper():>8}] {v.get('vuln_type', '?')} — {v.get('url', '?')}")
            if v.get("parameter"):
                lines.append(f"           param: {v['parameter']}")
        lines.append("")

    if res_f:
        lines.append("--- RESOLVED FINDINGS ---")
        rs = severity_summary(res_f)
        lines.append(f"  Critical: {rs['critical']}  High: {rs['high']}  Medium: {rs['medium']}  Low: {rs['low']}  Info: {rs['info']}")
        for v in res_f:
            lines.append(f"  [{v.get('severity', '?').upper():>8}] {v.get('vuln_type', '?')} — {v.get('url', '?')}")
        lines.append("")

    # Surface changes
    sd = surf_diff.get("domains", {})
    sp = surf_diff.get("open_ports", {})
    if sd.get("added") or sd.get("removed"):
        lines.append("--- SURFACE: DOMAINS ---")
        for d in sd.get("added", []):
            lines.append(f"  + {d}")
        for d in sd.get("removed", []):
            lines.append(f"  - {d}")
        lines.append("")
    if sp.get("added") or sp.get("removed"):
        lines.append("--- SURFACE: PORTS ---")
        for p in sp.get("added", []):
            lines.append(f"  + {p}")
        for p in sp.get("removed", []):
            lines.append(f"  - {p}")
        lines.append("")

    cu = surf_diff.get("crawled_urls", {})
    hu = surf_diff.get("historical_urls", {})
    lines.append(f"Crawled URLs: {cu.get('old_count', 0)} → {cu.get('new_count', 0)}")
    lines.append(f"Historical URLs: {hu.get('old_count', 0)} → {hu.get('new_count', 0)}")

    lines.append("")
    lines.append("=" * 64)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Compare two RedScanner JSON reports")
    parser.add_argument("old", type=Path, help="Path to older report.json")
    parser.add_argument("new", type=Path, help="Path to newer report.json")
    parser.add_argument("--output", "-o", type=Path, help="Write diff as JSON to this file")
    parser.add_argument("--json-only", action="store_true", help="Only output JSON (no text)")
    args = parser.parse_args()

    old_data = load_report(args.old)
    new_data = load_report(args.new)

    diff = diff_findings(
        old_data.get("vulnerabilities", []),
        new_data.get("vulnerabilities", []),
    )
    surf_diff = diff_surface(old_data, new_data)

    result = {
        "old_scan_id": old_data.get("scan_id"),
        "new_scan_id": new_data.get("scan_id"),
        "target": new_data.get("target"),
        "summary": {
            "new_count": len(diff["new_findings"]),
            "resolved_count": len(diff["resolved_findings"]),
            "unchanged_count": len(diff["unchanged_findings"]),
            "new_severity": severity_summary(diff["new_findings"]),
            "resolved_severity": severity_summary(diff["resolved_findings"]),
        },
        "new_findings": diff["new_findings"],
        "resolved_findings": diff["resolved_findings"],
        "surface_diff": surf_diff,
    }

    if args.output:
        args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"Diff JSON written to {args.output}")

    if not args.json_only:
        print(format_text_report(old_data, new_data, diff, surf_diff))


if __name__ == "__main__":
    main()