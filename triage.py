#!/usr/bin/env python3
"""
triage.py — Manual finding verification workflow for RedScanner reports.

Automated scanners (sqlmap, dalfox, nuclei, etc.) produce findings that still
need a human to confirm before they go in front of a client — this has been
an open item since the March SQLi run (7 critical findings flagged for manual
Burp Suite verification, carried forward through June and July without a
place to actually record the outcome).

This script closes that gap without touching the scan pipeline itself: it
works directly off an existing report.json, so it can be run any time after
a scan, independently of main.py.

Workflow:
    1. Export the findings that need a human look:
       python triage.py export output/<target>/<scan>/report.json

       Writes triage_template.json next to the report — one entry per
       critical/high finding, each with a stable finding_key and a
       status/note field for the analyst to fill in.

    2. Analyst edits triage_template.json by hand (or a tool does it),
       setting "status" to "confirmed" or "false_positive" for each entry
       and adding a "note" (e.g. "reproduced in Burp, session cookie
       exfiltrated" or "WAF blocks this in prod, sqlmap false positive").

    3. Apply the results back onto the report:
       python triage.py apply output/<target>/<scan>/report.json triage_template.json

       Writes report.verified.json (report.json + verification_status /
       verification_note on each matched finding) and a human-readable
       verification_summary.md in the same directory.

Findings are matched between report.json and the triage file by a stable
key (url + vuln_type + parameter + evidence + tool) — the same identity
scan_diff.py already uses to track a finding across scans — so re-running
export after a fresh scan of the same target will line back up with a
previous triage file for anything that hasn't changed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

VALID_STATUSES = {"unverified", "confirmed", "false_positive"}
DEFAULT_SEVERITIES = ("critical", "high")


def _finding_key(v: dict) -> str:
    """Stable identity for a finding, matching scan_diff.py's _finding_key
    fields (url, vuln_type, parameter, evidence, tool) but hashed down to a
    short hex string so it's a usable dict key / CLI-friendly identifier."""
    raw = "|".join(
        [
            v.get("url", "") or "",
            v.get("type", v.get("vuln_type", "")) or "",
            v.get("parameter", "") or "",
            (v.get("evidence", "") or "")[:500],
            v.get("tool", "") or "",
        ]
    )
    return hashlib.sha1(raw.encode("utf-8", "ignore")).hexdigest()[:12]


def load_report(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "vulnerabilities" not in data:
        print(f"Error: {path} is not a valid RedScanner report.json", file=sys.stderr)
        sys.exit(1)
    return data


# ── export ────────────────────────────────────────────────────────────────

def cmd_export(args: argparse.Namespace) -> None:
    report_path = args.report
    data = load_report(report_path)
    severities = {s.strip().lower() for s in args.severities.split(",") if s.strip()}

    candidates = [v for v in data.get("vulnerabilities", []) if v.get("severity") in severities]

    template = []
    for v in candidates:
        template.append(
            {
                "finding_key": _finding_key(v),
                "severity": v.get("severity"),
                "type": v.get("type", v.get("vuln_type")),
                "url": v.get("url"),
                "parameter": v.get("parameter"),
                "tool": v.get("tool"),
                "cvss_score": v.get("cvss_score"),
                "description": v.get("description"),
                "evidence": (v.get("evidence") or "")[:300],
                "status": "unverified",  # analyst sets to confirmed / false_positive
                "note": "",
            }
        )

    out_path = args.output or report_path.parent / "triage_template.json"
    out_path.write_text(
        json.dumps(
            {
                "scan_id": data.get("scan_id"),
                "target": data.get("target"),
                "severities_included": sorted(severities),
                "findings": template,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    print(f"Exported {len(template)} finding(s) ({', '.join(sorted(severities))}) needing review.")
    print(f"Triage template written to {out_path}")
    if not template:
        print("Nothing matched the requested severities — nothing to verify.")


# ── apply ─────────────────────────────────────────────────────────────────

def _load_triage_file(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    by_key: dict[str, dict] = {}
    for entry in data.get("findings", []):
        key = entry.get("finding_key")
        status = (entry.get("status") or "unverified").strip().lower()
        if status not in VALID_STATUSES:
            print(
                f"Warning: unknown status '{status}' for finding {key} "
                f"— treating as 'unverified'.",
                file=sys.stderr,
            )
            status = "unverified"
        if key:
            by_key[key] = {"status": status, "note": entry.get("note", "")}
    return by_key


def cmd_apply(args: argparse.Namespace) -> None:
    report_path = args.report
    data = load_report(report_path)
    triage_by_key = _load_triage_file(args.triage_file)

    matched = 0
    counts = {"confirmed": 0, "false_positive": 0, "unverified": 0}
    updated_vulns = []
    for v in data.get("vulnerabilities", []):
        key = _finding_key(v)
        result = triage_by_key.get(key)
        v = dict(v)
        if result:
            v["verification_status"] = result["status"]
            v["verification_note"] = result["note"]
            matched += 1
        else:
            v.setdefault("verification_status", "unverified")
            v.setdefault("verification_note", "")
        counts[v["verification_status"]] = counts.get(v["verification_status"], 0) + 1
        updated_vulns.append(v)

    data["vulnerabilities"] = updated_vulns
    data["verification_summary"] = counts

    out_path = args.output or report_path.parent / "report.verified.json"
    out_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    unmatched_triage = [k for k in triage_by_key if k not in {_finding_key(v) for v in data["vulnerabilities"]}]

    print(f"Matched {matched}/{len(triage_by_key)} triage entries against report findings.")
    if unmatched_triage:
        print(
            f"Warning: {len(unmatched_triage)} triage entry(ies) had no matching finding in "
            f"this report (finding may have changed or come from a different scan)."
        )
    print(f"Confirmed: {counts['confirmed']}  False positive: {counts['false_positive']}  "
          f"Still unverified: {counts['unverified']}")
    print(f"Verified report written to {out_path}")

    summary_path = out_path.with_name("verification_summary.md")
    summary_path.write_text(_format_summary_md(data, counts), encoding="utf-8")
    print(f"Verification summary written to {summary_path}")


def _format_summary_md(data: dict, counts: dict) -> str:
    lines = [
        f"# Verification summary — {data.get('target', '?')}",
        "",
        f"**Scan ID:** {data.get('scan_id', '?')}",
        "",
        f"- Confirmed: {counts.get('confirmed', 0)}",
        f"- False positive: {counts.get('false_positive', 0)}",
        f"- Still unverified: {counts.get('unverified', 0)}",
        "",
    ]

    for status, heading in [
        ("confirmed", "## Confirmed findings"),
        ("false_positive", "## False positives (excluded from client-facing count)"),
        ("unverified", "## Still needs manual review"),
    ]:
        rows = [v for v in data.get("vulnerabilities", []) if v.get("verification_status") == status]
        if not rows:
            continue
        lines.append(heading)
        lines.append("")
        for v in rows:
            lines.append(f"- [{v.get('severity', '?').upper()}] {v.get('type', '?')} — {v.get('url', '?')}")
            if v.get("verification_note"):
                lines.append(f"  note: {v['verification_note']}")
        lines.append("")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Manual finding verification workflow for RedScanner reports")
    sub = parser.add_subparsers(dest="command", required=True)

    p_export = sub.add_parser("export", help="Export findings needing manual verification")
    p_export.add_argument("report", type=Path, help="Path to report.json")
    p_export.add_argument(
        "--severities", default=",".join(DEFAULT_SEVERITIES),
        help=f"Comma-separated severities to include (default: {','.join(DEFAULT_SEVERITIES)})",
    )
    p_export.add_argument("--output", "-o", type=Path, help="Output path (default: triage_template.json next to report)")
    p_export.set_defaults(func=cmd_export)

    p_apply = sub.add_parser("apply", help="Apply a completed triage file back onto a report")
    p_apply.add_argument("report", type=Path, help="Path to report.json")
    p_apply.add_argument("triage_file", type=Path, help="Path to the completed triage_template.json")
    p_apply.add_argument("--output", "-o", type=Path, help="Output path (default: report.verified.json next to report)")
    p_apply.set_defaults(func=cmd_apply)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()