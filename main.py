#!/usr/bin/env python3
"""
RedScanner — web vulnerability discovery orchestrator with a research-driven red-team plan.

Usage:
    python main.py --profile full
    python main.py --profile lite
    python main.py --list-profiles
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import shutil
import sys
from datetime import datetime
from pathlib import Path

from modules.api_leak_scanner import APILeakScanner
from modules.naabu_scanner import NaabuScanner
from modules.nikto_scanner import NiktoScanner
from modules.recon import ReconEngine
from modules.report_generator import ReportGenerator
from modules.sqli_scanner import SQLiScanner
from modules.vuln_scanner import VulnScanner
from modules.wayback_enricher import WaybackEnricher
from modules.xss_scanner import XSSScanner
from core.config import ScanConfig
from core.db import ResultsDB
from core.models import ScanResult, Vulnerability
from core.red_plan import load_red_plan, merge_profiles
from core.surface import open_ports_from_vulns

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("redscanner.log"),
    ],
)
log = logging.getLogger("redscanner")

# Default profiles; overridden by assets/red_plan.json "profiles"
# "full" = all automated phases (wayback, naabu, nikto included). Use "lite" for a shorter run.
PROFILES: dict[str, list[str]] = {
    "full": [
        "recon",
        "wayback",
        "naabu",
        "nuclei",
        "xss",
        "sqli",
        "api_leak",
        "nikto",
    ],
    "lite": ["recon", "nuclei", "xss", "sqli", "api_leak"],
    "red-team": [
        "recon",
        "wayback",
        "naabu",
        "nuclei",
        "xss",
        "sqli",
        "api_leak",
        "nikto",
    ],
    "recon-only": ["recon"],
    "vuln-only": ["nuclei", "xss", "sqli"],
    "quick": ["recon", "nuclei"],
}

# Execution order for any subset of modules
MODULE_ORDER = [
    "recon",
    "wayback",
    "naabu",
    "nuclei",
    "xss",
    "sqli",
    "api_leak",
    "nikto",
]


def _sort_modules(modules: list[str]) -> list[str]:
    return sorted(modules, key=lambda m: MODULE_ORDER.index(m) if m in MODULE_ORDER else 100)


def log_optional_cli_status(config: ScanConfig) -> None:
    """Explain which external CLIs are on PATH (others are skipped with a warning in-module)."""
    tools = [
        ("subfinder", config.subfinder_path),
        ("httpx", config.httpx_path),
        ("assetfinder", config.assetfinder_path),
        ("xcrawl3r", config.xcrawl3r_path),
        ("waybackurls", config.waybackurls_path),
        ("gau", config.gau_path),
        ("naabu", config.naabu_path),
        ("nuclei", config.nuclei_path),
        ("dalfox", config.dalfox_path),
        ("sqlmap", config.sqlmap_path),
        ("nikto", config.nikto_path),
    ]
    ok = [name for name, path in tools if shutil.which(path)]
    missing = [name for name, path in tools if not shutil.which(path)]
    log.info("External tools on PATH: %s", ", ".join(ok) if ok else "(none)")
    if missing:
        log.warning(
            "Not installed or not on PATH (those phases will skip or use fallbacks): %s",
            ", ".join(missing),
        )


class RedScanner:
    """Main orchestrator that chains modules in a fixed security order."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.db = ResultsDB(config.output_dir / "results.db")
        self.scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.results = ScanResult(
            scan_id=self.scan_id,
            target=config.target,
            started_at=datetime.now(),
            modules_run=[],
            vulnerabilities=[],
            assets_discovered=[],
        )
        self._recon_domains: set[str] = {config.target}
        self._crawled_urls: list[str] = []

    async def run(self):
        log.info("Starting scan %s against %s", self.scan_id, self.config.target)
        if self.config.plan_title:
            log.info("Engagement plan: %s", self.config.plan_title)
        if self.config.methodology_frameworks:
            log.info(
                "Frameworks: %s",
                "; ".join(self.config.methodology_frameworks),
            )
        log.info("Modules (ordered): %s", ", ".join(_sort_modules(self.config.modules)))
        log.info("Output: %s", self.config.output_dir)
        log_optional_cli_status(self.config)

        os.makedirs(self.config.output_dir, exist_ok=True)

        for name in _sort_modules(self.config.modules):
            await self._run_module(name)

        self.results.vulnerabilities = self._deduplicate(self.results.vulnerabilities)
        self.results.finished_at = datetime.now()
        self._finalize_surface()
        self.db.save_vulns(self.scan_id, self.results.vulnerabilities)

        log.info("=" * 60)
        log.info("Generating Reports")
        log.info("=" * 60)
        reporter = ReportGenerator(self.config)
        reporter.generate(self.results)

        self._print_summary()
        return self.results

    async def _run_module(self, name: str) -> None:
        if name == "recon":
            log.info("=" * 60)
            log.info("PHASE: Reconnaissance (subfinder, assetfinder, httpx, xcrawl3r)")
            log.info("=" * 60)
            recon = ReconEngine(self.config)
            assets = await recon.run()
            self._recon_domains = set(recon.discovered_domains) or {self.config.target}
            self._crawled_urls = list(recon.crawled_urls)
            self.results.assets_discovered = assets
            self.results.modules_run.append("recon")
            self.db.save_assets(self.scan_id, assets)
            log.info("Discovered %s HTTP assets", len(assets))
            return

        if name == "wayback":
            log.info("=" * 60)
            log.info("PHASE: Historical URLs (waybackurls, gau)")
            log.info("=" * 60)
            urls = await WaybackEnricher(self.config).run(self._recon_domains)
            self.config.collected_urls.extend(urls)
            self.results.modules_run.append("wayback")
            log.info("Collected %s historical URLs for downstream scanners", len(urls))
            return

        if name == "naabu":
            log.info("=" * 60)
            log.info("PHASE: Port scan (naabu)")
            log.info("=" * 60)
            vulns = await NaabuScanner(self.config).run(self._recon_domains)
            self.results.vulnerabilities.extend(vulns)
            self.results.modules_run.append("naabu")
            return

        if name == "nuclei":
            log.info("=" * 60)
            log.info("PHASE: Nuclei")
            log.info("=" * 60)
            targets = self._get_scan_targets()
            vulns = await VulnScanner(self.config).run(targets)
            self.results.vulnerabilities.extend(vulns)
            self.results.modules_run.append("nuclei")
            log.info("Nuclei reported %s findings", len(vulns))
            return

        if name == "xss":
            log.info("=" * 60)
            log.info("PHASE: XSS (dalfox)")
            log.info("=" * 60)
            vulns = await XSSScanner(self.config).run(self._deep_targets())
            self.results.vulnerabilities.extend(vulns)
            self.results.modules_run.append("xss")
            log.info("Dalfox reported %s findings", len(vulns))
            return

        if name == "sqli":
            log.info("=" * 60)
            log.info("PHASE: SQLi (sqlmap)")
            log.info("=" * 60)
            vulns = await SQLiScanner(self.config).run(self._deep_targets())
            self.results.vulnerabilities.extend(vulns)
            self.results.modules_run.append("sqli")
            log.info("SQLmap reported %s findings", len(vulns))
            return

        if name == "api_leak":
            log.info("=" * 60)
            log.info("PHASE: API / secret patterns in JS")
            log.info("=" * 60)
            vulns = await APILeakScanner(self.config).run(self._deep_targets())
            self.results.vulnerabilities.extend(vulns)
            self.results.modules_run.append("api_leak")
            log.info("API leak scan reported %s findings", len(vulns))
            return

        if name == "nikto":
            log.info("=" * 60)
            log.info("PHASE: Nikto")
            log.info("=" * 60)
            vulns = await NiktoScanner(self.config).run(self._get_nikto_targets())
            self.results.vulnerabilities.extend(vulns)
            self.results.modules_run.append("nikto")
            log.info("Nikto parsed %s notable lines", len(vulns))
            return

        log.warning("Unknown module skipped: %s", name)

    def _get_scan_targets(self) -> list[str]:
        """Alive httpx URLs plus wayback/gau URLs, deduped."""
        seen: set[str] = set()
        ordered: list[str] = []

        for a in self.results.assets_discovered:
            if a.alive and a.url and a.url not in seen:
                seen.add(a.url)
                ordered.append(a.url)

        for u in self.config.collected_urls:
            if u and u not in seen:
                seen.add(u)
                ordered.append(u)

        if ordered:
            return ordered
        if self.config.base_url:
            return [self.config.base_url.rstrip("/")]
        return [f"http://{self.config.target}"]

    def _deep_targets(self) -> list[str]:
        """Subset of URLs for slow tools (dalfox, sqlmap, JS mining)."""
        all_t = self._get_scan_targets()
        cap = max(1, self.config.max_deep_scan_urls)
        return all_t[:cap]

    def _get_nikto_targets(self) -> list[str]:
        """Prefer a few unique scheme+host roots from alive assets."""
        roots: list[str] = []
        seen: set[str] = set()
        for a in self.results.assets_discovered:
            if not a.alive or not a.url:
                continue
            if a.url not in seen:
                seen.add(a.url)
                roots.append(a.url)
        if roots:
            return roots
        if self.config.base_url:
            return [self.config.base_url.rstrip("/")]
        return [f"http://{self.config.target}"]

    def _deduplicate(self, vulns: list[Vulnerability]) -> list[Vulnerability]:
        seen = set()
        unique: list[Vulnerability] = []
        for v in vulns:
            key = (v.url, v.vuln_type, v.parameter, v.evidence)
            if key not in seen:
                seen.add(key)
                unique.append(v)
        return unique

    def _finalize_surface(self) -> None:
        """Populate domains, URLs, ports for rich reporting."""
        r = self.results
        r.domains = sorted(self._recon_domains)
        r.urls_crawled = list(self._crawled_urls)
        r.urls_historical = list(dict.fromkeys(self.config.collected_urls))
        r.urls_scan_surface = self._get_scan_targets()
        r.open_ports = open_ports_from_vulns(r.vulnerabilities)

    def _print_summary(self):
        r = self.results
        duration = (r.finished_at - r.started_at).total_seconds()
        crit = sum(1 for v in r.vulnerabilities if v.severity == "critical")
        high = sum(1 for v in r.vulnerabilities if v.severity == "high")
        med = sum(1 for v in r.vulnerabilities if v.severity == "medium")
        low = sum(1 for v in r.vulnerabilities if v.severity == "low")
        info = sum(1 for v in r.vulnerabilities if v.severity == "info")

        log.info("")
        log.info("=" * 60)
        log.info("SCAN COMPLETE — %s", self.scan_id)
        log.info("Target: %s", r.target)
        log.info("Duration: %.1fs", duration)
        log.info("Assets discovered: %s", len(r.assets_discovered))
        log.info("Total findings: %s", len(r.vulnerabilities))
        log.info("  Critical: %s  High: %s  Medium: %s  Low: %s  Info: %s", crit, high, med, low, info)
        log.info("Reports saved to: %s", self.config.output_dir)
        log.info("=" * 60)


def parse_args():
    root = Path(__file__).resolve().parent
    default_plan = root / "assets" / "red_plan.json"

    p = argparse.ArgumentParser(description="RedScanner — red-team plan driven web assessment")
    p.add_argument("--target", "-t", help="Target domain (default: domain in red plan JSON)")
    p.add_argument(
        "--plan-file",
        type=Path,
        default=default_plan,
        help=f"Engagement plan JSON (default: {default_plan})",
    )
    p.add_argument("--profile", "-p", help="Profile name (see --list-profiles)")
    p.add_argument("--modules", "-m", help="Comma-separated modules (overrides profile)")
    p.add_argument("--output", "-o", default="./output", help="Output directory root")
    p.add_argument("--threads", default=10, type=int, help="Concurrent tasks (where supported)")
    p.add_argument("--timeout", default=30, type=int, help="HTTP/tool timeout (seconds)")
    p.add_argument("--rate-limit", default=50, type=int, help="Nuclei requests/sec")
    p.add_argument("--list-profiles", action="store_true", help="List profiles and exit")
    p.add_argument("--max-wayback", type=int, default=500, help="Cap historical URLs")
    p.add_argument(
        "--max-deep",
        type=int,
        default=25,
        help="Max URLs for dalfox, sqlmap, api_leak (nuclei uses full list)",
    )
    return p.parse_args()


def main():
    args = parse_args()
    plan = load_red_plan(args.plan_file)
    profiles = merge_profiles(PROFILES, plan)

    if args.list_profiles:
        print("Profiles:")
        for name, mods in sorted(profiles.items()):
            print(f"  {name}: {', '.join(mods)}")
        return

    target = (args.target or plan.get("domain") or "").strip()
    if not target:
        log.error('Set --target or add "domain" to %s', args.plan_file)
        sys.exit(1)

    if args.modules:
        modules = [m.strip() for m in args.modules.split(",") if m.strip()]
    else:
        profile_name = args.profile or "full"
        modules = profiles.get(profile_name)
        if not modules:
            log.error("Unknown profile %r. Use --list-profiles.", profile_name)
            sys.exit(1)

    bu = plan.get("base_url")
    base_url = bu.strip() if isinstance(bu, str) and bu.strip() else None

    manual = plan.get("manual_phases")
    if not isinstance(manual, list):
        manual = []

    refs = plan.get("research_references")
    if not isinstance(refs, list):
        refs = []

    frameworks = plan.get("methodology_frameworks")
    if not isinstance(frameworks, list):
        frameworks = []
    frameworks = [str(x).strip() for x in frameworks if str(x).strip()]

    plan_title = plan.get("title") if isinstance(plan.get("title"), str) else None
    plan_desc = plan.get("description") if isinstance(plan.get("description"), str) else None

    config = ScanConfig(
        target=target,
        modules=modules,
        output_dir=Path(args.output) / target / datetime.now().strftime("%Y%m%d_%H%M%S"),
        threads=args.threads,
        timeout=args.timeout,
        rate_limit=args.rate_limit,
        base_url=base_url,
        manual_phases=manual,
        research_references=[str(r) for r in refs],
        plan_title=plan_title,
        plan_description=plan_desc,
        methodology_frameworks=frameworks,
        max_wayback_urls=args.max_wayback,
        max_deep_scan_urls=args.max_deep,
    )

    scanner = RedScanner(config)
    asyncio.run(scanner.run())


if __name__ == "__main__":
    main()
