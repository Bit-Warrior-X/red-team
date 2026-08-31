#!/usr/bin/env python3
"""
RedScanner v0.4 — web vulnerability discovery orchestrator with a research-driven red-team plan.

Usage:
    python main.py --profile full
    python main.py --profile header-only
    python main.py --list-profiles
    python main.py --resume
    python main.py --target-file targets.txt --profile full
    python scan_diff.py output/<target>/<old>/report.json output/<target>/<new>/report.json
    python triage.py export output/<target>/<scan>/report.json
    python triage.py apply  output/<target>/<scan>/report.json triage_template.json
"""

from __future__ import annotations

__version__ = "0.4.0"

# Severity ranking, most→least severe, used by --fail-on gating.
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

import argparse
import asyncio
import logging
import os
import shutil
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from modules.api_leak_scanner import APILeakScanner
from modules.cdn_bypass_scanner import CDNBypassScanner
from modules.cors_scanner import CORSScanner
from modules.dirbust_scanner import DirbustScanner
from modules.header_scanner import HeaderScanner
from modules.http_methods_scanner import HTTPMethodsScanner
from modules.naabu_scanner import NaabuScanner
from modules.nikto_scanner import NiktoScanner
from modules.recon import ReconEngine
from modules.report_generator import ReportGenerator
from modules.sqli_scanner import SQLiScanner
from modules.tls_scanner import TLSScanner
from modules.vuln_scanner import VulnScanner
from modules.wayback_enricher import WaybackEnricher
from modules.xss_scanner import XSSScanner
from core.config import ScanConfig
from core.db import ResultsDB
from core.models import ScanResult, Vulnerability
from core.red_plan import load_red_plan, merge_profiles
from core.domain_scope import finding_matches_target
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

# resume.cfg always lives next to main.py so --resume can find it without
# already knowing which output directory a previous run used.
RESUME_CFG_PATH = Path(__file__).resolve().parent / "resume.cfg"

# Default profiles; overridden/extended by assets/red_plan.json "profiles".
# "full" = every automated phase, including the v0.3 modules (cors, tls,
# dirbust, cdn_bypass). Use "lite" for a shorter run.
PROFILES: dict[str, list[str]] = {
    "full": [
        "recon",
        "wayback",
        "naabu",
        "nuclei",
        "xss",
        "sqli",
        "api_leak",
        "header_check",
        "http_methods",
        "cors",
        "tls",
        "dirbust",
        "cdn_bypass",
        "nikto",
    ],
    "lite": ["recon", "nuclei", "xss", "sqli", "api_leak", "header_check"],
    "red-team": [
        "recon",
        "wayback",
        "naabu",
        "nuclei",
        "xss",
        "sqli",
        "api_leak",
        "header_check",
        "http_methods",
        "cors",
        "tls",
        "dirbust",
        "cdn_bypass",
        "nikto",
    ],
    "web-hardening": ["recon", "header_check", "http_methods", "cors", "tls"],
    "discovery": ["recon", "naabu", "dirbust"],
    "cdn-test": ["recon", "cors", "tls", "cdn_bypass", "header_check"],
    "recon-only": ["recon"],
    "vuln-only": ["nuclei", "xss", "sqli"],
    "quick": ["recon", "nuclei"],
    "header-only": ["recon", "header_check"],
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
    "header_check",
    "http_methods",
    "cors",
    "tls",
    "dirbust",
    "cdn_bypass",
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
        ("gobuster", config.gobuster_path),
        ("ffuf", config.ffuf_path),
        ("testssl.sh", config.testssl_path),
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

    def __init__(self, config: ScanConfig, scan_id: str | None = None):
        self.config = config
        self.db = ResultsDB(config.output_dir / "results.db")
        # On --resume, scan_id is carried over from the interrupted run so
        # previously-saved assets/vulnerabilities in results.db can be found
        # again. Otherwise generate a fresh one, as before.
        self.scan_id = scan_id or datetime.now().strftime("%Y%m%d_%H%M%S")
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
        log.info("RedScanner v%s — scan %s against %s", __version__, self.scan_id, self.config.target)
        if self.config.plan_title:
            log.info("Engagement plan: %s", self.config.plan_title)
        if self.config.methodology_frameworks:
            log.info(
                "Frameworks: %s",
                "; ".join(self.config.methodology_frameworks),
            )
        log.info("Modules (ordered): %s", ", ".join(_sort_modules(self.config.modules)))
        if self.config.resume_skip:
            log.info(
                "Resuming — already completed: %s",
                ", ".join(sorted(self.config.resume_skip)) or "(none)",
            )
        log.info("Output: %s", self.config.output_dir)
        log_optional_cli_status(self.config)

        os.makedirs(self.config.output_dir, exist_ok=True)

        for name in _sort_modules(self.config.modules):
            if name in self.config.resume_skip:
                self._restore_module(name)
            else:
                await self._run_module(name)
            self._write_resume_cfg()

        self.results.vulnerabilities = self._deduplicate(self.results.vulnerabilities)
        if self.config.strict_domain_reports:
            before = len(self.results.vulnerabilities)
            self.results.vulnerabilities = [
                v for v in self.results.vulnerabilities if finding_matches_target(v, self.config.target)
            ]
            log.info(
                "Strict domain filter: %s findings kept (%s removed outside %s)",
                len(self.results.vulnerabilities),
                before - len(self.results.vulnerabilities),
                self.config.target,
            )
        self.results.finished_at = datetime.now()
        self._finalize_surface()
        # NOTE: vulnerabilities are now persisted to results.db incrementally,
        # per module, inside _run_module (see db.save_vulns calls below) so
        # that an interrupted run leaves an accurate on-disk record for
        # --resume. There is no final bulk save here anymore (the old v0.2/
        # v0.3 code duplicated every finding into the db a second time here).

        log.info("=" * 60)
        log.info("Generating Reports")
        log.info("=" * 60)
        reporter = ReportGenerator(self.config)
        reporter.generate(self.results)

        self._print_summary()
        self._clear_resume_cfg()
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
            self.db.save_vulns(self.scan_id, vulns, module="naabu")
            return

        if name == "nuclei":
            log.info("=" * 60)
            log.info("PHASE: Nuclei")
            log.info("=" * 60)
            targets = self._get_scan_targets()
            vulns = await VulnScanner(self.config).run(targets)
            self.results.vulnerabilities.extend(vulns)
            self.results.modules_run.append("nuclei")
            self.db.save_vulns(self.scan_id, vulns, module="nuclei")
            log.info("Nuclei reported %s findings", len(vulns))
            return

        if name == "xss":
            log.info("=" * 60)
            log.info("PHASE: XSS (dalfox)")
            log.info("=" * 60)
            # Enhanced: pass crawled URLs with query parameters for broader surface
            vulns = await XSSScanner(self.config).run(
                self._deep_targets(),
                crawled_urls=self._crawled_urls,
            )
            self.results.vulnerabilities.extend(vulns)
            self.results.modules_run.append("xss")
            self.db.save_vulns(self.scan_id, vulns, module="xss")
            log.info("Dalfox reported %s findings", len(vulns))
            return

        if name == "sqli":
            log.info("=" * 60)
            log.info("PHASE: SQLi (sqlmap)")
            log.info("=" * 60)
            vulns = await SQLiScanner(self.config).run(self._deep_targets())
            self.results.vulnerabilities.extend(vulns)
            self.results.modules_run.append("sqli")
            self.db.save_vulns(self.scan_id, vulns, module="sqli")
            log.info("SQLmap reported %s findings", len(vulns))
            return

        if name == "api_leak":
            log.info("=" * 60)
            log.info("PHASE: API / secret patterns in JS")
            log.info("=" * 60)
            vulns = await APILeakScanner(self.config).run(self._deep_targets())
            self.results.vulnerabilities.extend(vulns)
            self.results.modules_run.append("api_leak")
            self.db.save_vulns(self.scan_id, vulns, module="api_leak")
            log.info("API leak scan reported %s findings", len(vulns))
            return

        if name == "header_check":
            log.info("=" * 60)
            log.info("PHASE: HTTP Security Headers (curl HEAD)")
            log.info("=" * 60)
            if not self.config.header_check_enabled:
                log.info("Header check disabled — skipping")
                self.results.modules_run.append("header_check")
                return
            targets = self._get_host_root_targets()
            vulns = await HeaderScanner(self.config).run(targets)
            self.results.vulnerabilities.extend(vulns)
            self.results.modules_run.append("header_check")
            self.db.save_vulns(self.scan_id, vulns, module="header_check")
            return

        if name == "http_methods":
            log.info("=" * 60)
            log.info("PHASE: HTTP method audit (WSTG-CONF-06)")
            log.info("=" * 60)
            targets = self._get_host_root_targets()
            vulns = await HTTPMethodsScanner(self.config).run(targets)
            self.results.vulnerabilities.extend(vulns)
            self.results.modules_run.append("http_methods")
            self.db.save_vulns(self.scan_id, vulns, module="http_methods")
            return

        if name == "cors":
            log.info("=" * 60)
            log.info("PHASE: CORS misconfiguration (WSTG-CLIENT-07)")
            log.info("=" * 60)
            targets = self._get_host_root_targets()
            vulns = await CORSScanner(self.config).run(targets)
            self.results.vulnerabilities.extend(vulns)
            self.results.modules_run.append("cors")
            self.db.save_vulns(self.scan_id, vulns, module="cors")
            return

        if name == "tls":
            log.info("=" * 60)
            log.info("PHASE: TLS/SSL assessment (WSTG-CRYP-01)")
            log.info("=" * 60)
            targets = self._get_host_root_targets()
            vulns = await TLSScanner(self.config).run(targets)
            self.results.vulnerabilities.extend(vulns)
            self.results.modules_run.append("tls")
            self.db.save_vulns(self.scan_id, vulns, module="tls")
            return

        if name == "dirbust":
            log.info("=" * 60)
            log.info("PHASE: Directory / file brute-force (WSTG-CONF-05)")
            log.info("=" * 60)
            # Capped by max_deep_scan_urls, same as dalfox/sqlmap/api_leak
            # (see core/config.py) — gobuster/ffuf/the builtin probe are all
            # relatively slow per target, so this intentionally does not run
            # against every crawled/historical URL.
            targets = self._deep_targets()
            vulns = await DirbustScanner(self.config).run(targets)
            self.results.vulnerabilities.extend(vulns)
            self.results.modules_run.append("dirbust")
            self.db.save_vulns(self.scan_id, vulns, module="dirbust")
            return

        if name == "cdn_bypass":
            log.info("=" * 60)
            log.info("PHASE: CDN/WAF bypass tests")
            log.info("=" * 60)
            if not self.config.cdn_origin_ip:
                log.info(
                    "cdn_bypass: no cdn_origin_ip set in red_plan.json — "
                    "origin-direct test will be skipped, other checks still run"
                )
            targets = self._get_host_root_targets()
            vulns = await CDNBypassScanner(self.config).run(targets)
            self.results.vulnerabilities.extend(vulns)
            self.results.modules_run.append("cdn_bypass")
            self.db.save_vulns(self.scan_id, vulns, module="cdn_bypass")
            return

        if name == "nikto":
            log.info("=" * 60)
            log.info("PHASE: Nikto")
            log.info("=" * 60)
            vulns = await NiktoScanner(self.config).run(self._get_host_root_targets())
            self.results.vulnerabilities.extend(vulns)
            self.results.modules_run.append("nikto")
            self.db.save_vulns(self.scan_id, vulns, module="nikto")
            log.info("Nikto parsed %s notable lines", len(vulns))
            return

        log.warning("Unknown module skipped: %s", name)

    def _restore_module(self, name: str) -> None:
        """Restore in-memory state for a module that a previous, interrupted
        run already completed (used on --resume instead of re-running it)."""
        if name == "recon":
            recon_dir = self.config.output_dir / "recon"
            subs_file = recon_dir / "subdomains.txt"
            crawled_file = recon_dir / "crawled_urls.txt"

            domains: set[str] = set()
            if subs_file.is_file():
                domains = {
                    line.strip() for line in subs_file.read_text(encoding="utf-8").splitlines() if line.strip()
                }
            self._recon_domains = domains or {self.config.target}

            if crawled_file.is_file():
                self._crawled_urls = [
                    line.strip() for line in crawled_file.read_text(encoding="utf-8").splitlines() if line.strip()
                ]

            assets = self.db.load_assets(self.scan_id)
            self.results.assets_discovered = assets
            self.results.modules_run.append("recon")
            log.info(
                "Resumed 'recon': %s domains, %s assets, %s crawled URLs restored from previous run",
                len(self._recon_domains), len(assets), len(self._crawled_urls),
            )
            return

        if name == "wayback":
            wb_file = self.config.output_dir / "recon" / "wayback_gau_urls.txt"
            urls: list[str] = []
            if wb_file.is_file():
                urls = [line.strip() for line in wb_file.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.config.collected_urls.extend(urls)
            self.results.modules_run.append("wayback")
            log.info("Resumed 'wayback': %s historical URLs restored from previous run", len(urls))
            return

        vulns = self.db.load_vulns(self.scan_id, module=name)
        self.results.vulnerabilities.extend(vulns)
        self.results.modules_run.append(name)
        log.info("Resumed '%s': %s findings restored from previous run", name, len(vulns))

    def _write_resume_cfg(self) -> None:
        try:
            RESUME_CFG_PATH.write_text(
                "target={}\n"
                "output_dir={}\n"
                "scan_id={}\n"
                "base_url={}\n"
                "modules={}\n"
                "completed_modules={}\n".format(
                    self.config.target,
                    self.config.output_dir,
                    self.scan_id,
                    self.config.base_url or "",
                    ",".join(self.config.modules),
                    ",".join(self.results.modules_run),
                ),
                encoding="utf-8",
            )
        except OSError as e:
            log.warning("Could not write resume.cfg: %s", e)

    def _clear_resume_cfg(self) -> None:
        """Remove resume.cfg once this scan finished all its modules and
        generated reports — only if it still belongs to this scan (a
        --target-file batch run may have started a newer resume.cfg for the
        next target by the time this one finishes)."""
        try:
            if not RESUME_CFG_PATH.is_file():
                return
            cfg = _parse_resume_cfg(RESUME_CFG_PATH.read_text(encoding="utf-8"))
            if cfg.get("target") == self.config.target and cfg.get("scan_id") == self.scan_id:
                RESUME_CFG_PATH.unlink()
                log.info("Scan completed successfully — resume.cfg cleared")
        except OSError as e:
            log.warning("Could not clear resume.cfg: %s", e)

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
        """Subset of URLs for slow tools (dalfox, sqlmap, api_leak, dirbust)."""
        all_t = self._get_scan_targets()
        cap = max(1, self.config.max_deep_scan_urls)
        return all_t[:cap]

    def _get_host_root_targets(self) -> list[str]:
        """Unique scheme+host roots from alive assets — used by modules that
        test per-host configuration rather than per-URL content (nikto,
        header_check, cors, tls, cdn_bypass)."""
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


def _host_from_url(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _resolve_base_url(
    target: str,
    plan_base_url: str | None,
    cli_base_url: str | None,
) -> str | None:
    """Use plan base_url only when its host matches target; CLI --base-url wins."""
    if cli_base_url:
        return cli_base_url.rstrip("/")
    if plan_base_url and _host_from_url(plan_base_url) == target.lower():
        return plan_base_url.rstrip("/")
    if plan_base_url:
        log.warning(
            "Ignoring plan base_url %s (host does not match target %s)",
            plan_base_url,
            target,
        )
    return None


def _parse_resume_cfg(text: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        data[k.strip()] = v.strip()
    return data


def _load_targets_file(path: Path) -> list[str]:
    if not path.is_file():
        log.error("Target file not found: %s", path)
        sys.exit(1)
    targets: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        targets.append(line)
    if not targets:
        log.error("Target file %s contained no targets", path)
        sys.exit(1)
    return targets


def parse_args():
    root = Path(__file__).resolve().parent
    default_plan = root / "assets" / "red_plan.json"

    p = argparse.ArgumentParser(description="RedScanner — red-team plan driven web assessment")
    p.add_argument("--target", "-t", help="Target domain (default: domain in red plan JSON)")
    p.add_argument(
        "--target-file",
        type=Path,
        help="Batch-scan targets from a text file, one hostname per line ('#' comments allowed). "
        "Runs the same profile/module set against each target sequentially. Mutually exclusive with --resume.",
    )
    p.add_argument(
        "--base-url",
        help="Override scan base URL (default: plan base_url when host matches -t, else http://<target>)",
    )
    p.add_argument(
        "--plan-file",
        "--plan",
        dest="plan_file",
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
        help="Max URLs for dalfox, sqlmap, api_leak, dirbust (nuclei uses full list)",
    )
    p.add_argument(
        "--strict-domain",
        action="store_true",
        help="Only keep findings whose URL host matches -t or is its subdomain (also set strict_domain_reports in red_plan.json)",
    )
    p.add_argument(
        "--no-header-check",
        action="store_true",
        help="Skip the HTTP security header check module",
    )
    p.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "info"],
        help="Exit with code 2 if any finding is at or above this severity "
        "(for CI/CD gating). Default: no gating, always exit 0.",
    )
    p.add_argument(
        "--resume",
        action="store_true",
        help="Resume the last interrupted scan from resume.cfg (written after every completed module). "
        "Mutually exclusive with --target-file.",
    )
    return p.parse_args()


def _build_config(args, plan, profiles, target: str, output_dir: Path, resume_skip: set[str] | None = None,
                   modules_override: list[str] | None = None, base_url_override: str | None = None) -> ScanConfig:
    """Build a ScanConfig for one target. Shared by the single-target,
    --resume, and --target-file code paths in main()."""
    if modules_override is not None:
        modules = modules_override
    elif args.modules:
        modules = [m.strip() for m in args.modules.split(",") if m.strip()]
    else:
        profile_name = args.profile or "full"
        modules = profiles.get(profile_name)
        if not modules:
            log.error("Unknown profile %r. Use --list-profiles.", profile_name)
            sys.exit(1)

    bu = plan.get("base_url")
    plan_base_url = bu.strip() if isinstance(bu, str) and bu.strip() else None
    cli_base_url = args.base_url.strip() if isinstance(args.base_url, str) and args.base_url.strip() else None
    if cli_base_url:
        base_url = _resolve_base_url(target, plan_base_url, cli_base_url)
    elif base_url_override:
        # --resume without an explicit --base-url: reuse whatever base_url
        # the interrupted run resolved to, instead of silently re-resolving
        # (which can flip https -> http if the plan's base_url no longer
        # matches, changing scan behavior mid-resume).
        base_url = base_url_override
    else:
        base_url = _resolve_base_url(target, plan_base_url, cli_base_url)

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

    def _truthy(val) -> bool:
        if val is True:
            return True
        if isinstance(val, str):
            return val.strip().lower() in ("1", "true", "yes", "on")
        return False

    strict_domain = args.strict_domain or _truthy(plan.get("strict_domain_reports"))

    nuclei_extra: list[str] = []
    raw_extra = plan.get("nuclei_extra_args")
    if isinstance(raw_extra, list):
        nuclei_extra = [str(x).strip() for x in raw_extra if str(x).strip()]

    nuclei_tags: list[str] = []
    raw_tags = plan.get("nuclei_tags")
    if isinstance(raw_tags, list):
        nuclei_tags = [str(x).strip() for x in raw_tags if str(x).strip()]

    nuclei_exclude_tags: list[str] = []
    raw_etags = plan.get("nuclei_exclude_tags")
    if isinstance(raw_etags, list):
        nuclei_exclude_tags = [str(x).strip() for x in raw_etags if str(x).strip()]
    if not nuclei_exclude_tags:
        nuclei_exclude_tags = ["dos", "fuzz"]

    header_check_enabled = not args.no_header_check
    if not args.no_header_check:
        if plan.get("header_check_enabled") is False or (
            isinstance(plan.get("header_check_enabled"), str)
            and not _truthy(plan.get("header_check_enabled"))
        ):
            header_check_enabled = False

    cdn_origin_ip = plan.get("cdn_origin_ip")
    cdn_origin_ip = cdn_origin_ip.strip() if isinstance(cdn_origin_ip, str) else ""

    dirbust_wordlist = plan.get("dirbust_wordlist")
    dirbust_wordlist = dirbust_wordlist.strip() if isinstance(dirbust_wordlist, str) else ""

    dirbust_extensions: list[str] = []
    raw_ext = plan.get("dirbust_extensions")
    if isinstance(raw_ext, list):
        dirbust_extensions = [str(x).strip() for x in raw_ext if str(x).strip()]

    kwargs = dict(
        target=target,
        modules=modules,
        output_dir=output_dir,
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
        strict_domain_reports=strict_domain,
        nuclei_extra_args=nuclei_extra,
        nuclei_tags=nuclei_tags,
        nuclei_exclude_tags=nuclei_exclude_tags,
        header_check_enabled=header_check_enabled,
        cdn_origin_ip=cdn_origin_ip,
        resume_skip=resume_skip or set(),
    )
    if dirbust_wordlist:
        kwargs["dirbust_wordlist"] = dirbust_wordlist
    if dirbust_extensions:
        kwargs["dirbust_extensions"] = dirbust_extensions

    return ScanConfig(**kwargs)


async def _run_targets(jobs: list[tuple[ScanConfig, str | None]]) -> list[ScanResult]:
    """Run one or more (config, scan_id) jobs sequentially in a single event loop."""
    results: list[ScanResult] = []
    for config, scan_id in jobs:
        scanner = RedScanner(config, scan_id=scan_id)
        results.append(await scanner.run())
    return results


def _fail_on_exit_code(results: list[ScanResult], threshold: str | None) -> int:
    """Return an exit code for CI gating: non-zero when any finding is at or
    above the --fail-on severity threshold across all scanned targets."""
    if not threshold:
        return 0
    limit = SEVERITY_RANK.get(threshold, 4)
    worst: tuple[str, str, str] | None = None  # (severity, target, vuln_type)
    total = 0
    for r in results:
        for v in r.vulnerabilities:
            rank = SEVERITY_RANK.get(v.severity, 4)
            if rank <= limit:
                total += 1
                if worst is None or rank < SEVERITY_RANK.get(worst[0], 4):
                    worst = (v.severity, r.target, v.vuln_type)
    if total:
        log.error(
            "--fail-on %s: %s finding(s) at or above threshold (worst: %s %s on %s) — exiting 2",
            threshold, total, worst[0], worst[2], worst[1],
        )
        return 2
    log.info("--fail-on %s: no findings at or above threshold — exiting 0", threshold)
    return 0


def main():
    args = parse_args()
    plan = load_red_plan(args.plan_file)
    profiles = merge_profiles(PROFILES, plan)

    if args.list_profiles:
        print("Profiles:")
        for name, mods in sorted(profiles.items()):
            print(f"  {name}: {', '.join(mods)}")
        return

    if args.resume and args.target_file:
        log.error("--resume and --target-file cannot be combined")
        sys.exit(1)

    if args.resume:
        if not RESUME_CFG_PATH.is_file():
            log.error("No resume.cfg found at %s — nothing to resume", RESUME_CFG_PATH)
            sys.exit(1)
        cfg = _parse_resume_cfg(RESUME_CFG_PATH.read_text(encoding="utf-8"))
        target = cfg.get("target", "")
        output_dir_str = cfg.get("output_dir", "")
        scan_id = cfg.get("scan_id") or None
        stored_base_url = cfg.get("base_url") or None
        completed = {m.strip() for m in cfg.get("completed_modules", "").split(",") if m.strip()}
        stored_modules = [m.strip() for m in cfg.get("modules", "").split(",") if m.strip()]

        if not target or not output_dir_str:
            log.error("resume.cfg at %s is malformed (missing target/output_dir)", RESUME_CFG_PATH)
            sys.exit(1)

        if args.target and args.target.strip() and args.target.strip() != target:
            log.warning(
                "Ignoring --target %s — resuming previous scan of %s instead",
                args.target, target,
            )

        # Explicit --profile/--modules on the CLI override the stored module
        # list; otherwise resume exactly what the interrupted run requested.
        modules_override = None
        if not args.modules and not args.profile:
            if not stored_modules:
                log.error("resume.cfg has no stored module list and no --profile/--modules given")
                sys.exit(1)
            modules_override = stored_modules

        config = _build_config(
            args, plan, profiles, target, Path(output_dir_str),
            resume_skip=completed, modules_override=modules_override,
            base_url_override=stored_base_url,
        )
        log.info("Resuming scan %s for %s (%s/%s modules already completed)",
                  scan_id, target, len(completed), len(config.modules))
        results = asyncio.run(_run_targets([(config, scan_id)]))
        sys.exit(_fail_on_exit_code(results, args.fail_on))

    if args.target_file:
        targets = _load_targets_file(args.target_file)
        if args.target and args.target.strip():
            log.info("--target ignored because --target-file was also given")
        jobs = []
        for t in targets:
            output_dir = Path(args.output) / t / datetime.now().strftime("%Y%m%d_%H%M%S")
            config = _build_config(args, plan, profiles, t, output_dir)
            jobs.append((config, None))
        log.info("Batch scan: %s targets from %s", len(jobs), args.target_file)
        results = asyncio.run(_run_targets(jobs))
        sys.exit(_fail_on_exit_code(results, args.fail_on))

    target = (args.target or plan.get("domain") or "").strip()
    if not target:
        log.error('Set --target or add "domain" to %s', args.plan_file)
        sys.exit(1)

    output_dir = Path(args.output) / target / datetime.now().strftime("%Y%m%d_%H%M%S")
    config = _build_config(args, plan, profiles, target, output_dir)
    results = asyncio.run(_run_targets([(config, None)]))
    sys.exit(_fail_on_exit_code(results, args.fail_on))


if __name__ == "__main__":
    main()
