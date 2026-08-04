# ============================================================
# core/config.py — RedScanner v0.3
# ============================================================

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional


@dataclass
class ScanConfig:
    target: str
    modules: list[str]
    output_dir: Path
    threads: int = 10
    timeout: int = 30
    rate_limit: int = 50  # nuclei requests per second

    # Engagement metadata (from assets/red_plan.json)
    base_url: Optional[str] = None
    manual_phases: list[dict[str, Any]] = field(default_factory=list)
    research_references: list[str] = field(default_factory=list)
    plan_title: Optional[str] = None
    plan_description: Optional[str] = None
    methodology_frameworks: list[str] = field(default_factory=list)

    # URLs collected by wayback/gau, merged into scan surface
    collected_urls: list[str] = field(default_factory=list)
    max_wayback_urls: int = 500
    max_nikto_hosts: int = 8
    max_deep_scan_urls: int = 25  # cap for dalfox, sqlmap, api_leak, dirbust

    # Scope / filtering
    strict_domain_reports: bool = False  # drop findings outside target / its subdomains

    # Nuclei template control
    nuclei_extra_args: list[str] = field(default_factory=list)
    nuclei_tags: list[str] = field(default_factory=list)
    nuclei_exclude_tags: list[str] = field(default_factory=lambda: ["dos", "fuzz"])

    # Header check module (v0.2+)
    header_check_enabled: bool = True

    # ── v0.3 additions ───────────────────────────────────────

    # CDN bypass scanner: origin IP (from red_plan.json cdn_origin_ip)
    cdn_origin_ip: str = ""

    # Directory brute-force: optional wordlist override and extensions
    dirbust_wordlist: str = ""
    dirbust_extensions: list[str] = field(default_factory=lambda: ["php", "html", "txt", "bak", "zip", "sql"])

    # Scan resume: set of module names already completed in a previous run
    resume_skip: set[str] = field(default_factory=set)

    # ── tool paths (auto-detected; override in red_plan.json or env) ─

    subfinder_path: str = "subfinder"
    httpx_path: str = "httpx"
    naabu_path: str = "naabu"
    nuclei_path: str = "nuclei"
    dalfox_path: str = "dalfox"
    sqlmap_path: str = "sqlmap"
    xcrawl3r_path: str = "xcrawl3r"
    nikto_path: str = "nikto"
    assetfinder_path: str = "assetfinder"
    waybackurls_path: str = "waybackurls"
    gau_path: str = "gau"
    # v0.3 new tools
    gobuster_path: str = "gobuster"
    ffuf_path: str = "ffuf"
    testssl_path: str = "testssl.sh"
