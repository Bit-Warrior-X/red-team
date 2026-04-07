
# ============================================================
# core/config.py
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
    rate_limit: int = 50  # requests per second

    # Engagement (from assets/red_plan.json)
    base_url: Optional[str] = None
    manual_phases: list[dict[str, Any]] = field(default_factory=list)
    research_references: list[str] = field(default_factory=list)
    plan_title: Optional[str] = None
    plan_description: Optional[str] = None
    methodology_frameworks: list[str] = field(default_factory=list)

    # URLs from wayback/gau merged into scan surface (deduped in main)
    collected_urls: list[str] = field(default_factory=list)
    max_wayback_urls: int = 500
    max_nikto_hosts: int = 8
    max_deep_scan_urls: int = 25  # dalfox, sqlmap, api_leak (nuclei uses full surface)

    # Tool paths (auto-detected or overridden)
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