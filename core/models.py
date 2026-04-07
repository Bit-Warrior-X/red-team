# ============================================================
# core/models.py
# ============================================================

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

@dataclass
class Asset:
    """A discovered subdomain, URL, or service."""
    url: str
    ip: Optional[str] = None
    port: Optional[int] = None
    status_code: Optional[int] = None
    title: Optional[str] = None
    tech: list[str] = field(default_factory=list)
    alive: bool = False
    source: str = ""  # which tool discovered it


@dataclass
class Vulnerability:
    """A single vulnerability finding."""
    vuln_type: str          # xss, sqli, ssti, lfi, misconfig, info_leak, etc.
    severity: str           # critical, high, medium, low, info
    url: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    evidence: Optional[str] = None
    description: str = ""
    remediation: str = ""
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    tool: str = ""          # which tool found it
    raw_output: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class ScanResult:
    """Complete result of a scan run."""
    scan_id: str
    target: str
    started_at: datetime
    modules_run: list[str] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    assets_discovered: list[Asset] = field(default_factory=list)
    finished_at: Optional[datetime] = None

    # Enriched attack surface (for reporting)
    domains: list[str] = field(default_factory=list)
    urls_crawled: list[str] = field(default_factory=list)
    urls_historical: list[str] = field(default_factory=list)
    urls_scan_surface: list[str] = field(default_factory=list)
    open_ports: list[dict[str, Any]] = field(default_factory=list)
