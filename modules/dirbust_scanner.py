# ============================================================
# modules/dirbust_scanner.py — Directory and file enumeration
# Maps to: OWASP WSTG-CONF-05 (Enumerate Infrastructure and
#          Application Admin Interfaces)
# Tools: gobuster (preferred), ffuf (alternative), curl built-in fallback
# ============================================================

from __future__ import annotations

import logging
import os
import re
import shutil

from core.config import ScanConfig
from core.models import Vulnerability
from core.tool_runner import run_tool

log = logging.getLogger("redscanner")

_CVSS: dict[str, float] = {
    "critical": 9.1,
    "high": 8.2,
    "medium": 5.3,
    "low": 3.1,
    "info": 0.0,
}

# Common wordlist locations (tried in order)
_WORDLISTS = [
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
]

# Paths probed when no external tool / wordlist is available
BUILTIN_PATHS = [
    # Admin / management interfaces
    "/admin", "/admin/", "/administrator", "/administrator/",
    "/admin/login", "/admin/login.php",
    "/manager", "/manager/", "/console", "/console/",
    "/panel", "/panel/", "/dashboard", "/dashboard/",
    "/controlpanel", "/control", "/backend",
    # Authentication
    "/login", "/login.php", "/signin", "/auth",
    # Sensitive files — secrets / source
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/.git", "/.git/config", "/.git/HEAD",
    "/web.config", "/.htaccess", "/.htpasswd",
    "/wp-config.php", "/config.php", "/config.inc.php",
    "/configuration.php", "/settings.php", "/database.php",
    "/app.config", "/appsettings.json",
    # Backups
    "/backup", "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/db.sql", "/database.sql", "/dump.sql", "/db_backup.sql",
    "/site.tar.gz", "/site.zip", "/www.zip",
    # Debug / info disclosure
    "/phpinfo.php", "/info.php", "/test.php",
    "/server-status", "/server-info",
    "/debug", "/debug/", "/test", "/dev", "/staging",
    # Spring Boot / Node actuators
    "/actuator", "/actuator/health", "/actuator/env",
    "/actuator/beans", "/actuator/mappings",
    "/health", "/healthz", "/status", "/metrics", "/prometheus",
    # API endpoints
    "/api", "/api/v1", "/api/v2",
    "/api/v1/users", "/api/v1/admin", "/api/v1/config",
    # Upload / files
    "/upload", "/uploads", "/files", "/static", "/assets",
    # Common files
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/.well-known/security.txt",
]

# HTTP statuses that count as "found" (not just 200)
_FOUND_STATUSES = {200, 204, 301, 302, 307, 401, 403}

# Paths/extensions that are high-value findings
_CRITICAL_PATTERNS = [
    r"/\.env",
    r"/\.git",
    r"/web\.config",
    r"wp-config\.php",
    r"settings\.php",
    r"config\.php",
    r"appsettings\.json",
]
_HIGH_ADMIN = ["/admin", "/administrator", "/manager", "/console", "/panel", "/dashboard", "/controlpanel", "/backend"]
_HIGH_BACKUP = [".zip", ".tar.gz", ".sql", ".bak", ".dump", ".tar"]
_MEDIUM_DEBUG = ["/debug", "/test", "/dev", "/staging", "/phpinfo", "/info.php", "/server-status", "/actuator"]


def _classify(path: str, status: int) -> tuple[str, float, str]:
    """Return (severity, cvss_score, vuln_type) for a discovered path."""
    p = path.lower()

    if status not in _FOUND_STATUSES:
        return "info", 0.0, "path_probed"

    for pattern in _CRITICAL_PATTERNS:
        if re.search(pattern, p):
            if status in (200, 204, 301, 302, 307):
                return "critical", _CVSS["critical"], "sensitive_file_exposed"
            if status in (401, 403):
                # Server actively denied access — the path exists (worth
                # noting) but this is the secure outcome, not an exposure.
                # (Previously misclassified as "critical" for any of
                # _FOUND_STATUSES, which flagged correctly-blocked .env/.git
                # paths as if the secrets were actually served.)
                return "low", 3.1, "sensitive_path_blocked"

    for prefix in _HIGH_ADMIN:
        if p.startswith(prefix):
            if status in (200, 301, 302, 307):
                return "high", 7.5, "admin_interface_found"
            if status == 403:
                return "medium", 5.3, "admin_interface_forbidden"

    for ext in _HIGH_BACKUP:
        if p.endswith(ext) and status == 200:
            return "high", _CVSS["high"], "backup_file_found"

    for prefix in _MEDIUM_DEBUG:
        if p.startswith(prefix) and status in (200, 301, 302):
            return "medium", _CVSS["medium"], "debug_endpoint_found"

    if status in (200, 301, 302):
        return "low", _CVSS["low"], "interesting_path_found"

    return "info", _CVSS["info"], "path_accessible"


def _remediation(path: str, vuln_type: str) -> str:
    p = path.lower()
    if ".env" in p or ".git" in p:
        return (
            "Immediately block access: add 'location ~ /\\. { deny all; }' in nginx.conf. "
            "Rotate any secrets that may have been exposed."
        )
    if "admin" in p or "manager" in p or "console" in p:
        return (
            "Restrict admin interfaces by IP allowlist or VPN. "
            "Enable multi-factor authentication on all admin accounts."
        )
    if any(ext in p for ext in [".zip", ".sql", ".bak", ".tar", ".dump"]):
        return (
            "Delete backup and database dump files from the web root. "
            "Store backups outside the document root or on a separate, access-controlled storage."
        )
    if "phpinfo" in p or "server-status" in p:
        return "Disable phpinfo pages and server-status in the production nginx/PHP config."
    if "debug" in p or "actuator" in p:
        return "Disable or restrict management and actuator endpoints in production. Apply IP filtering or authentication."
    return "Review this path and remove or restrict access if not required for normal operation."


class DirbustScanner:
    """
    Enumerates directories and files on HTTP targets.
    Priority: gobuster → ffuf → built-in curl path list.
    """

    def __init__(self, config: ScanConfig):
        self.config = config

    async def run(self, targets: list[str]) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        for url in targets:
            base = url.rstrip("/")
            if shutil.which(self.config.gobuster_path):
                v = await self._gobuster(base)
            elif shutil.which(self.config.ffuf_path):
                v = await self._ffuf(base)
            else:
                log.info(
                    "dirbust: gobuster/ffuf not on PATH — using built-in path list "
                    "(install gobuster for full enumeration)"
                )
                v = await self._builtin_probe(base)
            vulns.extend(v)
        log.info("Dirbust scanner reported %s findings", len(vulns))
        return vulns

    # ── gobuster ─────────────────────────────────────────────

    async def _gobuster(self, base_url: str) -> list[Vulnerability]:
        wordlist = self._find_wordlist()
        if not wordlist:
            log.warning("dirbust: no wordlist found — falling back to built-in paths")
            return await self._builtin_probe(base_url)

        ext = ",".join(self.config.dirbust_extensions) if self.config.dirbust_extensions else "php,html,txt,bak,zip,sql"
        result = await run_tool(
            [
                self.config.gobuster_path, "dir",
                "-u", base_url,
                "-w", wordlist,
                "-x", ext,
                "-q", "--no-progress",
                "-t", str(min(self.config.threads, 20)),
                "--timeout", f"{self.config.timeout}s",
                "-s", "200,204,301,302,307,401,403",
            ],
            timeout=300,
        )
        return self._parse_gobuster(base_url, result["stdout"])

    def _parse_gobuster(self, base_url: str, stdout: str) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        for line in stdout.splitlines():
            # Format: /path  (Status: 200) [Size: 1234]
            m = re.match(r"^(/\S+)\s+\(Status:\s*(\d+)\)", line.strip())
            if not m:
                continue
            path, status = m.group(1), int(m.group(2))
            if status == 404:
                continue
            sev, cvss, vtype = _classify(path, status)
            if sev not in ("critical", "high", "medium", "low"):
                continue
            vulns.append(Vulnerability(
                vuln_type=vtype,
                severity=sev,
                url=base_url + path,
                parameter=path,
                description=f"Path '{path}' returned HTTP {status} (gobuster)",
                remediation=_remediation(path, vtype),
                evidence=f"GET {path} → HTTP {status}",
                tool="gobuster",
                cvss_score=cvss,
            ))
        return vulns

    # ── ffuf ──────────────────────────────────────────────────

    async def _ffuf(self, base_url: str) -> list[Vulnerability]:
        wordlist = self._find_wordlist()
        if not wordlist:
            log.warning("dirbust: no wordlist found — falling back to built-in paths")
            return await self._builtin_probe(base_url)

        result = await run_tool(
            [
                self.config.ffuf_path,
                "-u", f"{base_url}/FUZZ",
                "-w", wordlist,
                "-mc", "200,204,301,302,307,401,403",
                "-t", str(min(self.config.threads, 20)),
                "-s",           # silent mode (no banner)
                "-of", "json",  # machine-readable output
            ],
            timeout=300,
        )
        return self._parse_ffuf(base_url, result["stdout"])

    def _parse_ffuf(self, base_url: str, stdout: str) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        try:
            import json as _json
            data = _json.loads(stdout)
            results = data.get("results", [])
        except Exception:
            # Fallback: parse plain text output line by line
            results = []
            for line in stdout.splitlines():
                m = re.search(r"(\S+)\s+\[Status:\s*(\d+)", line)
                if m:
                    results.append({"input": {"FUZZ": m.group(1)}, "status": int(m.group(2))})

        for item in results:
            if isinstance(item, dict):
                fuzz_val = item.get("input", {}).get("FUZZ") or item.get("url", "")
                path = "/" + str(fuzz_val).lstrip("/")
                status = int(item.get("status", 0))
            else:
                continue
            if status == 404:
                continue
            sev, cvss, vtype = _classify(path, status)
            if sev not in ("critical", "high", "medium", "low"):
                continue
            vulns.append(Vulnerability(
                vuln_type=vtype,
                severity=sev,
                url=base_url + path,
                parameter=path,
                description=f"Path '{path}' returned HTTP {status} (ffuf)",
                remediation=_remediation(path, vtype),
                evidence=f"GET {path} → HTTP {status}",
                tool="ffuf",
                cvss_score=cvss,
            ))
        return vulns

    # ── built-in curl fallback ────────────────────────────────

    async def _builtin_probe(self, base_url: str) -> list[Vulnerability]:
        """Check BUILTIN_PATHS one by one with curl. No external tool required."""
        vulns: list[Vulnerability] = []
        for path in BUILTIN_PATHS:
            url = base_url + path
            result = await run_tool(
                [
                    "curl", "-s", "-o", "/dev/null",
                    "-w", "%{http_code}",
                    "--max-time", "8",
                    "--max-redirs", "3",
                    "-A", "Mozilla/5.0",
                    url,
                ],
                timeout=12,
            )
            status_str = result["stdout"].strip()
            try:
                status = int(status_str)
            except ValueError:
                continue

            if status == 404 or status == 0:
                continue

            sev, cvss, vtype = _classify(path, status)
            if sev not in ("critical", "high", "medium", "low"):
                continue

            vulns.append(Vulnerability(
                vuln_type=vtype,
                severity=sev,
                url=url,
                parameter=path,
                description=f"Path '{path}' returned HTTP {status}",
                remediation=_remediation(path, vtype),
                evidence=f"GET {path} → HTTP {status}",
                tool="dirbust_scanner",
                cvss_score=cvss,
            ))
        return vulns

    # ── util ─────────────────────────────────────────────────

    def _find_wordlist(self) -> str | None:
        if self.config.dirbust_wordlist and os.path.exists(self.config.dirbust_wordlist):
            return self.config.dirbust_wordlist
        for path in _WORDLISTS:
            if os.path.exists(path):
                return path
        return None
